# Adversarial review of the locked Ory architecture

## Summary

Reviewed the 20 locked decisions against current upstream documentation
(May 2026 snapshot). Two CRITICAL gaps would block a clean build as written:
the AAL2 step-up enforcement is global rather than per-route, and the
glauth plugin scaffolding the design names ("glauth-kratos-backend"
implementing "Backend interface") doesn't match glauth's actual
v2.4/v2.5 plugin shape (Handler interface, Go `plugin` package). Six
HIGH issues require config or design changes (skip_consent semantics
miscast, recovery via magic link being deprecated, Hydra schema
migrations not automatic, Kratos courier singleton constraint, system
secret rotation rules, and Astro 6 hybrid-mode bug). Eleven MEDIUM and
six LOW items round out the operational gotchas.

## CRITICAL: would prevent the architecture from working

### C1. AAL2 step-up is global, not per-route

The locked decision (#5) says "AAL2 step-up enforced on `/admin/*`
routes." The Kratos config keys actually available are
`session.whoami.required_aal`, `selfservice.flows.settings.required_aal`,
and `selfservice.flows.login.required_aal`. None of these are
per-route; all are global to the Kratos process. From the step-up auth
docs: "set the required authentication model for these
operations/endpoints: User sign-in / `/sessions/whoami` endpoint" and
"Self-service user settings."

If we set `session.whoami.required_aal: highest_available` to satisfy
admin-route AAL2, every `whoami` call returns `null` for the identity
on AAL1 sessions belonging to MFA-enabled users (Q1 doc, hook.go
lines 248-256). That breaks the LDAP bridge BIND path (it relies on
populated `session.identity` to resolve the bind DN) for any family
member who has MFA enabled.

The actual mechanism Kratos exposes for per-resource step-up is the
`?aal=aal2` query parameter on the login init URL: the protected
service redirects unauthenticated-at-AAL2 users to
`auth.dunn.dev/self-service/login/browser?aal=aal2&return_to=...`,
Kratos performs the step-up, then redirects back. This is documented
in step-up-authentication but it is a per-request redirect dance
driven by the protected app, not a Kratos config setting.

For us this means:
- `/admin/*` AAL2 is implementable but only by having Caddy (or the
  Astro UI itself) detect "session present, AAL=1" and 302 to the
  step-up login URL with `aal=aal2`. Not a config flag.
- The Caddy `forward_auth` directive returns 2xx on AAL1 and we have
  to do the AAL gating in the protected app or in a custom Caddy
  matcher that inspects the JSON body of `/sessions/whoami`. Caddy
  forward_auth is binary (2xx pass / non-2xx fail); it cannot read
  AAL out of the response without a `handle_response` block.

Sources:
- [step-up authentication](https://www.ory.com/docs/kratos/mfa/step-up-authentication)
- [forward_auth directive](https://caddyserver.com/docs/caddyfile/directives/forward_auth)
- Q1 doc, `hook.go` lines 248-256

### C2. glauth plugin shape in the locked decision doesn't match upstream

Decision #11 names "glauth plugin (`glauth-kratos-backend`) implementing
glauth's Backend interface, calling Kratos public API for BIND."

glauth's actual plugin contract as of v2.4 / v2.5 is the **Handler**
interface (not "Backend"), composed of the go-ldap interfaces:

```go
type Handler interface {
    ldap.Binder    // Bind
    ldap.Searcher  // Search
    ldap.Closer    // Close
    ldap.Adder     // Add (write support)
    ldap.Modifier  // Modify
    ldap.Deleter   // Delete
    HelperMaker    // FindUser, FindGroup
}
```

Plugins are compiled as Go `.so` files via Go's `plugin` package and
loaded at glauth start. This is the same constraint glauth has had
since v2.0:

- Linux/macOS only. Windows is incompatible with Go's `plugin` package.
- The compiled .so must match the exact Go version, glauth version,
  and dependency versions used to build glauth itself. Any drift on
  any of these means the plugin won't load.
- v2.5.0 (April 2026) added "embedded plugins" as an alternative,
  which lets you build a glauth binary with the plugin baked in
  rather than loaded at runtime. This is the better path for us
  because it sidesteps the binary-version-coupling pain.

Practical implications for the locked design:
- Naming: "Backend interface" is wrong. It's "Handler interface."
- Method set: we have to implement Bind, Search, Close at minimum,
  plus the Helper methods (FindUser, FindGroup). The HelperMaker
  contract is non-trivial because glauth's group/user model has to
  be filled in even for a Kratos-backed handler.
- Loading: if we go the runtime-`.so` path, our plugin container has
  to be rebuilt whenever glauth itself rebuilds. If we go the
  embedded-plugin path (recommended given v2.5 support), our build
  artifact is "glauth-with-kratos-handler" rather than
  "glauth + plugin.so".
- The locked-decision "co-locate bridge in Jellyfin pod" (#13) is
  fine, but the bridge artifact is a glauth binary with our handler
  embedded, not "glauth + a plugin file."

Sources:
- [glauth Handler interface](https://pkg.go.dev/github.com/glauth/glauth/v2/pkg/handler)
- [glauth v2.5.0 release notes](https://github.com/glauth/glauth/releases) (embedded plugins)
- Q1/Q2 docs (LDAP bridge feasibility)

## HIGH: would require config changes or design adjustments

### H1. Recovery via magic link is deprecated; switch to recovery code

Decision #15 names "Kratos email magic link." The current Kratos docs
explicitly mark the link method as legacy: "should be considered
deprecated and is set to be removed in future releases." The
recommended method is the **code** strategy (one-time code), not the
**link** strategy.

Reasons given in the docs:
- Email virus scanners auto-open links and invalidate them.
- Mobile flows misbehave when the link opens in a different browser
  than the one that initiated recovery.
- Cross-browser confusion is worse with links than with codes the
  user types into the originating tab.

For us this changes the recovery decision to "Kratos one-time code
(via Fastmail SMTP) AND admin-issued recovery URL." The admin-issued
URL path is separate (admin API, no email), so that part stays.

Default code/link lifespan is 1 hour, configurable via
`selfservice.methods.code.config.lifespan` (or `link.config.lifespan`
for the legacy strategy).

Sources:
- [Account recovery and password reset](https://www.ory.com/docs/kratos/self-service/flows/account-recovery-password-reset)

### H2. Hydra schema migrations are not automatic

Hydra's docs are explicit: "Hydra doesn't create the database schema
automatically. You must run migrations before starting the server and
after every upgrade." This is `hydra migrate sql -e`.

Implication for the locked design: starting Hydra against a fresh
Postgres without first running `hydra migrate sql` produces a
crash-loop with schema-not-found errors. Same for every Hydra version
upgrade. The compose / pyinfra deployment story has to include a
migrate job that runs before `hydra serve`.

Kratos has the same model (`kratos migrate sql`) but its docs are
softer about the requirement. Both must run before serving.

Sources:
- [Hydra dependencies and environment](https://www.ory.com/docs/hydra/self-hosted/dependencies-environment)

### H3. Kratos courier must run as a singleton

The mail courier worker "must run as a singleton." If we run multiple
Kratos replicas (we won't at this scale, but we might via systemd
restart loops), every replica running with the default
`--watch-courier` will deliver duplicate emails. The supported pattern
for >1 instance is: turn off `--watch-courier` on the serving
instances and run a separate `kratos courier watch` process.

For our deployment (single carmine pod, single Kratos process) the
default `--watch-courier` works, but the assumption of singleton is
load-bearing. If we ever scale to two pods we'll silently double up
recovery emails until we notice.

Recommended: document this constraint loudly in the carmine deploy
spec and don't add a second Kratos replica without separating courier.

Sources:
- [Mail courier (self-hosted)](https://www.ory.com/docs/kratos/self-hosted/mail-courier-selfhosted)

### H4. Hydra system secret cannot be rotated; cookie secret can

The Hydra `secrets.system` value (`SECRETS_SYSTEM` env var) "can only
be set against a fresh database. Key rotation is not supported. This
secret is used to encrypt the database and needs to be set to the
same value every time the process (re-)starts."

If we don't set it explicitly Hydra generates a random one and "emits
[it] to the logs. Note this down, otherwise you won't be able to
restart Hydra."

Implication:
- The secret must be generated up-front, stored in our secret manager
  (sops? 1Password connect?), and treated as immutable for the life
  of the Hydra database. Losing it means rebuilding the Hydra DB
  from scratch and re-registering all 16 OIDC clients.
- `secrets.cookie` is rotatable (prepend new key to list, keep old
  key for a window, drop old key after sessions expire) but the
  rotation must use the prepend-then-drop pattern; replacing the
  list invalidates every signed cookie.

The locked decision doesn't call out secret management. Add it.

Sources:
- [Hydra deployment config](https://www.ory.com/docs/hydra/self-hosted/configure-deploy)
- [Hydra secrets and key rotation](https://www.ory.com/docs/hydra/self-hosted/secrets-key-rotation)

### H5. skip_consent does not bypass authentication; it bypasses the consent UI only

Decision #8 plus the implication "consent is a transparent server-side
hop" needs careful reading. `skip_consent: true` on a Hydra client
means: "after the user authenticates, do not render a consent screen;
auto-grant the requested scopes." It does **not** mean "no user
authentication required."

The flow with `skip_consent=true`:
1. App redirects user to Hydra (`/oauth2/auth`).
2. Hydra checks for an active login session. If none, redirects to
   our login UI. The user must authenticate via Kratos here.
3. After login, Hydra fires the consent flow. With `skip_consent=true`
   on the client, our consent endpoint sees `client.skip_consent: true`
   and immediately accepts.
4. Hydra issues tokens.

Risk: a stolen Kratos session cookie at `dunn.dev` lets an attacker
silently get tokens for any of the 16 trusted clients (the consent UI
that would normally surface "this app wants access to..." is
suppressed). At AAL1, no MFA challenge fires.

This is the correct design for first-party trusted apps, but the
threat model needs to acknowledge it: the session cookie is the keys
to all 16 apps. Mitigation strategies:
- Short normal-flow session lifespan (the 90 days in #6 is generous;
  consider 30 days for non-admin).
- Consider AAL2 step-up at OAuth initiation for a subset of
  high-value clients (Vaultwarden, admin tooling) by setting their
  client config to require AAL2 on the login flow.
- Rotate `secrets.cookie` quarterly to invalidate any leaked cookies
  after the rotation window.

Sources:
- [Skip consent](https://www.ory.com/docs/oauth2-oidc/skip-consent)
- [Login and consent flow](https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow)

### H6. Astro 6 hybrid-mode bug for Cloudflare bindings

[withastro/astro#15237](https://github.com/withastro/astro/issues/15237)
(closed January 2026) documents a real conflict: `Astro.locals.runtime.env`
is removed in Astro 6, but the replacement `import { env } from
'cloudflare:workers'` fails the build for prerendered pages. The
issue was assigned to a maintainer and closed but the linked
discussion suggests the fix relies on explicit `prerender: false` on
every SSR route — relying on a global default produces wrong-mode
rendering.

For our locked design: `/auth/consent`, `/auth/login`, and any other
Hydra-talking route must explicitly set `export const prerender = false`.
Static pages should explicitly set `export const prerender = true`.
Don't rely on inference.

Sources:
- [Astro Cloudflare adapter](https://docs.astro.build/en/guides/integrations-guide/cloudflare/)
- [withastro/astro#15237](https://github.com/withastro/astro/issues/15237)

## MEDIUM: edge cases and operational gotchas to plan for

### M1. /sessions/whoami behind forward_auth: shape works, AAL info is in body not status

Caddy's `forward_auth` is binary: 2xx pass, non-2xx redirect. Kratos'
`/sessions/whoami` returns 200 for any active session and 401 for no
session. AAL information is in the JSON body
(`authenticator_assurance_level`), which forward_auth's basic mode
doesn't read.

For AAL2 enforcement on `/admin/*` (decision #5), we need either:
- A `handle_response` block in Caddy that parses the JSON response
  and conditionally redirects to `/self-service/login/browser?aal=aal2`.
  This is supported by Caddy but adds reverse-proxy logic complexity.
- A separate forward_auth target (a small endpoint we host) that
  calls `/sessions/whoami`, inspects AAL, and returns 200/401/302 to
  Caddy based on the policy.

Decision #18 ("Hydra admin API reachability from Workers") should be
broadened to include this: an Astro-server or carmine-resident "auth
policy" endpoint that wraps `whoami` with AAL gating, called by
forward_auth on `/admin/*`.

Sources: forward_auth docs, Q1 doc on AAL.

### M2. Kratos session cleanup is manual; needs scheduled job

Kratos has `kratos cleanup sql` for pruning expired flows and
sessions. It does not run automatically. Hydra has `hydra janitor`
for the same purpose. Both must be scheduled.

For a homelab with 5-25 users this is low pressure but unbounded
growth still happens (login flows, consent challenges, expired
sessions). Recommend:
- systemd timer or Kubernetes CronJob running `kratos cleanup sql -e`
  weekly with default batch size and `--keep-last 168h`.
- Same cadence for `hydra janitor --tokens --requests --grants`.

Sources:
- [kratos cleanup sql](https://www.ory.com/docs/kratos/cli/kratos-cleanup-sql)
- [hydra janitor](https://www.ory.sh/docs/hydra/cli/hydra-janitor)

### M3. CORS allowlist is per-origin literal; wildcard subdomain pattern needs verification

The locked design has origins `auth.dunn.dev` and `home.dunn.dev`.
Q4 doc claims `https://*.dunn.dev` works. The Kratos CORS docs show
both literal and wildcard examples. What the docs don't say is
whether the wildcard support is regex-style or literal-glob; community
issues (`ory/kratos#3583`) show people hitting CORS errors with
wildcards that "should work."

Recommendation: list each origin literally in `allowed_origins`. With
16 apps that's 16 entries, but it's deterministic. Wildcard-expand
later only after verifying behavior in the lab.

Sources:
- [CORS settings](https://www.ory.com/docs/kratos/guides/setting-up-cors)
- [ory/kratos#3583](https://github.com/ory/kratos/discussions/3583)

### M4. Session cookie domain at dunn.dev means every subdomain receives the cookie

Decision #3 (cookie domain `dunn.dev`) is the right choice for
cross-subdomain sessions. The trade-off: every subdomain on
`dunn.dev` receives the session cookie on every request. Apps with
weak XSS hygiene become session-stealers (HttpOnly mitigates the
basic case, but Service Worker registration on a vulnerable subdomain
can read or proxy the request including cookies).

Mitigation:
- Don't host arbitrary user-controlled subdomains on `dunn.dev`.
  Currently we don't, but if `paste.dunn.dev` (or any user-content
  service) appears later, that's a session-leak vector.
- Use a separate Set-Cookie domain for "low-trust" subdomains if
  ever needed. Kratos config supports this if we run a second
  cookie scope (more complex; defer).
- Treat any subdomain on `dunn.dev` as "in the auth perimeter."
  Document this in the deployment policy for new apps.

Sources:
- [Multi-domain cookies](https://www.ory.com/docs/kratos/guides/multi-domain-cookies)

### M5. WebAuthn rp.id = dunn.dev locks us in permanently

Decision #1 is correct (and Q4 doc covers it) but the consequence
deserves explicit acknowledgment in operational docs: a passkey
registered with `rp.id = dunn.dev` cannot be migrated to a narrower
or different rp.id without invalidating the credential. If we ever
decide to split the auth domain (e.g. move to `id.dunn.dev`-only
passkeys), every existing passkey must be re-registered.

This is a one-way door. Explicitly note it in onboarding.

Sources:
- [Passkey docs](https://www.ory.com/docs/kratos/passwordless/passkeys)
- [WebAuthn RP ID](https://web.dev/articles/webauthn-rp-id)

### M6. Identity schema changes are hard; design for forward compatibility

Kratos docs warn: "Avoid complex identity schemas... The more complex
the schema, the more difficult it is to introduce changes in the
future." The docs do not document a clean migration path for trait
schema evolution. Community practice is:
- Make every new trait optional.
- Never rename traits in-place; add new and migrate.
- Use schema versioning (`schema_id`) and run an admin-side
  migration script that rewrites identities to the new schema id.

The locked decision (#7) lists `{username, email, displayName?, recoveryEmail?}`
plus `metadata_admin.groups[]`. This is reasonable for v0. Add an
explicit "no breaking schema changes" policy: traits are append-only
and renames go through a deprecation cycle.

Sources:
- [Customize identity schema](https://www.ory.com/docs/kratos/manage-identities/customize-identity-schema)

### M7. Recovery email is a single point of failure

Decision #15 (Kratos email recovery + admin-issued recovery URL)
exposes the standard email-as-trust risk. If a family member's
Fastmail/iCloud is compromised, an attacker can:
1. Initiate recovery flow, receive code or link.
2. Reset the password.
3. Log in.

Kratos by default does not require a second factor before allowing
password reset via the recovery flow ("by default this doesn't
require the second MFA factor"). The docs note that "organizations
can configure it to require multi-factor authentication for account
recovery" but the configuration mechanism is not documented in the
recovery page itself.

For us:
- Recovery via email is acceptable for non-admin family.
- For admin (`metadata_admin.groups` includes `admin`), require a
  second factor at recovery time. This needs verification: it's not
  clear from the docs if this can be configured per-identity or only
  globally.
- Admin-issued recovery URL (decision #15's other half) is the safer
  fallback for admin accounts.

Action: investigate whether
`selfservice.flows.recovery.required_aal` or equivalent allows
per-flow AAL2 enforcement on recovery. If not, document admin-recovery
as the only path for admins and disable email recovery for admin
identities at the schema level.

Sources:
- [Account recovery](https://www.ory.com/docs/kratos/self-service/flows/account-recovery-password-reset)

### M8. Bridge co-located in Jellyfin pod has access to Kratos admin API

Decision #11 + #13: the bridge holds a Kratos admin API token and runs
in the Jellyfin pod. If the Jellyfin pod is compromised (Jellyfin has
had auth-bypass and SSRF CVEs in the past), the attacker has admin
API access and can read/modify every identity.

Mitigations to consider:
- Run the bridge in its own pod on a separate network namespace,
  exposing only the LDAP listener to the Jellyfin pod. Modest
  complexity increase, real blast-radius reduction.
- Issue a scoped admin token if Kratos admin API supports
  fine-grained tokens. As of current docs, Kratos admin port is
  unauthenticated by default; "auth" is network isolation. So this
  mitigation reduces to "lock the admin port behind tighter network
  ACL than just-Jellyfin-pod."
- Use Oathkeeper in front of the admin API to enforce JWT-based
  scoped access. Adds a deployment unit but enables principle of
  least privilege.

Decision #13 is fine for v0; the upgrade path to a separate bridge
pod should be documented as an explicit "production hardening" step.

Sources: Q1 doc on Kratos admin API auth; locked decision rationale.

### M9. Hydra admin API exposure: open question (#18) needs a closed-form decision

Decision #18 leaves a real architectural choice open: Hydra admin
either gets exposed as `auth-admin.dunn.dev` with source-IP allowlist,
or the consent service runs on carmine.

Cloudflare Workers egress IPs are not stable enough for a strict
allowlist (Cloudflare publishes ranges but they're large and
shared with every Workers customer). Source-IP allowlisting Workers
to a private origin is fundamentally weak: any Cloudflare customer
can hit the origin.

Recommendation: close this open question by running the consent
service on carmine. Astro Workers becomes a thin redirector that
sends the user to `auth.dunn.dev/auth/consent?...`, and the consent
endpoint itself is an Astro SSR route hosted on carmine (or a small
Go service co-located with Hydra). This avoids exposing the admin
API beyond the carmine host.

Cloudflare Tunnel is a third option: Cloudflare Tunnel from carmine
to a non-public hostname locked to `cloudflared`-only ingress. This
preserves the Workers-runs-Astro shape while keeping admin API off
the public internet.

Sources: Q4 doc, Cloudflare Tunnel docs.

### M10. Kratos passkey strategy native API flow only landed in Hydra v26.2 (March 2026)

From the Hydra changelog, v26.2.0 (March 2026): "Native API flow
support for passkeys." This means passkey registration/auth via the
API flow (not browser flow) is recently added. If our Astro UI uses
API flows for passkey registration on cross-subdomain SPA-style flow,
we must pin Hydra to >= 26.2 (or Kratos equivalent — verify the
matching Kratos version supports the API flow nodes).

Check: which Kratos version added passkey to API flows? The Kratos
v25.4.0 (November 2025) breaking changes don't mention this, but
it's plausible passkeys-on-API-flow needed a corresponding Kratos
change. Verify in the lab before locking the version.

Sources: Hydra changelog v26.2.0; need to verify Kratos changelog.

### M11. Tailscale WebFinger fetch known to be fussy

Q3 doc already cites
[tailscale/tailscale#16155](https://github.com/tailscale/tailscale/issues/16155).
Worth restating as a mitigation guidance: serve the static JRD with
`Content-Type: application/jrd+json`, no trailing newline,
`Access-Control-Allow-Origin: *`, and the issuer string in `href`
must byte-match Hydra's `/.well-known/openid-configuration` issuer
(including trailing-slash handling). One of these slightly off and
Tailscale rejects with "invalid JSON."

Mitigation already in plan: deploy and test with `tailscale up
--login-server=...` against the lab tenant before locking the
configuration.

Sources: Q3 doc, RFC 7033.

## LOW: things to be aware of but not blocking

### L1. Kratos v25.4 (Nov 2025) breaking changes that affect us

- Recovery flow: the `require_verified_address` hook now redirects
  users to a verification flow instead of returning plain errors.
  Affects integration tests; the new shape is the right shape but
  any pre-25.4 test fixtures need updating.
- OIDC registration: node groups for failing fields changed from
  `oidc` to `default`. We don't use OIDC sign-up (we issue Hydra
  tokens, not consume them), so this is informational only.
- `x-total-count` header removed from `GET /admin/sessions`. If we
  build a "list of active sessions" admin view (decision #19's
  audit log), we have to use keyset pagination or a count query;
  don't rely on the header.
- Account linking now returns 400 (was 200) on failure in API mode.
  Test fixtures must be updated.

Sources: Kratos changelog v25.4.0.

### L2. Hydra v26.2 (March 2026) feature: optionally do not store skipped consents

"Optionally do not store skipped consents" is a new flag. If we set
`skip_consent: true` per client and enable this option, Hydra won't
even write a consent record on each token issuance. Saves DB rows.
For us at homelab scale, the storage saving is irrelevant but the
side-effect to audit trail matters: turning it on means we can't
correlate "user got Vaultwarden token at 14:32" with a Hydra DB row.
If we want that correlation, leave the option off.

Sources: Hydra changelog v26.2.0.

### L3. Hydra v25.4 cap on refresh token rotation grace period at 30 days

If we rely on long-lived refresh tokens with rotation grace, the cap
is now 30 days. Probably fine; flagged for awareness.

Sources: Hydra changelog v25.4.0.

### L4. Astro 6 prerender flag must be explicit on every route

Don't rely on a global default for prerender mode. From M1 / H6:
explicit `export const prerender = true` on static, `export const
prerender = false` on SSR routes. Add a lint rule or pre-commit hook
that flags any new `.astro` file without an explicit prerender
declaration.

Sources: Astro docs, withastro/astro#15237.

### L5. RFC 7033 WebFinger is permissive; our static response is fine

The RFC allows JRDs with empty links arrays, missing optional
members, etc. Our planned static response (subject + one link, with
`http://openid.net/specs/connect/1.0/issuer` rel) is well within the
spec. Watch for: `Access-Control-Allow-Origin: *` is the recommended
default and is what Tailscale expects.

Sources: RFC 7033.

### L6. Kratos passkey strategy `rp.origins` is plural; WebAuthn strategy `rp.origin` is singular

Q4 doc already calls this out. Re-flag for the config-writing pass:

- `selfservice.methods.passkey.config.rp.origins` is a list (we want
  this for cross-subdomain).
- `selfservice.methods.webauthn.config.rp.origin` is a single string
  (this is the second-factor security-key strategy; we likely don't
  enable it).

If we accidentally use `origin` (singular) under `passkey`, Kratos
will probably reject the config or silently ignore it. Use the right
key for each strategy.

Sources: Q4 doc; Kratos passkey vs webauthn config schema.

## Recent upstream changes affecting our design

### Kratos changelog (May 2025 - May 2026)

- **v25.4.0 (2025-11-07).** Breaking: recovery `require_verified_address`
  now redirects via verification flow rather than returning errors.
  OIDC registration node groups renamed from `oidc` to `default`.
  Account linking returns 400 (was 200) on API-mode failure.
  `x-total-count` header removed from `GET /admin/sessions`.
- **v26.2.0 (2026-03-20).** Native API flow support for passkeys
  (relevant if our Astro SPA registers passkeys via API flow). Auto
  account linking for Google and Apple. Captcha strategies for
  recovery and verification flows. Faster OIDC login.

Sources: Kratos changelog raw.

### Hydra changelog (May 2025 - May 2026)

- **v25.4.0 (2025-11-07).** Refresh token rotation grace capped at 30
  days. Keyset pagination replaces offset-based across endpoints.
  Case-insensitive user code handling.
- **v26.2.0 (2026-03-20).** "Optionally do not store skipped consents."
  Subject algorithm caching revised to fix incorrect pairwise
  calculations (we use `public`, so this doesn't directly affect us).
  Policy URI validation strengthened during client creation.

Sources: Hydra changelog.

### glauth changelog (May 2025 - May 2026)

- **v2.5.0 (2026-04-19).** Embedded plugins (lets us build a glauth
  binary with the Kratos handler baked in). RISC-V support. OTLP
  tracing. StartTLS / LDAPS feature parity. Fix for "credentials
  leaked on INFO log level" — set log level to WARN or higher in
  production.

Sources: [glauth releases](https://github.com/glauth/glauth/releases).

### Astro Cloudflare adapter (May 2025 - May 2026)

- **v13.3.0 (Astro 6 compatibility).** Pages dropped as deployment
  target; Workers is the only supported path. `astro dev` now uses
  `workerd` runtime. `Astro.locals.runtime.env` removed; replacement
  is `import { env } from 'cloudflare:workers'`. Image service
  default changed to `'cloudflare-binding'`.

Sources: Astro docs.

## Verified-working assumptions

These locked decisions are explicitly supported by current upstream
docs and have no surprises:

- **Decision #1, WebAuthn rp.id = `dunn.dev`.** Spec-compliant; Kratos
  passkey strategy supports `rp.id` at the registrable parent and
  `rp.origins` as a list. Documented at the passkey configuration
  page.
- **Decision #3, cookie domain `dunn.dev` with SameSite=Lax.** Both
  `cookies.domain` and `session.cookie.domain` keys exist in current
  config schema. Multi-domain cookies guide explicitly supports the
  shape where `session.cookie.domain` overrides `cookies.domain`.
- **Decision #4, passkey-preferred + password fallback.** Standard
  Kratos pattern. Both methods can be enabled simultaneously; the UI
  surfaces both options.
- **Decision #6, 90-day session lifespan.** Configurable via
  `session.lifespan`. No upper-bound caveat in docs.
- **Decision #8, OIDC consent skip per client.** `--skip-consent`
  flag during client creation, persists in DB, retrievable via
  `hydra get oauth2-client`.
- **Decision #9, Hydra subject = public.** Default behavior.
- **Decision #10, WebFinger as static JSON.** RFC 7033 allows it;
  Tailscale consumes it; Cloudflare Pages function or Caddy `respond`
  block both work.
- **Decision #12, LDAP DN format `uid=<username>,ou=users,dc=dunn,dc=dev`.**
  Matches Jellyfin LDAP plugin's expectations (Q2 doc). Plugin
  doesn't construct DNs by templating; it searches and binds the
  resolved DN, so the bridge picks the convention.
- **Decision #14, single Postgres with separate kratos/hydra DBs.**
  Standard recommendation. Kratos and Hydra docs both support this
  pattern (separate database within a shared instance).
- **Decision #20, public reachability via DNS-only Cloudflare with
  Envoy SNI router on carmine.** No upstream documentation contradicts
  this; it's an architectural choice unrelated to Ory specifically.

## Recommended pre-build adjustments

1. **Replace "Backend interface" with "Handler interface"** in the
   bridge spec, and choose embedded-plugin (v2.5.0+) over runtime-`.so`
   loading. Naming and shape should match glauth's actual contract.
2. **Reframe AAL2 step-up from "config flag" to "redirect dance."**
   Specify the Caddy `handle_response` configuration or the small
   auth-policy endpoint that gates `/admin/*` based on `whoami` JSON
   body, not just status code.
3. **Replace recovery "magic link" with recovery "code"** in
   decision #15. Document that Kratos's link strategy is deprecated
   and we should use the code strategy from day one.
4. **Add scheduled cleanup jobs** for Kratos and Hydra to the
   deployment plan: `kratos cleanup sql` and `hydra janitor` weekly.
5. **Decide #18 by closing the open question**: run the consent
   service on carmine (or via Cloudflare Tunnel) rather than
   exposing Hydra admin API behind a Workers IP allowlist.
6. **Add `secrets.system` and `secrets.cookie` to the secret
   management plan**, with explicit "system secret is immutable for
   the life of the database" warning.
7. **Add migration job to deployment**: `hydra migrate sql` and
   `kratos migrate sql` must run before the serve commands on every
   deploy.
8. **Add explicit prerender flags to every Astro route** to dodge
   the v6 hybrid-mode bug. Lint or pre-commit check.
9. **Decide on admin-recovery policy**: if email recovery for
   admins is unacceptable, configure or document the admin-issued
   URL path as the only admin recovery option, and disable email
   recovery for `metadata_admin.groups` containing `admin`.
10. **Document the cookie-leak perimeter**: every subdomain on
    `dunn.dev` is in the auth perimeter. New subdomains require
    XSS / Service Worker hygiene review.

## Sources

### Kratos
- https://www.ory.com/docs/kratos/guides/multi-domain-cookies
- https://www.ory.com/docs/kratos/guides/configuring-cookies
- https://www.ory.com/docs/kratos/guides/setting-up-cors
- https://www.ory.com/docs/kratos/passwordless/passkeys
- https://www.ory.com/docs/kratos/mfa/step-up-authentication
- https://www.ory.com/docs/kratos/self-service/flows/account-recovery-password-reset
- https://www.ory.com/docs/kratos/self-hosted/mail-courier-selfhosted
- https://www.ory.com/docs/kratos/manage-identities/customize-identity-schema
- https://www.ory.com/docs/kratos/cli/kratos-cleanup-sql
- https://raw.githubusercontent.com/ory/kratos/refs/heads/master/CHANGELOG.md
- https://github.com/ory/kratos/issues/516
- https://github.com/ory/kratos/issues/4538
- https://github.com/ory/kratos/discussions/3583

### Hydra
- https://www.ory.com/docs/oauth2-oidc/skip-consent
- https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow
- https://www.ory.com/docs/hydra/cli/hydra-create-oauth2-client
- https://www.ory.com/docs/hydra/self-hosted/configure-deploy
- https://www.ory.com/docs/hydra/self-hosted/secrets-key-rotation
- https://www.ory.com/docs/hydra/self-hosted/dependencies-environment
- https://www.ory.sh/docs/hydra/cli/hydra-janitor
- https://github.com/ory/hydra/blob/master/CHANGELOG.md

### glauth
- https://github.com/glauth/glauth
- https://github.com/glauth/glauth/releases
- https://pkg.go.dev/github.com/glauth/glauth/v2/pkg/handler
- https://pkg.go.dev/github.com/glauth/glauth/v2/pkg/plugins

### Astro / Cloudflare
- https://docs.astro.build/en/guides/integrations-guide/cloudflare/
- https://github.com/withastro/astro/issues/15237
- https://developers.cloudflare.com/workers/static-assets/migration-guides/migrate-from-pages/

### Caddy
- https://caddyserver.com/docs/caddyfile/directives/forward_auth

### Standards
- https://datatracker.ietf.org/doc/html/rfc7033
- https://web.dev/articles/webauthn-rp-id

### Tailscale
- https://tailscale.com/kb/1240/sso-custom-oidc
- https://github.com/tailscale/tailscale/issues/16155
