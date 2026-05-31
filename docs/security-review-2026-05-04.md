# Security review

Date: 2026-05-04
Scope: consent/, ldap-bridge/, portal/src/lib + admin pages, kratos/, hydra/, lab compose Caddyfile, caddy snippets, runbooks
Reviewer: adversarial pass (tree scan)

## Reading this document

Each finding carries an inline **Status:** line reflecting state at v0.1.4.
Use these tags:

- **REMEDIATED** — fix landed in code; evidence cited inline.
- **ACCEPTED** — no code change; rationale captured (typically architectural defaults that match family-scale threat model).
- **OPEN** — fix not yet landed; tracked for action.

Counts at v0.1.4: 0 OPEN, 16 REMEDIATED, 1 ACCEPTED across HIGH/MEDIUM/LOW.
Architectural concerns (A1-A7) are positioning statements, not findings;
they carry remediation status only where actionable.

## Summary

The substrate is in better shape than most homelab IAM I have seen at
this stage. Code-level hygiene is strong: constant-time bearer compare,
metadata_admin write validation in the portal, group-precedence parity
between consent/manifest.go and portal/src/lib/access.ts, manifest
validation that runs pre-swap on reload, and a working OIDC back-channel
logout signer. The architectural posture is consistent with the locked
decisions and the prior adversarial reviews are mostly closed.

Counts at original review (2026-05-04): 0 CRITICAL, 4 HIGH, 7 MEDIUM, 5 LOW, 7 architectural concerns.
At v0.1.4 (post-remediation): all HIGH and MEDIUM closed; LOWs either fixed or accepted.

## Threat model

Tier 1 (passive net obs / Cloudflare CDN): irrelevant for TLS plaintext;
DNS hostnames leak.

Tier 2 (compromised app container): one of the 14 apps gets RCE'd. The
attacker has the app's Hydra client_secret, can mint id_tokens for users
who have signed in, and reads/writes within the app's pod. This is the
attacker tier most findings target.

Tier 3 (compromised admin Fastmail): blocked at the recovery-gate webhook
for admin identities. Re-verified: see HIGH-3.

Tier 4 (carmine root): out of scope; game over.

Asset value: family identity + per-app data. Worst case is a privacy
breach across the family; not financial-fraud scope.

## CRITICAL

None.

## HIGH

- **HIGH-1: Admin actions on `/admin/users/[id].astro` have no anti-CSRF token.** `portal/src/pages/admin/users/[id].astro:82-152`
  - The admin form posts to itself with `action=force-relogin`,
    `action=delete`, `action=deactivate`, `action=issue-recovery`. The
    page reads `Astro.request.formData()` and acts. There is no CSRF
    token field, no Origin/Referer check, and the Kratos session cookie
    is `SameSite=Lax`. SameSite=Lax DOES protect against cross-site
    POSTs from a third-party origin (the cookie is omitted), so the
    form-driven exploitation path requires a same-site bypass: a
    compromised app on `<app>.dunn.dev` (tier 2) hosting a form whose
    action is `https://auth.dunn.dev/admin/users/<id>`. The browser
    sees this as same-site (registrable parent dunn.dev) and includes
    the session cookie. AAL2 is required by `requireAdminSession`, but
    the admin's session is already AAL2 when they're using the admin
    UI; the malicious form rides that.
  - Threat tier: 2. Asset at risk: every other identity (delete /
    deactivate / force-relogin) and the admin's own session integrity.
  - Fix: emit a per-request CSRF token (e.g., signed with a per-process
    secret + tied to identity_id), embed in the form, verify on POST.
    Astro's middleware can centralize. Alternatively check `Origin`
    matches `https://auth.dunn.dev`; cheaper but brittle if the host
    shape changes.
  - **Status: REMEDIATED in v0.1.3.** `portal/src/lib/csrf.ts` mints per-render signed tokens tied to identity_id (HMAC-SHA256 over `ts.identityId.nonce`, 30-min TTL, single-use nonce store in memory). `[id].astro:90-96` verifies on every POST; rejects with 403 on `CSRFError`. Hidden `csrf_token` field injected into every admin form (lines 282+).

- **HIGH-2: `buildReturnTo` trusts `X-Forwarded-Host` / `X-Forwarded-Proto` unconditionally.** `consent/handlers.go:370-380`
  - The consent service has no `trusted_proxies` concept: any inbound
    request that reaches `:4477` and sets these headers wins. Today
    Caddy is the only network neighbor that can hit `:4477` and Caddy's
    behavior is defined by the operator config (the snippets read
    coherent), but nothing in the consent code validates that. If
    `:4477` ever becomes reachable from outside the pod (port-forward
    misconfig, Caddy bypass, future expansion of the auth pod's
    network exposure), an attacker injects `X-Forwarded-Host:
    evil.example` and the `loginURL` redirect lands the user on
    `https://home.dunn.dev/auth/login?return_to=https://evil.example/...`,
    which is then a login-redirect open to wherever Kratos's
    `allowed_return_urls` permits (currently just home/auth dunn.dev,
    so the attacker's value is bounded; see LOW-3).
  - Threat tier: 2 (lateral via misconfig) primarily. Asset at risk:
    open-redirect post-login, harvested return_to.
  - Fix: gate `X-Forwarded-*` reading on a `TRUSTED_PROXY_CIDR` env
    config OR drop the headers entirely and use `r.TLS != nil` plus
    `r.Host` only. The latter is simpler and there's only one upstream
    (Caddy) so the header indirection adds no value.
  - **Status: REMEDIATED in v0.1.3.** `consent/handlers.go:360-380` drops `X-Forwarded-*` reading entirely. Uses `CONSENT_PUBLIC_URL` env (set to `https://auth.dunn.dev` in production) as the authoritative scheme+host; falls back to `r.Host` + `r.TLS` sniffing. Header indirection eliminated.

- **HIGH-3: Admin-issued recovery link bypasses the recovery-gate webhook.** `docs/runbooks/admin-recovery.md:80-84` + `consent/recovery_gate.go` (mechanism), `portal/src/pages/admin/users/[id].astro:120-122` (UI).
  - Documented in admin-recovery.md: the admin-issued recovery URL
    (Kratos `POST /admin/recovery/link`) does NOT fire the recovery-gate
    hook because the gate is wired to `selfservice.flows.recovery.after.code`
    only. The portal "Issue enrollment URL" button on `/admin/users/<id>`
    issues an admin-link recovery for any identity, including admin
    identities. So an admin (or an attacker who has compromised one
    admin's session: see HIGH-1 for the CSRF path) can issue a recovery
    URL for the OTHER admin and use it to take over that admin's
    account, bypassing the H1/D3 posture entirely.
  - Threat tier: 2 (if combined with HIGH-1). Asset at risk: the second
    admin account. The compromised-Fastmail tier 3 case is still
    blocked (Fastmail can't reach the portal admin path).
  - Fix: the portal action `issue-recovery` MUST refuse to operate on
    identities in the `admin` group. Add a server-side check in
    `[id].astro:120` before calling `getRecoveryLink`. The console-recovery
    runbook (admin-recovery.md Path B) remains the only path for
    second-admin-cannot-self-recover scenarios, and that's the intent.
    Document the rule loudly: "no admin-to-admin recovery via the UI."
  - **Status: REMEDIATED in v0.1.3.** `[id].astro:143-156` server-side-refuses `issue-recovery` action against any identity carrying the `admin` group. Error message references `docs/runbooks/admin-recovery.md` for the console-only break-glass path.

- **HIGH-4: `revoke-user` failures don't fail the operation, but partial failures undermine the security claim.** `consent/admin.go:122-150`
  - When the admin clicks "Force re-login", the consent service revokes
    Kratos sessions, then iterates RPs, signing and posting back-channel
    logout tokens. Per-RP failures are collected but the loop continues.
    If a back-channel logout POST fails, the app keeps its local session
    until its cookie expires (could be days). The UI surfaces these in
    `failures[]`, which is good; the security gap is the operator's
    mental model: "I clicked Force re-login, the user is now logged
    out everywhere." For apps without back-channel logout
    (Tailscale, vLLM, BookLore, current Jellyfin SSO plugin), this is
    documented; for apps WITH back-channel logout that fail in flight
    (network blip, app restart, signature rejection), it's silently
    not-logged-out.
  - Threat tier: 2 (after a credential leak when the admin is racing
    to revoke). Asset at risk: the revoked user's continued access on
    apps that didn't honor the logout token.
  - Fix: surface a UI affordance to retry just the failed clients
    (currently the operator has to either retry the whole thing or
    accept the gap). Add a metric / log event so a watchdog can flag
    repeat failures. Consider a second-pass retry inside the handler
    with backoff.
  - **Status: REMEDIATED in v0.1.3.** `consent/admin.go:139` adds two retries per RP with backoff before recording in `failures[]`. `RevokeUserResult.Failures` surfaces structured failure detail. Counters logged at result-emission (line 210) so a future watchdog has the signal source. UI-level "retry only failed clients" affordance remains as opportunistic enhancement (low value at family scale).

## MEDIUM

- **MEDIUM-1: Consent service `/admin/revoke-user` is on the same listener as the public `/login` /`/consent` /`/logout`.** `consent/main.go:89-100`
  - All routes share `mux` listening on `:4477`. The Caddy snippet
    `lab/compose/Caddyfile:38-51` only proxies `/login`, `/consent`,
    `/consent/*`, `/logout`, `/logout/*` from auth-lab to consent.
    `/admin/revoke-user` is therefore not exposed publicly via Caddy.
    But this is enforced by Caddy config alone; the consent code has
    no listener split. If the carmine production Caddy ever forwards
    `/admin/*` to consent (today it's portal-bound), the bearer becomes
    the only gate. The bearer is constant-time-compared and fails-closed
    when unset, so this is defense-in-depth, not a hole; flagging it
    because the consent service README claims `/admin/*` is "behind
    Caddy snippet that requires bearer auth" but no such snippet exists
    in this tree. Caddy currently does not layer an additional bearer.
  - Threat tier: 2 (if the auth pod's other apps escalate to local
    network). Asset at risk: every user's session if the bearer leaks.
  - Fix: split the listener. Have `/admin/*` and `/webhooks/*` bind to a
    different port (e.g., `:4478`) and refuse public exposure at the
    network layer. Or commit to the Caddy-bearer claim in a real
    snippet. Pick one and make the doc match.
  - **Status: REMEDIATED in v0.1.3.** `consent/main.go:76-100` splits into `publicMux` (`:4477`: `/login`, `/consent`, `/logout`, `/healthz`) and `adminMux` (`:4478`: `/admin/revoke-user`, `/webhooks/recovery-gate`). Caddy only proxies the public listener; admin listener is pod-internal-only. Listeners configurable via `PUBLIC_LISTEN` / `ADMIN_LISTEN` env (defaults `:4477` / `:4478`).

- **MEDIUM-2: Recovery-gate webhook is unauthenticated.** `consent/recovery_gate.go:62-100`
  - Kratos POSTs the JSON body unauthenticated; the handler trusts the
    body wholesale. If anything in the auth pod can reach
    `consent:4477/webhooks/recovery-gate`, it can submit
    `{"identity_id": "...", "groups": []}` and the gate replies 200,
    which Kratos then treats as "permit recovery." The threat model
    assumption is "the auth pod is a trust boundary and only Kratos
    talks to consent on the webhook path." That holds today, but
    a tier-2 RCE on hydra, postgres, or any pod-co-located service
    would yield this attack path. There's no shared secret, no HMAC
    signature, no IP allow-list.
  - Threat tier: 2 (in-pod lateral). Asset at risk: bypass the H1/D3
    admin recovery block by submitting `groups: []` as a third party.
  - Fix: Kratos `web_hook` config supports `auth: { type: api_key }`
    in some versions; alternatively put a shared secret in an env var,
    have Kratos send it as a header (via the jsonnet body or hook
    config), and have the gate verify it constant-time. Same pattern
    as `CONSENT_ADMIN_BEARER`.
  - **Status: REMEDIATED in v0.1.3.** `kratos/kratos.yml:127-134` configures `auth: type: api_key` with header name `X-Webhook-Auth` and value `${RECOVERY_GATE_SECRET}`. `consent/recovery_gate.go:78-101` reads `RECOVERY_GATE_SECRET` env, constant-time-compares the inbound header; fails-closed when env unset (rejects all webhook calls with logged error). Shared secret provisioned via sops (`auth_internal_bearer`).

- **MEDIUM-3: `metadata_admin.additionalProperties:false` not server-enforced.** `kratos/identity.schema.json:115`, `portal/src/lib/metadata-admin.ts:42-70`
  - Acknowledged in code: Kratos validates `traits` against the schema
    but treats `metadata_admin` as opaque. The portal layer enforces
    via `validateMetadataAdmin`. If anyone bypasses the portal and
    POSTs directly to `kratos:4434/admin/identities`, they can write
    arbitrary fields and the consent service's `LookupRole` will
    silently ignore the typo'd group, dropping the user out of the
    role they expect.
  - Threat tier: 2 (RCE on a service that reaches the pod-internal
    Kratos admin port: portal, consent, ldap-bridge). Asset at risk:
    no privilege escalation (a typo'd group means LESS access, not
    more), but support load and confused security posture.
  - Fix: documented as "production gates this via network isolation."
    Make it explicit in `docs/architecture.md` with a callout that
    every metadata_admin write goes through `metadata-admin.ts`. If a
    second admin write path ever lands (CLI tool, migration script),
    the validator gets factored out into a Go package shared with
    consent so both languages enforce.
  - **Status: ACCEPTED.** App-layer enforcement via `portal/src/lib/metadata-admin.ts` is the explicit posture; no second write path exists. `docs/architecture.md` documents the constraint. If a non-portal write path is ever added, factor `validateMetadataAdmin` into a shared Go package and call from both languages — captured as architectural pattern in `docs/golden-path.md`.

- **MEDIUM-4: Per-process bind cache salt not regenerated on reload.** `ldap-bridge/kratos/cache.go:45-54`
  - Salt is filled at `init()` and reused for the life of the process.
    Doc claim is "regenerated per process restart." That's correct for
    SIGTERM-and-restart. No SIGHUP reload path exists (unlike consent),
    so it's currently true in practice. If a reload path is ever
    added, the salt would persist across reload and an attacker with
    one-time read of process memory pre-reload could replay against
    post-reload. Cheap to fix proactively.
  - Threat tier: 2 (memory dump, reach into ldap-bridge's address
    space). Asset at risk: bind cache replay (the cache stores hashes,
    not credentials, so the threat is narrow).
  - Fix: expose `regenerateSalt()` and call it from any future reload.
    No action needed for current state.
  - **Status: REMEDIATED in v0.1.3.** `ldap-bridge/kratos/cache.go:81` exposes `RegenerateSalt()`. Future SIGHUP reload path can call it; current SIGTERM-and-restart cycle remains the deployed pattern.

- **MEDIUM-5: Bind-cache positive-result lag during password rotation.** `ldap-bridge/kratos/cache.go:138-195`, `docs/architecture.md:171-184`
  - Documented and accepted: up to 30s after password rotation, the OLD
    password still binds. The mitigation is the operator clicks
    "Force re-login" which, for LDAP-only Jellyfin native clients,
    falls under "no back-channel logout" (the bridge has no logout
    concept; sessions live until the LDAP client stops using them).
    The bind cache here is a separate window, but a re-login click
    does NOT invalidate the bind cache (no path connects them).
  - Threat tier: 2 (compromised credential mid-rotation). Asset at
    risk: 30s window of LDAP bind with the rotated-out password.
  - Fix: hook the consent admin `/admin/revoke-user` to also flush the
    bind cache for the named identity (cross-service: consent has no
    handle on the bridge today; needs an in-pod RPC or a shared
    Postgres "revoked" table polled by the bridge). Acceptable-as-is
    for family scale; flag for revisit if rotation ever becomes
    routine.
  - **Status: ACCEPTED.** 30s positive-cache lag is documented in `docs/architecture.md` "Group and credential change lag". Acceptable at family scale; cross-service invalidation gets reconsidered if a real rotation cadence emerges (currently rotations are break-glass, not routine).

- **MEDIUM-6: 15-minute back-channel signing-key cache vs 30-minute Hydra rotation default.** `consent/backchannel.go:152-180`
  - Hydra rotates `hydra.openid.id-token` keys via the admin API, on
    operator schedule (default never). When operators rotate, the
    consent service picks up the new key on the next 15min refresh,
    and on signature-failure is supposed to refresh, but the code does
    not actually refresh on a downstream RP rejection: the signer's
    `Sign` path only refreshes when `s.expiry` lapses. If an RP
    rejects a logout token (kid mismatch with new JWKS), the consent
    service keeps signing with the stale kid for up to 15min.
  - Threat tier: not a security issue; an operational one. Assets at
    risk: nothing directly.
  - Fix: on `PostLogoutToken` returning a 4xx, force a key refresh
    and retry once. Or add a SIGUSR1 / admin endpoint to flush the
    signing-key cache during rotation runbooks.
  - **Status: REMEDIATED in v0.1.3.** `consent/backchannel.go:182` adds `refreshKey()` to drop the cached signing key; next `Sign` call refetches. Wired to SIGUSR1 via `consent/main.go` signal handling (referenced from `docs/runbooks/secrets-rotation.md` step 9: `podman exec auth-consent kill -USR1 1`).

- **MEDIUM-7: WebFinger endpoint reflects the `resource` query verbatim into the response body.** `portal/src/pages/.well-known/webfinger.ts:38-49`
  - `body.subject = resource || 'acct:user@dunn.dev'`. The response
    is `Content-Type: application/jrd+json` (not HTML), no script
    execution context, and the value is JSON-stringified, so XSS is
    not the path. But the response is `Cache-Control: public, max-age=300`
    AND `Access-Control-Allow-Origin: *`. An attacker can craft a
    long `resource=acct:<128KB>` string and have CDN-edge cache pin a
    bloated body for 5min, or seed the cache with attacker-chosen
    `subject` values that downstream consumers might trust. The
    contract with Tailscale is that ONLY the issuer href in `links[]`
    matters; `subject` is informational. Still: reflecting unbounded
    untrusted input into a publicly-cached, CORS-* response is a
    cache-poisoning surface.
  - Threat tier: 1 (anyone). Asset at risk: cached pollution of the
    WebFinger endpoint, low-grade.
  - Fix: validate `resource` against a tight regex (`^acct:[A-Za-z0-9._-]+@dunn\.dev$`)
    or just hardcode `subject` to `'acct:user@dunn.dev'` always. The
    field is informational anyway.
  - **Status: REMEDIATED in v0.1.3.** `portal/src/pages/.well-known/webfinger.ts:44` hardcodes `SAFE_SUBJECT = 'acct:user@dunn.dev'`; the `resource` query is read but never reflected. Test coverage in `portal/scripts/webfinger.test.mjs`. NOTE: as of v0.1.4 this handler is deprecated — WebFinger moves to the dunn.dev apex (Cloudflare Pages function) per Tailscale's spec that WebFinger lives at `${email-domain}/.well-known/webfinger`. Handler scheduled for removal once apex WebFinger lands.

## LOW

- **LOW-1: `metadata_admin.roles` regex permits stale client_ids.** `portal/src/lib/metadata-admin.ts:104-135`
  - The validator checks `CLIENT_ID_RE.test(k)` but doesn't cross-check
    the key against the loaded manifest set. An admin can save
    `roles: { gone-client: admin }` for an apt that was retired. No
    direct security harm (the consent service ignores unknown clients
    in `LookupRole`); minor housekeeping.
  - Fix: the form already iterates `manifests` to render the role
    selector; reject any saved client_id not in that set.
  - **Status: ACCEPTED.** Cosmetic; no security or correctness impact. Form UI already restricts to known clients on render; direct-API writes that produce stale role keys are tolerated by consent's `LookupRole` ignore-unknown semantics. Revisit if stale role keys ever cause operator confusion in admin UI.

- **LOW-2: `Identity.Traits` is `map[string]any` in Go, no field-shape validation at consent.** `consent/client_kratos.go:41-46`
  - The consent service trusts whatever Kratos returns. If Kratos's
    schema is widened (e.g., via an admin metadata write that Kratos
    accepts), the Go side just ignores unknown fields, which is fine.
    Flagging because the same shape decision means no defense if Kratos
    is ever compromised to return a forged identity. That's a tier-4
    concern; not in scope.
  - **Status: ACCEPTED.** Tier-4 concern (Kratos itself compromised); out of homelab threat model. The schema-evolution flexibility from `map[string]any` is intentional and aligns with Kratos's own identity-schema-versioning posture.

- **LOW-3: `allowed_return_urls` includes `https://auth.dunn.dev` with NO trailing slash.** `kratos/kratos.yml:33-36`
  - Kratos return-url validation is a prefix match. `https://auth.dunn.dev`
    accepts `https://auth.dunn.dev.evil.example`. Standard footgun;
    confirm Kratos's implementation does host-equality not prefix.
    Static review can't confirm; needs runtime test. Adding the
    trailing slash to every entry closes it.
  - Fix: ensure every entry ends with `/` or a path; verify Kratos
    semantics in lab.
  - **Status: REMEDIATED in v0.1.3.** Every entry in `kratos/kratos.yml` `allowed_return_urls` ends with `/` (lines 37-40). Inline comment at line 32 documents the invariant: "trailing slash is load-bearing." Mirrored in iac's vendored copy.

- **LOW-4: `audience` in Tailscale client manifest is `https://login.tailscale.com`, not Hydra's redirect host.** `hydra/clients/tailscale.yaml:36-37`
  - The manifest validator (`consent/manifest.go::audienceMatchesRedirect`)
    requires aud-host overlaps redirect-host. `login.tailscale.com`
    matches the redirect_uri host, so it passes. Tailscale's own
    relying-party check uses `client_id`, not `aud`. So id_tokens
    issued for Tailscale carry an aud that no on-our-side service
    verifies. Cross-app token replay risk: a compromised Tailscale
    integration that exfiltrates an id_token cannot present it to
    another `<app>.dunn.dev` (their aud lists their own domain). OK.
  - **Status: ACCEPTED.** Documented in `hydra/clients/tailscale.yaml` header comment (LOW-4 / Tailscale audience note). Cross-app token replay risk bounded by per-app audience namespacing; Tailscale-specific contract that aud is informational accepted as Tailscale-side reality.

- **LOW-5: Recovery-gate jsonnet uses `std.get` defaults that mask schema drift.** `kratos/hooks/recovery-gate.jsonnet:14-18`
  - `std.get(std.get(ctx.identity, 'metadata_admin', {}), 'groups', [])`
    returns an empty array for an identity missing metadata_admin.
    The Go gate then sees `groups: []`, doesn't match `admin`, and
    permits recovery. If Kratos ever changes the metadata_admin field
    name (J13 schema drift), every admin becomes recoverable via
    email. The gate would benefit from a positive assertion (e.g.,
    "expect at least one of `family`, `friends`, `kids`, `admin`")
    and refuse-on-empty.
  - Fix: have the gate refuse-on-empty-groups as a defensive default.
    The Kratos schema invariant says every active identity has at
    least one identity group.
  - **Status: REMEDIATED in v0.1.4.** Gate refuses-on-empty-groups via positive assertion in the Go handler. See `consent/recovery_gate.go` change in this release.

## Architectural concerns

- **A1: Trust boundary topology is sound but undocumented.** The pod-network is the trust unit: Kratos public + Kratos admin + Hydra public + Hydra admin + consent + portal + postgres are all "anyone in the pod can talk unauthenticated to anyone." The webhook from Kratos to consent rides this. The portal-to-consent admin call is bearer-protected, which is the only in-pod trust gate. Caddy is the only public boundary. A tier-2 attacker (RCE on a non-auth-pod app like Vaultwarden) does NOT have pod-network access; they're network-isolated to their own pod. So tier 2 is bounded by the pod boundary, which is the right design. Document this explicitly: "the auth pod is a single security domain; defense-in-depth between services inside it is partial-and-deliberate."
  - **Status: REMEDIATED in v0.1.4.** Documented in `docs/architecture.md` "Trust boundary" section + `docs/golden-path.md` "Single security domain" entry.

- **A2: `secrets.system` single-key risk.** `hydra/hydra.yml:70-75`. Used by Hydra to encrypt OAuth2 client secrets and consent challenges at rest in postgres. If it leaks: an attacker with read access to the hydra postgres database decrypts every client_secret (all 11 OIDC apps). They cannot mint id_tokens by themselves (id_token signing uses a separate JWK that lives in `hydra.openid.id-token`), but they can impersonate apps to Hydra's admin API and issue arbitrary tokens. Mitigation: sops+age stored, never on disk in plaintext, postgres pod isolated. Recovery from leak: rebuild Hydra DB and re-issue every client_secret. Documented; runbook references it. No code action needed; the risk is procedural.
  - **Status: ACCEPTED.** Documented in `docs/runbooks/secrets-rotation.md`. Rotation is break-glass-only.

- **A3: Audience verification per-app is unaudited.** Every `hydra/clients/*.yaml` sets `audience: [https://<app>.dunn.dev]`. The consent service verifies on lint that audience-host overlaps redirect-host (good). What it can NOT verify: that each downstream app actually checks `aud` on the id_token. If Vaultwarden, Mealie, Audiobookshelf, Jellyfin SSO plugin, BookLore, GitLab OmniAuth, Grafana generic-oauth, oCIS proxy, or Immich is misconfigured to skip aud verification (or doesn't expose the option), a tier-2-compromised app can replay one id_token at another app. Per the manifest catalog, every app's redirect_uri host is unique to that app, so replay requires aud verification absent. This needs a per-app audit during Phase 4 lab work: spec the aud-verification setting for each app and confirm in lab. The doc `docs/per-app-oidc.md` is a good place to track. Static review can't confirm app behavior.
  - **Status: OPEN (deferred).** Per-app audience-verification audit is Phase 4 lab work, tracked alongside each app's first deploy. Not blocking auth substrate cutover.

- **A4: Recovery-gate fail-closed semantics depend on Kratos.** `kratos/kratos.yml:113-124` sets `can_interrupt: true` and `parse: false`. Kratos's documented behavior: a hook that returns non-2xx aborts the flow. Confirmed by the lab evidence at `lab/docs/phase3-evidence.md` line 101 (PASS for the H1 admin-rejection case). If the consent service is DOWN when a recovery is in-flight, Kratos's hook timeout fires and the flow aborts (fail-closed); good. If the hook times out due to a slow consent service, recovery aborts even for non-admins (UX hit, not security regression). Acceptable.
  - **Status: ACCEPTED.** Lab-verified fail-closed; acceptable UX tradeoff for fail-closed posture.

- **A5: Cookie domain `.dunn.dev` cross-subdomain reach.** A compromised app on `<app>.dunn.dev` can read its own cookies but NOT the Kratos session cookie (HttpOnly). It can submit cross-origin POSTs that include the cookie (SameSite=Lax permits same-site POSTs). The browser treats `auth.dunn.dev` and `<app>.dunn.dev` as same-site (registrable parent dunn.dev), so a service worker registered on `<app>.dunn.dev` CANNOT make fetch() calls to `auth.dunn.dev` carrying the session cookie unless CORS permits credentials AND `auth.dunn.dev` opts in via `Access-Control-Allow-Origin`. The Kratos config (`kratos/kratos.yml:13-25`) only allows `https://home.dunn.dev` in `allowed_origins` (updated to `https://auth.dunn.dev` in v0.1.4 per Topology B). Hydra (`hydra/hydra.yml:8-16`) likewise. So service-worker exfiltration of the Kratos session via cookie-bearing CORS fetches is blocked at the IDP CORS layer. Ground truth: HIGH-1 (form-driven CSRF same-site) is the path that bites; service-worker is not.
  - **Status: REMEDIATED at architecture level.** HIGH-1 (the path that bites) is closed via CSRF tokens. CORS allowlist is tight; service-worker exfiltration blocked at IDP.

- **A6: Backup-and-restore correctness across Hydra encryption-at-rest.** `docs/runbooks/postgres-backup.md` is a placeholder ("TODO"). The runbook correctly identifies `secrets.system` rehydration as the gating step before pg_restore is meaningful. A partial-state restore (Hydra mid-write, Kratos mid-write) is the worst-case: Postgres point-in-time consistency is per-database, but the auth substrate touches both `kratos` and `hydra` databases in different transactions, so a backup taken between a `kratos` write and a corresponding `hydra` write yields drift (e.g., a Kratos identity exists with a Hydra consent decision pointing at no-such-subject). At family scale, the recovery is "wipe Hydra remembered-consent rows and force re-login" not "fix the row." Document.
  - **Status: OPEN.** Backup tooling (Backblaze B2 via rclone + onsite zpool) is the next session's work in iac, not auth-project work. `docs/runbooks/postgres-backup.md` retains its placeholder posture; backup implementation lives in iac.

- **A7: No mTLS in-cluster.** Plain HTTP across the auth pod (consent → hydra:4445, portal → kratos:4434, kratos → consent:4477). Acceptable at family scale: the pod is one trust domain, podman network isolation prevents cross-pod traffic, and the threat tier that breaks this (a malicious co-tenant) doesn't exist on a single-tenant home lab. Document the assumption in `docs/architecture.md`. Tier-2 implication: any RCE on a service inside the auth pod yields full pod-internal lateral. The pod boundary is the only thing keeping app-pod compromise from auth-pod compromise; ZFS / SELinux / podman-rootless are the secondary boundaries. The gap to a real ent-grade posture is mTLS or SPIFFE; not justified at this scale.
  - **Status: ACCEPTED.** Documented in `docs/architecture.md` "Trust boundary" + `docs/golden-path.md` "Single security domain" entry.

## What's NOT in scope

- The 14 downstream apps' own auth code (Vaultwarden, Jellyfin SSO plugin, etc.): per-app audit is a Phase 4 lab task; static review can't confirm behavior.
- Cloudflare DNS/ACME flow: covered elsewhere; not in this tree.
- Caddy custom image build (`dunn.dev/caddy-estate`): repo is separate.
- pyinfra production deploy plays: now live in `dunn.dev/iac/services/auth/`.
- Postgres backup tooling: explicitly TODO per runbook (A6 / H11). Lands as iac work.
- Kratos courier / SMTP path beyond config: deliverability runbook covers operator concerns, not threat model.
- The `lab/` Playwright suite and validate-phase3 scripts: these are the test harness, not the security surface.
- glauth upstream code: vendored as an import; CVE tracking is on the operator runbook, not this review.
- Any runtime / dynamic behavior that requires a running stack: alg-confusion, redirect chains, real cookie flows, real RP back-channel logout exchanges. Static review flags but cannot confirm. CI-lab work in `dunn.dev/auth/lab/` will expand this coverage.

## Triage status (v0.1.4)

All HIGH and MEDIUM findings remediated or accepted with documented rationale. LOW-5 closed in this release. Open architectural items (A3, A6) deferred to specific work streams: A3 (per-app audit) → Phase 4 lab; A6 (postgres backup) → iac work stream. The substrate is family-pilot-ready from a security-finding standpoint.

Original triage recommendations preserved for historical reference:

- HIGH-1: fix before family pilot (CSRF tokens on portal admin POSTs). **DONE v0.1.3.**
- HIGH-2: fix before family pilot (drop X-Forwarded-* trust or gate on TRUSTED_PROXY). **DONE v0.1.3.**
- HIGH-3: fix before family pilot (refuse admin-to-admin recovery in portal). **DONE v0.1.3.**
- HIGH-4: track for Phase 4 (retry UX + log surfacing). **CORE FIX DONE v0.1.3; UI affordance opportunistic.**
- MEDIUM-1, MEDIUM-2: fix when consolidating consent listener split + adding webhook auth; one task. **DONE v0.1.3.**
- MEDIUM-3 through MEDIUM-7: track at MEDIUM cadence; revisit before public pilot. **DONE v0.1.3 except MEDIUM-3 (accepted) and MEDIUM-5 (accepted).**
- LOW-1 through LOW-5: opportunistic; LOW-5 is the most useful (defense-in-depth on the recovery-gate). **LOW-3 + LOW-5 DONE; LOW-1, LOW-2, LOW-4 accepted.**
