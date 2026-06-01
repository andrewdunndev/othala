# Adversarial review — Phase 3 pre-validation

## Summary

The substrate is consistent with the locked decisions and the consent
service's role/claim resolution is well-tested in unit tests. The
substantial gaps are at component boundaries: the admin UI on Cloudflare
Workers has no plausible path to the Kratos admin port (the same gap
the consent service was built to solve, duplicated for Kratos admin),
the consent service's role precedence does not match the portal's
"Effective Access" view (drift between two implementations of the same
algorithm), and `apply-clients.sh` will push our consent-service-only
yaml fields (`roles`, `group_role_map`, `emit_groups_claim`) at Hydra
where they don't belong.

The skip_consent threat model meets the locked posture but has no
mitigation for stolen-cookie blast radius beyond the existing 90-day
session lifespan. Recovery is wired but not differentiated for admins
(a stolen Fastmail can self-recover an admin account at AAL1). Audit
log is a stub. No backup story for Postgres. SIGHUP-driven manifest
reload is missing the deploy-pipeline hook the comment claims.

Counts: 4 CRITICAL, 11 HIGH, 13 MEDIUM, 7 LOW.

## CRITICAL findings (block validation)

### C1. Admin UI on Workers cannot reach Kratos admin port

**Location:** `portal/src/lib/admin-api.ts:15-23`, `portal/wrangler.toml`,
`portal/src/lib/admin.ts:33-41`

`adminBase()` falls back to `http://kratos:4434`. That hostname is
pod-internal and unreachable from Cloudflare Workers. `wrangler.toml`
sets `KRATOS_PUBLIC_URL` and `HYDRA_PUBLIC_URL` but no
`KRATOS_ADMIN_URL` for the production env, so every `/admin/*` page in
production resolves to "fetch http://kratos:4434" from the edge,
which fails. The decision (`STATUS.md` row "Hydra admin reachability")
explicitly forbids exposing the Hydra admin port on the public
internet, and the same logic applies to the Kratos admin port (which
is unauthenticated by Kratos design; only network isolation gates it).

Same architectural mismatch the consent service was built to solve,
left unsolved for Kratos admin. The admin UI today would either:
have to call a server-side proxy on carmine (mirror of the consent
service pattern), or accept that the admin port is exposed publicly
through Caddy with bearer-token auth.

`portal/src/lib/admin.ts:33-41` repeats the same pattern for
`HYDRA_ADMIN_URL` (only used for the read-only OAuth2 client list,
which is also unreachable from Workers).

**Recommended fix:** decide between two paths and document.
(a) Build a small "admin proxy" service co-located with Kratos on
carmine, serving the subset of admin operations the UI needs. Same
shape as consent service.
(b) Move the admin UI off Workers onto carmine (host it under
`dag.dunn.dev/admin/*` instead of `home.dunn.dev/admin/*`) so it
shares the carmine pod network with Kratos.

This is a locked-decision second-order effect: the locked decision
"Astro adapter Cloudflare Workers" combined with "admin port stays
internal" makes admin UI on Workers impossible without a proxy.

**Effort:** 2-4 days for the admin proxy path; 1 day for the
relocation path (drop Workers for admin, keep it for the public home
portal).

### C2. Consent service does not gate on access-* group membership

**Location:** `consent/handlers.go:103-190`, `consent/manifest.go:148-187`

The portal documents access-* groups as "what you can reach" with the
home tile launcher and Caddy snippets enforcing them. The consent
service does not check `access-<clientId>` membership at any point: a
user with `family` group but missing `access-keep` who somehow lands
on `keep.dunn.dev/identity/connect/oidc-signin` (e.g., a bookmark, or
clicking a link that bypasses the home portal) gets a valid id_token
because the consent flow only checks "session exists" plus role
derivation.

The architecture says "Apps enforce authz reading the OIDC `groups`
claim." That works for apps that read groups (Mealie, GitLab,
Audiobookshelf), but fails for:
- Vaultwarden (until upstream role mapping ships, every signed-in
  user is a regular member; the access-keep gate is the only stop).
- BookLore (no upstream group mapping; gate is access-library).
- Immich, oCIS, Grafana (these read groups but won't enforce
  `access-<app>` themselves; they're checking their own JIT mapping).

So the access-* group is enforced by Caddy for forward-auth apps and
the home portal tile launcher, but NOT enforced for OIDC apps. That
contradicts the architecture doc's "tile renders only if the user is
in the matching access-* group" framing as a security boundary.

**Recommended fix:** in `handleConsent`, after `GetIdentity`, check
that `metadata_admin.groups` contains `access-<consent.Client.ClientID>`.
If missing, reject with `consent_required` or `access_denied`.
Document that the access-* group is the canonical entry gate for
OIDC apps.

**Effort:** 30 minutes code + 1h tests.

### C3. apply-clients.sh pushes consent-only fields into Hydra

**Location:** `hydra/apply-clients.sh:39-41`

The script does `yq -j ". + {client_secret: ...}"` and POSTs the
entire yaml as the Hydra client body. The yamls now carry `roles`,
`group_role_map`, and `emit_groups_claim` (consent-service-only
fields), which Hydra's client object does not define.

Three possible Hydra behaviors:
- Silently strip unknown fields (best case, but undocumented).
- Reject the request (4xx, halts deploy).
- Accept and persist arbitrary metadata in the client object (clutters
  Hydra DB; risk of conflict with future Hydra schema additions).

Hydra v2.x `expose_internal_errors: false` is set, so a rejection
would surface as a generic 500 in the deploy log without indicating
which field caused it.

**Recommended fix:** filter the yaml before send. Either:
- Whitelist the OIDC fields the script forwards.
- Move consent-service fields under a top-level `consent:` key in the
  yaml, and drop that key during the apply.

**Effort:** 1h.

### C4. Portal "Effective Access" disagrees with consent service on group precedence

**Location:** `portal/src/lib/access.ts:36`, `consent/manifest.go:175-185`

The portal's `access.ts` walks identity groups in a hardcoded
precedence: `['admin', 'family', 'friends', 'kids']`. The consent
service walks `metadata_admin.groups` in declared order (the order
the user array is stored in Kratos).

Concrete divergence: a user whose identity has groups
`['family', 'admin']` (admin appended after family by an admin who
edited the form):

- Portal `pickIdentityGroup`: walks the precedence list, finds `admin`
  first, returns `admin` -> "Effective access: admin via admin".
- Consent service `LookupRole`: walks user groups in stored order,
  finds `family` first, returns `family -> user`.

Concrete divergence #2: a custom future identity group not in the
precedence list. Portal: falls through to `for (const g of userGroups)`
which is now stored-order. Consent: stored-order. So new groups
agree, but the four canonical groups follow different rules.

`consent/manifest_test.go:166-191` even hardcodes the assumption that
declared order wins (the test labels groups `[admin, family]` ->
admin and `[family, admin]` -> user). The portal explicitly contradicts
this.

**Recommended fix:** pick one. Either:
- Consent service walks the precedence list (matches portal, breaks
  current consent unit tests including
  `TestManifest_LookupRole_AdminGroupBeatsFamilyWhenFirst`).
- Portal walks user-stored order (matches consent, breaks UX
  expectation that an admin-tagged user's effective access shows
  admin regardless of where the admin group sits in the list).

Recommendation: enforce precedence on the admin form (write
`identityGroups` in canonical order on save), so stored order ALWAYS
matches precedence. Document the canonical order. Keep both code
paths walking stored order.

**Effort:** 2h: change form save logic + document + cross-check test.

## HIGH findings (should fix before family rollout)

### H1. Admin recovery uses email, same path as non-admin

**Location:** `kratos/kratos.yml:99-104`, locked decision M7 from
prior review.

`flows.recovery.use: code` is global. An admin who loses their
device hits the same flow a regular family member does: email a code
to the address on file, type it back, set new password. AAL2 is not
required for recovery. So if the admin's Fastmail is compromised,
the attacker gets admin without ever touching the device.

The decision-doc M7 mitigation said "investigate whether
`selfservice.flows.recovery.required_aal` allows per-flow AAL2." Not
done in current config. Today: admin recovery and non-admin recovery
are identical paths.

The admin-issued recovery URL exists (`getRecoveryLink` in
`portal/src/lib/admin-api.ts`), but only an admin who is already
logged in can issue one. If the only admin loses their device, the
admin-issued path is unreachable; only email recovery works.

**Recommended fix:** lock down. Two options:
- Disable email recovery globally; admin issues all recovery URLs
  manually. Family-scale acceptable; first-admin recovery becomes a
  break-glass procedure (e.g., direct DB password reset documented
  in a runbook).
- Add a Kratos hook that rejects recovery for identities with admin
  group. Verify the hook mechanism supports this in current Kratos.

State plainly: recovery for admin is the weakest link in the auth
posture today. Pick the mitigation before family rollout.

**Effort:** 1-2 days plus runbook authoring.

### H2. SIGHUP reload claim mismatches deployment plan

**Location:** `consent/main.go:67-70`, `consent/main.go:117-127`

Comment says "in production the deploy pipeline rolls the pod, but
reload is cheap." There is no deploy pipeline yet that does this.
The carmine deployment story (decision.md) says quadlets via pyinfra,
but no quadlet manifest signals the pod to SIGHUP after `apply-clients.sh`
runs. So in production, when an admin edits a yaml in the auth repo,
they'd need to SSH to carmine and `kill -HUP` the consent pod
themselves.

Acceptable for v1, but document the operator runbook step so it
doesn't get forgotten. Better: the apply-clients.sh script can SIGHUP
the consent service after the Hydra apply completes (assuming the
script runs on carmine, which is the production deploy shape).

**Recommended fix:** extend `apply-clients.sh` to SIGHUP the consent
service when run on carmine (env var like `CONSENT_PID_FILE` or
`CONSENT_RELOAD_HOOK`). Document.

**Effort:** 1h.

### H3. Hydra cookie-secret rotation requires running both old and new cookies; not configured

**Location:** `hydra/hydra.yml:76-77`, locked decision H4.

Only one entry in `secrets.cookie`. Rotating cookies (the locked
guidance "rotate `secrets.cookie` quarterly") requires prepending
the new key while keeping the old one until sessions expire. There
is no env-var convention for "list of comma-separated secrets" in
the rendered config, so the rotation runbook is not implementable
without a config change.

Same for Kratos `secrets.cookie` and `secrets.cipher`
(`kratos/kratos.yml:177-181`). One element each, no list slot for
the prepend-then-drop pattern.

**Recommended fix:** define an env var per slot (e.g.,
`HYDRA_COOKIE_SECRET_NEW`, `HYDRA_COOKIE_SECRET_OLD`) and template
the config to a list. Document the rotation runbook.

**Effort:** 2h, plus runbook.

### H4. Audiobookshelf role names collide with admin/user identity tokens

**Location:** `hydra/clients/listen.yaml:32-44`, `consent/handlers.go:144-170`

Audiobookshelf hardcodes the role names `admin`, `user`, `guest` on
its side, so the yaml emits literal `groups: ["admin"]`. This
overrides the auto groups claim by design (last-write-wins).

Risk: the merged id_token's `groups: ["admin"]` is what
Audiobookshelf reads, but a future app that's added later, sharing
the same audience prefix or a webhook-ingest pattern, might also
read `groups: ["admin"]` and treat it as cross-app admin status.

Mitigation today: each app's audience is distinct, so the id_token
issued for client `listen` only validates against `https://listen.dunn.dev`.
Apps verify audience. So this risk is fine in the OIDC threat model
provided every app verifies `aud`.

Action: add an integration test that asserts every consent yaml's
`audience` field is set, and document the constraint.

**Effort:** 1h test + 30min docs.

### H5. Kratos session passed verbatim to consent service; no server-side validation against Hydra subject

**Location:** `consent/handlers.go:65-94`

When `login.Skip` is false, the handler trusts whatever cookie the
browser sends. It does not validate that the cookie's identity ID
matches whatever Hydra had pinned on the login challenge. With
SameSite=Lax this is hard to abuse, but a misconfigured app on a
weakly-bounded subdomain could in theory forward the cookie. (M4 in
prior review covered the cookie-leak perimeter risk; this is the
consent-service surface of it.)

After `cfg.Kratos.Whoami` returns, the code uses `session.Identity.ID`
as the subject without further check. There is no anti-CSRF check on
the `?login_challenge=` redirect, but Hydra's challenge token already
provides one-shot semantics, so this is fine.

The header injection ladder: if Caddy's `X-Forwarded-*` headers can
be spoofed by an upstream tier (they can't in our topology, but
worth flagging), `buildReturnTo` returns a URL the user is then
redirected back to. Since this URL goes to Kratos's
`?return_to=` parameter, and Kratos validates against
`allowed_return_urls`, the spoof can't redirect off-domain. Safe
today; add a comment.

**Recommended fix:** add a comment that `X-Forwarded-*` trust is
load-bearing on the Caddy layer's strip-and-replace behavior.

**Effort:** 30min documentation.

### H6. WebFinger byte-mismatch with Hydra issuer (trailing slash)

**Location:** `portal/public/.well-known/webfinger:6`,
`hydra/hydra.yml:24-26`

Webfinger has `"href": "https://dag.dunn.dev"` (no trailing slash).
Hydra's `urls.self.issuer` is `https://dag.dunn.dev/` (trailing
slash). Per the prior review M11, "issuer string in `href` must
byte-match Hydra's `/.well-known/openid-configuration` issuer
including trailing-slash handling."

Tailscale custom OIDC will reject "invalid JSON" or "issuer
mismatch."

**Recommended fix:** make webfinger href byte-match Hydra issuer.
Pick one (with or without trailing slash) and apply consistently.

**Effort:** 5min.

### H7. WebFinger response headers not configured

**Location:** `portal/public/.well-known/webfinger`,
`portal/wrangler.toml`

Per prior review L5: webfinger should serve as
`Content-Type: application/jrd+json` with
`Access-Control-Allow-Origin: *`. Cloudflare Workers static-asset
serving uses `application/json` by default for files without a
matching extension. Astro's static handling depends on the asset
delivery layer's MIME type guessing, which for a file named
`webfinger` (no extension) is ambiguous.

**Recommended fix:** verify in lab that the response actually carries
`application/jrd+json`. If not, set up the static-asset handler with
`_headers` (Cloudflare Pages convention; Workers equivalent depends
on adapter version) or serve via a small Worker route handler.

**Effort:** 1h investigation + fix.

### H8. Identity schema accepts arbitrary additional metadata_admin properties

**Location:** `kratos/identity.schema.json:113-115`

`metadata_admin.additionalProperties: true`. While this gives schema
flexibility for future fields, it also means a client (admin UI)
that posts a malformed `metadata_admin` blob will silently store
fields the consent service ignores. Cycle: an admin types a typo'd
key (`grupos` instead of `groups`); Kratos accepts; consent service
sees nothing in `metadata_admin.groups`; user has no access.

Compounding: the admin UI's `updateIdentity` does PUT (full replace),
so a partial-form edit can wipe `roles` overrides if the form
doesn't preserve them. Reading the code: the form DOES preserve them
(reads `formValues.roleOverrides`), but only for clients in the
manifest; future role overrides for new clients added between form
load and submit could be dropped.

**Recommended fix:** tighten the schema (`additionalProperties: false`
under metadata_admin), and add explicit field validation in the
admin form's POST handler.

**Effort:** 2h schema tighten + form validation.

### H9. listIdentities pagination capped at per_page=250

**Location:** `portal/src/lib/admin-api.ts:78-84`

The portal calls `/admin/identities?per_page=250` without following
the Link header for pagination. At family scale (5-25 users) this
is fine. If we ever add bot/service identities or migrate from a
larger system, the admin UI silently truncates. The L1 finding
(`x-total-count` removed from sessions) doesn't apply here, but the
identities endpoint also paginates with Link headers per Kratos
v25.4.

**Recommended fix:** add a comment that 250 is hardcoded ceiling at
family scale; if it ever needs to grow, follow Link pagination
similar to `ldap-bridge/kratos/client.go:166-220`.

**Effort:** 30min comment + later (when needed) implementation.

### H10. Service-account / anonymous bind path for Jellyfin not implemented

**Location:** `ldap-bridge/DESIGN.md:144-148`,
`ldap-bridge/kratos/handler.go:97-123`

DESIGN.md lists this as an open question. The handler today rejects
empty bind DN. Jellyfin's LDAP plugin sends an anonymous bind first
to look up the user DN. This will fail in lab as soon as Jellyfin
is wired in.

**Recommended fix:** confirm Jellyfin's bind sequence in lab. Two
plausible patches:
- Allow anonymous bind to return an empty success that lets the
  plugin proceed to its search.
- Recognize a configured service-account DN+password and check it
  against an env var (no Kratos identity for the service account).

**Effort:** 4h lab + implement.

### H11. Postgres has no backup configured today

**Location:** `lab/compose/compose.yml:17-34`, no production backup
config visible.

`pg_data` volume in compose is the only data layer. If carmine's
disk fails, every passkey enrollment, every session, every Hydra
client secret is gone. Family scale = catastrophe (kids re-enroll
passkeys, parents re-enroll passkeys, admin manually re-creates 11
OIDC clients with new secrets pushed to every app).

`secrets.system` non-rotatable means even a partial restore (lost
WAL) requires regenerating clients with the same secret values, and
if the system secret is also lost, the at-rest encrypted client
secrets can't decrypt.

**Recommended fix:** before family rollout, configure pg_dump to a
mounted ZFS dataset with snapshots. Document the restore runbook
including secrets.system rehydration from Bitwarden.

**Effort:** 1 day setup + runbook.

## MEDIUM findings (fix during validation cycle)

### M1. Consent service has no rate-limit on Kratos GetIdentity

**Location:** `consent/handlers.go:137-142`

Every consent challenge fires a Kratos admin API call. Hydra remembers
consent for 1h (`consentRememberFor = 3600`), but a misbehaving
client doing repeated re-auth (Tailscale clients renewing tokens)
hits Kratos hard. No circuit breaker.

Mitigation: 10s HTTP client timeout in `client_kratos.go:25`. So
worst case is degraded latency, not infinite blocking.

**Recommended fix:** if the lab shows Tailscale or Immich mobile
hammering the consent flow, add a 30s in-process cache of the
identity lookup keyed by subject.

### M2. Consent reload doesn't validate before swap

**Location:** `consent/manifest.go:91-128`

`Reload` accepts the new manifest set into memory if every yaml
parses. It does NOT call `ValidateManifests` before swap. A reload
that introduces an undeclared role in `group_role_map` would succeed,
and during the next consent flow some users would get
`role="" claims=nil ok=false` (silently emit groups-only).

**Recommended fix:** `Reload` should call `ValidateManifests` and
abort the swap on findings, mirror the explicit `--validate-manifests`
mode behavior.

### M3. Bind cache stores positive results in plaintext SHA256(key)

**Location:** `ldap-bridge/kratos/cache.go:126-156`

The cache key is `sha256(username + NUL + password)`, no per-process
salt. Same password across processes -> same hash. Acceptable today
(the cache is in-memory and short-lived), but a memory dump of the
process gives an attacker rainbow-table-able password hashes for
every recently-bound user.

**Recommended fix:** add a per-process random salt to the key
construction. Init once at startup.

### M4. Bind cache positive results survive password rotation

**Location:** `ldap-bridge/kratos/cache.go:108-156`

If a user changes their password in Kratos, any bind cache entry for
the OLD password is still good for up to 30s. The user binds
successfully with the old password against the bridge for 30s after
they rotated.

Acceptable at homelab scale; document. Or: drop the bind cache on
manifest reload as a rough invalidation signal.

### M5. Identity cache TTL of 30s means group changes lag

**Location:** `ldap-bridge/kratos/cache.go:46-74`,
`consent/handlers.go:137-142`

Admin removes user from `access-keep`. User has up to 30s of valid
LDAP bind / consent flow with the old groups. For OIDC the 1h Hydra
remember + 30-day refresh window is the bigger lag, but the
consent-side cache adds nothing here.

**Recommended fix:** document the lag clearly. If revocation is
truly time-critical (admin recovers from mistake fast), add an admin
action that bumps a generation counter the bridge respects.

### M6. SIGHUP race during deploy

**Location:** `consent/main.go:117-127`

If a deploy renders a partial yaml (e.g., editor saves an empty file
mid-write) and SIGHUP fires twice quickly, the second handler call
runs after the first completes. Reload is mutex-protected via
`sync.Mutex` inside `m.mu` writes, so the second call simply reads
the now-completed disk state. Fine. But if SIGHUP fires DURING the
file-system write (kubectl apply, `cp` half-write), the parser sees
truncated yaml and aborts the reload - documented behavior. Net:
race-safe, but if "apply-clients.sh" SIGHUPs the consent service
without first verifying the manifest dir is consistent, an in-flight
write can cause a logged reload failure.

**Recommended fix:** apply-clients.sh should atomic-swap the manifest
directory (write to dir.tmp, rename) or sleep briefly between yaml
write and SIGHUP.

### M7. Consent service uses 4097 as its only port; healthz unauthenticated

**Location:** `consent/main.go:78`, `consent/main.go:171-174`

Single port, no separate health/admin port. `/healthz` is on the same
port as `/login`, `/consent`, `/logout`. If Caddy ever exposes `:4477`
publicly (misconfig), `/healthz` is fine but the other endpoints
become attack surface even though they require challenge tokens.

**Recommended fix:** add a comment in the README noting the public
exposure shape: this service is only reachable via Caddy on
`dag.dunn.dev/{login,consent,logout}`. Direct access to :4477 from
the public internet must be prevented at the network layer.

### M8. Verification flow is a stub

**Location:** `portal/src/pages/auth/verification.astro`

Comment says "Real implementation in Phase 3." If a user signs up
(registration is enabled per kratos.yml... wait, registration is
disabled in production, but enabled in lab) with an email, Kratos
emits a verification flow. Without a working /auth/verification
page, the user lands on a TODO.

The lab will hit this every time a new test identity is created via
Kratos's verification trigger. Either disable verification globally
or ship the page.

**Recommended fix:** ship the verification page (mirror recovery's
shape; Kratos exposes the same `flow.ui.nodes` pattern).

### M9. Logout flow does not propagate to apps

**Location:** `consent/handlers.go:196-221`,
`portal/src/pages/auth/logout.astro`

The portal logout hits Kratos's `/self-service/logout/browser` which
clears the Kratos cookie. The consent service's `/logout` accepts
Hydra logout challenges. But: the user's app sessions (Vaultwarden,
Mealie, etc.) are NOT invalidated. OIDC RP-initiated logout is not
implemented per-client.

For "I left my iPad at the coffee shop" scenarios, the user logs
out of home portal, but Vaultwarden's local session continues until
its own cookie expires. They have to log out of every app
individually.

**Recommended fix:** decide whether to implement OIDC back-channel
logout (Hydra supports it). For family scale, document the gap and
recommend session-revoke-via-admin-UI as the recovery path. The
admin can revoke all sessions for an identity; that's the closest
thing to "log everyone out everywhere."

### M10. Tailscale `roles.user.claim_emit: {}` is suppressed by emit_groups_claim: false

**Location:** `hydra/clients/tailscale.yaml:33-44`

The yaml has both `roles.user.claim_emit: {}` (empty) AND
`emit_groups_claim: false`. The role merge runs and produces no new
claims; the auto groups suppression drops the auto groups. End
result: the id_token has email, preferred_username, name; no groups.

This is the intended shape per the comment. But it's a fragile
combination: if someone in the future adds an actual claim to
`roles.user.claim_emit`, that claim will land in the id_token but
the user might miss the implicit "groups also gets dropped" behavior.
Document the contract; consider an explicit lint rule.

**Recommended fix:** add a manifest validator that warns when
`emit_groups_claim: false` is paired with a non-empty `claim_emit`
that includes a `groups` key. Today's `ValidateManifests`
(`consent/manifest.go:268-292`) doesn't check this.

### M11. portal/access.ts identity-group precedence list omits future groups

**Location:** `portal/src/lib/access.ts:36`,
`portal/src/lib/manifests.ts:48`

`IDENTITY_GROUP_PRECEDENCE` is hardcoded `['admin', 'family',
'friends', 'kids']`. `knownIdentityGroups` derives from manifest
`group_role_map` keys plus the same hardcoded set. So if a manifest
adds an identity group not in the four canonical (e.g., `service`,
`elder`), `pickIdentityGroup` falls through to the
"any other group key" loop, which uses Object iteration order over
the user's group array.

OK at v0; document the canonical set and state explicitly that new
identity groups need to be added to the precedence list.

### M12. Layout.astro / styles untested for SSR-vs-prerendered consistency

**Location:** `portal/src/layouts/Layout.astro` (not read but
referenced everywhere)

Astro 6's hybrid mode (per H6 in prior review) is finicky. Every
SSR page sets `prerender = false`. The shared layout is imported
by both. If a static asset (CSS, font) is bundled differently
across SSR and prerendered builds, there could be drift between
"the home portal works" and "/auth/login renders correctly."

**Recommended fix:** lab smoke test that hits a static page and an
SSR page back-to-back and asserts identical CSS.

### M13. handlers_test.go has no test for handleLogin / handleConsent

**Location:** `consent/handlers_test.go:1-43`

Only tests `buildReturnTo`. The actual flow logic in
`handleLogin`, `handleConsent`, `handleLogout` is unit-tested only
via the manifest+claims layer. The HTTP layer (cookie passthrough,
redirect URL construction, error mapping) has no coverage.

**Recommended fix:** add httptest-based tests with mock Hydra/Kratos
servers. Document the contract: skip / no-skip / no-session paths.

## LOW findings (track + revisit)

### L1. "16 trusted apps" count is wrong

**Location:** `docs/STATUS.md:26`, `docs/decision.md:53`,
`docs/decision.md:121`

The repo has 11 OIDC client yamls. The architecture lists 12 tile
slots (memory, listen, cinema, tune, larder, keep, library, vault,
gather, llm, forge, observe). With 2 forward-auth (tune+gather) and
1 LDAP-bound (cinema, which also has an OIDC client for browser
SSO), the total auth-attached app count is around 13. "16 trusted
apps" appears in three doc locations and twice in code comments.
Aligning to a single number reduces confusion.

### L2. consent/handlers.go comments say "14 trusted clients"

**Location:** `consent/handlers.go:99`

"All 14 trusted clients have skip_consent: true." There are 11 in
the manifest dir today.

### L3. consent service binary committed to repo

**Location:** `consent/consent` (9.7 MB)

Build artifact in the working tree. Likely ignored at git level;
verify `.gitignore`.

### L4. ldap-bridge binary committed

**Location:** `ldap-bridge/glauth-kratos` (9.3 MB)

Same as L3.

### L5. Go module path `dunn.dev/auth/consent` and `dunn.dev/auth/ldap-bridge` use the marketing domain

**Location:** `consent/go.mod`, `ldap-bridge/go.mod`

`dunn.dev/auth/...` is fine for private modules. If we ever publish
the LDAP bridge upstream as discussed, it'll need a public-domain
import path (gitlab.com/dunn.dev/auth/ldap-bridge or github.com/...).
Document the rename plan if it's an upstream candidate.

### L6. No dependency pinning for Hydra and Kratos image tags in production

**Location:** `lab/compose/compose.yml:37,48,62,90` pins to v2.2.0 /
v1.3.0; production deployment story unverified.

When carmine deploys via pyinfra, the image tag has to be pinned to
known-good versions; "latest" is a CVE-scope risk. Document.

### L7. Recovery email "from" address noreply@dunn.dev

**Location:** `kratos/kratos.yml:163-164`

The from address is fine, but receiving family members may treat
"noreply" as spam. Watch for deliverability in lab. Fastmail's
SPF/DKIM should make this a non-issue, but verify after first
recovery test.

## Decisions to lock or revisit

### D1. Admin UI runtime location

The locked decision "Astro adapter Cloudflare Workers" plus the
locked decision "admin port stays internal" are jointly inconsistent
(C1). Pick a path. Recommended: keep the home portal on Workers,
host the admin UI on carmine under `dag.dunn.dev/admin/*`. This is
NOT a revision of either locked decision; it's a clarification that
"home portal" and "admin UI" are different deployment targets.

### D2. Access-* group enforcement layer

Currently access-* groups gate the home portal tile launcher and
forward-auth Caddy snippets. They do NOT gate the OIDC consent flow
(C2). Decide whether this is the intended posture or a gap. If the
intent is "access-* is the OIDC entry gate," the consent service
must check it. If the intent is "apps that read groups enforce
themselves," document it explicitly because today's posture leaks
to apps that don't read groups (Vaultwarden, BookLore).

### D3. Admin recovery posture

H1 surfaces that admin email recovery == admin Fastmail compromise
== admin takeover. Decide:
- Disable email recovery for admin identities (Kratos-side hook or
  schema constraint).
- Keep email recovery; document that admin Fastmail is part of the
  trust boundary.
- Pre-issue durable admin-recovery tokens stored in Bitwarden as a
  break-glass option separate from email.

### D4. Logout propagation

OIDC back-channel logout vs admin-driven session revoke (M9).
Decision today is implicit (back-channel not implemented). Make it
explicit.

### D5. Webfinger byte-match for issuer

Trailing slash inconsistency (H6) is one byte. Decide once.

### D6. Apply-clients.sh field filtering

The yamls now mix Hydra OIDC fields and consent-service fields. The
script must filter (C3). Decide on the convention: top-level `consent:`
namespace, or per-field whitelist.

## Validation simulation gaps

The upcoming lab E2E test should specifically verify:

1. **Admin UI reachability of Kratos admin from Workers (C1).** Do
   the admin pages actually render against a deployed-on-Workers
   wrangler with `KRATOS_ADMIN_URL=https://...` (whatever path is
   chosen)? Confirm the answer before the next phase.

2. **Consent flow without access-\* group (C2).** Provision a test
   identity with `groups: ["family"]` only (no access-keep), navigate
   directly to a Vaultwarden OIDC redirect URL, observe that the
   consent flow accepts. Confirm whether the issued token grants
   Vaultwarden access. Document the gap.

3. **Admin form group precedence (C4).** Create an identity via
   admin form with groups in non-canonical order. Verify the
   consent service emits the role the portal "Effective Access"
   panel claims it would.

4. **apply-clients.sh against a real Hydra (C3).** Apply the
   current yamls; observe whether Hydra accepts, rejects, or
   silently strips. Capture the evidence.

5. **Webfinger byte-match (H6, H7).** `tailscale up
   --login-server=...` against the lab tenant. Capture the failure
   mode if any.

6. **Anonymous LDAP bind (H10).** Wire Jellyfin in the lab; observe
   the bind sequence. Decide the service-account or anonymous-bind
   shape based on what the plugin actually does.

7. **Postgres backup + restore round-trip.** Even a single rsync to
   a separate volume, then test the restore. Confirms the runbook
   works before family rollout.

8. **Recovery flow for admin identity (H1).** Trigger a recovery
   for an admin identity. Observe AAL of the resulting session.
   Document.

9. **SIGHUP reload during apply (M6).** Run `apply-clients.sh` while
   `kill -HUP` fires from a parallel terminal; confirm consent
   service stays up with the previous manifest set.

10. **Logout propagation (M9).** Sign in to two apps, click home
    portal logout, observe whether each app's local session persists.
    Document for family runbook.

11. **Verification flow for new identity (M8).** Create an identity
    with verification enabled; navigate the verification flow. The
    /auth/verification page is a stub today.

12. **Bind cache password rotation (M4).** Bind, change password in
    Kratos, bind with old password within 30s. Confirm the cache
    behavior; document.
