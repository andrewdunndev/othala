# Security

Othala issues the tokens and gates the access that everything downstream trusts.
This document states where the trust boundary sits, what is defended and by
which file, and what is knowingly not defended.

## Reporting a vulnerability

Do not open a public issue or merge request. Open a **confidential issue** at
<https://gitlab.com/dunn.dev/othala/-/issues>, ticking "This issue is
confidential" before you submit; those are visible only to project members.
Include the affected component and commit or tag, what an attacker gains,
reproduction steps, and relevant deployment specifics. A flaw in upstream Ory Kratos or Hydra rather than
in this glue goes to Ory (<https://www.ory.sh/docs/ecosystem/security>); a note
here is still welcome.

Expect acknowledgement within 3 business days and an assessment within 10. One
maintainer, best effort, no on-call, no bounty, coordinated disclosure: fixed privately, released, then
published, with credit unless you decline it. Fixes land on the newest tag; older
tags are not backported.

## The trust boundary

**Trusted:** the host, the pod network, Postgres, the operator's shell, and
anything that can reach the Kratos or Hydra admin APIs. Lose one of those and
everything is lost; no control here is written to survive it.

**Untrusted:** every HTTP request, inbound header, cookie, manifest field, and
value a downstream app hands back.

- **The Ory admin APIs authenticate nobody.** They are protected by bind address
  (`KRATOS_ADMIN_BIND_HOST` in `kratos/kratos.yml`, `HYDRA_ADMIN_BIND_HOST` in
  `hydra/hydra.yml`) and network reachability, and nothing else. Exposing
  either port is total compromise.
- **`metadata_admin` is writable only through the Kratos admin API.** Every
  authority decision reads from it, which is why it is always fetched fresh from
  the admin API and never taken from a session payload (`/sessions/whoami` omits
  it).

## Controls

Each names its enforcer and the test that fails if it stops working.

- **Entry gate, fail-closed.** `enforceAccessGate` / `enforceGroupGate`,
  `portal/src/lib/gate.ts`: state exactly `active`, plus membership in at least
  one group the app's own manifest binds (OR-semantics). No manifest, an empty
  binding, or a failed lookup denies; a group's name, a role mapping and the
  admin marker admit nobody. Tests: `portal/scripts/gate-property.test.mjs`,
  `e2e/playwright/tests/t-access-model.spec.ts`.
- **Read-boundary refusal.** `refuseNonCanonical`, `portal/src/lib/gate.ts`:
  denies every app when a stored group name could not have been written
  by any path this codebase owns (`GROUP_RE`, `portal/src/lib/access-groups.ts`).
  Test: `portal/scripts/noncanonical-repair.test.mjs`.
- **Portal admin authority.** `requireAdminSession`, `portal/src/lib/admin.ts`:
  active session, assurance level exactly `aal2`, and the `metadata_admin.admin`
  marker read fresh from the admin API (`parseIdentity`,
  `portal/src/lib/identity-facts.ts`). No group grants it. Tests:
  `portal/src/lib/identity-facts.test.ts`, `e2e/playwright/tests/f-aal2-bypass.spec.ts`.
- **Internal-network admin listener (PORTAL_ADMIN_BIND_HOST).** `portal/src/server/listen.ts`: privileged routes
  on a separate internal-network listener whose mux is disjoint from the public one,
  guarded by one bearer secret compared with `bearerMatches`
  (constant-time, fail-closed on an unset secret). Test:
  `portal/scripts/public-mux-disjoint.test.mjs`.
- **Recovery is not a path to admin.** The recovery `after` hook in
  `kratos/kratos.yml` posts `kratos/hooks/recovery-gate.jsonnet` to that internal
  gate before the privileged settings session issues; `shouldRefuseRecovery`
  (`portal/src/lib/access.ts`) refuses an admin-marked target, so a compromised
  mailbox does not become admin authority. Tests:
  `portal/scripts/admin-port.test.mjs`, `e2e/playwright/tests/j-recovery-flow.spec.ts`.
- **Claims decide role, never entry.** `composeIDTokenClaims` / `lookupRole`,
  `portal/src/lib/claims.ts`: a per-app role, every claim gated on the granted
  scope, and `deepMergeClaims` skipping `__proto__`, `constructor`, `prototype`.
  Tests: `portal/scripts/claims-inject.fuzz.test.mjs`, `e2e/playwright/tests/t-access-model.spec.ts`.
- **Manifest validation, fail-closed.** `validateClients` and
  `audienceMatchesRedirect`, `portal/src/lib/manifests.ts`, reject a duplicate
  `client_id`, an empty audience, an audience with no exact-origin redirect
  match, an undeclared role in `group_role_map`, an empty access binding;
  `loadClientManifests` then drops each such file, so its app is an unknown client
  and is refused at login and consent, while the rest keep serving (its Hydra client keeps
  its last registered config, so its refresh tokens and client_credentials grant keep working until the manifest is fixed or the client is deleted from Hydra); if the directory itself cannot load,
  `portal/src/lib/manifest-store.ts` serves the last known good set, or the empty
  set on a cold start, which denies everywhere. Tests:
  `portal/scripts/manifests-loader.test.mjs`, `portal/scripts/manifest-validate.fuzz.test.mjs`, `portal/src/lib/manifest-store.test.ts`.
- **A device grant needs a fresh second factor and a shown code.** A
  verification link can carry someone else's code, so `handleLogin` and
  `handleConsent` (`portal/src/lib/oauth2-handlers.ts`) hold any request whose
  `request_url` is Hydra's device verification path (`isDeviceRequest`,
  `portal/src/lib/device.ts`) to a sign-in inside the fresh window at `aal2`,
  refuse an identity with no second factor, and always confirm against the code
  this browser entered, whatever `skip_consent` says. The portal enforces this
  because Hydra ignores `prompt` and `max_age` there. Tests:
  `portal/scripts/oauth2-handlers.test.mjs`, `e2e/playwright/tests/zo-device-phishing.spec.ts`,
  `e2e/playwright/tests/zp-device-aal1-refused.spec.ts`.
- **forward_auth never trusts a header.** `portal/src/pages/api/forward-auth.ts`
  takes the required group from an operator-set query parameter and the user's
  groups from the admin API; no inbound identity header is read, and `HEAD`
  reuses the `GET` decision verbatim. The status contract (200/401/403/503) is in
  [`ARCHITECTURE.md`](ARCHITECTURE.md) § The status contract. Test:
  `portal/scripts/forward-auth.test.mjs`.
- **Browser hardening.** `applySecurityHeaders`, `portal/src/middleware.ts`:
  frame-ancestors and `X-Frame-Options`, `nosniff`, `Referrer-Policy`,
  `Cross-Origin-Opener-Policy`, HSTS, and a `form-action` bounded to the
  configured apex. CSRF on state-changing POSTs is Astro's `security.checkOrigin`
  (`portal/astro.config.mjs`) plus `portal/src/lib/csrf.ts`. Tests:
  `e2e/playwright/tests/m-security-headers.spec.ts`, `e2e/playwright/tests/r-admin-post-origin.spec.ts`,
  `portal/scripts/oauth2-handlers.test.mjs`.
- **Abuse resistance ships with the install.** `othala-routes` in `caddy/othala.caddy` rate-limits the
  Kratos self-service paths keyed on `{client_ip}` and overwrites
  `X-Forwarded-For` at every `reverse_proxy`, so a client cannot mint a fresh
  bucket per request; `kratos/kratos.yml` bounds password-hash work
  (`hashers.argon2`) and code guessing (`max_submissions`, `lifespan`). Test:
  `e2e/playwright/tests/zq-edge-rate-limit.spec.ts`.
- **Credential and session hygiene.** Self-registration is disabled in
  `kratos/kratos.yml`, so enrolment is admin-initiated; breach checking and a
  minimum length gate passwords; a password change fires
  `revoke_active_sessions`; force-logout is `revokeSubject`
  (`portal/src/lib/revoke.ts`). Full eviction (audit, delete credential, then
  revoke) is documented in `docs/runbooks/lost-device.md`, proven live by
  `e2e/playwright/tests/p-eviction.spec.ts`.
- **Telemetry carries no secrets.** `portal/src/server/otel.mjs` scrubs session
  cookies, CSRF tokens, bearer headers, challenge ids and one-time codes out of
  spans before export. Test: `portal/scripts/otel-redaction.test.mjs`.

## Accepted risks

- **Plaintext inside the trusted host.** Both Postgres DSNs set
  `sslmode=disable` and both tracing exporters set `insecure: true`
  (`kratos/kratos.yml`, `hydra/hydra.yml`). Each assumes the hop stays inside one
  pod on one host; on a segmented network, fix them before deploying.
- **The CSP carries no `script-src`** (`portal/src/middleware.ts`). A strict one
  breaks the WebAuthn ceremony's injected inline scripts and the portal's inline
  theme script, so an XSS in the portal is not contained by CSP. See
  `site/src/content/docs/guides/hardening.md`.
- **Rate limiting depends on a third-party Caddy module.** A binary built without
  it refuses to load `caddy/othala.caddy`, so the failure is a refusal to start,
  not a silently unlimited edge. Confirm it is compiled in.
- **The identity-header strip matches names, not spellings.** Caddy cannot
  match `X_Remote_User`, which WSGI and CGI upstreams fold into the same
  variable as `X-Remote-User`. An app behind `othala-forward-auth` that trusts
  a proxy identity header must read the hyphenated name only.
- **`{client_ip}` is only as good as `trusted_proxies`.** Behind a trusted load
  balancer without `trusted_proxies_strict`, Caddy takes the leftmost
  `X-Forwarded-For` entry, which the client chose. See `DEPLOY.md`.
- **Sessions are long-lived and `whoami` answers at the first assurance level**
  (`kratos/kratos.yml`, `session`). A stolen cookie stays valuable for the
  session lifespan; revocation ends it sooner.
- **Role rank is a convention no code enforces.** `lookupRole`
  (`portal/src/lib/claims.ts`) reads declaration order in `consent.roles` as
  descending privilege, so a manifest listing roles ascending silently downgrades
  its users. The direction is fail-safe; the silence is not.
- **A member with no second factor: the mailbox holder keeps the account.** An emailed code proves the mailbox, not the person. A passkey or TOTP the mailbox holder adds is accepted, and the email-change gate only guards members who already hold a passkey or password.
- **A refused device keeps polling.** Hydra has no device-grant reject, so a
  denied or refused code answers `authorization_pending` until it expires.

## Out of scope

- Anything that first requires a compromised host, the operator's shell, or
  reachability to the Ory admin APIs. Break-glass recovery is console-only.
- Dependency CVEs with no exploit path through this code. Report those upstream.
- The `e2e/` harness: RFC 6761 reserved domain `othala.test`, throwaway secrets.
- Volumetric network-layer flooding, which needs upstream capacity to absorb;
  application-layer abuse is in scope and listed under Controls.
