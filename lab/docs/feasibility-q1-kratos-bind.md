# Q1: Kratos API-flow login as LDAP BIND mechanism

## Verdict

YELLOW. The API flow shape works for password verification, and the AAL behavior is configurable in a way that lets first-factor verification return 200, but four real risks make this a "build with eyes open" rather than a clean GREEN:

1. Self-hosted Kratos has no built-in per-identity rate limiting (the throttle issue is open since 2020). Brute force protection is the operator's problem.
2. Even at AAL1, an MFA-enabled identity returns 200 with `session.identity` scrubbed to null when the bridge would expect a populated identity. The bridge has to read the session token / call `whoami` (or correlate flow + identity) to get the identity ID.
3. No webhook fires on admin-API identity create/update/delete. Identity events exist as OpenTelemetry trace events only, so cache invalidation has to be poll-based or OTel-span-based.
4. Filtering `/admin/identities` by trait (e.g. group=family) is not in OSS. Only `credentials_identifier` exact match and `ids` lookup work, plus `organization_id`. Group-style filtering needs a SEARCH-time fan-out or an external index.

The pattern is sound. None of the gaps are blockers at homelab scale. They do force specific implementation choices in the bridge.

## API correctness

- Endpoints confirmed:
  - `POST /self-service/login/api` — initialize an API-type login flow. Returns flow object with `id`, `type: "api"`, `expires_at`, `request_url`, `ui` (action URL, method, nodes).
  - `POST /self-service/login?flow=<id>` — submit credentials. Headers required: `Accept: application/json`, `Content-Type: application/json`.
- Request/response shapes:
  - Init response (200): `{ id, type: "api", expires_at, issued_at, request_url, ui: { action, method: "POST", nodes: [...] } }`.
  - Submit body for password method: `{ "method": "password", "identifier": "<username-or-email>", "password": "<plain>" }`.
  - Success (200, AAL satisfied): `{ session_token, session: { id, active, identity: {...}, ... } }`. Session token is `s.Token` from the source.
  - Success (200, AAL2 unsatisfied for an MFA-enabled identity at AAL1 flow): same shape but `session.identity` is set to `null` deliberately to "preserve the user's privacy in case of a phishing attack." See `selfservice/flow/login/hook.go` lines 248-256: the API branch always returns 200 with `Session` and `Token`; only `Session.Identity` is nil-ed when `checkAAL` fails.
  - Failure (400): JSON error object plus the flow embedded with UI messages on the password node.
- Verdict: shape matches what the bridge needs. The bridge must always pull identity from `session.identity` AND fall back to a lookup keyed by the BIND DN/`identifier` if `session.identity` is null (MFA-edge case below).

Sources: [user-login docs](https://www.ory.com/docs/kratos/self-service/flows/user-login), `selfservice/flow/login/hook.go` lines 218-260 in the upstream tree.

## Rate limiting

- Default behavior: none in self-hosted. The `x-ory-ratelimit-bucket: kratos-public-medium` strings in source (`selfservice/flow/login/handler.go` lines 428, 558, 716, 862) are OpenAPI swagger annotations consumed by Ory Network's edge gateway, not in-process middleware. Grep across `/tmp/kratos-src` for `ratelimit|throttle|RateLimit|Throttle` returns only those swagger comments and the changelog. No code path enforces a per-identity or per-IP cap.
- Kratos security docs explicitly delegate this to the operator: "When self-hosting the Ory Kratos Identity Server, it's the responsibility of the administrator to implement and manage rate limiting or other measures."
- Issue [#654](https://github.com/ory/kratos/issues/654) (throttling, 2020) and [#3037](https://github.com/ory/kratos/issues/3037) (RFC for throttle + lockout, 2022) are still open and stale.
- Configurable: not in Kratos itself. The supported approach is to put it behind a reverse proxy / Oathkeeper / API gateway that enforces ratelimits.
- Risk for our use case (Apple TV, Jellyfin reconnect storms):
  - With no built-in cap, BIND storms hit Kratos directly. At homelab scale that is fine for correctness but does mean every reconnect = 1 password hash check (Argon2 by default), which is intentionally expensive.
  - Mitigation: cache successful BINDs in the bridge for a short TTL (60s) keyed by identifier+password-hash; this collapses storm patterns. Layer reverse-proxy rate limits (Caddy / nftables) on the LDAP front-end as defense in depth.
  - Without bridge-side caching the Argon2 cost dominates; with it the storm is absorbed on the bridge side and Kratos sees one BIND per TTL window.

Sources: [security docs](https://www.ory.com/docs/kratos/concepts/security), [#654](https://github.com/ory/kratos/issues/654), [#3037](https://github.com/ory/kratos/issues/3037), source grep of `/tmp/kratos-src`.

## MFA in BIND path

- Default behavior with MFA-enabled identity: covered above. For API-type flows the password POST returns 200 with `session_token`, but `session.identity` is nulled out when the configured `session.whoami.required_aal` requires AAL2 and the session is still AAL1. The session is real, just scrubbed.
- The relevant config keys (verified via search and source-side `ViperKey...AAL` references):
  - `session.whoami.required_aal` — controls whether `/sessions/whoami` accepts AAL1 sessions. This is what `checkAAL` in `hook.go` reads.
  - `selfservice.flows.settings.required_aal` — protects settings.
  - `selfservice.flows.login.required_aal` — controls what AAL the login flow itself can be initialized at.
  - Values: `aal1` (lax) or `highest_available` (strict, Ory Network default).
- Configuration options:
  - Set `session.whoami.required_aal: aal1` to make the API flow return 200 with a populated `session.identity` even for users with TOTP/WebAuthn configured.
  - Keep `selfservice.flows.settings.required_aal: highest_available` if you want settings (password change, etc.) to still demand a full AAL2 session.
- Recommended approach for LDAP bind (first-factor only):
  - Run a dedicated Kratos config (or namespace) for the bridge with `session.whoami.required_aal: aal1`. Treat the bridge's BIND as a first-factor check by definition.
  - If you want stricter behavior: leave `required_aal: highest_available` and have the bridge interpret "200 with `session.identity == null`" as "password correct, MFA pending." For LDAP BIND that still translates to a successful bind because BIND only verifies the first factor; you just need to fetch the identity ID via `/admin/identities?credentials_identifier=<bind-dn>` to populate the SEARCH response.
  - Do NOT pass `?aal=aal2` on the init call. That triggers the AAL2 branch which expects an existing AAL1 session (`ErrSessionRequiredForHigherAAL`, `handler.go` line 186).
- Caveat: there is a documented vulnerability ([GHSA-wc43-73w7-x2f5](https://github.com/ory/kratos/security/advisories/GHSA-wc43-73w7-x2f5)) where `highest_available` mis-handles `code + mfa` credential combinations. Patched in 2024, but a reminder that this corner of the code is finicky.

Sources: [step-up auth docs](https://www.ory.com/docs/kratos/mfa/step-up-authentication), [self-hosted MFA](https://www.ory.com/docs/kratos/self-hosted/mfa), [discussion #2996](https://github.com/ory/kratos/discussions/2996), [discussion #3408](https://github.com/ory/kratos/discussions/3408), `selfservice/flow/login/hook.go` lines 89-100, 248-256.

## CSRF / API-flow auth shape

- Confirmed CSRF-free: the Kratos docs describe CSRF as a browser-flow concern. API flows return a flow object suitable for native apps and explicitly warn against using API flows in browsers because they bypass CSRF protection. From the docs: "Never use API flows to implement Browser applications! Using API flows in Single-Page-Apps as well as server-side apps opens up several potential attack vectors, including Login and other CSRF attacks." For a server-side LDAP bridge this is exactly the right shape.
- Required headers:
  - `Accept: application/json` on both the init and the submit (this is what flips the response shape; without it Kratos may try to redirect).
  - `Content-Type: application/json` on the submit.
  - No CSRF token, no session cookie required for an unauthenticated login init.
- For SEARCH path against admin API: `Authorization: Bearer <admin-token>` (the admin API itself has no built-in auth, so put it behind a network boundary or front it with Oathkeeper).

Sources: [user-login docs](https://www.ory.com/docs/kratos/self-service/flows/user-login).

## Prior art

- Existing projects:
  - [neutronth/kratos@strategy-ldap](https://github.com/neutronth/kratos/tree/strategy-ldap) — fork attempting to add an LDAP authentication strategy *into* Kratos (Kratos-as-LDAP-client). This is the inverse direction of our bridge. No README content, low activity.
  - [ory/kratos#274](https://github.com/ory/kratos/issues/274) — original LDAP feature request from 2020. Closed/stale, no maintainer endorsement of any specific approach.
  - [ory/kratos#4538](https://github.com/ory/kratos/issues/4538) — open feature request for a dedicated admin "validate credentials" API. The fact that this is still open implies the API self-service flow remains the canonical mechanism for validating a password from a back-channel service.
  - No published "Kratos LDAP bridge" project found via search. The pattern is original to us at the level of search visibility (May 2026).
- Community discussion:
  - Multiple discussions confirm the LDAP-in-front-of-Kratos pattern is the only architectural option people have used; LDAP-as-source-of-truth-for-Kratos is unimplemented.
  - Authentik and Authelia both ship LDAP outposts/providers natively. Kratos does not, by design (Ory's position is that LDAP is legacy and they will not implement it natively).

Verdict on prior art: no off-the-shelf bridge to fork. Comparable patterns (Authentik LDAP outpost, glauth proxy modes, privacyidea LDAP proxy) are useful as architectural references for cache-vs-direct-bind tradeoffs. Authentik's "direct vs cached" outpost split is the most relevant precedent.

Sources: [#274](https://github.com/ory/kratos/issues/274), [#4538](https://github.com/ory/kratos/issues/4538), [neutronth fork](https://github.com/neutronth/kratos/tree/strategy-ldap), [Authentik LDAP outpost](https://docs.goauthentik.io/add-secure-apps/providers/ldap/), [glauth](https://github.com/glauth/glauth), [privacyidea-ldap-proxy](https://github.com/privacyidea/privacyidea-ldap-proxy).

## Webhooks / cache invalidation

- Available hooks: only self-service flow hooks. The configurable trigger points are `before` and `after` for `login`, `registration`, `recovery`, `settings`, `verification`. Each can fire `web_hook` actions with a Jsonnet-templated body that includes `ctx.identity` (id and traits).
- Critical gap: there is NO hook for admin-API CRUD. `POST /admin/identities`, `PUT /admin/identities/{id}`, `DELETE /admin/identities/{id}` do not fire user-configurable webhooks. Source confirms: `x/events/events.go` defines `IdentityCreated`, `IdentityUpdated`, `IdentityDeleted` as OpenTelemetry semantic-convention trace events (`semconv.Event`) emitted via `trace.WithAttributes` — these go to the OTel exporter, not to a webhook subscriber.
- Recommended pattern:
  - Bridge maintains an in-memory or BoltDB cache of identities for SEARCH responses.
  - For invalidation: poll `/admin/identities` on a TTL (e.g. 30s) since at homelab scale the list is small. Use ETag / `Last-Modified` if present, or a hash of the response.
  - Wire the `after` hooks for `registration` and `settings` to also POST to the bridge so user-driven changes invalidate within seconds. This covers most real-world identity churn.
  - Admin-driven changes (operator running `kratos identities import`, etc.) are caught only by the poll. Acceptable at homelab cadence.
  - If OTel-driven invalidation is appealing later, ship Kratos's OTel traces to a sidecar that filters for `IdentityCreated/Updated/Deleted` and POSTs to the bridge. This is more plumbing than it's worth at this scale.

Sources: [Ory Actions](https://www.ory.com/docs/kratos/hooks/configure-hooks), [webhook guide](https://www.ory.sh/docs/guides/integrate-with-ory-cloud-through-webhooks), `x/events/events.go` lines 24-26 and 388-410.

## Identity listing for SEARCH

- `/admin/identities` behavior (verified in `identity/handler.go` lines 100-308):
  - Method: `GET /admin/identities`. Routed via `admin.GET(RouteCollection, h.list)`. Auth scheme in OpenAPI: `oryAccessToken` (Bearer token) for Ory Network; in self-hosted OSS the admin port itself is unauthenticated by default and must be network-isolated or fronted by Oathkeeper.
  - Pagination: supports both keyset (`page_token`, `page_size`) and page-number (`page`, `per_page`) styles via `x.ParseKeysetOrPagePagination`. Response includes Link header for next page.
  - Response: array of identities. With `include_credential=password` (or other) the credentials are included; otherwise credentials are stripped. `metadata_admin` is included on this admin endpoint. Traits are always included.
- Filtering options (mutually exclusive — `requestedFilters > 1` returns 400):
  - `ids=<uuid>&ids=<uuid>` — fetch by ID, max 500.
  - `credentials_identifier=<exact>` — exact match on a credential identifier (the username/email registered against the password credential). This is the canonical "look up by username" path for LDAP BIND DN resolution.
  - `preview_credentials_identifier_similar=<partial>` — similarity search. Marked EXPERIMENTAL and "WILL BE REMOVED IN AN UPCOMING RELEASE WITHOUT ANY MIGRATION PATH." Do not depend on it.
  - `organization_id=<uuid>` — only useful if you adopt Ory's org model.
  - `include_credential` — repeated, controls credential expansion.
- Filter-by-trait: not available in OSS. The advanced search API (`/admin/preview/search/v0beta1/collections/identities/documents/search` with `query_by=traits.email`, `filter_by`) is Ory Network only, per the docs and per maintainer aeneasr in [discussion #3591](https://github.com/ory/kratos/discussions/3591): "It's unlikely [in OSS] because it needs a second search engine and that depends on scale, frequency of changes and so on." Recommended workarounds: list-and-client-filter, or direct SQL query against the `identities` table.

Implication for the bridge SEARCH path:
- BIND DN -> identity: use `credentials_identifier`. Fast, exact, supported.
- LDAP SEARCH for "all users in `cn=family,ou=groups,...`": no native filter. Options:
  1. Encode the group as a trait (e.g. `traits.groups: ["family"]`), list all identities once on a poll, filter in the bridge. At homelab scale (< 1000 identities) this is fine.
  2. Encode group membership in `metadata_admin` and same approach.
  3. Use `ids=<uuid>...` with a precomputed group->ids map maintained in the bridge.

Sources: [list-identities](https://www.ory.com/docs/kratos/manage-identities/managing-users-identities) (404 at the URL given but documented in source), [search API](https://www.ory.com/docs/kratos/manage-identities/search/identity-search-api), [discussion #2379](https://github.com/ory/kratos/discussions/2379), [discussion #3591](https://github.com/ory/kratos/discussions/3591), `identity/handler.go` lines 117-244.

## Gotchas / risks

1. **MFA + null identity in API flow response.** When `session.whoami.required_aal: highest_available` and the user has TOTP, the password POST returns 200 with `session.identity == null`. If the bridge needs the identity ID after a successful BIND (it does, for SEARCH consistency), it must call `/admin/identities?credentials_identifier=<bind-dn>` to retrieve it. Build this fall-back path from day one or set `session.whoami.required_aal: aal1` for the bridge's Kratos.
2. **No built-in rate limiting.** Argon2 password verification is expensive by design. A reconnect storm of N clients with M reconnects/sec each = N*M Argon2 hashes/sec on Kratos. Cache successful BINDs in the bridge with a short TTL (~60s) keyed by `(identifier, hashed-password)` to absorb storms. Layer external rate limits (Caddy, nftables) on the LDAP listener.
3. **No admin-CRUD webhooks.** Cache invalidation must be polling-based or driven by self-service `after` hooks. Admin-side identity edits (operator CLI, scripted updates) only get picked up by polling. Pick a poll interval that matches your churn tolerance.
4. **No OSS trait filtering.** SEARCH for "users in group X" requires list-and-filter in the bridge. Plan for the bridge to maintain its own group->identity index, ideally driven by a trait field in the identity schema.
5. **`preview_credentials_identifier_similar` is doomed.** Do not use it for fuzzy username lookup; the docstring promises removal without migration.
6. **Admin API has no auth in self-hosted.** Default config exposes admin endpoints unauthenticated on port 4434. Lock this down via network policy, Tailscale ACLs, or Oathkeeper before exposing.
7. **CSRF warning is real.** Make sure the bridge process never proxies the API flow response back to a browser. API flows are explicitly marked unsafe for browser use.
8. **Account lockout is on the operator.** Without throttle-after-N-fails behavior, brute force is rate-only-limited. Bridge can implement a per-identifier failure counter with exponential backoff before it ever calls Kratos.
9. **`?aal=aal2` on init is not the path.** Init at AAL1 (default). Setting `aal=aal2` requires an existing AAL1 session and will reject otherwise (`ErrSessionRequiredForHigherAAL` in `handler.go`).
10. **highest_available CVE history.** [GHSA-wc43-73w7-x2f5](https://github.com/ory/kratos/security/advisories/GHSA-wc43-73w7-x2f5) shows this code has had subtle bypass bugs; pin to a recent Kratos release and watch advisories.

## Sources

- Docs:
  - https://www.ory.com/docs/kratos/self-service/flows/user-login
  - https://www.ory.com/docs/kratos/mfa/overview
  - https://www.ory.com/docs/kratos/mfa/step-up-authentication
  - https://www.ory.com/docs/kratos/self-hosted/mfa
  - https://www.ory.com/docs/kratos/concepts/security
  - https://www.ory.com/docs/kratos/hooks/configure-hooks
  - https://www.ory.sh/docs/guides/integrate-with-ory-cloud-through-webhooks
  - https://www.ory.com/docs/kratos/manage-identities/search/identity-search-api
- GitHub issues / discussions:
  - https://github.com/ory/kratos/issues/274 (LDAP feature request)
  - https://github.com/ory/kratos/issues/654 (throttling)
  - https://github.com/ory/kratos/issues/3037 (throttling RFC)
  - https://github.com/ory/kratos/issues/4538 (admin API credential validation)
  - https://github.com/ory/kratos/discussions/2379 (lookup by email)
  - https://github.com/ory/kratos/discussions/2996 (2FA login flow shape)
  - https://github.com/ory/kratos/discussions/3408 (2FA bypass with Hydra+JSON)
  - https://github.com/ory/kratos/discussions/3591 (filter identities by trait)
  - https://github.com/ory/kratos/security/advisories/GHSA-wc43-73w7-x2f5
- Source (ory/kratos default branch, fetched May 2026):
  - `selfservice/flow/login/handler.go` lines 146-275, 426-862
  - `selfservice/flow/login/hook.go` lines 86-100, 218-260, 282-340
  - `identity/handler.go` lines 100-308
  - `x/events/events.go` lines 22-30, 386-415
- Comparable projects:
  - https://github.com/neutronth/kratos/tree/strategy-ldap
  - https://github.com/glauth/glauth
  - https://github.com/privacyidea/privacyidea-ldap-proxy
  - https://docs.goauthentik.io/add-secure-apps/providers/ldap/
