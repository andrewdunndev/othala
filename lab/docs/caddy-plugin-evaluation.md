# Caddy forward-auth plugin evaluation

Date: 2026-05-02

## Summary

Pick **caddy-security (greenpau)** as the forward-auth substrate in front of
kanidm for the lab. It is actively maintained (release v1.1.62 on 2026-04-13,
last commit 2026-04-25, maintainer responding within hours on issues filed
days ago), supports a generic OIDC provider with PKCE and JWKS discovery,
handles cross-subdomain cookies (`cookie domain *.example.com`), and supports
header injection from claims (`inject header "Remote-Email" from
"email_address"`). It is a known-working pairing with kanidm: a homelab
walkthrough from 2025-07 shows the full Caddyfile + kanidm OAuth2 client
combo. The single-maintainer governance is the main risk; fallback is
oauth2-proxy as a sidecar process per app, which is heavier operationally
but proven and widely deployed (14k stars, release 2026-04-14).

The model is "authentication portal issues a JWT cookie, then `authorize`
directive validates inline" — not classic forward_auth. For our shape (one
Caddy sidecar per app, same xcaddy build pattern, single config syntax) the
inline model is actually a better fit than forward_auth: no second hop, no
inter-process IPC, the JWT cookie covers the whole `*.dunn.dev` subdomain
tree from one portal.

## caddy-security

- **Maturity**: 2.1k stars, 98 forks, project started 2022-01. v1.1.62
  released 2026-04-13. Underlying library `greenpau/go-authcrunch` v1.1.39
  released 2026-04-13 (same day). Releases roughly weekly: v1.1.56 →
  v1.1.62 between 2026-03-27 and 2026-04-13.
- **Maintainer state**: Paul Greenberg (greenpau) is sole primary
  maintainer. Active on issue tracker through May 2026 — replied to issue
  #486 within ~10 minutes of it being filed (2026-05-01). External
  contributors landing PRs (e.g. ebardsley CLA-signed contribution merged
  2026-04-25). No fork drama, no governance dispute, no abandonment
  signals. **Risk: single maintainer, no co-maintainer succession.**
- **Last release / commit**: v1.1.62 on 2026-04-13. Last commit on `main`
  is 2026-04-25 (`breakfix: caddy placeholder not replaced within
  user_group_filters`).
- **Issue tracker velocity**: 16 open issues, 345 closed (status: nearly
  all 2026-Q1 issues are already closed). Recent breakfixes closed within
  days of being filed: #485 closed 2026-05-02 (filed 2026-05-01), #483
  closed 2026-04-25, #481 closed 2026-04-10. No long-unanswered open
  security issues. Open issues skew toward features (multi-domain auth,
  refresh-token UX, persistent sessions), not bugs.
- **OIDC client capability for kanidm**: Yes. Supports a "Generic OAuth2
  provider" backed by OIDC discovery (`metadata_url`) which then
  auto-resolves `jwks_uri`. PKCE is enabled by default for the generic
  provider. Group/role claim mapping uses `transform user` directives that
  match on claim values and apply roles. Confirmed working against kanidm
  in a 2025-07-12 blog walkthrough (tricked.dev) and a Home Assistant
  community thread. Caveat from the walkthrough: kanidm groups must be the
  authorization basis, not roles, and you must use shared keys per host.
- **JWT cookie handling**:
  - Cookie domain configurable per-domain (`cookie domain
    *.{$CADDY_BASE_HOST}` and the `domains` map in JSON config).
  - Multi-domain config tested in issue #161 (open feature request for
    sharing one auth portal across truly separate registrable domains;
    same-domain wildcard subdomains work today).
  - Cookie name configurable, lifetime configurable, `Secure` and
    `HttpOnly` are set.
  - Logout supported via `trust logout redirect uri domain ... path
    suffix /` directive (now documented per issue #465 closed 2026-03-10).
  - Recent regression in v1.1.32+ where the portal deleted the
    `access_token` cookie after successful OIDC login (#471) was fixed in
    a follow-up release.
- **Forward-auth use case fit**: Architecturally, caddy-security is NOT a
  classic forward_auth backend. The `authorize` directive runs inline in
  the same Caddy process, validates a JWT cookie that the
  `authentication portal` previously issued, and (optionally) injects
  request headers from claims before the request reaches the upstream
  reverse_proxy. This is documented as the intended pattern. Issue #460
  (open, work-in-progress, filed 2026-03-05) explicitly tracks "make
  authorize plugin work as forward_auth" — meaning even the maintainer
  acknowledges classic forward_auth shape is not yet there. Issue #462
  closed 2026-03-30 shipped a partial step: a "System API" that lets
  `authorize` reach a remote `authentication portal` for Basic/API-key
  auth; OIDC over System API is the next step but not yet shipped.
  - For our one-Caddy-sidecar-per-app-pod shape, the inline model is a
    feature, not a bug: each pod's Caddy embeds both `authentication
    portal` and `authorize`, no second-hop IPC.
- **Real-world kanidm integration reports**:
  - tricked.dev, 2025-07-12: full Caddyfile + kanidm `system oauth2`
    setup, ESPHome behind it, group-based authorization. Notes a
    bootstrap race when kanidm and Caddy run on the same host (Caddy's
    OIDC discovery fires before Caddy itself is up); workaround is
    Cloudflare Tunnel or splitting the host.
  - kanidm GitHub Discussion #3777: example Caddyfile with kanidm behind
    Caddy reverse proxy. Cert renewal between Caddy and kanidm is the
    fiddly bit; auth flow itself works.
  - Home Assistant community thread (2022-12, still referenced):
    caddy-security with JWT cookie scoped to `.my.home.assistant`,
    "running for weeks, no hiccups."
- **Verdict**: **green-yellow**. Active maintainer, active project, fits
  our shape on paper, has community evidence with kanidm specifically.
  Yellow on single-maintainer risk and on the "we're depending on a model
  that's not classic forward_auth" — if the model bites in lab, the
  fallback is oauth2-proxy.

## caddy-jwt + custom plugin we write

- **Plugin status**:
  - **ggicci/caddy-jwt** is the active option: v1.1.2 on 2026-03-08, 118
    stars, supports `jwk_url` for JWKS endpoint key fetch, extracts
    tokens from query/header/cookie, supports nested claim paths via
    `meta_claims`. xcaddy buildable. Pure JWT validator, no OIDC client
    flow.
  - BTBurke/caddy-jwt last pushed 2020-10, last release 2017 — abandoned
    for v2 work.
  - golgeek/caddy-auth-jwt and forks: stale, ~1 star each, not
    maintained.
- **Custom plugin scope estimate**: To get a kanidm-aware Caddy plugin
  that does OIDC client (authorize endpoint redirect, code exchange, JWT
  cookie set, JWKS validation, header injection, logout), we'd write
  ~300-500 lines of Go covering: (1) `caddyhttp.MiddlewareHandler` impl,
  (2) OIDC discovery + JWKS cache, (3) PKCE state, (4) cookie session
  store, (5) header injection from claims, (6) Caddyfile UnmarshalCaddy
  wiring. Achievable in a focused week. ggicci/caddy-jwt would cover the
  validation half, leaving us writing the OIDC-client + cookie-set half.
  But: writing forward_auth code is a known security minefield (see
  CEbbinghaus's 2025-10 review in kanidm #2774 finding bugs in every
  open-source forward_auth implementation he tested, including nonce
  discard and access-token substitution). Rauthy's docs warn "Use
  Forward Auth only as a last resort." We are not the right team to
  ship a novel auth proxy.
- **Verdict**: **red as a primary path**. Reasonable as a thin
  contribution to ggicci/caddy-jwt if we end up doing pure JWT-cookie
  validation against a kanidm-issued cookie that some other component
  set; not reasonable as the way we get OIDC client + cookie issuance.

## oauth2-proxy as separate process

- **Maturity**: 14k stars, v7.15.2 on 2026-04-14, last push 2026-05-02.
  CNCF-adjacent, deployed at scale across the industry.
- **OIDC against kanidm**: Proven working. Multiple homelab writeups,
  kanidm `#2774` recommends it, pando85's setup uses kanidm + Nginx +
  oauth2-proxy in production.
- **Operational cost**: Separate process per app pod (or one shared
  oauth2-proxy with `--upstream`-per-app), separate config, separate
  health/metrics surface, separate version-pin. Caddy's built-in
  `forward_auth` directive then points at it.
- **Conceptual congruity vs caddy-security**: Lower. We lose the
  "single xcaddy build, single Caddyfile" property the user asked for.
- **Verdict**: **green as fallback**, **yellow as primary**. If
  caddy-security trips us in lab, oauth2-proxy is the next pick because
  the security story is rock solid and the pattern (Caddy
  `forward_auth` → oauth2-proxy → kanidm) is well-trod.

## Caddy built-in forward_auth (against future kanidm endpoint)

- **Status**: Built into Caddy core today. Works against any HTTP auth
  endpoint that returns 2xx + headers on auth success or 3xx redirect
  to login on failure. Standard config: `forward_auth host:port { uri
  /verify; copy_headers Remote-User Remote-Groups Remote-Email }`.
- **Blocker**: kanidm issue #2774 ("forward_auth support in kanidm")
  was closed 2024-10-22 as `completed` BUT the actual resolution was
  "we will not implement this in kanidm core; use external middleware"
  (yaleman, Firstyear). Kanidm maintainers explicitly view native
  forward_auth as unspecced, security-fraught, and out of scope. They
  point users to oauth2-proxy, traefik-forward-auth,
  espresso-lab/oidc-forward-auth-middleware, and Rauthy.
- **Implication for our upstream contribution plan**: If our plan was
  "contribute native forward_auth to kanidm," that contribution will
  be rejected. The kanidm answer is and will be "use a sidecar OIDC
  client that speaks forward_auth on one side and OIDC on the other."
  Our upstream contribution target should pivot to either (a)
  improving an existing OIDC-forward-auth shim, or (b) the
  authorization-server end of the conversation (claims, scopes,
  group-based access).
- **Verdict**: **not the right answer for kanidm specifically**. For
  Authelia or self-hosted-IDPs that DO speak forward_auth natively,
  this is the cleanest pattern. For kanidm, no.

## Recommendation

**Pick caddy-security as the lab substrate.** Rationale, in order:

1. Conceptual congruity with the existing xcaddy + caddy-dns/cloudflare
   build pattern. Same image, same Caddyfile syntax, one process per
   sidecar.
2. Active maintenance with strong velocity (releases weekly, issues
   closed in days, maintainer responsive within hours).
3. Existing community evidence of working against kanidm specifically,
   with the exact shape we want (OIDC client + JWT cookie scoped to a
   subdomain wildcard + group-based authz + header injection to
   downstream apps).
4. The "not classic forward_auth" model is acceptable for our shape
   because we run Caddy as a sidecar per app — the inline `authorize`
   directive is the right ergonomics, not a downgrade.

**Rank-ordered fallback list**:

1. **caddy-security** (primary).
2. **oauth2-proxy as Caddy `forward_auth` upstream** — proven, heavier,
   adopt if caddy-security's cookie / multi-domain / single-maintainer
   risk bites in lab.
3. **espresso-lab/oidc-forward-auth-middleware** behind Caddy
   `forward_auth` — Rust, kanidm-specifically referenced from kanidm
   docs, but small (17 stars, v4.0.3 on 2026-01-20) and CEbbinghaus
   flagged correctness concerns in 2025-10 (nonce discard). Only if 1
   and 2 both fail.
4. **Custom Caddy plugin** — last resort, do not start here.

## Lab-validation plan

Specific things to verify in the GCP lab before committing to
caddy-security in production. These are the failure modes we expect
based on the above research, in order of likelihood:

1. **Cross-subdomain cookie**. Issue a JWT cookie at `auth.example.com`,
   confirm the cookie is sent on requests to `app1.example.com` and
   `app2.example.com`. Verify the `Domain=.example.com` attribute.
   Confirm `Secure`, `HttpOnly`, `SameSite=Lax`. Test logout clears the
   cookie everywhere.
2. **Generic OIDC against kanidm**. Configure `oauth identity provider
   kanidm` with `metadata_url
   https://idm.example.com/oauth2/openid/<client_id>/.well-known/openid-configuration`.
   Confirm OIDC discovery succeeds, JWKS is fetched, login round-trips,
   id_token is validated. Test with kanidm account, group claim
   present.
3. **PKCE**. Confirm PKCE is on by default for the generic provider
   (per docs claim), capture the auth-code request, verify
   `code_challenge` is sent.
4. **Group-based authz**. Map a kanidm group (e.g. `homelab_users`) to
   a caddy-security role via `transform user` and gate `app1` on it.
   Verify a user in the group passes; a user not in the group is
   denied with the right error.
5. **Header injection**. `inject header "Remote-User" from "preferred_username"`,
   `Remote-Groups` from groups claim, `Remote-Email` from email.
   Confirm the upstream app sees the headers. Check claim path syntax
   when claims are nested.
6. **Bootstrap race**. The tricked.dev writeup flagged
   caddy-security's OIDC discovery firing before kanidm is reachable
   when both run on the same host. In lab, run both in separate
   container/host. If we ever co-locate them, plan for retry/backoff
   or split-host deploy.
7. **Concurrent sessions / restart behavior**. Issue #468 confirms
   sessions are NOT persisted across container restart today. Verify
   how disruptive re-auth on Caddy reload is for our app set; if it's
   user-visible every Caddy reload, we need to either pin Caddy
   reloads to off-hours or accept the UX.
8. **Wildcard cert + cookie domain interaction**. Issue #480 (closed
   2026-04-10) shows users tripped on this with the latest version.
   Test our specific config matches the post-fix shape.
9. **Logout / `trust logout redirect`**. Verify logout URL works
   across all subdomains and cookie is fully cleared.
10. **Upgrade rollback discipline**. caddy-security's v1.1.32+
    regression around access_token cookie deletion (#471) shows that
    point releases can break auth. Pin the caddy-security version in
    our xcaddy build, gate upgrades through lab smoke before
    production roll.

## Sources

- caddy-security repo: https://github.com/greenpau/caddy-security
- caddy-security v1.1.62 release (2026-04-13): https://github.com/greenpau/caddy-security/releases/tag/v1.1.62
- caddy-security issue #460 "feature: authorize plugin to work as forward_auth" (open, WIP, 2026-03-05): https://github.com/greenpau/caddy-security/issues/460
- caddy-security issue #462 "feature: auth proxy in authorize plugin" (closed 2026-03-30, partial System API for Basic/API-key): https://github.com/greenpau/caddy-security/issues/462
- caddy-security issue #486 "Infinite redirect after upgrade" (open, maintainer-responded 2026-05-01): https://github.com/greenpau/caddy-security/issues/486
- caddy-security issue #471 "Regression: portal deletes access_token cookie after successful OIDC login (v1.1.32+)" (closed): https://github.com/greenpau/caddy-security/issues/471
- caddy-security issue #468 "question: persist sessions across container restarts" (open): https://github.com/greenpau/caddy-security/issues/468
- caddy-security issue #161 "Multi domain authentication via a single auth portal" (open): https://github.com/greenpau/caddy-security/issues/161
- caddy-security issue #278 "breakfix: Injected headers not present" (closed, documents inject-header model): https://github.com/greenpau/caddy-security/issues/278
- go-authcrunch underlying lib: https://github.com/greenpau/go-authcrunch
- AuthCrunch docs (auth portal overview): https://docs.authcrunch.com/docs/authenticate/intro
- AuthCrunch OAuth2 overview: https://docs.authcrunch.com/docs/authenticate/oauth/oauth2
- tricked.dev "Kanidm and caddy security properly securing websites" (2025-07-12): https://tricked.dev/blog/kanidm-caddy-security/
- kanidm forward_auth issue #2774 (closed 2024-10-22 as "completed" via deferral to external middleware): https://github.com/kanidm/kanidm/issues/2774
- kanidm Discussion #3777 "Example Caddy Configuration": https://github.com/kanidm/kanidm/discussions/3777
- kanidm Discussion #3322 "Kanidm behind Caddy reverse proxy using docker compose": https://github.com/kanidm/kanidm/discussions/3322
- Home Assistant community "Reverse Proxy SSO Authentication using Caddy/caddy-security with a jwt cookie" (2022-12): https://community.home-assistant.io/t/reverse-proxy-sso-authentication-using-caddy-caddy-security-with-a-jwt-cookie/498898
- Caddy `forward_auth` directive docs: https://caddyserver.com/docs/caddyfile/directives/forward_auth
- ggicci/caddy-jwt v1.1.2 (2026-03-08): https://github.com/ggicci/caddy-jwt
- BTBurke/caddy-jwt (last release 2017): https://github.com/BTBurke/caddy-jwt
- oauth2-proxy v7.15.2 (2026-04-14): https://github.com/oauth2-proxy/oauth2-proxy
- espresso-lab/oidc-forward-auth-middleware v4.0.3 (2026-01-20): https://github.com/espresso-lab/oidc-forward-auth-middleware
- Rauthy advanced forward_auth (security caveats): https://sebadob.github.io/rauthy/work/forward_auth.html
- sevensolutions/traefik-oidc-auth (referenced in kanidm #2774 as a working alternative): https://github.com/sevensolutions/traefik-oidc-auth
