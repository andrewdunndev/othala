# Authelia evaluation

## Summary

Authelia is a yellow candidate for this estate. As an OIDC provider it covers
the eight OIDC apps with documented integration guides for every one of them
(Vaultwarden, Mealie, Audiobookshelf, Immich, BookLore, oCIS, Grafana, GitLab,
Tailscale, Jellyfin), forward-auth works cleanly with Caddy, and the security
posture is the strongest of any candidate (memory-safe Go, OIDC-Certified,
Argon2id by default, 0 high/critical CVEs in the last 18 months). The
load-bearing problem is structural: Authelia ships no LDAP server and the
maintainers have explicitly closed the request to add one (issue #3451), so
Jellyfin needs an external LDAP server (LLDAP, GLAuth) standing alongside
Authelia, breaking the "single substrate" property we want. Customisability is
also limited: the React/MUI portal is themeable only through palette knobs the
maintainers add, BYO-frontend is explicitly off the roadmap, and theme-park
style external CSS is blocked by CSP.

## Maintenance + sustainability

- Last release: v4.39.19 on 2026-04-12. v4.39.x is on a roughly monthly point
  release cadence (v4.39.0 line shipped 19 patches between mid-2025 and April
  2026). v4.40.0 milestone exists on GitHub with 24 open issues and is ~4%
  complete (no due date).
- Commit cadence: ~1067 commits to `master` in the last 6 months
  (2025-11-01 to 2026-05-02), roughly 175/month. A large share is renovate
  bot dependency churn; human-author commits are a smaller subset.
- Contributors: top human contributors all-time are
  `james-d-elliott` (1602), `clems4ever` (802), `nightah` (594),
  `Crowley723` (49), `hendrik1120` (38). The Core Team is three people
  (Clément Michaud, Amir Zarrinkafsh, James Elliott) plus a Maintainers Team
  (Manuel Nuñez, Brynn Crowley). The about page states a self-acknowledged
  bus factor of 3. Distinct human commit authors in the last 6 months: ~30+,
  but the work concentrates on the same handful of names.
- Governance: independent project, no incorporated entity, no commercial
  parent. Funded by Open Collective sponsors (Descope, Stytch, CodeRabbit,
  ~$60 USD since August 2025 at the small-tier level per the public
  sponsors page). Apache 2.0 licensed.
- Sustainability verdict: yellow. The project is healthy now (active
  releases, OIDC certification kept current, security advisories handled
  promptly) but the bus factor of 3 with no commercial backing is an honest
  long-tail risk. Five-year survival is plausible but not underwritten by
  anything other than the same three maintainers continuing to volunteer.

## Security practices

- Substrate language: Go 1.x (memory-safe). Frontend is React 19 +
  TypeScript + MUI 7.
- CVE history (last 18 months, Nov 2024 - May 2026):
  - CVE-2026-33525 / GHSA-gmfg-3v4q-9qr4: low severity, reflected XSS in
    page generation, disclosed 2026-03-21.
  - CVE-2025-24806 / GHSA-m5mf-3963-4x26: low severity, regulation
    (brute-force throttle) applied separately to username vs email logins,
    disclosed 2025-02-19.
  - No high or critical advisories in the window. The last high-severity
    advisory was CVE-2021-32637 (nginx auth bypass) in May 2021.
- Default-secure posture:
  - Argon2id password hashing default with cryptographically secure salt.
  - HTTPS-only by design (the architecture page explicitly refuses HTTP on
    grounds that session cookies require Secure).
  - Cookies set HttpOnly, Secure, SameSite=Lax by default.
  - Default response headers include X-Content-Type-Options: nosniff,
    X-Frame-Options: DENY, strict-origin-when-cross-origin Referrer-Policy,
    a restrictive Permissions-Policy, and a strict CSP (which is what blocks
    theme-park style external CSS).
  - Adaptive login delays (mean of last 10 successful attempts plus
    randomised jitter) to defeat user-enumeration timing attacks.
  - Per-IP token-bucket rate limits on sensitive endpoints (password reset,
    2FA).
  - At-rest encryption of sensitive DB columns (TOTP secrets, WebAuthn
    keys, OAuth sessions) with HMAC signatures.
  - PIE binary, full RELRO, BIND_NOW.
- Audit reports: no public independent third-party audit found. The team
  references "security pro" framing in SECURITY.md but no commissioned
  pen-test report is published.
- Verdict: green. This is the strongest security posture of any candidate
  in the comparison set. The CVE record over 18 months is two low-severity
  issues, both fixed promptly. The defaults are conservative and fail-closed.

## Capabilities for our app stack

- OIDC IDP: yes, fully OpenID-Certified for Basic OP, Implicit OP, Hybrid
  OP, Form Post OP, and Config OP profiles. Supports Authorization Code,
  Implicit, Hybrid, Device Authorization Grant (RFC 8628), Client
  Credentials, and Refresh Token grants. Client auth: client_secret_basic,
  client_secret_post, client_secret_jwt, private_key_jwt, none. Signing:
  RS/ES/PS/HS 256/384/512. PKCE S256. PAR (RFC 9126). JARM. RFC 9207
  issuer ID. Token introspection (RFC 7662) with optional JWT response
  (RFC 9701). Custom scopes and custom claims via claims policies mapped
  from authentication-backend attributes. JWK rotation by appending keys.
  Deliberately no Dynamic Client Registration, no CIBA, no password grant.
- LDAP server (built-in): no. Authelia consumes external LDAP backends
  (Active Directory, FreeIPA, GLAuth, LLDAP) as an authentication source,
  but does not expose an LDAP server downstream. Issue #3451 ("Add ability
  to expose authelia as an LDAP server") was closed 2022-12-22 by
  james-d-elliott as "fairly far off in our roadmap if we decide to
  implement it" and converted to an idea/discussion (#4620). No movement
  since. The maintainer suggested SCIM 2.0 as the more likely future path,
  and SCIM itself is also still an open issue (#7668, opened 2024-08-12,
  not on the active roadmap).
- Forward-auth: yes, native. Endpoint at `/api/authz/forward-auth`. Returns
  200/302/401/403 and propagates Remote-User, Remote-Groups, Remote-Email,
  Remote-Name headers. Caddy, Envoy, HAProxy, NGINX, NGINX Proxy Manager,
  SWAG, Skipper, Traefik (v1 and v2) all documented.
- SAML: no. Listed as "Planned" on the roadmap with no implementation
  start. Issue #493 has been open since December 2019.
- Passkey as primary auth: as of v4.39.x, passkeys are primarily a 2FA
  factor. Conditional mediation (passkey-as-username-less primary login)
  is in active development: PR #11858 merged 2026-04-22 ("feat(web):
  passkey conditional mediation"), follow-on PR #11925 opened 2026-05-02.
  The roadmap as published does not list "passkey as primary" as a
  separate item. Best guess: it lands in v4.40.x given recent merges.
- SCIM: no. Open issue #7668 since August 2024, not on active roadmap.
- User self-service: password reset is supported (HMAC-signed JWT flow
  with configurable lifespan, email-based). TOTP enrollment and WebAuthn
  enrollment exist via the user portal. A user-facing dashboard / control
  panel is on the active roadmap but not yet shipped (initial
  implementation slated for v4.40.0 per the roadmap). The portal today is
  spartan: 1FA login, 2FA registration, password reset.

Per-app fit table:

| App | Pattern | Authelia path |
|-----|---------|---------------|
| Vaultwarden | OIDC | works (documented client guide) |
| Mealie | OIDC | works (documented client guide) |
| Audiobookshelf | OIDC | works (documented client guide) |
| Immich | OIDC | works (documented client guide) |
| BookLore | OIDC | works (documented client guide) |
| oCIS | OIDC | works (documented client guide) |
| Grafana | OIDC | works (documented client guide) |
| GitLab | OIDC | works (documented client guide) |
| Jellyfin | LDAPS | needs glue: external LDAP server (LLDAP or GLAuth) alongside Authelia. Authelia OIDC + Jellyfin SSO Plugin is the documented alternative but not the LDAP path you specified. |
| Navidrome | forward-auth + Subsonic API bypass | works: Navidrome reads `Remote-User`; Subsonic /rest/* endpoints can be configured to bypass forward-auth and fall back to Navidrome's native auth. Standard pattern. |
| Sonarr/Radarr (*arr) | forward-auth + API key bypass | works: Authelia access-control rules can exempt /api/* paths so the *arr API keys keep working for Prowlarr/sonarr-Telegram-bots/etc, while UI is gated by Authelia. |
| vLLM | OAuth2 client credentials | works: client credentials grant is supported. |
| Tailscale | custom OIDC + WebFinger | partial: Authelia is documented as a Tailscale OIDC issuer but does not serve WebFinger itself. You serve `.well-known/webfinger` from your domain root (Caddy snippet, static JSON) pointing at Authelia. Documented in the Authelia Tailscale guide. |

## Customizability

- BYO UI: no. Maintainers have stated explicitly in discussion #7469 that a
  headless / custom-frontend split is "not something we'll invest time
  into since we're heavily using react." There is no documented headless
  API contract for login / recovery / passkey enrollment that a third-party
  UI could target stably.
- Theming: limited. Built-in light/dark themes plus a planned "custom
  theme" facility that the maintainers describe as creating MUI palette
  YAML and binding it to a theme name (per discussion #8839 / issue
  #4517). Strict CSP blocks theme-park-style external CSS injection.
  Today: the practical override surface is logo and a couple of colour
  knobs.
- Custom flows: no visual flow designer (this is an Authentik / Hanko
  feature). Authorisation logic is expressed as YAML access-control rules
  with `domain`, `resources`, `subject`, `methods`, `networks`, `policy`
  fields. Powerful for forward-auth gating, but it's policy-as-config, not
  custom-flow.
- Branding: logo replacement and (planned) palette overrides. No copy
  override beyond i18n strings. No template override.

Customisability verdict: red for "BYO UI / custom flows", yellow for
"branding". If you need a bespoke login experience, Authelia is the wrong
substrate.

## Architecture

- Single container: yes. One Go binary, one image (`authelia/authelia`).
  Optional companion containers are ones you'd run anyway (your DB, redis
  if used, an external LDAP if you have one).
- Database: SQLite (file), PostgreSQL, or MySQL/MariaDB for the persistent
  store (sessions, OIDC client state, TOTP, WebAuthn, regulation
  records). Optional Redis for distributed session storage; not required
  for single-node deployments.
- Footprint: comparison sources cite "under 30 MB RAM" for typical
  homelab loads. Best guess: a 5-25 user estate with 16 OIDC clients sits
  comfortably under 100 MB resident, including SQLite. Idle CPU is
  negligible.
- Reverse-proxy integration: forward-auth via `/api/authz/forward-auth`,
  one Caddyfile snippet per protected vhost using the `forward_auth`
  directive. Caddy v2.5.1 minimum. Trusted-proxies care needed (Caddy
  defaults to not trusting any).

## Community + ecosystem

- Homelab traction: very high. Authelia is one of the two names (the
  other being Authentik) that comes up in every r/selfhosted SSO
  discussion. ~27.7k stars, ~1.4k forks on GitHub.
- Tutorials: abundant. Caddy community wiki, simplehomelab series,
  apalrd's adventures, jellywatch SSO comparisons, multiple long-form
  blog posts published in 2025-2026.
- Documentation quality: strong by self-hosted-SSO standards. The
  per-application OIDC client integration guides (180+ apps) are kept
  current and follow a consistent template. Integration guides per
  reverse-proxy are similarly maintained.
- Validated integrations from our app list: all 10 of the OIDC-shaped apps
  we asked about (Vaultwarden, Mealie, Audiobookshelf, Immich, BookLore,
  oCIS, Grafana, GitLab, Tailscale, Jellyfin) appear on the official
  client integration page with dedicated guides. Navidrome is well-trodden
  via the Externalized Authentication / Remote-User header pattern.
- Posture toward AI-assisted contributions: no AGENTS.md file in the repo
  (404 confirmed). CONTRIBUTING.md does not mention AI, LLM, Copilot, or
  generated code in any policy direction. Code search across the repo for
  "AI generated", "LLM", "ChatGPT", "copilot", "artificial intelligence"
  returns no policy hits. Issue search returns no maintainer policy
  thread on the topic. Best guess: there is no explicit ban or explicit
  blessing; standard contribution rules apply (DCO-equivalent: PRs get
  squashed; CI must pass; coverage must not regress).

## AI/LLM contribution policy

No explicit policy. The repo has no AGENTS.md. CONTRIBUTING.md is silent
on AI. No issue/PR/discussion thread surfaced a maintainer position. This
contrasts with kanidm, which has an explicit AI/LLM ban. Treat Authelia as
"unspecified, default to disclose if you contribute upstream."

## Pros for our use

- Strongest security posture of the candidate set: Go, OIDC-Certified,
  Argon2id default, conservative defaults, only two low-severity CVEs in
  the last 18 months.
- All 10 named OIDC apps in our stack have first-party documented
  integration guides; no novel client wiring required.
- Single Go binary, single container, SQLite-capable: matches the
  "one-process homelab service" shape we want.
- Caddy forward_auth integration is well-trodden, official, and
  one-snippet-per-vhost.
- Navidrome and *arr API-bypass patterns are a known idiom, not a hack.
- Tailscale custom-OIDC has an official guide.
- Active development: ~175 commits/month, monthly point releases, OIDC
  certification kept current, passkey conditional-mediation just landed
  (April 2026), admin dashboard targeted for v4.40.0.

## Cons for our use

- No built-in LDAP server, and the request to add one was closed in 2022
  with a "not on the roadmap" disposition. Jellyfin's supported path
  (LDAP plugin) requires standing up an external LDAP (LLDAP, GLAuth)
  alongside Authelia, which breaks the "single substrate" goal. The
  fallback is Jellyfin's OIDC SSO plugin against Authelia, which works
  but is not the path you stipulated.
- No SAML. If any future app in the estate is SAML-only, Authelia can't
  serve it today. SAML is "Planned" but unstarted.
- No SCIM. User provisioning to downstream apps is whatever each app's
  OIDC sync logic does on first login.
- BYO UI is explicitly off the table per maintainer statement. If the
  customisability axis matters as much as the maintainership axis, this
  is the load-bearing reason to look elsewhere.
- Theming today is logo + palette only. CSP blocks theme-park.
- No admin dashboard yet (planned for v4.40.0); today everything is YAML
  config files reloaded on change. Fine for IaC, friction for ad-hoc
  family-member edits.
- Bus factor of 3, no commercial backing. Healthy now, but the 5-year
  question is honestly "yellow."
- Passkey-as-primary is shipping piecemeal and is not generally
  available in the current 4.39.x line.

## Verdict

Yellow. Authelia is the right substrate for the eight OIDC apps and the
forward-auth pair (Navidrome, *arr) and Tailscale. The load-bearing reason
it's not green is the LDAP-server gap: Jellyfin via LDAPS forces a second
identity-source process (LLDAP/GLAuth) into the deployment. If you're
willing to use Jellyfin's OIDC SSO plugin instead of LDAPS, the gap closes
and Authelia becomes a green candidate on capability. The customisability
axis remains red regardless: if BYO UI is a hard requirement, Authelia is
out.

## Sources

- https://github.com/authelia/authelia
- https://github.com/authelia/authelia/blob/master/CONTRIBUTING.md
- https://github.com/authelia/authelia/blob/master/SECURITY.md
- https://github.com/authelia/authelia/security/advisories
- https://github.com/authelia/authelia/releases
- https://github.com/authelia/authelia/issues/3451
- https://github.com/authelia/authelia/discussions/4620
- https://github.com/authelia/authelia/issues/7668
- https://github.com/authelia/authelia/issues/493
- https://github.com/authelia/authelia/discussions/7469
- https://github.com/authelia/authelia/issues/8839
- https://github.com/authelia/authelia/pull/11858
- https://github.com/authelia/authelia/pull/11925
- https://github.com/authelia/authelia/milestone/21
- https://www.authelia.com/
- https://www.authelia.com/information/about/
- https://www.authelia.com/roadmap/
- https://www.authelia.com/roadmap/active/dashboard-control-panel-and-cli-for-admins/
- https://www.authelia.com/integration/openid-connect/introduction/
- https://www.authelia.com/integration/openid-connect/clients/
- https://www.authelia.com/integration/openid-connect/clients/jellyfin/
- https://www.authelia.com/integration/openid-connect/clients/tailscale/
- https://www.authelia.com/integration/proxies/introduction/
- https://www.authelia.com/integration/proxies/caddy/
- https://www.authelia.com/integration/ldap/introduction/
- https://www.authelia.com/configuration/identity-providers/openid-connect/provider/
- https://www.authelia.com/configuration/identity-validation/reset-password/
- https://www.authelia.com/overview/prologue/architecture/
- https://www.authelia.com/overview/security/measures/
- https://opencollective.com/authelia-sponsors
- https://www.navidrome.org/docs/usage/integration/authentication/
- https://github.com/nikarh/jellyfin-plugin-authelia
- https://www.cerbos.dev/blog/authelia-vs-authentik-2026-idp
- https://blog.houseoffoss.com/post/the-state-of-open-source-identity-in-2025-authentik-vs-authelia-vs-keycloak-vs-zitadel
- https://selfhostedguides.com/zitadel-cloud-native-iam/
- https://caddy.community/t/securing-web-apps-with-caddy-and-authelia-in-docker-compose-an-opinionated-practical-and-minimal-production-ready-login-portal-guide/20465
- https://www.simplehomelab.com/traefik-auth-bypass/
