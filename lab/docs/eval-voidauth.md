# voidauth evaluation

## Summary

Yellow-leaning-red for our specific use case. voidauth is a competently
built, fast-moving, single-maintainer TypeScript SSO that nails the easy
80% (OIDC IDP, ProxyAuth/forward-auth, passkeys, MFA, group-based authz)
in a single container. The load-bearing factor against it for our shape
is missing capabilities, not quality: no LDAP server (open feature
request, not on the roadmap), no SAML, no OAuth2 client_credentials in
the admin schema, no WebFinger (so no native Tailscale custom-OIDC
path). For our 16-app stack, those gaps force compensating components
(separate LDAP server for Jellyfin, a different IDP for Tailscale,
workarounds for vLLM) that erase the "single substrate" benefit we are
trying to buy.

## Maintenance + sustainability

- Project age: First commit 2025-04-18; v1.0.0 released 2025-07-11; this
  evaluation written 2026-05-02. Roughly 12.5 months old, 10 months
  post-1.0.
- Last release: v1.12.2 on 2026-04-27 (5 days before this writing).
- Commit cadence: ~50 commits/month sustained over the last 6 months.
  43 tagged releases in 10 months post-1.0 (about one release every
  7 days). Active development, not maintenance mode.
- Contributors: 14 total contributors per the GitHub API. Distribution
  is heavily skewed:
  - notquitenothing (Derek Paschal): 830 commits, primary maintainer
  - MrNavaStar: 24 commits (mostly the "Declared OIDC clients" feature)
  - dependabot: 16 commits
  - Nerdtality: 9 commits (mostly OIDC guide docs)
  - Everyone else: 1-6 commits, predominantly OIDC-app-guide doc PRs
- Governance / bus factor: Bus factor 1. The voidauth GitHub org has
  exactly two repos (voidauth and .github) and 7 watchers. The
  maintainer's other public repos are personal utility scripts (PowerShell
  helpers, a Jellyfin file renamer, a FreeDNS updater); none have more
  than 3 stars. voidauth is essentially this individual's first
  significant project. He responds quickly in issues and discussions
  (his README explicitly promises "I will likely respond quickly") which
  is great while it lasts but reinforces the single-maintainer concern.
- Sustainability verdict: Currently very healthy in terms of activity
  and responsiveness. Structurally fragile because the project lives or
  dies with one person, has no organizational backing, has only two
  small Patreon-style sponsors visible in the README, and has no
  contributor pipeline producing peers (the second-most-active human
  contributor has 24 commits to his 830). Five-year survival is
  plausible if Derek stays interested but is not underwritten by
  anything else.

## Security practices

- Substrate language: TypeScript on Node.js (>= 24.11). Express 5,
  Postgres 18 or SQLite (better-sqlite3) via Knex. Some of the Lemmy
  community has explicitly noted "allergy to running critical
  infrastructure like authentication on node" as a concern. That is a
  taste/risk judgment, not a verdict, but it is the dominant reservation
  raised in public threads.
- Crypto / IDP heavy lifting: Built on `oidc-provider` (panva, the
  reference Node OIDC implementation, very widely used), `jose` (panva,
  the de facto JOSE library), `@simplewebauthn/server` for WebAuthn,
  `argon2id` for password hashing, `helmet` for HTTP headers,
  `express-rate-limit` for rate limiting, `keygrip` for cookie signing
  with rotation, `zod` for input validation. These are all the right
  choices. Not rolling its own crypto.
- Default-secure posture observed in code:
  - `devInteractions` disabled (no debug prompt page in prod)
  - Backchannel logout enabled
  - Token revocation enabled
  - Storage encryption at rest using `STORAGE_KEY` (32+ chars required,
    plus `STORAGE_KEY_SECONDARY` slot for rotation)
  - Hardened base image: production Dockerfile uses
    `dhi.io/node:24-alpine3.22` (Docker Hardened Images, distroless
    variant). Most homelab projects do not bother with this.
  - CodeQL workflow enabled in CI (`.github/workflows/codeql.yml`)
  - GitHub build attestations + SLSA provenance in the release workflow
  - Dependabot configured
  - Configurable rate limit (`API_RATELIMIT`) plus extra rate limiting
    on sensitive OIDC endpoints (visible in March 2026 commit)
  - Multi-arch (amd64+arm64) image
  - Explicit MFA-required flags on users / groups / OIDC clients /
    ProxyAuth domains
  - Recent security-conscious work: passkeys without user verification
    no longer satisfy MFA (PR #363, April 2026); initial admin
    credentials no longer printed in logs, replaced by a one-time reset
    link (PR #369, April 2026); SMTP TLS cipher / minimum-version env
    vars (PR #364)
- CVE history: No published CVEs. No GitHub Security Advisories filed.
  This is consistent with both a low-attention project and a clean one;
  it does not prove either. The README itself states: "VoidAuth has not
  been audited and uses 3rd party packages for much of its
  functionality, use at your own risk."
- Vulnerability disclosure: SECURITY.md exists. Disclosure path is email
  to voidauth@voidauth.app or a private GitHub Security Advisory draft.
  Plain but adequate.
- Authentication mechanisms:
  - Password (argon2id) with optional zxcvbn strength check
  - TOTP MFA
  - WebAuthn / passkeys, including passkey-only accounts (since v1.1.0)
    and passkey naming (April 2026)
  - Email verification with verification links
  - Password reset via email
  - "Remember me" support, MFA-aware
  - "Expiring users" (account access expiration), April 2026
- Recovery story: Email-based password reset; admin can issue reset
  links. CLI command exists to generate a password reset link for an
  existing user. No documented break-glass passkey backup beyond
  enrolling multiple authenticators.

## Capabilities for our app stack

- OIDC IDP capability: Yes. authorization_code, implicit, refresh_token
  grant types in admin schema. Response types include code, id_token,
  hybrid combinations. Client auth methods: client_secret_basic,
  client_secret_post, client_secret_jwt, none. Per-client `groups`
  scope, `skip_consent`, `require_mfa` flags. Wildcard redirect URIs
  supported. Declared OIDC clients via env vars or Docker labels (live
  reload via Docker socket). PKCE supported by default
  (`oidc-provider` enforces it).
- LDAP server (built-in): No. Tracked in two open issues:
  - #237 (LDAP client / sync from external LDAP, open since pre-2026)
  - #377 (basic LDAP server endpoints to authenticate clients that only
    speak LDAP, open since 2026-04-18, zero comments)
  - The maintainer has acknowledged both but neither has a milestone or
    "in-progress" label.
- Forward-auth: Yes, well-documented. Two endpoints:
  - `/api/authz/forward-auth` for Caddy / Traefik
  - `/api/authz/auth-request` for NGINX (separate endpoint to work
    around NGINX `auth_request` limitations)
  - Sets `Remote-User`, `Remote-Email`, `Remote-Name`, `Remote-Groups`
    headers on success.
  - Supports identifying users by session cookie or by HTTP Basic auth
    in `Authorization` / `Proxy-Authorization` headers (relevant for
    API/CLI clients).
  - Wildcard ProxyAuth domains with most-specific-wins matching, but
    matching is glob-based, not regex. There is no first-class "bypass
    these paths" rule; the workaround is to either chain it in the
    reverse proxy (don't run forward_auth on those routes) or rely on
    Basic-auth passthrough.
- Path bypass for API endpoints (Subsonic API on Navidrome, *arr API on
  Sonarr/Radarr): Not a first-class feature. Issue #271 ("Support Basic
  Auth Passthrough") is open since 2026-01 and the maintainer's
  response is "out of scope, do it in your reverse proxy." This matches
  Authelia's posture but is more annoying than tinyauth's per-path
  bypass list. Achievable by configuring the reverse proxy to skip
  forward_auth for `/rest/*` (Subsonic) or `/api/*` with API-key
  presence (the *arr stack).
- SAML: Not supported. Zero issues, zero discussion, no roadmap mention.
- OAuth2 client_credentials: Not exposed in admin schema. The admin
  `GRANT_TYPES` enum is `['implicit', 'authorization_code',
  'refresh_token']`. Underlying `oidc-provider` supports
  client_credentials and a `ClientCredentials` TTL is configured, but
  there is no UI / declared-client path to enable it for an OIDC app.
  Would require a code change. Not acceptable for vLLM out of the box.
- Custom IDP for Tailscale (OIDC + WebFinger): WebFinger is not
  implemented. Only the standard OIDC discovery endpoints from
  `oidc-provider` are exposed. There is no `/.well-known/webfinger`
  route in `server/routes/`. Issue #144 ("OIDC federation?") raised
  WebFinger as a "would be nice" in May 2026; the maintainer replied
  that federation "would require significant rewriting, so it may be a
  while." Without WebFinger, voidauth cannot be wired to Tailscale's
  custom-OIDC GA path; you would need a separate IDP (or fronting
  voidauth with something that does WebFinger).
- Passkey / WebAuthn as primary: Yes. Passkey-only accounts supported
  since v1.1.0. Passkey management (naming, sorting, multi-device)
  shipped in March-April 2026. WebAuthn user-verification correctly
  treated as MFA-equivalent only when actually performed.
- Groups / authz: Group system fits our shape. Groups can be assigned to
  OIDC clients (denies token issuance to non-members), to ProxyAuth
  domains (denies forward-auth), and are emitted in the `groups` claim
  for downstream apps that do their own authz (Jellyfin, Grafana, etc.).
  `MFA Required` and `Auto Assign on invite` are first-class group
  flags. The hard-wired `auth_admins` group bypasses all restrictions,
  which is a sharp edge to remember.

### Per-app fit table

| App | Need | voidauth fit | Notes |
|---|---|---|---|
| Vaultwarden | OIDC | Yes | Standard OIDC client. Group claim available. |
| Mealie | OIDC | Yes | Standard OIDC client. |
| Audiobookshelf | OIDC | Yes | Standard OIDC client. |
| Immich | OIDC | Yes | One open issue (#287) about an Immich OIDC edge case. Generally works. |
| BookLore | OIDC | Yes (untested) | No published guide; standard OIDC should work. |
| oCIS | OIDC | Yes (untested) | Standard OIDC. |
| Grafana | OIDC | Yes | Standard OIDC; groups claim drives Grafana orgs/roles. |
| GitLab | OIDC | Yes (untested) | Standard OIDC. |
| Jellyfin | LDAPS preferred | Workable via OIDC plugin only | voidauth ships an explicit OIDC-Guides recipe for Jellyfin via the 9p4/jellyfin-plugin-sso. **No LDAP server option**. If LDAP is a hard requirement, voidauth cannot satisfy it. |
| Navidrome | Forward-auth + Subsonic API bypass | Partial | Forward-auth works. Subsonic API bypass is on you in the reverse proxy. No first-class bypass rule. |
| Sonarr/Radarr/etc. | Forward-auth + API key bypass | Partial | Same as Navidrome. Reverse-proxy-level bypass on API key presence. |
| vLLM | OAuth2 client_credentials | **No** | Grant type not exposed. Would require patching voidauth or a different IDP. |
| Tailscale | Custom OIDC + WebFinger | **No** | WebFinger not implemented. Would need a separate IDP (e.g., tsidp, dex, kanidm) or a WebFinger-emitting front. |

## Customizability

- BYO UI: No. The frontend is a fixed Angular 21 SPA built into the
  Docker image. There is no public theme system beyond CSS variables
  and a small set of swap-in assets.
- Theming: Possible within the bounds the project provides. Configurable
  via env vars (`APP_TITLE`, `APP_COLOR`, `APP_FONT`) plus a
  `/app/config/branding` mount where you can drop your own `logo.svg`,
  `favicon.svg`, and `apple-touch-icon.png`. Sufficient to remove all
  visible "VoidAuth" branding from the end-user surface (the README
  explicitly calls this out). Not sufficient if you want a substantially
  different login flow / page layout.
- Email templates: EJS templates mounted from `/app/config`, with
  defaults in `default_email_templates/`. Editable.
- Custom flows: No. Login, MFA, passkey enrollment, and consent screens
  are baked into the Angular app. There is no "stages / flows" concept
  like Authentik. Interaction policy is extensible in TypeScript code
  (the maintainer has added user-approval, user-expired,
  email-not-validated, MFA-required, group-missing checks) but that is
  source-edit territory, not config.
- i18n: A translation framework was just merged (PR #294, March 2026)
  with the language switcher initially hidden. New, immature.

## Architecture

- Single container (one Node process serving both API and frontend) plus
  a database. Postgres 18 is the recommended adapter; SQLite via
  better-sqlite3 is supported and is now the only embedded option after
  sqlite3 was removed in March 2026.
- Memory footprint: ~150 MB RAM and ~360 MB image as of v1.6.0
  (the v1.6.0 release notes mention "cut memory usage in half from
  280MB to 150MB and image size from 660MB to 360MB"). Lightweight by
  homelab standards.
- Reverse proxy required for TLS termination. Documented Caddy and
  NGINX recipes; Traefik covered by the same `/api/authz/forward-auth`
  endpoint. No built-in TLS.
- Stateless other than DB; horizontally scalable in principle, though
  not a stated goal.
- Configuration: env-var-driven, one of the better env-var docs in this
  category. Optional Docker socket mount for live OIDC client
  declaration via container labels.

## Community + ecosystem

- Adoption signals:
  - 1,979 GitHub stars, 61 forks (as of 2026-05-02). Crossed 1k stars in
    Dec 2025 (v1.6.0 release notes).
  - GitHub Discussions enabled and used; Q&A and announcements active.
  - Lemmy: maintainer posts release announcements to `c/selfhosted` on
    multiple instances (lemmy.world, lemmy.ml, lemmy.ca). Threads exist
    for v1.1.0, v1.2.0, v1.3.0, v1.6.0, etc., with engaged commenters.
  - Reddit: thin. Direct `site:reddit.com voidauth` returns nothing
    indexed, which is unusual for a project at this star count and
    suggests the audience is centered on Lemmy / GitHub Discussions
    rather than Reddit.
  - AlternativeTo page added 2026-01-10; 8 likes, one 5-star review.
    Listed alongside Keycloak, Authentik, Zitadel.
  - One personal blog (Stephen O'Toole, "voidauth-for-authentication-of-
    services-sso" and "my-year-2025-self-hosting") writes that voidauth
    was their pick for SSO, then notes they migrated to Pocket ID
    because passkey-only felt more polished.
  - Awesome-selfhosted: not present in the canonical list as of this
    writing. Listed on the smaller "awesome-docker-compose" site.
  - HN / Lobsters: no significant front-page coverage found.
- Tutorials: Mostly the project's own OIDC-Guides (community-maintained
  recipe set covering ~25 apps). A few independent blog posts. Nothing
  near the YouTube / blog volume of Authelia or Authentik.
- Validated integrations with our app list, per the project's own
  OIDC-Guides:
  - Vaultwarden: yes
  - Immich: yes
  - Jellyfin: yes (via 9p4 SSO plugin, OIDC)
  - Jellyseerr: yes
  - Open WebUI: yes
  - Pangolin, Paperless-ngx, Portainer, Proxmox, Seafile, Memos, Komodo,
    Mastodon, Wiki.js, Grist, Manyfold, Cloudflare ZeroTrust,
    AutoCaliWeb, Beszel, ByteStash, Dawarich, Dockhand, Actual Budget,
    Arcane, Unraid: yes
  - Mealie, Audiobookshelf, BookLore, oCIS, GitLab, Grafana,
    Sonarr/Radarr, Navidrome, vLLM, Tailscale: not in the guide. Some
    will Just Work as standard OIDC; vLLM and Tailscale will not.

## AI/LLM contribution policy

None. CONTRIBUTING.md does not mention AI, LLMs, copilot, generated
content, model output, ChatGPT, or any related term. There is no
DCO/CLA, no policy on AI-assisted contributions, and no `ai`/`llm`/
`copilot` issues or PR template guidance. Contribution standards are
limited to: passes TypeScript + ESLint, follows the PR template, lists
all features/fixes, attaches frontend screenshots. Defacto: anything
goes; the maintainer reviews PRs personally.

## Maturity verdict

- Production-ready for our use? **No, not as a sole substrate**. Maybe,
  for a strict subset.
- Reasoning:
  - For the OIDC-only subset of our stack (Vaultwarden, Mealie,
    Audiobookshelf, Immich, BookLore, oCIS, Grafana, GitLab) plus
    forward-auth (Navidrome, *arr) plus Jellyfin via the OIDC plugin,
    voidauth is plausibly production-ready today: real users running it,
    weekly releases, sane defaults, recognized libraries underneath. We
    would not be the bleeding edge.
  - For our specific shape it falls short on three load-bearing
    requirements: LDAP server (Jellyfin's "supported path"), OAuth2
    client_credentials (vLLM), and WebFinger for Tailscale custom-OIDC.
    None of these are roadmap items with milestones.
  - Bus-factor concern is real but not unique. Authelia historically had
    similar concerns and survived; kanidm is also dominated by one
    voice. The difference is that voidauth has no foundation, no
    employer behind it, no second co-maintainer with comparable commit
    rights, and one year of total runway.
  - The maintainer's instinct on hard problems (federation: "would
    require significant rewriting, may be a while"; basic-auth bypass:
    "out of scope") is to defer rather than expand scope. That is
    healthy for project survival but it means features we need are
    unlikely to land soon.

## Pros for our use

- Single container + one DB. Operationally lighter than Authentik,
  comparable to Authelia.
- Clean modern UI out of the box, passkey-first, MFA-first. End-user
  experience for a family of 5-25 would be excellent.
- Group system maps cleanly onto our 10 access groups + 3 identity
  groups model.
- Forward-auth implementation is solid and the docs for Caddy / NGINX /
  Traefik are unusually clear.
- Trustworthy library choices (panva oidc-provider + jose, simplewebauthn,
  argon2id, helmet) and security-conscious defaults (Hardened Image,
  CodeQL, attestations, rate limits, devInteractions disabled).
- Live OIDC-client declaration via Docker labels would fit our IaC
  posture nicely.
- Active and responsive maintainer; weekly releases; visible quality bar.
- AGPL-3.0; no rug-pull risk.

## Cons for our use

- LDAP server is the headline gap. Jellyfin's first-class auth path
  is the LDAP plugin; voidauth pushes you to the OIDC plugin instead,
  which works but means we depend on a third-party Jellyfin plugin for
  the most user-facing app in the family.
- No OAuth2 client_credentials grant in the admin schema. vLLM does not
  fit out of the box.
- No WebFinger. Tailscale custom-OIDC GA path is blocked. We would need
  a different IDP for Tailscale or a WebFinger shim.
- No SAML. (Probably not load-bearing for our app list, but worth
  noting against Authentik / Zitadel / Keycloak.)
- No regex/path-bypass rules in ProxyAuth; Subsonic / *arr API bypass
  is a reverse-proxy responsibility.
- Single maintainer, no organizational backing. Five-year forecast is
  unsupported by anything other than current personal momentum.
- Project is 12 months old. No third-party security audit. No CVE
  history because there has not been time for one to be filed.
- No theme/flow extensibility. What you see is what you get; deviations
  require source edits.
- Built on Node.js, which is a real concern for some auditors and a
  taste objection for others. Not disqualifying on its own.

## Verdict

**Yellow, leaning red.** voidauth is the most pleasant single-container
SSO in this category right now, and if our stack were "10 OIDC apps
plus forward-auth" we would seriously consider it. But our stack is
"OIDC + LDAP for Jellyfin + WebFinger for Tailscale + client_credentials
for vLLM," and voidauth covers only the first of those. The
load-bearing reason is capability gap, not quality. Adopting voidauth
would either require ratcheting our requirements down (drop LDAPS,
drop Tailscale custom-OIDC, drop vLLM machine auth) or running a
second IDP alongside it, which defeats the point of choosing the
single-container option in the first place. The bus-factor and
no-audit risks make it harder to recommend taking on those compromises
for a 5-year homelab plan.

## Sources

- voidauth repository: <https://github.com/voidauth/voidauth>
- voidauth README: <https://github.com/voidauth/voidauth/blob/main/README.md>
- voidauth SECURITY.md: <https://github.com/voidauth/voidauth/blob/main/SECURITY.md>
- voidauth CONTRIBUTING.md: <https://github.com/voidauth/voidauth/blob/main/CONTRIBUTING.md>
- voidauth Dockerfile: <https://github.com/voidauth/voidauth/blob/main/Dockerfile>
- voidauth release workflow: <https://github.com/voidauth/voidauth/blob/main/.github/workflows/release.yml>
- voidauth releases page: <https://github.com/voidauth/voidauth/releases>
- voidauth contributors API: <https://api.github.com/repos/voidauth/voidauth/contributors>
- voidauth Getting Started docs: <https://voidauth.app/#/Getting-Started>
- voidauth OIDC App Guides (per-app recipes): <https://voidauth.app/#/OIDC-Guides>
- voidauth ProxyAuth docs: <https://voidauth.app/#/ProxyAuth-and-Trusted-Header-SSO-Setup>
- Issue #237 (LDAP/AD support): <https://github.com/voidauth/voidauth/issues/237>
- Issue #377 (basic LDAP server endpoints): <https://github.com/voidauth/voidauth/issues/377>
- Issue #144 (OIDC federation / WebFinger): <https://github.com/voidauth/voidauth/issues/144>
- Issue #271 (Basic Auth passthrough / API bypass): <https://github.com/voidauth/voidauth/issues/271>
- Issue #365 (RFC 8707 resource indicators): <https://github.com/voidauth/voidauth/issues/365>
- Maintainer profile (Derek Paschal / notquitenothing): <https://github.com/notquitenothing>
- panva/node-oidc-provider (the OIDC engine voidauth wraps): <https://github.com/panva/node-oidc-provider>
- AlternativeTo entry: <https://alternativeto.net/software/voidauth/about/>
- Cloudnews comparative review: <https://cloudnews.tech/voidauth-the-open-source-gatekeeper-to-unify-access-to-your-self-hosted-apps-and-why-it-might-make-sense-compared-to-keycloak-authelia-or-paid-sso/>
- Stephen O'Toole, "VoidAuth for authentication of services (SSO)": <https://o-toole.com/voidauth-for-authentication-of-services-sso/>
- Stephen O'Toole, "My year 2025: Self hosting" (later switched to Pocket ID): <https://o-toole.com/my-year-2025-self-hosting/>
- Lemmy thread (developer commenting on rationale, Node.js concern raised): <https://lemmy.world/post/33393066>
- Lemmy v1.6.0 / 1k-star release thread: <https://lemmy.world/post/40391354>
- Tailscale custom OIDC requirements (WebFinger): <https://tailscale.com/docs/integrations/identity/custom-oidc>
