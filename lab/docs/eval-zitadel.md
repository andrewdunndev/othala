# Zitadel evaluation

## Summary

**Yellow leaning red** for our use case. Zitadel is a serious, well-funded,
actively maintained OIDC IDP with strong customizability and excellent
SAML/SCIM/passkey support, but three load-bearing factors push it off the
short list: (1) it cannot act as an LDAP server (Jellyfin loses the supported
auth path), (2) the v4 minimum deploy is three containers (Traefik + zitadel
core + Next.js login UI + Postgres = four), with no single-binary mode and no
embedded DB, (3) the CVE cadence is high enough that "drop-everything" patch
cycles are part of the operating cost. The customizability story is genuinely
the best of the candidates we are looking at, but for a 16-app, 25-user
homelab estate the operational shape is mismatched.

## Maintenance + sustainability

**Releases.** Active and fast. Latest stable is `v4.14.0` (2026-04-24);
`v5.0.0-base` cut as a prerelease 2026-03-23. v3 line still receiving
patches (`v3.4.9` on 2026-03-17). Cadence is multi-release-per-month with
parallel maintenance branches: that is enterprise-grade release engineering,
not a hobby project.

**Repository activity.** 13.7k stars, 1.05k forks, last push
2026-05-01 (one day ago). Primary language Go (~22 MB), with substantial
TypeScript (3.5 MB) for the v4 Next.js login UI.

**Contributors.** 30 contributors via the API, 200+ claimed by the company.
Top-of-funnel is heavily concentrated in Zitadel-employed developers:
`livio-a` (1043), `adlerhurst` (529), `peintnermax` (489), `hifabienne` (481),
`eliobischof` (251), `muhlemmer` (231), `stebenz` (229), `fforootd` (173).
The first 10 contributors account for nearly all activity; this is a
company-driven OSS project with light external contribution, not a community
project.

**Governance / commercial backing.** Zitadel Inc. is the venture-backed
company behind it. ~23 employees as of Feb 2026. $15.5M raised over 3 rounds,
including a $9M Series A in Nov 2024 led by Nexus Venture Partners (also
Floodgate). Customer base reported as 150+ across NA/EU.
SOC 2 Type II achieved.

**Open-core split.** License is **AGPLv3** on the GitHub repo (Apache 2.0
referenced on the marketing site for some components: this is a discrepancy
worth noting; the repo `LICENSE` is AGPLv3). Cloud and self-hosted run the
same codebase; there is no documented feature stripping. An "Enterprise" tier
exists for paid support/SLA, not for feature gating. So OSS edition is fully
capable, but AGPL is meaningfully more restrictive than Apache 2.0 if you
ever wanted to embed or redistribute.

**Sustainability verdict.** Yellow-green. Real funding, real customers, real
team. The risks are: (a) classic VC pressure on a 23-person company means
the cloud business needs to grow into the cap table or the OSS could become
a casualty of pivots; (b) the AGPL license narrows the rescue community
relative to Apache-licensed peers; (c) contributor concentration means a
small team departure would hit hard. 5-year survival is more likely than
not, but is conditional on the company surviving.

## Security practices

**Substrate.** Go core. AGPLv3. Built around event sourcing on Postgres.

**Audit posture.** Cure53 pentest results published for H2 2022. SOC 2
Type II achieved. No more recent public pentest report surfaced.

**CVE history (selected, last 18 months).** This is the load-bearing concern:

| CVE | Date | Severity | Class |
|-----|------|----------|-------|
| CVE-2025-67494 | 2025-12-08 | **Critical** | Unauth Full-Read SSRF via V2 Login |
| CVE-2026-29191 | 2026-03-04 | **Critical** | 1-Click ATO via XSS in /saml-post |
| CVE-2025-27507 | 2025-03-04 | **Critical** | IDOR in Admin API affecting LDAP config |
| CVE-2026-32130 | 2026-03-11 | High | SCIM auth bypass via URL encoding |
| CVE-2026-32131 | 2026-03-11 | High | Cross-tenant info disclosure (Mgmt API) |
| CVE-2026-29067 | 2025-12-08 | High | ATO via improper instance validation V2 Login |
| CVE-2025-67495 | 2025-12-08 | High | ATO via DOM-based XSS in V2 Login |
| CVE-2025-64431 | 2025-11-05 | High | IDOR in Org API: cross-tenant data tamper |
| CVE-2025-64101 | 2025-10-29 | High | ATO via X-Forwarded-Proto header injection |
| CVE-2025-64103 | 2025-10-29 | High | Bypass second auth factor |
| CVE-2025-53895 | 2025-07-15 | High | Broken authn/authz in session API |
| CVE-2025-48936 | 2025-05-28 | High | ATO via X-Forwarded-Proto injection |
| CVE-2025-46815 | 2025-05-06 | High | IdP intent token reuse |
| CVE-2025-31123 | 2025-03-31 | High | Expired JWT keys usable for grants |
| CVE-2024-49757 | 2024-10-25 | High | User registration bypass |

That is **3 criticals and 12+ highs in 18 months**. Account takeover (ATO)
appears as a class repeatedly: header injection, XSS, DOM XSS, IDOR. The
v4 Login UI rewrite shipped with several of its own classes of bugs. The
positive read is that disclosure is fast and patches ship quickly. The
negative read is that any homelab operator on Zitadel is signing up for a
non-trivial monthly patch cycle on the same software that fronts every
service in the estate.

**Defaults.** Opinionated: PostgreSQL-only (CockroachDB support dropped),
masterkey for at-rest encryption (immutable after init: lose it = lose
data), forced HTTP/2 upstream, mandatory TLS for production. Sane.

## Capabilities for our app stack

| Need | App(s) | Zitadel fit | Notes |
|------|--------|-------------|-------|
| OIDC IDP | Vaultwarden, Mealie, Audiobookshelf, Immich, BookLore, oCIS, Grafana, GitLab | **Native, strong** | Discovery URL, scopes, claims all standard. Community guides exist for Mealie, Audiobookshelf, Immich, Vaultwarden (via `timshel` fork). |
| LDAPS server | Jellyfin | **Missing** | Zitadel can *consume* LDAP as an upstream IDP, but cannot *act as* an LDAP server. Open feature request (#1929) since 2020; maintainer states "we currently lack the capacity." Workaround: GlAuth-bridge plugin (community PoC, unmaintained). |
| Forward-auth | Navidrome, Gather *arr | **Not built-in; pair with oauth2-proxy** | Zitadel has no native ForwardAuth handler (issue #6912 open). Standard pattern is oauth2-proxy → Zitadel OIDC. Per-path API bypass for Subsonic/*arr APIs has to be implemented at the proxy layer (oauth2-proxy `--skip-auth-route` or Caddy matcher). |
| OAuth2 client-credentials | vLLM | **Native** | Service Accounts with client-credentials flow are first-class. |
| Custom OIDC IDP for Tailscale | Tailscale | **Yes** | Documented integration exists; you supply the WebFinger endpoint at your domain root. Same shape as any OIDC issuer. |
| Access groups + identity groups | ~10 + 3 | **Yes via Projects/Roles + Org structure** | Zitadel's authz model is `Project → Role → User Grant` with Organizations as the multi-tenant boundary. More structure than authelia/kanidm but maps cleanly. |
| Passkey / WebAuthn | All | **Strong** | First-class. Can be primary factor (passwordless), enforceable by policy, supports Autofill UI work in progress. |
| SCIM | (future) | **Yes (Preview)** | SCIM v2.0 server implementation, marked Preview in docs. Working but expect API churn. |
| SAML | (future) | **Yes** | First-class IdP; separate `zitadel/saml` Go library underneath. |
| User self-service | All | **Yes** | Console + API for password reset, MFA registration, profile, session management. |

**Per-app fit summary.** 8/8 OIDC apps work cleanly. Tailscale clean.
vLLM clean. The two big problems are Jellyfin LDAPS (no path) and forward-auth
(needs oauth2-proxy pairing — adds a 5th container before you have shipped
your first authz rule).

## Customizability

**This is Zitadel's strength.** The customization story is genuinely best
in class among the candidates, with one caveat about where the line is drawn.

- **BYO login UI.** v4 split the login UI out as a forkable Next.js 15
  application. You can deploy your own login UI as a separate service that
  talks to the Zitadel core via session APIs, with full control over screens,
  flows, branding, languages. Reference: `quochuydev/zitadel-login-ui`
  (community example), Zitadel's official `zitadel/typescript` repo for the
  SDK.
- **Theming via Console.** Per-organization branding is built-in: logo,
  primary/background/warn colors (light + dark variants computed
  automatically with WCAG checking via tinycolor2), font, hide name on
  registration, etc. No CSS overrides exposed in the console; full theme
  control requires forking the Next.js login UI.
- **Custom OIDC scopes/claims.** Yes, via Actions (v2: external webhook
  model that runs on token issuance/auth flow events). Note this is the
  surface that the migration-from-v1 friction lives in.
- **SDKs.** First-party: Go, Node, Python (community), .NET (community),
  Java (community), TypeScript/React/Next.js (first-party, used by their
  own login UI), plus passport.js / next-auth / oidc-client-ts integration.

**Caveat.** "Customizability" in Zitadel means "fork the Next.js UI app and
deploy it as a service." It does not mean drop a CSS file in a directory
and restart. For us that means another build, another container, another
update cadence. Not free.

## Architecture

**Minimum deploy shape.** v4 (current) is **three Zitadel-side containers**
plus a database plus a reverse proxy:

1. `zitadel` — Go core (API, gRPC)
2. `zitadel-login` — Next.js login UI (separate container, runs in same
   network namespace as the core via `network_mode: service:zitadel` per the
   compose example)
3. PostgreSQL 14–18
4. Reverse proxy (Traefik / NGINX / Caddy / Apache, with HTTP/2 upstream
   support)

Optional but commonly added: Redis (standalone mode only — Cluster/Sentinel
not supported), OTEL collector. For forward-auth on the *arr stack and
Navidrome, add oauth2-proxy: that is **5 containers minimum** to cover
our stack.

**Database requirements.**
- PostgreSQL 14 to 18 only.
- CockroachDB support **dropped** in current versions.
- No embedded option (no SQLite, no in-process DB).
- Masterkey encrypts data at rest and is immutable after init.

**Resource footprint at family scale.** Per maintainers and docs:
- Test/small: ~512 MB RAM, <1 CPU core for the Zitadel process itself.
- Practical homelab with Postgres and Login UI: 2-4 GB RAM total (Login UI
  Next.js process + Postgres tuning + Zitadel core + headroom for password
  hashing CPU spikes).
- Disk: 10 GB minimum for DB + images.
- Recommended 4 CPU cores for password hashing burst capacity.

**Reverse-proxy integration shape.** Requires HTTP/2 upstream (h2c or h2):
not every Caddy/NGINX config defaults to this; reverse proxy config is
slightly more involved than for typical OIDC IDPs. Documented configs exist
for Traefik v3, NGINX, Caddy v2, Apache 2.4.

## Community + ecosystem

**Homelab traction.** Lower than authelia/kanidm. The center of gravity
of the Zitadel community is B2B SaaS developers building multi-tenant
products on top of Zitadel, not homelab operators. Reddit `r/selfhosted`
mentions are sparse compared to Authelia/Authentik/Keycloak. The
self-hosting documentation is widely criticized as undermaintained: GitHub
discussion #8166 is a representative thread where users describe doing
~3 hours of trial-and-error to land a working install, with maintainer
acknowledgment that the docs are confusing for self-hosters.

**Tutorials with our app list.**
- Vaultwarden + Zitadel: yes (community thread; requires the timshel OIDC
  fork of Vaultwarden).
- Mealie + Zitadel: yes (GH discussion #3557 with working configuration).
- Audiobookshelf + Zitadel: not Zitadel-specific, but Audiobookshelf's
  generic OIDC discovery flow works.
- Immich + Zitadel: generic OIDC works; no Zitadel-specific official guide.
- Grafana + Zitadel: covered by Zitadel's own integrations docs.
- GitLab + Zitadel: standard OIDC client.
- Tailscale + Zitadel: official Tailscale partnership, dedicated docs and
  community guides (e.g. ibnunowshad.com walkthrough).

The integration material exists; it is just thinner per-app than what
exists for Authelia or Keycloak in the homelab community.

**Independent assessment.** Niraj Kumar's "Brittle ZITADEL" post (Feb 2026)
documents 23+ engineering hours of identity-plumbing work for a small
multi-tenant ERP, citing five operational issues: Login V2 service split
adding moving parts, v1 API deprecation pressure, brittle config (BASEURI
double-path bug as exemplar), Actions v1→v2 migration adding webhook
latency and failure modes, and the security-patch cadence. The author
ranks Keycloak / FusionAuth / Logto / SuperTokens above Zitadel for
self-hosted multi-tenant identity.

## AI/LLM contribution policy

**No explicit policy.** `CONTRIBUTING.md` does not address AI-generated,
LLM-assisted, or Copilot-assisted contributions. GitHub Copilot is mentioned
neutrally as an optional VSCode extension in the dev environment setup. No
DCO is required (no DCO bot in PR checks). No CLA is mentioned in the
contributing doc either, though contributors should verify before submitting
substantive changes.

For our purposes (we are a consumer not a contributor) this is irrelevant
unless we plan to upstream patches. If we did, the absence of policy is
neutral-to-permissive.

## Multi-container concern

**Actual minimum deploy:** 4 containers for the stack itself (Traefik,
zitadel core, zitadel login UI, Postgres). 5 with oauth2-proxy for the
forward-auth apps. 6 if you add Redis for cache. There is **no single-binary
mode**, **no embedded DB**, and **no "all-in-one" image**. The v4
architecture explicitly went the *other* direction by splitting the Login UI
into its own Next.js service.

**Operational complexity vs single-binary alternatives.** Compared to
Authelia (single binary, file backend or one Postgres) or kanidm (single
binary + SQLite), Zitadel is a different category. You are running:
- Two Zitadel processes that must stay on compatible versions (core + login UI).
- A Postgres instance you have to back up, vacuum, and version-track.
- A masterkey that, if lost, costs you everything.
- Updates that frequently include security advisories that must be applied
  promptly.

**Does the "real cluster shape at family scale" feeling materialize?** Yes.
It is built for B2B SaaS, where the per-user/per-tenant cost of operating
3 nodes × 4 CPU × 16 GB is amortized over thousands of paying users. At 25
users and 16 apps you are running a small enterprise-IAM substrate to serve
a household, and the failure modes (Postgres corruption, masterkey loss,
Login UI version skew) hit the same way they would at scale. The single
homelab operator absorbs all of it.

## Pros for our use

- OIDC IDP coverage is excellent and covers 8/13 apps cleanly.
- Customizability via Next.js Login UI fork is the strongest in this candidate
  set if branding/UX control matters.
- Passkey-as-primary-factor with policy enforcement is first-class.
- SCIM, SAML, audit log streaming all present and functional.
- Active development, real funding, real team, real customer base. 5-year
  survival probability is high.
- Tailscale custom-OIDC integration is officially documented.
- Same codebase OSS vs cloud: no feature stripping.

## Cons for our use

- **No LDAP server.** Jellyfin loses its supported auth path. Workaround
  options (GlAuth bridge, jellyfin-plugin-sso going OIDC instead) exist but
  add complexity or change the Jellyfin posture.
- **No forward-auth.** Requires oauth2-proxy as a fifth container, with
  per-app API bypass rules implemented at the proxy layer for Subsonic/*arr.
- **4-container minimum** with no single-binary or embedded-DB option.
  No graceful degradation toward smaller shapes.
- **CVE cadence is high.** 3 criticals + 12+ highs in 18 months. Several are
  account-takeover class. Operating Zitadel = signing up for monthly patch
  vigilance.
- **AGPLv3** on the repo (note: marketing site claims Apache in places,
  which is a discrepancy to verify before any embedding/redistribution).
- **Documentation widely reported as weak for self-hosters**, with a
  ~3-hour first-install learning curve being the typical community report.
- **v4 architecture changes (Login UI split, Actions v1→v2 webhook model)
  add operational moving parts** without obvious benefit at homelab scale.
- **Masterkey immutability** is a sharp edge in a homelab where backup
  hygiene is variable.
- **Customizability requires forking and deploying a Next.js app**, which
  is real customizability but is also a real maintenance cost.
- **Community gravity is enterprise SaaS, not homelab.** Per-app integration
  guides are thinner than Authelia/Keycloak.

## Verdict

**Yellow leaning red.**

Load-bearing reason: **shape mismatch**. The minimum deploy is 4-5
containers with no single-binary fallback, no embedded DB, no LDAP server,
no forward-auth, and a CVE cadence that demands monthly patch vigilance.
For an estate where the operator is one person serving a household, the
gap between Zitadel's intended deployment shape (B2B SaaS with a SRE team)
and our actual shape (one operator, 25 users, 16 apps) is the wrong way
around: we are paying enterprise operational cost for capabilities (SCIM,
multi-org, fork-the-login-UI customization) that we will not exercise at
this scale.

Zitadel becomes the right choice if any of these flip:
- We grow to 100+ users and several distinct organizations.
- We need to embed identity in a SaaS product we are building.
- We commit to running it at production-cluster scale (3-node HA) anyway
  for other reasons.
- BYO login UI customization is a hard requirement we cannot achieve with
  a simpler stack.

None of those apply today.

For the homelab estate, prefer a single-binary candidate that does the
Jellyfin LDAPS + forward-auth + OIDC IDP roles in one process. Zitadel
should remain on the watchlist for if/when scale, customer model, or
customization needs change.

## Sources

- [Zitadel GitHub repo](https://github.com/zitadel/zitadel) — license, stars, language stats, push activity
- [Zitadel releases](https://github.com/zitadel/zitadel/releases) — release cadence (v4.14.0, v5.0.0-base, v3.4.9)
- [GitHub security advisories for zitadel/zitadel](https://github.com/zitadel/zitadel/security/advisories) — CVE list
- [Zitadel requirements docs](https://zitadel.com/docs/self-hosting/manage/requirements) — Postgres 14–18, Redis standalone, reverse proxy HTTP/2
- [Zitadel Docker Compose deploy](https://zitadel.com/docs/self-hosting/deploy/compose) — container layout
- [Minimum self-hosted specs (help center)](https://help.zitadel.com/what-are-zitadel-minimum-self-hosted-specs)
- [Hardware requirements discussion #2079](https://github.com/zitadel/zitadel/discussions/2079) — maintainer guidance on 3×(4 CPU, 16 GB) prod HA, 512 MB single-node minimum
- [LDAP server feature request #1929](https://github.com/zitadel/zitadel/discussions/1929) — Zitadel cannot act as LDAP server
- [Forward auth feature request #6912](https://github.com/zitadel/zitadel/issues/6912) — no native forward-auth
- [Custom Login UI guide](https://zitadel.com/docs/guides/integrate/login-ui/login-app) — Next.js fork model
- [Tailscale custom OIDC + Zitadel walkthrough (ibnunowshad.com)](https://ibnunowshad.com/post/zitadel-as-an-oidc-provider-for-tailscale/)
- [Mealie + Zitadel discussion #3557](https://github.com/mealie-recipes/mealie/discussions/3557)
- [Vaultwarden + Zitadel forum thread](https://vaultwarden.discourse.group/t/oidc-fork-by-timshel-and-zitadel/3575)
- [Self-hosting community sentiment discussion #8166](https://github.com/zitadel/zitadel/discussions/8166)
- [Niraj Kumar, "Brittle ZITADEL" (Feb 2026)](https://medium.com/@nirajkvinit/brittle-zitadel-why-self-hosting-feels-brittle-and-what-to-do-next-70566cfc43a1)
- [Pentest results H2 2022 (Cure53)](https://zitadel.com/blog/pentest-results-h2-2022)
- [Zitadel Series A announcement, Nov 2024](https://www.prnewswire.com/news-releases/zitadel-raises-9-million-series-a-to-advance-cloud-native-identity-infrastructure-302311461.html) — $9M led by Nexus Venture Partners
- [PitchBook Zitadel profile](https://pitchbook.com/profiles/company/497962-18) — funding history and team size
- [Zitadel SCIM v2.0 docs](https://zitadel.com/docs/guides/manage/user/scim2)
- [Zitadel passkeys feature page](https://zitadel.com/docs/concepts/features/passkeys)
- [Zitadel open source page](https://zitadel.com/opensource)
