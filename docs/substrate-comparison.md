# Substrate comparison

Wider evaluation of SSO substrate candidates against the dunn.dev estate's needs. Run after the initial Authentik → kanidm narrowing, on the basis that kanidm felt like fighting the framework and might not be the best-shaped option.

## Candidates evaluated

| Candidate | Per-candidate eval |
|---|---|
| Authentik | (superseded earlier; substrate concern with Django) |
| kanidm | `../upstream/firstyear-walk/findings.md`, `../lab/docs/headless-api-notes.md` |
| Authelia | `../lab/docs/eval-authelia.md` |
| Hanko | `../lab/docs/eval-hanko.md` |
| voidauth | `../lab/docs/eval-voidauth.md` |
| Zitadel | `../lab/docs/eval-zitadel.md` |

## Selection criteria

User-stated, in order:

1. **Community + sustainability** — likely to be maintaining in 5+ years
2. **Good security practices** — substrate quality, opinionated-secure, CVE history
3. **Customizability** — at minimum CSS skin, ideally BYO UI elements

Plus implicit:
4. **Capabilities for our app stack** — OIDC IDP, LDAPS for Jellyfin, forward-auth for Navidrome/Gather
5. **Single container preferred** (not absolute)
6. **Resource footprint at family scale**

## Drop list (with reasons)

### Hanko — RED
**Not an IDP.** Hanko is a passkey-as-a-service backend for app developers to embed, not an IDP that aggregates apps. Maintainers explicitly rejected OIDC IdP capability in PR #869 (June 2023): "we don't want to support OIDC Provider capabilities ... developer experience would suffer." 0 of 13 apps fit. Structural mismatch.

### Zitadel — RED for our scale
**Multi-container architecture mismatch + CVE cadence.** v4 minimum is 4 containers (Traefik + Zitadel core + Next.js login UI + Postgres), 5 with oauth2-proxy for forward-auth. No single-binary mode, no embedded DB. 3 critical + 12+ high CVEs in 18 months with account-takeover as a recurring class. Customizability is genuinely best-in-class (forkable Next.js login UI, per-org branding) but you absorb enterprise operational cost without the user base to amortize it.

### voidauth — RED for our timeline
**Single maintainer, capability gaps, too immature for a 5-year bet.** Project is 12 months old. Single maintainer (Derek Paschal, 830 of ~870 commits). Bus factor 1, no organizational backing. Capability gaps: no LDAP server, no WebFinger (Tailscale custom-OIDC blocked), no `client_credentials` (vLLM blocked), no SAML, no first-class API path bypass. The OIDC subset works but every other pattern needs a workaround.

## Viable shortlist: kanidm vs Authelia

Two candidates remain after the drops. Both are technically viable; the choice hinges on tradeoffs.

### Side-by-side

| Dimension | kanidm | Authelia |
|---|---|---|
| **Substrate** | Rust (memory-safe) | Go (memory-safe) |
| **Containers** | 1 (everything built-in) | 1 standalone, 2 with companion LDAP (lldap) for Jellyfin |
| **OIDC IDP** | yes, built-in | yes, since v4 |
| **LDAPS** | yes, built-in | no — needs lldap or similar companion |
| **Forward-auth** | needs caddy-security plugin | **built-in, the design center** |
| **SAML** | no | planned since 2019, unstarted |
| **SCIM** | yes, in-progress | suggested (not on active roadmap) |
| **Passkey as primary** | yes, by design | yes (just landed 4.39, April 2026) |
| **Customizability ceiling** | CSS skin on HTMX UI | CSS skin + theming, no BYO UI per maintainer |
| **BYO custom login form** | structurally not viable (no CORS, single-host cookie, RP-id binding) | explicitly declined by maintainer |
| **Bus factor** | 1 primary maintainer (Firstyear) | ~3 core maintainers, ~30+ active human contributors / 6 months |
| **Last release** | 1.10.0 (2026-05-01) | 4.39.19 (2026-04-12) |
| **CVE history (18mo)** | clean (single-maintainer Rust) | clean (2 low-severity, no high/critical) |
| **AI/LLM contribution policy** | explicit ban (AGENTS.md, Anthropic-specific trigger) | not addressed (silent) |
| **Funding model** | independent / personal | Open Collective (~$60/yr, small-scale) |
| **Homelab traction** | growing, smaller than Authelia | very large, dominant in self-hosted SSO |
| **Per-app fit (8 OIDC + 1 LDAP + 2 forward-auth)** | 9/11 native, 2 via plugin | 10/11 native, 1 via lldap companion |
| **Resource footprint at family scale** | very small | very small |

### Where they tie

- **Substrate quality.** Both memory-safe. Both opinionated-secure by default. Both have clean CVE histories.
- **Customizability ceiling.** Both decline BYO UI. CSS skin is the cap on either path. Andrew's original "fully custom Astro login" goal is dead either way.
- **Family UX shape.** Both require the bounce-to-auth-subdomain pattern (home.dunn.dev → auth.dunn.dev for login → back). Brief 1-2s redirect, standard SSO pattern.
- **OIDC RP integration with our 8 OIDC-native apps.** Both work cleanly.

### Where kanidm wins

- **Single container.** LDAPS for Jellyfin is in the same binary. Operationally simpler, one image to maintain.
- **Apple TV / Infuse path.** Jellyfin LDAP plugin works against kanidm directly. With Authelia the LDAP plugin needs lldap (or Jellyfin moves to the OIDC plugin, which doesn't support native clients like Infuse on Apple TV).
- **SCIM.** kanidm is shipping SCIM as the data-model spine. Authelia suggests SCIM as a future direction without commitment.

### Where Authelia wins

- **Bus factor.** 3 maintainers + 30+ regular contributors over 6 months vs kanidm's primary single-maintainer dependency. Sustainability over a 5-year homelab horizon meaningfully better.
- **Forward-auth is the design center.** Built-in, no plugin layer, no architectural mismatch. caddy-security is fine but it's a layer we add specifically because kanidm closed the door on native forward-auth.
- **Less "fighting the framework."** No AI/LLM ban. No closed contribution doors (we're not contributing anyway, but the door being open vs closed says something about project posture). Multi-maintainer means less single-person idiosyncrasy.
- **Homelab tutorial abundance.** Authelia is the dominant self-hosted SSO project on r/selfhosted. Validated guides for every app on our list, from multiple authors.

### The trade explicitly

**The fork is "single binary kanidm" vs "Authelia + lldap (two binaries) + better-supported framework."**

| If Andrew values most | Pick |
|---|---|
| Operational simplicity (one container does it all) | kanidm |
| Sustainability over a 5+ year horizon | Authelia |
| Built-in forward-auth (no plugin) | Authelia |
| Apple TV / Infuse SSO via Jellyfin LDAP plugin | kanidm |
| Frictionless homelab community / tutorials | Authelia |
| Memory safety substrate (both are memory-safe; kanidm is Rust, lldap is also Rust, Authelia is Go) | tie (slight nudge to kanidm pure-Rust) |

## Recommendation: Authelia + lldap

The Phase 0 findings on kanidm (AI ban, closed contribution doors, structurally constrained UI) confirmed Andrew's suspicion that we were "fighting the framework." Authelia is less fighty:

- **Forward-auth is built-in, not a plugin.** The capability we need most for Navidrome and Gather is the framework's design center, not something we layer on.
- **Bus factor 3 vs 1.** For a 5+ year homelab IDP at the center of the security posture, multi-maintainer is meaningfully safer. Firstyear's responsiveness is currently good, but it's one person.
- **lldap as companion.** lldap (github.com/lldap/lldap) is a tiny Rust LDAP-only daemon designed specifically to pair with Authelia (and other OIDC IDPs that don't ship LDAP). It's purpose-fit, ~5MB binary, single container, well-maintained. Authelia uses lldap as its user backend; Jellyfin's LDAP plugin points at lldap directly. The "two containers" cost is two well-defined containers each doing one job.
- **Customizability ceiling is the same** (CSS skin only on either substrate). The "fully custom Astro login" goal is dead regardless. So the dimension where kanidm felt like fighting (UI customization rejection) doesn't actually differ between candidates.
- **No upstream contribution path on either side.** Both projects decline BYO UI; Authelia hasn't slammed the door on forward-auth or headless API but also hasn't stated appetite. Either way we're consumers.

The decision is reversible: lab harness validates either substrate with the same Playwright contract and Caddy patterns. Lab cost a few hours either way. Andrew's original "single container" preference becomes "two purpose-fit containers" — a small concession for the sustainability and built-in-forward-auth wins.

## Final outcome — 2026-05-02

**Decision: Authentik with eyes-open hardening.**

After the wider eval and a follow-up Pocket-ID evaluation (`../lab/docs/eval-pocket-id.md` — RED, doesn't serve LDAP), the picture clarified:

- **Authelia + lldap was wrong-shaped.** Making lldap (a "Light LDAP" daemon) the root of identity for the entire estate when its primary consumer is just Jellyfin inverts the layering.
- **Pocket-ID has the same LDAP-server gap as voidauth and Authelia.** Doesn't fit shape.
- **kanidm's downsides** (bus factor 1, AI ban, closed contribution doors, structurally constrained UI) are real costs even from a consumer perspective.
- **Authentik's upsides** (largest community, LDAP outpost architecture that solves the source-of-truth concern cleanly, proxy outpost for native forward-auth, free OSS tier covers everything we use, mature ecosystem with validated integrations for every app on our list) hold up under scrutiny.

The Django substrate concern that originally drove the move was real but addressable. After researching six alternatives, the answer is to manage the Django risk via a hardening package rather than escape it via a substrate change. The hardening package — admin path basicauth + Authentik admin-MFA + version pinning + audit logging + correct trusted-proxy CIDRs — is documented in `decision.md`.

### What changes vs the original Authentik plan

- **Public reachability simplifies:** DNS-only Cloudflare + port-forward 443 on home router. No CF Tunnel, no CF Access. One auth feel for the family. Privacy + simplicity.
- **Admin path hardening:** Caddy `basicauth` with bcrypt-hashed shared admin password (in Bitwarden) on `/if/admin/*` and equivalent app admin paths. Plus Authentik admin-MFA flow. Bcrypt's CPU cost is the brute-force cap (no separate rate-limit plugin needed in the custom Caddy image).
- **Custom Caddy image** (`dunn.dev/caddy-estate`): direct `go build` from upstream Caddy + plugin Go modules (no xcaddy). Just one plugin: `caddy-dns/cloudflare` for DNS-01 ACME. Forward-auth comes from Authentik's proxy outpost, no Caddy plugin needed.
- **dunn.dev/auth becomes the IaC home:** retiring `dunn.dev/bench-sso-iac` in favor of consolidating Authentik blueprints, lab harness, custom Caddy image, Astro home portal, and per-pattern snippets here.
- **No upstream contributions to Authentik** — consumer posture, occasional bug reports.

### What stays from the kanidm-era prep

- **Three-state Astro home portal at home.dunn.dev** — pre-auth (Sign-In button → bounces to auth.dunn.dev), post-auth (tile launcher filtered by groups claim), infra-down (status panel via CF Worker polling Authentik /health). Folds the prior `status.dunn.dev` into `home.dunn.dev`.
- **Tailscale not load-bearing** — admin paths work without it.
- **No split identity** — every login through Authentik. Bitwarden master password is the one intentional exception.
- **Bench infrastructure** (GCP scripts, Playwright contract) ports forward as the Authentik bench under `lab/`.

### Reversal path

If Authentik's commercial trajectory degrades the free-tier offering for our use case, the eval evidence in this repo is the playbook for the next move. **kanidm** is the documented fallback (with bus-factor and AI-ban tradeoffs accepted in exchange for substrate quality). Bench harness in `lab/` is reusable for either substrate.

Watch-outs that would trigger a re-eval:
- Free-tier features (LDAP outpost, proxy outpost, custom branding, blueprints) moving to enterprise tier
- Maintainer governance shifts (acquisition, license change, project pivot)
- Specific deployment-derived issue with no upstream fix path

None of these are likely in the next 12-24 months. Default posture: ship deployment, monitor advisories, file bugs as encountered.
