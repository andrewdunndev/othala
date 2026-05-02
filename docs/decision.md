# SSO stack fit — decision

**Status:** Provisional, decided 2026-05-02. Contingent on Phase 0 research and Phase 1 lab outcomes. Reversible at the post-lab decision gate.

**Decision:** Move from Authentik to **kanidm** before production cutover on carmine. Replace the prior bench-sso-iac (Authentik test environment) with a kanidm bench under this repo's `lab/`. Plan upstream contributions to kanidm for forward-auth and (conditionally) first-class headless flow API.

This file captures the architectural decisions for the SSO substrate.

## Why kanidm

**Substrate risk on Django is real and growing.** AI-driven attack tooling makes authorization-gap fuzzing cheap. The CyberArk research on Authentik (CVE-2024-37905 privesc, CVE-2024-42490 cert-key leak) found exactly the class of bug LLMs accelerate. Django itself remains a substrate where a developer mistake (`Model.objects.filter(**user_input)`) becomes CVE-2025-64459. Both are mitigable through hardening, but the substrate is not the asset we want at the centre of our security posture for the next decade.

**Kanidm is purpose-fit for our shape.** Single-binary Rust, memory-safe, opinionated-secure defaults, built-in LDAPS + OIDC, passkeys as primary auth. The codebase is small enough to read end-to-end. The shape matches "homelab IDP for a family of 5-25" exactly, not "B2B SaaS toolkit" (Ory) or "enterprise IDP" (Keycloak).

**The cost we feared is the contribution we want.** Kanidm's gaps for our stack (no forward-auth endpoint, possibly-immature headless API) are not blockers. They are upstream contribution targets aligned with the existing pattern (bootc, composefs, rpm-ostree).

## App-stack mapping

Production carmine will run 13+ services through kanidm:

| App | Pattern | Substrate |
|---|---|---|
| Immich, Vaultwarden, Mealie, Audiobookshelf, BookLore, oCIS, Grafana, GitLab, Tailscale | OIDC native | kanidm OAuth2 |
| Jellyfin | LDAPS | kanidm built-in LDAPS |
| Navidrome | Forward auth + Subsonic API bypass | Custom Caddy (forward-auth plugin) |
| Gather (sonarr/radarr/sabnzbd/qbittorrent/prowlarr) | Forward auth | Same Caddy pattern |
| vLLM | OAuth2 client credentials | kanidm OAuth2 |

Forward-auth is the only architectural gap. The custom Caddy image (already built for cloudflare DNS-01 plugin) extends to host a forward-auth plugin via the same xcaddy pattern. Lab validates plugin choice empirically.

## Architectural decisions

### 1. Substrate
Kanidm replaces Authentik as the central IDP. Single binary, single SQLite file, hosted on carmine in its own pod (matching existing per-service-user pattern under `services/auth/`).

### 2. Public reachability
Cloudflare Tunnel (cloudflared) for almost everything. Outbound-only from carmine, no port-forwarding, full WAF + DDoS in front of the login surface.

**Exception: upload-heavy subdomains** (Immich confirmed; oCIS to validate). CF Tunnel has per-request body size limits (~100MB) that fail on 4K phone video uploads. These subdomains use gray-cloud DNS direct to carmine via port-forward 443. WAF lost on those subdomains, mitigated by strong app auth + Caddy rate-limiting + (optional) GeoIP allowlist. Once Tailscale is pervasive, mobile clients prefer Tailnet path.

### 3. Forward auth
Extend the custom Caddy image. xcaddy build with `caddy-cloudflare` (DNS-01) + a forward-auth plugin. Same image is the universal Caddy sidecar for the estate. Plugin selection candidates (in preference order):
1. caddy-security (greenpau) — preferred for conceptual congruity, validate maturity in lab
2. caddy-jwt + a small custom kanidm-aware plugin we write (~200 LOC Go)
3. oauth2-proxy as a separate process (last resort, breaks one-process-per-pod)

### 4. Frontend
**Layer 2 target:** custom Astro/Tailwind login page matching dunn.dev/design. Kanidm Yew UI retained for self-service flows (passkey enrollment, account settings) with CSS skin. Spend design effort on the every-day surface.

Layer 2 viability gated on Phase 0 research (kanidm `/v1/auth/*` headless API maturity). If headless support is too immature, fall back to Layer 1 (CSS skin only) and queue an upstream headless-flow-API contribution.

### 5. Home portal
Three-state Astro app on Cloudflare Pages at `home.dunn.dev`. Single URL, single brand:
- Pre-auth: passkey-prompt login
- Post-auth: tile grid filtered by ID-token `groups` claim
- Infra-down: friendly status panel

Health check via Cloudflare Worker that pings kanidm and stores status in Workers KV. Page reads KV, not carmine directly. Folds the previously-planned standalone `status.dunn.dev` into `home.dunn.dev`.

### 6. Bootstrap order on carmine
1. Carmine boots (bootc immutable image)
2. **Kanidm pod starts** — first service, no dependencies, admin via `kanidmd` CLI on the host
3. Cloudflare Tunnel comes up, `auth.dunn.dev` becomes publicly reachable
4. **Tailscale comes online as a kanidm OIDC client**
5. All other app pods come up as kanidm OIDC clients
6. Web admin path opens, gated by Cloudflare Access pointed at kanidm OIDC

### 7. Tailscale posture
Not load-bearing. Admin paths must work without Tailscale. Tailscale is the convenience layer for remote access, not a trust dependency. Implication: kanidm admin gate uses Cloudflare Access pointed at kanidm OIDC, not Tailscale-only.

### 8. No split identity
Every login goes through kanidm. No CF Access with non-kanidm IDP. No "log in with Google/GitHub" anywhere. Tailscale uses kanidm OIDC. forge.dunn.dev uses kanidm OIDC, not GitHub OIDC.

**Intentional exception:** Bitwarden master password. The password manager retains independent auth as the break-glass-of-last-resort.

### 9. Upstream contributions
Two targets, sequenced after Phase 0 research clarifies viability. See `docs/contribution-strategy.md` for the full posture, including the "document independently" fallback if upstream rejects.

## Reversibility

Reversible at the post-lab decision gate. Fallback if outcomes are red is documented in `docs/contribution-strategy.md` — the bias is to stay with kanidm even if upstream contributions are difficult, by documenting the patterns independently in this repo.

## Lab plan

Lab work proceeds in three phases:
- Phase 0 — Research: walk the kanidm maintainer's stance on contributions, map kanidm's headless flow API, validate Caddy plugin maturity
- Phase 1 — GCP lab: provision, configure, wire each pattern (OIDC, LDAPS, forward auth), build home portal prototype, retarget Playwright suite, phone test
- Phase 2 — Decision lock: capture outcomes, update this doc with green/yellow/red, queue follow-up work

## Lab outcome

_To be filled in at the end of Phase 2. Update this section with green/yellow/red on the kanidm move, evidence summary, and pointers to per-pattern findings under `lab/docs/`._
