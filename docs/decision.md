# SSO stack fit — decision

**Status:** Decided 2026-05-02. Substrate: **Authentik with eyes-open hardening**, after a wider evaluation of alternatives (kanidm, Authelia, Hanko, voidauth, Pocket-ID, Zitadel) returned to the original choice.

## Decision

**Authentik** is the central IDP. Free OSS tier; no commercial features used (everything in our stack is in the free tier). Hardening package applied to address the Django substrate concern.

This repo (`dunn.dev/auth`) is the IaC/YAML home for the entire auth deployment: Authentik blueprints, custom Caddy image build, lab harness, Astro home portal, and the per-pattern Caddyfile snippets. The retiring `dunn.dev/bench-sso-iac` repo is superseded.

## How we got here

The journey across the eval was extensive. Quick history:

1. **Original choice (carmine ROADMAP):** Authentik. Django, largest ecosystem.
2. **Concern:** Django + AI-attack threat model. Pivoted to evaluate kanidm.
3. **kanidm Phase 0 research surfaced:** explicit AI/LLM ban (AGENTS.md, Feb 2026, includes Anthropic-specific refusal trigger), forward-auth contribution closed by maintainers (issues #2407, #2774), browser BYO-UI structurally not viable (PR #2980 closed 2026-04-30).
4. **Wider eval:** Authelia (no LDAP server; lldap-as-companion is wrong-shaped per our needs), Hanko (not an IDP), voidauth (single maintainer + capability gaps), Pocket-ID (no LDAP server), Zitadel (multi-container architecture mismatch + CVE cadence).
5. **Outcome:** the project that scores best on the user's stated criteria (community sustainability + good security + customizability) is the one we started with — Authentik.

Full per-candidate evaluations under `../lab/docs/eval-*.md`; comparison synthesis at `substrate-comparison.md`.

## Architectural decisions locked

### 1. Substrate: Authentik (free OSS tier)
Everything our estate uses is in the free tier:
- OIDC IDP, OAuth2, SAML
- LDAP outpost (for Jellyfin native auth path)
- Proxy outpost (for Navidrome / Gather forward-auth)
- Visual flow designer, branding, custom CSS
- Blueprints (declarative IaC, the basis of `../authentik/blueprints/`)
- RADIUS PAP, MFA, passkeys, recovery flows

The enterprise-tier features (RADIUS EAP-TLS, RAC, federation between instances) are not on our roadmap. Watch-out: if Authentik moves currently-free features behind the paywall, revisit substrate. kanidm is the documented fallback (we have the evaluation evidence ready).

### 2. LDAP outpost co-located in the Jellyfin pod
Authentik's outpost architecture lets us deploy the LDAP outpost inside the Jellyfin pod. LDAP queries are local to the pod; the outpost queries back to authentik-server over the network. Single source of truth (Authentik) plus deployment locality. The Apple TV / Infuse SSO path works via this LDAP plugin as supported by Jellyfin.

### 3. Proxy outpost for forward-auth (Navidrome, Gather)
Authentik's proxy outpost handles forward-auth natively. Caddy directs unauthenticated traffic to the outpost endpoint (`/outpost.goauthentik.io/auth/caddy`); the outpost validates the user's session and returns identity headers. No separate forward-auth plugin needed.

### 4. Public reachability: DNS-only Cloudflare + port-forward 443
Cloudflare's role shrinks to:
- DNS hosting (free, fast)
- DNS-01 ACME for cert provisioning via the Cloudflare API (out-of-band, not in the request path)

No CF Tunnel, no CF Access, no CF in the auth or request path. Family auth flow has one feel (Authentik), no Cloudflare challenges in the way. Privacy + simplicity tradeoff: lose CF WAF/DDoS at the edge, gain a clean trust boundary. Caddy-side rate limiting and the inherent strength of bcrypt + long random passwords cover what WAF was contributing.

### 5. Admin path hardening: basicauth + Authentik
Admin paths (`/if/admin/*`, app admin paths) are gated by:
- Caddy `basicauth` with a 64-char random password (bcrypt hashed, stored in Bitwarden, shared by admins)
- Authentik OIDC with admin-MFA flow (re-prompt for TOTP/passkey on every admin session, not honoring the 90-day session)
- bcrypt's natural CPU slowness as the brute-force cap (no separate rate-limit plugin needed)

Family members never see this layer. Admin operators (Andrew, possibly Jane) enter the Basic Auth credential, then their personal Authentik creds.

### 6. Custom Caddy image (`dunn.dev/caddy-estate`)
Built directly from upstream Caddy + plugin Go modules with `go build` (no xcaddy). One plugin: `caddy-dns/cloudflare` for DNS-01 ACME. Forward-auth is handled by Authentik's proxy outpost, so no second plugin is needed.

### 7. Home portal: three-state Astro on Cloudflare Pages
`home.dunn.dev` is an OIDC RP. Three states by Authentik reachability: pre-auth (Sign-In button → bounces to auth.dunn.dev), post-auth (tile launcher filtered by group claims), infra-down (status panel via a Cloudflare Worker that polls Authentik). Folds the prior planned `status.dunn.dev` into `home.dunn.dev`.

### 8. Tailscale not load-bearing
Admin paths and recovery paths must work without Tailscale. Tailscale is the convenience layer for remote access, not a trust dependency.

### 9. No split identity
Every login goes through Authentik. No CF Access with a non-Authentik IDP. No "log in with Google/GitHub" anywhere. forge.dunn.dev (GitLab) uses Authentik OIDC. Tailscale uses Authentik OIDC.

**Intentional exception:** Bitwarden master password. The password manager retains independent auth as the break-glass-of-last-resort.

### 10. Upstream contributions: not a focus
Authentik is consumer-only for us. We file occasional bug reports backed by deployment evidence. No code contributions planned. The estate's contribution arc (bootc, composefs, rpm-ostree) doesn't extend to Authentik because the stack is mature and the gaps we identified during eval (Django substrate, commercial trajectory) aren't things we'd contribute fixes for.

## Hardening package

The Django substrate concern (CyberArk's research on CVE-2024-37905, CVE-2024-42490, plus general AI-attack risk on Python codebases) is real but addressable. The package:

1. **Admin UI never on public internet via untrusted paths.** The Caddy `basicauth` gate plus Authentik's admin-MFA flow plus a long random password are the layers.
2. **Version-pin in the quadlet, drop AutoUpdate** on the Authentik image. Subscribe to goauthentik.io/security advisories; alert on new CVEs into the same channel as bootc rebuild alerts.
3. **Audit logging via alloy → Loki for every authz event.** Overlaps with `config-deviation-audit` t10 in the immutable tree.
4. **Set `AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS` correctly** to Caddy's internal CIDR (CVE-2024-47070 mitigation).
5. **No public exposure of admin API.** `/api/v3/*` is reachable only via the same paths gated by basicauth.

## Family UX

1. iPad / iPhone opens `home.dunn.dev` (PWA on home screen)
2. Page renders dunn.dev brand → "Sign in" button visible (pre-auth state)
3. Tap Sign In → redirect to `auth.dunn.dev` (briefly visible URL change)
4. Authentik login UI (branded via custom CSS) → conditional UI passkey autofill → Face ID / Touch ID
5. Redirect back to `home.dunn.dev` → tile grid renders based on group membership (post-auth state)
6. Tap tile → app-side OIDC redirect → already authenticated → app loads

Steps 3-5 happen in ~1-2 seconds. Standard SSO bounce pattern; no confusing intermediate auth screens.

## What's in this repo (IaC structure)

```
auth/
├── docs/                       # this file + architecture + contribution-strategy + substrate-comparison
├── authentik/
│   └── blueprints/             # Authentik IaC: flows, groups, scopes, brand, per-app providers
├── caddy/
│   ├── Containerfile           # custom dunn.dev/caddy-estate image, direct go build
│   ├── Makefile
│   └── snippets/               # reusable Caddyfile patterns (admin-path, oidc-app, ldap-app, forward-auth)
├── lab/
│   ├── compose/                # docker-compose stack for GCP-based pattern validation
│   ├── scripts/                # gcp.sh, deploy.sh, smoke.sh, configure-apps.sh, set-passwords.sh
│   ├── tests/                  # Playwright suite
│   ├── Makefile
│   └── docs/                   # eval-*.md per-candidate evaluations + research findings
├── portal/                     # Astro home portal (three-state)
└── upstream/
    └── firstyear-walk/         # historical context for the kanidm rejection
```

## Reversibility

Reversible at any time by re-evaluating substrate. The eval evidence is durable in this repo. If Authentik's commercial trajectory makes free-tier insufficient for our needs, kanidm becomes the documented fallback (with the bus-factor and AI-ban tradeoffs accepted). Bench harness is reusable for either substrate.

## Memory pointers

- Cloudflare role: DNS-only, no proxy/tunnel in request path → `feedback`/`project` memory updated
- Authentik substrate + hardening package → `project` memory updated
- kanidm evaluated and rejected → `project` memory updated with link to substrate-comparison
