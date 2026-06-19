# SSO stack fit: decision

> **SUPERSEDED (architecture). HISTORICAL RATIONALE ONLY.**
> This document is the original substrate-selection record. The
> **substrate choice itself remains the decision in force**: Ory Kratos +
> Hydra + Postgres, a custom glauth-kratos LDAP bridge, and a custom Caddy
> image. Keep this for "why Ory, not kanidm/Authelia/Zitadel."
>
> The **architecture** described below has been superseded by the converged
> Othala/dag end-state. Do NOT read the topology, frontend, or IaC-structure
> sections here as current. The current shape is:
>
> - **Othala is the OSS project**; `dag.dunn.dev` is the deployed instance
>   (rune motif ᛞ→ᛟ, door to home). The old name `auth`/`auth.dunn.dev` is
>   retired. GitLab project: `dunn.dev/othala`.
> - **One all-TypeScript application** (Astro Node SSR, in `portal/`,
>   published as the `othala` image) fronts Ory and is Hydra's login +
>   consent + logout provider. NOT Cloudflare Workers. State is per-request
>   from Kratos; no Workers KV.
> - **The Go consent service and util runner are legacy**, retired at the
>   deploy-repo cutover. Their behaviour now lives in the TS app. The custom
>   back-channel-logout signer was DELETED. Hydra signs natively, no key at
>   rest.
> - **Admin authority is the `OTHALA_ADMIN_IDS` allowlist**, not the
>   `admin` group (display-only).
> - **Secrets are sops + age** (your sops-encrypted secrets store).
>   Bitwarden is out.
> - **The deploy repo vendors a released tag** under `services/dag/` (no submodule).
>
> Reversed rows are annotated inline below. The Ory substrate choice, the
> LDAP bridge design, and the identity/auth-policy decisions remain current.
> For the authoritative architecture, read [`../ARCHITECTURE.md`](../ARCHITECTURE.md).
> For release state, read [`STATUS.md`](STATUS.md).

**Status:** Decided 2026-05-02. Substrate: **Ory Kratos + Hydra + custom glauth-kratos LDAP bridge + Astro Node SSR portal on carmine + custom Caddy image (direct go build)**.

After evaluating multiple IdP substrates (kanidm, Authelia, Hanko, voidauth, Pocket-ID, Zitadel), Andrew's reframe ("I want UX excellence, not flow customization") flipped the call to Ory. The 4 feasibility validations went GREEN/YELLOW with manageable risks, and the adversarial review against upstream docs caught two CRITICAL issues that are now corrected in the locked architecture.

## Why Ory

The journey here was extensive (prior eval evidence retained in git history). Short version:

- **kanidm:** AI/LLM ban in AGENTS.md (Anthropic refusal trigger), forward-auth + BYO-UI explicitly closed by maintainers, bus factor 1
- **Authelia:** no LDAP server; lldap-as-companion is wrong-shaped (lldap as source of truth for the whole estate when its only consumer is Jellyfin)
- **Hanko:** not an IDP, doesn't fit shape
- **voidauth:** single maintainer, capability gaps (no LDAP, no WebFinger, no client_credentials)
- **Pocket-ID:** consumes external LDAP, doesn't serve LDAP; same gap as Authelia/voidauth
- **Zitadel:** multi-container architecture mismatch + concerning CVE cadence

Ory's offer for our shape:
- Total UI control via a custom Astro app, matching the estate visual language exactly. *(The original draft said "Astro on Cloudflare Workers"; reversed: the app runs as Astro Node SSR. Visual language comes from `@dunn.dev/reference`, not a `dunn.dev/design` package.)*
- Composable architecture: Kratos (identity), Hydra (OAuth2/OIDC), each binary doing one thing
- Free OSS forever; Ory Network is the SaaS commercialization, self-hosted is fully featured Apache 2
- The LDAP bridge gap becomes a contribution opportunity: a glauth Kratos backend, publishable upstream

The cost: BYO UI (we build the Astro app), 4-5 components instead of one, smaller homelab community to lean on. Trades we accept.

## Locked architectural decisions

### Identity foundations

| Decision | Value | Notes |
|---|---|---|
| WebAuthn `rp.id` | `dunn.dev` (registrable parent) | **One-way.** Origins list is `https://dag.dunn.dev`. (`home.dunn.dev` was the original Topology-A user host; dropped, since the IdP and the UI live on the same FQDN, `dag.dunn.dev`.) Any future subdomain that needs WebAuthn assertion is a registrable child of `dunn.dev`. |
| Username convention | `first.last` (e.g., `andrew.dunn`) | LDAP DN-friendly. |
| Cookie domain | `.dunn.dev`, `SameSite=Lax`, `HttpOnly` | Required for cross-subdomain Astro UI calls to Kratos. |
| Identity schema | traits = {username, email, displayName?, recoveryEmail?} + `metadata_admin.groups[]` | Groups in metadata_admin (Ory-shaped: admin-managed, user can't self-escalate via settings flow). |

### Auth policy

| Decision | Value | Notes |
|---|---|---|
| Passkey policy | Preferred + password fallback | Family won't enroll consistently; lockout protection. |
| MFA | Optional default | AAL2 step-up enforced at app-layer (Astro SSR), not at Caddy or globally. |
| Sessions | 90 days normal, 1 day admin | `session.lifespan: 2160h` global; admin SSR pages enforce shorter via re-auth on AAL2. |
| Recovery | Code strategy (numeric code via email) + admin-issued URL | **Magic link is deprecated** in current Kratos; we use code. |
| Onboarding | Admin creates user → emit one-time enrollment URL → text via Signal/iMessage | No password ever transits a channel. |

### OIDC posture

| Decision | Value | Notes |
|---|---|---|
| Hydra subject identifier | `public` | Family scale, no app-to-app correlation concern. |
| Consent | `oidc.skip_consent: true` per client manifest | Family never sees consent screens; trusted first-party clients auto-accept. |
| Tailscale WebFinger | Cloudflare Pages function at `dunn.dev/.well-known/webfinger` (apex) | RFC 7033 + Tailscale KB-1240 require WebFinger at `${email-domain}/.well-known/webfinger`, NOT on the IdP subdomain. Pages function lives in the dunn.dev apex repo. Consulted only once during Tailscale tenant setup; lock-in afterward. |

### LDAP bridge

| Decision | Value | Notes |
|---|---|---|
| Implementation | glauth Handler interface (NOT Backend), embedded plugin (compile-time, custom binary) | Adversarial review correction: glauth v2.5.0 added embedded plugins as the recommended path. |
| DN format | `uid=<username>,ou=users,dc=dunn,dc=dev` | uid as RDN attribute, "users" container. |
| Deployment | Co-located in Jellyfin pod (production); standalone container (lab) | Smaller blast radius; LDAP traffic local in production. |
| BIND mechanism | Kratos `/self-service/login/api` flow with implicit aal=aal1 | Bridge runs API-flow login per-bind; password verification only (session token discarded). |
| BIND cache | 30s TTL on positive results | Absorbs Apple TV / Jellyfin reconnect storms (Argon2 is expensive). |
| Identity cache | 30s TTL with polling refresh | Kratos doesn't fire admin-side webhooks; polling is the pattern. |
| Admin token | Identity-read-only scope | Bridge can't mutate identities, just list them. |

### Frontend

| Decision | Value | Notes |
|---|---|---|
| Framework | ~~Astro 6 with Cloudflare Workers adapter~~ **REVERSED: Astro Node SSR on carmine** | Workers adapter dropped; admin port (`kratos:4434`) unreachable from a Worker. Portal runs as a Node process in the auth pod. |
| Output mode | hybrid; `export const prerender = false` on every SSR page | No inheritance in Astro 6 hybrid mode. |
| AAL2 enforcement on /admin/* | App-layer SSR guard (`requireAdminSession` in `portal/src/lib/admin.ts`) | **Not Caddy.** Adversarial review correction: Kratos AAL is per-flow, not per-route. |
| Health check | ~~Cloudflare Worker polls Kratos `/health/ready` every 30s, stores in Workers KV; Astro page reads KV~~ **REVERSED: per-request in-pod fetch** | KV dropped with Workers adapter. `index.astro` fetches `kratos:4433/health/alive` directly (2s timeout). |

### Public reachability

| Decision | Value | Notes |
|---|---|---|
| DNS | Cloudflare DNS-only (gray cloud, no proxy) | No CF Tunnel, no CF Access. No third-party in the auth/request path. |
| Network | Port-forward 443 on home router → Envoy SNI router → per-pod Caddy | Direct path; one auth feel for the family (no CF challenges). |
| TLS | Per-pod Caddy with DNS-01 ACME via Cloudflare API | Custom dunn.dev/caddy-estate image, direct go build, one plugin. |

### Hardening

| Decision | Value | Notes |
|---|---|---|
| Admin path gate | Caddy forward_auth for "session present"; AAL2 enforced at Astro SSR | App-layer step-up via `?aal=aal2&refresh=true` redirect to Kratos. |
| Session cookie | `HttpOnly`, `SameSite=Lax`, `domain=.dunn.dev` | Per-app log leakage of cookie names is acceptable; HttpOnly prevents JS access. |
| `secrets.system` (Hydra) | Generate once, store in ~~Bitwarden~~ **sops + age** (`carmine.hydra_system_secret`), **never rotate** without DB rebuild | **REVERSED: Bitwarden out.** Per Hydra docs; baked into the operator playbook. |
| `hydra-migrate` init | Runs `hydra migrate sql up` before `hydra serve` on every boot | Hydra schema migration is not automatic. |
| Kratos courier | Singleton (replica:1) | Multiple couriers can double-send. |

### Operations

| Decision | Value | Notes |
|---|---|---|
| Postgres | Single instance, separate `kratos` and `hydra` databases | Ory's recommended pattern. |
| Audit log | alloy → Loki (archival) + small `recent_activity` table for admin UI (last 100 events) | |
| SMTP | Fastmail | App password from ~~Bitwarden~~ **sops** via `SMTP_PASS` env var. **REVERSED: Bitwarden out.** |

### Posture

| Decision | Value |
|---|---|
| Tailscale not load-bearing | Admin/auth/recovery paths must work without Tailscale. |
| No split identity | All login through Kratos. Bitwarden master password is one intentional exception (Bitwarden is personal tooling, outside this stack). |
| Upstream contributions | Likely target: glauth-kratos backend as upstream embedded plugin contribution. The plugin has standalone value beyond our kit. |

## Adversarial review findings folded in

The full prior adversarial review is retained in git history. Highlights:

- **CRITICAL: Kratos AAL is global-or-per-flow, not per-route.** Original lock said "Caddy enforces AAL2 on /admin/*"; corrected to app-layer SSR guard.
- **CRITICAL: glauth uses Handler interface (since v2.4), not Backend.** Original lock said "Backend, runtime .so"; corrected to "Handler, embedded plugin (compile-time)".
- **HIGH: Magic-link recovery is deprecated.** Use code strategy.
- **HIGH: Hydra schema migration is not automatic.** Added `hydra-migrate` init container.
- **HIGH: Kratos courier must be singleton.** Configured replica:1.
- **HIGH: `secrets.system` is non-rotatable.** Documented prominently.
- **HIGH: `skip_consent` threat model gap acknowledged.** Stolen session = tokens for all 14 auth-touching surfaces (11 OIDC + 1 LDAP + 2 forward-auth); acceptable at family scale, revisit if any app gains banking-tier ops.

## What's in this repo (IaC structure)

> **HISTORICAL.** This tree is the original layout sketch (note the
> `portal/` "Astro UI on Cloudflare Workers" + `wrangler.toml` +
> `public/.well-known/webfinger` lines, all reversed). The current layout
> is in [`../README.md`](../README.md) "Layout" and
> [`../ARCHITECTURE.md`](../ARCHITECTURE.md) "Where the code lives": one
> Astro Node SSR app in `portal/` (published as `othala`), consent/util as
> legacy-pending-removal, no Workers/wrangler, WebFinger served off the
> dunn.dev apex.

```
auth/
├── docs/
│   ├── decision.md           # this file
│   ├── ARCHITECTURE.md       # production topology + load-bearing decisions
│   ├── contribution-strategy.md
│   └── STATUS.md             # cross-session "where we are" entry point
├── kratos/
│   ├── kratos.yml            # server config
│   ├── identity.schema.json
│   └── README.md
├── hydra/
│   ├── hydra.yml             # server config
│   ├── clients/              # 11 OIDC client manifests
│   ├── apply-clients.sh      # idempotent apply against running Hydra
│   └── README.md
├── ldap-bridge/              # glauth-kratos custom binary
│   ├── main.go               # imports glauth + our handler
│   ├── kratos/               # Handler interface implementation
│   ├── glauth.cfg
│   ├── Containerfile, Makefile, README.md
│   └── go.mod
├── portal/                   # Astro Node SSR app (Othala app, published as othala image)
│   ├── astro.config.mjs, package.json
│   ├── src/
│   │   ├── lib/{kratos,admin-api,oauth2-handlers,gate,claims,revoke,...}.ts
│   │   └── pages/{index,auth/*,admin/*,oauth2/*}.astro
│   └── README.md
└── e2e/                      # QEMU-CI smoke harness (compose + scripts + gen-secrets)
```

## Family UX

> *(Original sketch used `home.dunn.dev`; the user-facing host is now
> `dag.dunn.dev`: the IdP and the family UI share one FQDN. The consent
> "service" is now the Othala app's in-process consent handler.)*

```
Mom opens iPad → dag.dunn.dev (PWA on home screen)
  ↓
Three states by Kratos /health reachability:
  1. Pre-auth: dunn.dev brand + "Sign in" button
  2. Post-auth: tile launcher filtered by metadata_admin.groups
  3. Infra-down: friendly status panel
  ↓
Sign in: Astro page calls Kratos API flow → WebAuthn challenge → Face ID
  ↓
Tile tap → app's OIDC redirect → Hydra (login_challenge → Othala consent handler auto-accepts)
        → app session via standard OIDC code exchange
```

The bounce happens in ~1-2 seconds. Standard SSO bounce; brief dag.dunn.dev URL shift; no Cloudflare challenges, no consent screens for trusted apps.

## Reversibility

If lab outcomes are red on the load-bearing parts (LDAP bridge BIND mechanism, Astro+Kratos cross-subdomain, Hydra `skip_consent` semantics), the documented fallback is **kanidm** (single binary, opinionated-secure, but bus-factor and AI-ban tradeoffs accepted in exchange for substrate quality). Bench harness is reusable for either substrate. Eval evidence is retained in git history.
