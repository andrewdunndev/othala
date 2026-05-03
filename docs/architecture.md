# Architecture

Production topology after the locked Ory pivot. Custom Caddy image (direct go build), DNS-only Cloudflare in front, port-forward 443 on home router, Kratos + Hydra + glauth-kratos + consent service on carmine, Astro UI on Cloudflare Workers.

## Topology

```
                           home.dunn.dev (Cloudflare Workers + static assets)
                           ├─ /                       three-state landing/launcher
                           ├─ /auth/{login,recovery,settings,verification,consent}
                           ├─ /admin/{users,groups,oauth2,activity}  (SSR + AAL2 guard)
                           └─ /.well-known/webfinger  (static JSON for Tailscale)
                                  │
                                  │ fetch() to Kratos public API
                                  │ fetch() to consent service for OIDC handoff
                                  ↓
                           Cloudflare DNS (gray cloud, no proxy)
                                  │
                                  ↓
                           home IP : 443 (port-forwarded)
                                  │
                                  ↓
                           carmine
                             ├─ Envoy (L4 SNI router on 80/443)
                             ├─ per-pod Caddy sidecars (dunn.dev/caddy-estate, DNS-01 ACME)
                             ├─ auth pod
                             │    ├─ kratos (4433 public, 4434 admin)
                             │    ├─ kratos-courier (singleton, sends recovery emails)
                             │    ├─ hydra (4444 public, 4445 admin internal-only)
                             │    ├─ hydra-migrate (init container, schema migrations)
                             │    ├─ consent service (4477 internal; carmine pod-network)
                             │    └─ postgres (kratos + hydra databases)
                             ├─ jellyfin pod
                             │    ├─ jellyfin
                             │    └─ glauth-kratos bridge (LDAPS 636 in-pod)
                             └─ all other app pods
                                  ├─ caddy sidecar (TLS via DNS-01 ACME)
                                  └─ app container

home portal health check:
  Cloudflare Worker (cron) → kratos:4434/health/ready → Workers KV
  index.astro → reads KV → state determination
```

## Cloudflare's role

DNS hosting + DNS-01 ACME via API + hosting the home portal Astro on Workers + a single cron Worker for the health check. **Not in the auth or app request path.** Never sees TLS plaintext for app/auth flows.

## Bootstrap order on carmine

1. Carmine boots (bootc immutable image, ZFS pools, networking)
2. Postgres pod up
3. **Hydra schema migration** (init container; runs `hydra migrate sql up`)
4. Kratos + Hydra serve up
5. Consent service up
6. Caddy sidecars obtain DNS-01 certs
7. App pods come up as Hydra OIDC clients (or LDAP via bridge for Jellyfin)
8. Tailscale joins as Hydra OIDC client (custom-OIDC + WebFinger)

Tailscale is not load-bearing. Admin paths work without it.

## Auth patterns

### OIDC native — keep, larder, listen, memory, vault, library, forge, observe

Per-app Caddyfile snippet:
```caddyfile
keep.dunn.dev {
  import oidc-app vaultwarden 80
}
```

App handles its own OIDC redirect to `https://auth.dunn.dev/oauth2/auth?...`, exchanges code for tokens via `https://auth.dunn.dev/oauth2/token`. Caddy is just the TLS terminator + reverse proxy.

### LDAP outpost — cinema (Jellyfin)

The glauth-kratos bridge co-located in the Jellyfin pod presents identities over LDAPS:636. Jellyfin's LDAP plugin binds against `localhost:636`. Bridge translates BIND to a Kratos public-API login flow; SEARCH to Kratos admin-API identity listing.

Per-app Caddyfile:
```caddyfile
cinema.dunn.dev {
  import ldap-app jellyfin 8096
}
```

LDAP traffic never hits Caddy.

### Forward auth — tune (Navidrome), gather/* (Sonarr, Radarr, etc.)

Caddy forward_auth against Kratos `/sessions/whoami`. Subsonic API and shares bypass auth (native clients use HTTP Basic).

```caddyfile
tune.dunn.dev {
  @subsonic path /rest/* /share/*
  handle @subsonic {
    reverse_proxy navidrome:4533
  }
  handle {
    import forward-auth navidrome 4533
  }
}
```

### Client-credentials — llm (vLLM)

Caddy validates the `Authorization: Bearer` token via Hydra's `/admin/oauth2/introspect`. Same in-pod sidecar pattern.

### Custom OIDC — Tailscale

Tailscale custom-OIDC against Hydra. Doesn't use PKCE. WebFinger response served as a static JSON file at `home.dunn.dev/.well-known/webfinger`.

## Admin path gating

```
Family member hits home.dunn.dev/admin/*
  ↓
Caddy forward_auth → Kratos /sessions/whoami
  - 401: redirect to home.dunn.dev/auth/login
  - 200: user is authenticated (any AAL); pass through
  ↓
Astro SSR page (admin/*.astro) calls requireAdminSession(Astro):
  - whoami again on the SSR side
  - Identity must be in admin group (metadata_admin.groups includes "admin")
  - authenticator_assurance_level must be aal2
    - If aal1: redirect to https://auth.dunn.dev/self-service/login/browser?refresh=true&aal=aal2&return_to=...
  ↓
On aal2: render admin UI
```

Per adversarial review: AAL is enforced at the SSR layer because Kratos AAL is per-flow, not per-route. Caddy alone can't conditionally gate on JSON-body claims.

## Group model

Two types of groups in `metadata_admin.groups[]`:

**Identity groups** — who you are: `admin`, `family`, `friends`, `kids` (deferred).

**Access groups** — what you can reach (one per app):
`access-keep`, `access-larder`, `access-listen`, `access-cinema`, `access-tune`, `access-memory`, `access-vault`, `access-gather`, `access-library`, `access-llm`, `access-forge`, `access-observe`.

The home portal tile launcher renders only tiles for `access-*` groups the user is in. Apps enforce authz reading the OIDC `groups` claim (injected by the consent service from `metadata_admin.groups`).

## Custom Caddy image

`dunn.dev/caddy-estate`: built directly via `go build` from upstream Caddy + plugin Go modules (no xcaddy). One plugin: `caddy-dns/cloudflare`. Forward-auth via Caddy's built-in `forward_auth` directive against Kratos.

## Reversibility

If lab outcomes red, fallback is kanidm (single-binary, bus-factor and AI-ban accepted in exchange for substrate quality). Bench harness reusable. Eval evidence in `lab/docs/`.
