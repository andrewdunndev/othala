# Architecture

Status: active design. The lab in `lab/` validates each pattern before carmine cutover. This doc tracks the intended shape and gets updated with empirical findings.

## Production topology (intended)

```
internet
  │
  ↓
Cloudflare (DNS, WAF, DDoS, cache, Pages)
  │
  ├─→ home.dunn.dev (Cloudflare Pages)        ← three-state Astro portal
  │
  └─→ cloudflared tunnel (outbound from carmine, no port-forwarding)
        │
        ↓
      carmine (single bootc host)
        │
        ├─→ kanidm pod                         ← auth.dunn.dev, OIDC + LDAPS
        ├─→ envoy (L4 SNI router)              ← *.dunn.dev to per-pod Caddy
        └─→ app pods (per-service users, rootless podman)
              ├─ caddy sidecar (custom image: dunn.dev/caddy-estate)
              │   ├─ DNS-01 cert via cloudflare plugin
              │   └─ forward-auth via plugin (selected in lab)
              └─ app container

Exception: memory.dunn.dev (Immich)
  internet → Cloudflare DNS only (gray cloud, no proxy)
            → port-forward 443 on home router → carmine envoy → immich pod
  Reason: photo/video uploads exceed CF Tunnel size limit
```

## Bootstrap order

1. carmine boots (bootc, ZFS pools imported, networking up)
2. **kanidm pod starts** — first service, no dependencies. Admin via `kanidmd` CLI on the host (no web admin UI exposed).
3. cloudflared tunnel quadlet starts; `auth.dunn.dev` becomes publicly reachable.
4. **Tailscale comes online as kanidm OIDC client.** Devices join the mesh.
5. App pods come up as kanidm OIDC clients (or LDAPS for Jellyfin).
6. Web admin gate (`auth.dunn.dev/ui/admin`) opens, gated by Cloudflare Access pointed at kanidm OIDC.

Tailscale is not load-bearing. Admin paths work without it (CLI + Cloudflare Access). Tailscale enables mesh-VPN convenience but every surface keeps a non-Tailscale fallback.

## Auth patterns

### OIDC native

Apps with built-in OIDC support point at `https://auth.dunn.dev` and exchange auth codes for tokens. ID token carries `groups` claim for app-side authz.

Apps: Immich, Vaultwarden, Mealie, Audiobookshelf, BookLore, oCIS, Grafana, GitLab, Tailscale, vLLM (client-credentials variant).

### LDAPS

Jellyfin uses kanidm's built-in LDAPS server for the LDAP plugin. memberOf attribute drives Jellyfin admin role. No LDAP outpost worker (kanidm has LDAPS in the core).

### Forward auth (Caddy plugin)

Apps without native SSO are gated by Caddy. Per-service Caddyfile pattern:

```caddyfile
tune.dunn.dev {
  tls { dns cloudflare {env.CF_API_TOKEN} }

  # Native API bypass — Subsonic clients use HTTP Basic
  reverse_proxy /rest/* localhost:4533
  reverse_proxy /share/* localhost:4533

  # Web UI behind kanidm forward auth
  forward_auth https://auth.dunn.dev {
    uri /oauth2/forward_auth
    copy_headers X-Kanidm-Username X-Kanidm-Groups X-Kanidm-Email
    require_group access-tune
  }
  reverse_proxy localhost:4533
}
```

The `/oauth2/forward_auth` endpoint is the upstream contribution target. Until merged, the Caddy plugin handles OIDC client work in-process.

Apps: Navidrome, Gather (sonarr, radarr, sabnzbd, qbittorrent, prowlarr).

## Group model

Two types of groups, same as Authentik era:

**Identity groups** — who you are:
- admin
- family
- friends
- kids (deferred)

**Access groups** — what you can reach:
- access-keep (Vaultwarden)
- access-larder (Mealie)
- access-listen (Audiobookshelf)
- access-cinema (Jellyfin)
- access-tune (Navidrome)
- access-memory (Immich)
- access-vault (oCIS)
- access-gather (*arr stack)
- access-library (BookLore)
- access-llm (vLLM)

A user's tile launcher (home portal) renders only tiles for `access-*` groups they're members of. A user's app authz is enforced both at the proxy (forward-auth `require_group`) and at the app (OIDC `groups` claim check).

## Home portal three-state design

```
home.dunn.dev (Cloudflare Pages, edge-cached)

  on load: fetch /api/health (CF Worker reads kanidm /health from Workers KV)

  ├─→ kanidm unreachable  → STATE 1: status panel
  ├─→ no kanidm session    → STATE 2: passkey-prompt login
  └─→ valid session        → STATE 3: tile grid filtered by groups claim
```

Health-check loop: a Cloudflare Worker on a 30s cron pings kanidm `/health`, stores `{status, last_seen}` in Workers KV. Page reads KV via Worker route, never hits carmine directly. Edge-fast for visitors, doesn't hammer carmine during outage page-refresh storms.

## Custom Caddy image (`dunn.dev/caddy-estate`)

Built directly from upstream Caddy + plugin Go modules with `go build` (no xcaddy). Same pattern as basef builds ZFS and NVIDIA from source: pull the modules, write the entry point, link in one binary, no helper tool in the chain.

Modules:
- `github.com/caddyserver/caddy/v2` (core + standard modules)
- `github.com/caddy-dns/cloudflare` (DNS-01 ACME)
- forward-auth plugin selected based on the substrate decision

Same image is the sidecar for every app pod. One process per pod, one config syntax (Caddyfile), one image to maintain.

## Reversibility

If lab outcomes are red, the fallback is to stay with Authentik and apply the hardening package documented in the original evaluation. Bench infrastructure (GCP scripts, compose patterns, Caddyfile structure, Playwright contract) is reusable for either substrate. Sunk cost in the kanidm path: ~2-4 weeks of lab + research.
