# Architecture

Final shape after substrate evaluation. Authentik IDP, custom Caddy with cloudflare DNS-01, DNS-only Cloudflare in front, port-forward 443 on home router. No CF Tunnel, no CF Access, no third-party in the auth path.

## Production topology

```
internet
  │
  ↓
DNS lookup → Cloudflare DNS (gray cloud, no proxy)
  │
  ↓
home IP : 443 (port-forwarded on home router)
  │
  ↓
carmine
  ├─→ Envoy (L4 SNI router on 80/443)
  ├─→ per-pod Caddy sidecars (TLS via DNS-01 ACME, custom dunn.dev/caddy-estate image)
  ├─→ Authentik pod
  │     ├─ authentik-server (auth.dunn.dev)
  │     ├─ authentik-worker
  │     ├─ postgres
  │     └─ proxy outpost (used by tune, gather)
  ├─→ Jellyfin pod
  │     ├─ jellyfin
  │     └─ LDAP outpost (co-located, queries authentik-server over network)
  └─→ all other app pods (per-service users, rootless podman)

home.dunn.dev (Cloudflare Pages, edge-cached)
  └─→ three-state Astro app (pre-auth / post-auth tiles / infra-down)
       OIDC RP against Authentik
       Cloudflare Worker polls authentik /health, stores in Workers KV
```

Cloudflare's only roles: DNS hosting, DNS-01 ACME via API, hosting the home portal Astro on Pages. None of these are in the synchronous auth request path.

## Bootstrap order on carmine

1. carmine boots (bootc immutable image, ZFS pools imported, networking up)
2. **Authentik pod starts** — first auth-related service
3. Caddy sidecars obtain DNS-01 certs via Cloudflare API for `*.dunn.dev`
4. App pods come up as Authentik OIDC clients (or LDAP via outpost for Jellyfin)
5. Tailscale joins the mesh as an Authentik OIDC client (Tailscale's custom OIDC pattern with WebFinger)
6. home.dunn.dev (Cloudflare Pages) reachable from the internet directly; OIDC redirects to auth.dunn.dev work

Tailscale is not load-bearing. Admin paths work without it (basicauth gate at Caddy + Authentik OIDC + admin-MFA flow).

## Auth patterns

### OIDC native

Apps with built-in OIDC support point at `https://auth.dunn.dev/application/o/<slug>/.well-known/openid-configuration` and exchange auth codes for tokens. ID token carries `groups` claim for app-side authz.

Apps: Vaultwarden, Mealie, Audiobookshelf, Immich, BookLore, oCIS, Grafana, GitLab, vLLM (client-credentials variant), Tailscale.

Pattern (per-pod Caddyfile):

```caddyfile
keep.dunn.dev {
  tls { dns cloudflare {env.CF_API_TOKEN} }
  reverse_proxy vaultwarden:80
}
```

The app handles its own OIDC redirect; Caddy is a plain proxy.

### LDAP outpost (Jellyfin only)

Authentik LDAP outpost runs as a separate process. In production, the outpost is **co-located in the Jellyfin pod**: LDAP queries are localhost-to-localhost; the outpost queries back to authentik-server on the network for user data. Single source of truth (Authentik), local LDAP for Jellyfin's plugin.

Pattern:

```caddyfile
cinema.dunn.dev {
  tls { dns cloudflare {env.CF_API_TOKEN} }
  reverse_proxy jellyfin:8096
}
```

LDAP traffic is internal to the pod, doesn't traverse Caddy. Apple TV / Infuse SSO works through Jellyfin's LDAP plugin.

### Forward auth (Navidrome, Gather)

Caddy redirects unauthenticated traffic to the Authentik proxy outpost. The outpost validates the session and returns identity headers; Caddy passes those to the upstream app.

Pattern:

```caddyfile
tune.dunn.dev {
  tls { dns cloudflare {env.CF_API_TOKEN} }

  # Outpost endpoints (login, callback, sign-out)
  handle /outpost.goauthentik.io/* {
    reverse_proxy authentik-server:9000
  }

  # Native API bypass — Subsonic clients use HTTP Basic
  @subsonic path /rest/* /share/*
  handle @subsonic {
    reverse_proxy navidrome:4533
  }

  # Web UI: gated by Authentik forward-auth
  handle {
    forward_auth authentik-server:9000 {
      uri /outpost.goauthentik.io/auth/caddy
      copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid X-Authentik-Jwt
      trusted_proxies private_ranges
    }
    reverse_proxy navidrome:4533
  }
}
```

Same pattern for Sonarr, Radarr, sabnzbd, qbittorrent, prowlarr (all under `gather.dunn.dev` paths or per-subdomain).

### Admin path hardening

Admin paths (Authentik admin, Vaultwarden admin, GitLab admin, Grafana admin, Jellyfin admin, Immich admin) get a Caddy basicauth layer in addition to Authentik OIDC.

Pattern (Authentik admin shown; same shape for any admin path):

```caddyfile
auth.dunn.dev {
  tls { dns cloudflare {env.CF_API_TOKEN} }

  @admin path /if/admin/*
  handle @admin {
    basicauth {
      admin {env.ADMIN_BCRYPT_HASH}
    }
    reverse_proxy authentik-server:9000
  }

  reverse_proxy authentik-server:9000
}
```

64-char random password lives in Bitwarden. Bcrypt's natural CPU slowness is the brute-force cap.

For app-level admin paths (e.g., Grafana `/admin`, Immich `/admin`), the same pattern wraps the path matcher in the relevant pod's Caddyfile.

## Group model

| Type | Examples | Used for |
|---|---|---|
| Identity | admin, family, friends, kids | Who you are; controls Authentik admin panel access, recovery flows |
| Access | access-keep, access-larder, access-listen, access-cinema, access-tune, access-memory, access-vault, access-gather, access-library, access-llm | What you can reach; per-app authz |

Tile launcher in home.dunn.dev renders only tiles for `access-*` groups the user is a member of. Apps enforce authz both at the OIDC `groups` claim and at the proxy (forward-auth `trusted_proxies` + Authentik group membership policies).

## Home portal three-state design

```
home.dunn.dev (Cloudflare Pages, edge-cached)

  on load: fetch /api/health (CF Worker reads Authentik /health from Workers KV)

  ├─→ Authentik unreachable → STATE 1: status panel
  ├─→ no Authentik session  → STATE 2: passkey-prompt login (Sign In button → bounce)
  └─→ valid session         → STATE 3: tile grid filtered by groups claim
```

CF Worker pings Authentik `/health` on a 30s cron, stores `{status, last_seen}` in Workers KV. Astro page reads from KV at load time, not from carmine directly. Edge-fast for visitors, doesn't hammer carmine during family page-refresh storms.

## Reversibility

If Authentik's commercial trajectory degrades the free-tier offering meaningfully, the eval evidence in `lab/docs/eval-*.md` and `docs/substrate-comparison.md` becomes the playbook for the next move. kanidm is the documented fallback (with bus-factor and AI-ban tradeoffs accepted in exchange for substrate quality).
