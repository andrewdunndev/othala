# caddy/snippets

Reusable Caddyfile patterns. Each `*.caddy` file defines a snippet (named with parens, e.g., `(oidc-app)`) that production per-app Caddyfiles import via `import <name> <args>`.

| Snippet | Use case | Apps |
|---|---|---|
| `oidc-app` | OIDC-native app, plain reverse proxy | Vaultwarden, Mealie, Audiobookshelf, Immich, oCIS, BookLore, GitLab, Grafana |
| `ldap-app` | App with LDAP plugin, plain reverse proxy (LDAP traffic goes pod-internal to bridge) | Jellyfin |
| `forward-auth` | App without native SSO, gated by Caddy forward_auth → Kratos session | Navidrome, Sonarr, Radarr, qBittorrent, sabnzbd, Prowlarr |
| `admin-session` | Admin path: requires Kratos session (any AAL); AAL2 step-up enforced at SSR | auth.dunn.dev/admin/* |

## Per-app Caddyfile pattern

```caddyfile
import oidc-app.caddy
import ldap-app.caddy
import forward-auth.caddy
import admin-session.caddy

keep.dunn.dev {
    import oidc-app vaultwarden 80
}

cinema.dunn.dev {
    import ldap-app jellyfin 8096
}

tune.dunn.dev {
    # Subsonic API bypass: native clients use HTTP Basic, no SSO check
    @subsonic path /rest/* /share/*
    handle @subsonic {
        reverse_proxy navidrome:4533
    }
    # Web UI: forward-auth via Kratos
    handle {
        import forward-auth navidrome 4533
    }
}
```

## Why no rate-limit plugin

The custom Caddy image (`dunn.dev/caddy-estate`) ships with one plugin: `caddy-dns/cloudflare` for DNS-01 ACME. We deliberately don't include `caddy-ratelimit` because:

- Bcrypt's natural CPU cost is the primary brute-force defense on auth paths
- For DDoS-style spam, Caddy's built-in connection limits are sufficient at family scale
- A separate plugin adds attack surface and a second maintenance vector

If a specific attack surfaces in production that warrants rate limiting, we add the plugin then; not by default.
