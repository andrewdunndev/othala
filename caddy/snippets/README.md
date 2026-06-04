# caddy/snippets — reusable patterns

Generic Caddyfile snippets for the four ways an app can sit behind Othala.
Each `*.caddy` file defines a named snippet (parens syntax, e.g.
`(forward-auth)`) that a top-level Caddyfile imports with
`import <name> <args>`.

These are an **integration reference for adopters to copy**, not deploy
config. They are deliberately generic: `kratos:4433` for the Kratos public
API, `{env.OTHALA_PUBLIC_URL}` for the login redirect, and
`{args[0]}:{args[1]}` for the upstream backend. Pass your own container
name and port at import time.

The **Apps** column below lists how the maintainer's instance
(`dag.dunn.dev`) uses each pattern — a worked example, not a requirement.

| Snippet | Use case | Apps (example) |
|---|---|---|
| `oidc-app` | OIDC-native app, plain reverse proxy | Vaultwarden, Mealie, Audiobookshelf, Immich, oCIS, BookLore, GitLab, Grafana |
| `ldap-app` | App with an LDAP plugin, plain reverse proxy (LDAP traffic goes pod-internal to the bridge) | Jellyfin |
| `forward-auth` | App without native SSO, gated by Caddy `forward_auth` → Kratos session | Navidrome, Sonarr, Radarr, qBittorrent, sabnzbd, Prowlarr |
| `admin-session` | Admin path: requires a Kratos session (any AAL); AAL2 step-up enforced at the app's SSR layer | `<host>/admin/*` |

The headline pattern is `forward-auth`: it uses Caddy's **built-in**
`forward_auth` directive (no plugin) to verify a Kratos session before
proxying. The only plugin any of these assume is `caddy-dns/cloudflare`,
and only for DNS-01 TLS — see `../README.md`.

## Putting it together

A top-level Caddyfile imports the snippets it needs, then references them
per host:

```caddyfile
import oidc-app.caddy
import ldap-app.caddy
import forward-auth.caddy
import admin-session.caddy

keep.example.com {
    import oidc-app vaultwarden 80
}

cinema.example.com {
    import ldap-app jellyfin 8096
}

tune.example.com {
    # Bypass SSO for API paths whose clients use HTTP Basic, not a session
    @api path /rest/* /share/*
    handle @api {
        reverse_proxy navidrome:4533
    }
    # Web UI: forward-auth via Kratos
    handle {
        import forward-auth navidrome 4533
    }
}
```

## A note on rate limiting

The snippets assume a Caddy build with a single plugin —
`caddy-dns/cloudflare` for DNS-01 ACME — and **no** `caddy-ratelimit`. The
reasoning, if you're deciding whether to add it:

- Bcrypt's natural CPU cost is the primary brute-force defense on auth paths.
- For DDoS-style spam, Caddy's built-in connection limits are sufficient at
  household/family scale.
- A separate plugin adds attack surface and a second maintenance vector.

If a specific attack surfaces that warrants it, add the plugin then — not
by default.
