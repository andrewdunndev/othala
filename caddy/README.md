# caddy

Auth-specific Caddyfile snippets for the dunn.dev estate's universal
Caddy sidecar.

The Caddy image is built and published by a separate repo:

- Source: <https://gitlab.com/dunn.dev/caddy-estate>
- Registry: `registry.gitlab.com/dunn.dev/caddy-estate:latest`
- Pinned to UBI 9 micro runtime via `dunn.dev/pipeline` catalog 2.3.1+.

Caddy is built from upstream Caddy + the `caddy-dns/cloudflare`
plugin (DNS-01 ACME for `*.dunn.dev`). Forward-auth uses Caddy's
built-in `forward_auth` directive against Kratos `/sessions/whoami`,
no plugin needed.

## Snippets

The `snippets/` directory holds auth-specific Caddyfile patterns
that get volume-mounted into the Caddy sidecar at deploy time:

| Snippet | Purpose |
|---|---|
| `oidc-app.caddy` | OIDC-native app per-host config |
| `ldap-app.caddy` | LDAP-bound app (Jellyfin) plain reverse proxy |
| `forward-auth.caddy` | Caddy `forward_auth` against Kratos `/sessions/whoami` |
| `admin-session.caddy` | Auth admin path with AAL2 enforcement at SSR |
| `portal.caddy` | Home portal Caddyfile chunk |

See `../ARCHITECTURE.md` ("Auth patterns") for how each pattern composes
into the per-app Caddyfiles in production.
