# caddy/snippets — reusable patterns

Two named Caddyfile snippets, one per way an app can sit behind Othala.
Copy them; nothing here is tied to a particular deployment. Both take the
upstream as `{args[0]}:{args[1]}`, so you pass your own container name and
port at import time.

| Snippet | For an app that… |
|---|---|
| `oidc-app` | speaks OIDC itself — Caddy is only TLS + reverse proxy |
| `forward-auth` | has no SSO you want to use — Caddy's built-in `forward_auth` checks the Kratos session first |

Only `forward-auth` involves Kratos at request time. The
one plugin either assumes is `caddy-dns/cloudflare`, and only for DNS-01
TLS — swap that block for whatever issues your certificates.

## Importing

`import` the files once, then invoke the snippet inside each site block:

```caddyfile
import snippets/*.caddy

metrics.example.com {
	import oidc-app grafana 3000
}

listen.example.com {
	import forward-auth audiobookshelf 13378
}
```

Give each site block a concrete host. `forward-auth`
builds the post-login `return_to` from the request's own scheme and host, and
a site block with a real host address is what pins that host down.
`allowed_return_urls` in `kratos/kratos.yml` is the backstop — and because
those entries are `https`-only, an edge that sees plain `http` (TLS
terminated somewhere upstream) produces a value Kratos refuses, and the user
lands on the portal rather than back at the service.
