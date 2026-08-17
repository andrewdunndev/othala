# caddy/snippets — reusable patterns

Four named Caddyfile snippets, one per way an app can sit behind Othala.
Copy them; nothing here is tied to a particular deployment. The three that
proxy take the upstream as `{args[0]}:{args[1]}`, so you pass your own
container name and port at import time. `admin-session` takes no arguments and
proxies nothing (see below).

| Snippet | For an app that… |
|---|---|
| `oidc-app` | speaks OIDC itself — Caddy is only TLS + reverse proxy |
| `ldap-app` | binds to the LDAP bridge instead — also only TLS + reverse proxy |
| `forward-auth` | has no SSO you want to use — Caddy's built-in `forward_auth` checks the Kratos session first |
| `admin-session` | exposes an admin path needing *a* session; AAL2 step-up stays at the app's SSR layer |

Only `forward-auth` and `admin-session` involve Kratos at request time. The
one plugin any of them assume is `caddy-dns/cloudflare`, and only for DNS-01
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

`oidc-app`, `ldap-app`, and `forward-auth` proxy to the upstream themselves.
`admin-session` deliberately does not — it gates the request and leaves the
site block to add its own `reverse_proxy`, so you can gate one path of an app
you route several ways.

Give each site block a concrete host. `forward-auth` and `admin-session`
build the post-login `return_to` from the request's own scheme and host, and
a site block with a real host address is what pins that host down.
`allowed_return_urls` in `kratos/kratos.yml` is the backstop — and because
those entries are `https`-only, an edge that sees plain `http` (TLS
terminated somewhere upstream) produces a value Kratos refuses, and the user
lands on the portal rather than back at the service.
