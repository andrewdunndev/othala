# caddy/snippets

Two named snippets, one per way an app sits behind Othala. Both take the
upstream as `{args[0]}:{args[1]}` (container name and port).

| Snippet | For an app that... |
|---|---|
| `oidc-app` | speaks OIDC itself; Caddy is only TLS + reverse proxy |
| `forward-auth` | has no usable SSO; Caddy `forward_auth` asks the portal to check the session and the required group (third argument) |

```caddyfile
import snippets/*.caddy

metrics.example.com {
	import oidc-app grafana 3000
}

listen.example.com {
	import forward-auth audiobookshelf 13378 audiobookshelf-access
}
```

Give each site block a concrete host: `forward-auth` builds the post-login
`return_to` from the request's scheme and host. `allowed_return_urls` in
`kratos/kratos.yml` is `https`-only, so an edge that sees plain `http` (TLS
terminated upstream) produces a value Kratos refuses, and the user lands on the
portal rather than back at the service.

`forward-auth` takes the required group as its third argument. A signed-in
member outside the group gets a 403 from the portal, returned as is; only a 401
redirects to login. Leaving the argument out is refused with 403, not allowed.
