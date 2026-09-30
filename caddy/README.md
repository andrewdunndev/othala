# caddy: integration example

Reference for adopters, not deploy config: Othala does not ship or run Caddy.
Copy and adapt these patterns for putting an app behind Othala's Kratos session
with Caddy's stock [`forward_auth`](https://caddyserver.com/docs/caddyfile/directives/forward_auth)
(no plugins on the auth path). The one assumed plugin is
[`caddy-dns/cloudflare`](https://github.com/caddy-dns/cloudflare), for DNS-01
TLS only; swap it for any other issuer.

| File | What it is |
|---|---|
| `Caddyfile` | Worked top-level Caddyfile for one Othala instance: Kratos browser surface, Hydra OAuth2 surface and the app behind one hostname. |
| `snippets/` | Generic `oidc-app` and `forward-auth` snippets; see its README. |

See [`../ARCHITECTURE.md`](../ARCHITECTURE.md) ("The forward-auth request
path") for how each pattern fits the topology.
