# caddy — integration example

How to put an app behind Othala's Kratos session using
[Caddy](https://caddyserver.com)'s built-in `forward_auth` directive.

This directory is a **reference for adopters**, not deploy config. Othala
does not ship or run a Caddy container — these are copy-and-adapt patterns
you drop into your own reverse proxy in front of your own apps.

## What it shows

- **Gating an app with no native SSO** behind a Kratos session, using
  Caddy's built-in [`forward_auth`](https://caddyserver.com/docs/caddyfile/directives/forward_auth)
  directive against Kratos `/sessions/whoami`. **No Caddy plugins are
  required for the auth path** — `forward_auth` ships with stock Caddy.
- **TLS via DNS-01 ACME** using the
  [`caddy-dns/cloudflare`](https://github.com/caddy-dns/cloudflare) plugin.
  This is the one plugin the example assumes, and only for certificate
  issuance. Swap it for any other DNS provider, an HTTP-01 solver, or
  upstream TLS termination — the `forward_auth` patterns are unaffected.

## Files

| File | What it is |
|---|---|
| `Caddyfile` | A worked top-level Caddyfile for a single Othala instance: how to route the Kratos browser surface, the Hydra OAuth2 surface, and the app itself behind one hostname. |
| `snippets/` | Reusable, generic Caddyfile snippets for the two ways an app sits behind Othala. Each `*.caddy` file defines one named snippet (parens syntax, e.g. `(forward-auth)`) that a top-level Caddyfile imports with `import <name> <args>`: `oidc-app` (OIDC-native app, plain reverse proxy), `forward-auth` (no native SSO, gated by Caddy `forward_auth` against the Kratos session). |

The snippets are written generically — `kratos:4433`,
`{env.OTHALA_PUBLIC_URL}`, and `{args[0]}:{args[1]}` backends — so you
import them and pass your own container name and port. Nothing here is
hard-coded to a specific deployment.

See [`../ARCHITECTURE.md`](../ARCHITECTURE.md) ("The forward-auth request
path") for how each pattern fits the overall Othala topology.
