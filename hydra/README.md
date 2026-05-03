# hydra

Ory Hydra configuration as IaC.

## Files

| File | Purpose |
|---|---|
| `hydra.yml` | Server config: DSN, serve URLs, CORS, login/consent/logout URLs (point at home.dunn.dev), TTLs, secrets, PKCE off |
| `clients/*.yaml` | One YAML per OAuth2/OIDC client. Each maps to a `hydra create oauth2-client` invocation. |
| `apply-clients.sh` | Apply all client manifests to a running Hydra (idempotent: creates new, updates existing). |

## Clients shipped

| client_id | App | Grant | Notes |
|---|---|---|---|
| `keep` | Vaultwarden | authorization_code | OIDC standard |
| `larder` | Mealie | authorization_code | OIDC standard |
| `listen` | Audiobookshelf | authorization_code | OIDC standard, mobile redirect |
| `cinema` | Jellyfin | authorization_code | Web only; native clients use LDAP via the bridge |
| `memory` | Immich | authorization_code | Web + iOS app |
| `vault` | oCIS | authorization_code | OIDC standard |
| `library` | BookLore | authorization_code | OIDC standard |
| `forge` | GitLab | authorization_code | OIDC standard |
| `observe` | Grafana | authorization_code | OIDC standard |
| `tailscale` | Tailscale | authorization_code | NO PKCE; WebFinger served at home.dunn.dev |
| `llm` | vLLM | client_credentials | Machine-to-machine; Caddy validates bearer via Hydra introspect |

Forward-auth-only apps (Navidrome, *arr stack) do **not** have Hydra clients — their auth is via Caddy `forward_auth` against Kratos `/sessions/whoami` directly. The home portal itself is a Kratos consumer (session reader), not a Hydra OAuth2 client.

## skip_consent

Every client manifest sets `skip_consent: true`. The 16 trusted apps don't render a consent screen. The consent handler service on carmine reads this flag and auto-accepts. New clients (anything not in `clients/`) get the standard consent screen.

## secrets.system non-rotatable

`hydra.yml` references `${HYDRA_SYSTEM_SECRET}`. **Generate once. Store in Bitwarden. Never rotate without rebuilding the Hydra database.** Documented at the top of `hydra.yml`.

## Schema migrations

Hydra does not run schema migrations on startup. The lab compose stack and production pyinfra both include a `hydra-migrate` init step (`hydra migrate sql up -e --yes`) that runs before `hydra serve`. Forgetting this is a documented foot-gun.

## Apply order

1. Postgres up
2. `hydra migrate sql up` (creates schema)
3. Hydra serve up
4. `apply-clients.sh` (creates/updates OAuth2 clients)

Each app's `<APP>_CLIENT_SECRET` env var must be set in the operator's environment before running `apply-clients.sh`. Secrets are sourced from Bitwarden via `make <app>-secrets` in production.
