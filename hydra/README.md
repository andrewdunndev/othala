# hydra

Ory Hydra configuration + OIDC client catalog.

## Files

| File | Purpose |
|---|---|
| `hydra.yml` | Server config: DSN, serve URLs, CORS, login/consent/logout URLs (point at dag.dunn.dev per Topology B v0.2.0), TTLs, secrets, PKCE off |
| `clients/*.yaml` | One YAML per OAuth2/OIDC client. Each has `oidc:` (forwarded to Hydra) and `consent:` (read by the othala app for role/claim emission) namespace blocks. |

Client registration: the legacy `apply-clients.sh` / `util/` runner was
retired at E1 (source deleted). The in-app successor is
`portal/src/lib/register-clients.ts`. The live deploy-side registration
path is documented in `DEPLOY.md` ("Client registration").

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
| `tailscale` | Tailscale | authorization_code | NO PKCE; WebFinger served at dunn.dev apex (Cloudflare Pages function — see `docs/apex-webfinger-followup.md`) |
| `llm` | vLLM | client_credentials | Machine-to-machine; Caddy validates bearer via Hydra introspect |

Forward-auth-only apps (Navidrome, *arr stack) do **not** have Hydra clients — their auth is via Caddy `forward_auth` against Kratos `/sessions/whoami` directly. They DO have entries in the tile dashboard (`portal/src/content/apps/<slug>.md`) so the family launcher knows they exist.

## skip_consent

Every client manifest sets `skip_consent: true`. The 11 OIDC clients listed above don't render a consent screen. The consent handler service reads this flag and auto-accepts. New clients (anything not in `clients/`) get the standard consent screen.

## secrets.system non-rotatable

`hydra.yml` references `${HYDRA_SYSTEM_SECRET}`. **Generate once. Store in sops as `carmine.hydra_system_secret`. Never rotate without rebuilding the Hydra database.** Documented at the top of `hydra.yml`. Break-glass rotation procedure in `docs/runbooks/secrets-rotation.md`.

## Schema migrations

Hydra does not run schema migrations on startup. The iac quadlet stack and the lab compose stack both include a `hydra-migrate` init step (`hydra migrate sql up -e --yes`) that runs before `hydra serve`. Forgetting this is a documented foot-gun.

## Apply order (production)

1. Postgres up
2. `hydra migrate sql up` (creates schema)
3. Hydra serve up
4. Consent + portal up
5. `make auth-apply-clients HOST=carmine` (iac wrapper around the `auth-util` image's `apply-clients` command — registers OIDC clients in Hydra)

Each app's `<APP>_CLIENT_SECRET` env var is sourced from sops by iac. The util image receives the secrets as env vars at `podman run` time. Adding a new OIDC consumer is: add the YAML here, add the sops entry, re-run `make auth-apply-clients`.
