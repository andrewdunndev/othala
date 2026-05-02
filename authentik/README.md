# authentik

Authentik configuration as IaC. Blueprints define everything Authentik knows about: flows, stages, groups, scope mappings, providers, applications. Same blueprints run in the lab and in production.

## Layout

| Path | Contents |
|---|---|
| `blueprints/00-custom-scopes.yaml` | Custom OIDC scope mappings (e.g., `email_verified` for apps that require it) |
| `blueprints/01-flows-authentication.yaml` | Authentication flow: identification → password/passkey → MFA → user_login |
| `blueprints/02-groups.yaml` | Identity groups (admin, family, friends) and access groups (access-keep, access-larder, etc.) |
| `blueprints/03-test-users.yaml` | Test users for the lab. Production deploy substitutes real users (secrets injected from Bitwarden). |
| `blueprints/04-brand.yaml` | dunn.dev branding: logo, colors, custom CSS, default flow binding |
| `blueprints/apps/*.yaml` | One blueprint per OIDC client + access policy (keep, larder, listen, cinema, tune, memory) |

## Outpost shape (production)

Authentik supports outposts: separate processes that present a specific protocol (LDAP, proxy/forward-auth) backed by the central Authentik instance. The decision document (`../docs/decision.md`) calls for:

- **LDAP outpost co-located in the Jellyfin pod.** LDAP queries from Jellyfin to localhost; the outpost queries back to Authentik over the network. Single source of truth (Authentik), local LDAP for the Apple TV / Infuse path.
- **Proxy outpost for forward-auth.** Used by Navidrome and the Gather (sonarr/radarr/etc) stack. Caddy directs unauthenticated requests through the outpost.

Outpost configurations are managed via the Authentik admin UI or API, not blueprints.

## Conventions

- Blueprint filenames are `NN-purpose.yaml` (numbered for clear ordering during apply)
- Per-app blueprints under `apps/<slug>.yaml` create one OAuth2 provider, one application, and one access-group policy binding
- All client_id values are short slug names matching the subdomain (`keep`, `larder`, etc.)
- Scope mappings include `email_verified: true` for apps that reject logins without it (since Authentik 2025.10 stopped emitting this by default)

## Conventions: subdomain naming

| Subdomain | App | Pattern |
|---|---|---|
| auth | Authentik | (the IDP) |
| keep | Vaultwarden | OIDC |
| larder | Mealie | OIDC |
| listen | Audiobookshelf | OIDC |
| cinema | Jellyfin | LDAP outpost |
| tune | Navidrome | forward auth |
| memory | Immich | OIDC |
| vault | oCIS | OIDC |
| gather | sonarr/radarr/qbit/sabnzbd/prowlarr | forward auth |
| library | BookLore | OIDC |
| forge | GitLab | OIDC |
| observe | Grafana | OIDC |
| llm | vLLM | OAuth2 client_credentials |
| home | home portal (Cloudflare Pages) | OIDC RP |
