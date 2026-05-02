# lab

GCP-based test environment for SSO pattern validation. Spins up Authentik + app stubs on a single VM, applies the blueprints from `../authentik/blueprints/`, runs Playwright tests against the auth flows.

Replaces the prior `dunn.dev/bench-sso-iac` repo.

## Quick start

```bash
# Set required env vars (see .env.example in repo root)
cp ../.env.example .env
# Edit .env with GCP project, domain, Cloudflare API token, Authentik secrets

# Build the custom Caddy image locally (or load on VM during deploy)
make caddy-image

# Provision GCP VM (~2 min)
make up

# Update DNS (Cloudflare *.test.dunn.dev → VM IP, gray cloud)
make dns-update   # prints the record to add

# Sync files to VM
make sync

# Wait for auto-deploy (Authentik bootstrap + blueprints)
make deploy

# Smoke tests
make smoke

# Playwright (from your dev machine)
make test

# Tear down
make down
```

## What's tested

| Pattern | Apps |
|---|---|
| OIDC native | Vaultwarden (keep), Mealie (larder), Audiobookshelf (listen), Immich (memory) |
| LDAP outpost | Jellyfin (cinema) |
| Forward auth via Authentik proxy outpost | Navidrome (tune) with Subsonic API bypass |
| Admin path basicauth | Authentik admin (`/if/admin/*`) |

## Layout

| Path | Contents |
|---|---|
| `compose/compose.yml` | Authentik server + worker + postgres + Caddy + app stubs |
| `compose/Caddyfile` | Caddy config with DNS-01 + admin basicauth + forward-auth pattern |
| `compose/jellyfin-ldap.xml` | Pre-seeded Jellyfin LDAP plugin config |
| `scripts/gcp.sh` | GCP VM lifecycle (up, down, ssh, ip, scp) |
| `scripts/setup-vm.sh` | VM startup script (installs podman, clones repo, writes .env) |
| `scripts/deploy.sh` | Compose stack startup + blueprint wait + token generation |
| `scripts/smoke.sh`, `smoke-local.sh` | Smoke tests |
| `scripts/configure-apps.sh` | Per-app post-deploy configuration (Audiobookshelf, Immich OIDC) |
| `scripts/set-passwords.sh` | Set test user passwords via Authentik API |
| `tests/` | Playwright suite (auth flows, app reachability, group access) |
| `Makefile` | Lab targets: up/down/sync/deploy/smoke/test/logs |
| `docs/` | Per-candidate substrate evaluations (eval-*.md) — historical research |

## Bench → carmine production

Blueprints in `../authentik/blueprints/` are reused identically. Production carmine runs Authentik via pyinfra-managed quadlets; the same blueprints applied via the same volume mount. Caddy patterns under `../caddy/snippets/` are referenced by per-pod Caddyfiles in carmine's `services/<app>/caddy/Caddyfile`.

What changes lab → production:
- Domain: `test.dunn.dev` → `dunn.dev`
- Secrets: Bitwarden-injected, not env defaults
- Container runtime: rootless podman quadlets (per-service users), not docker-compose
- LDAP outpost: co-located in Jellyfin pod (in production), runs alongside authentik-server (in lab compose)
- Proxy outpost: dedicated quadlet (in production), runs alongside authentik-server (in lab compose)
