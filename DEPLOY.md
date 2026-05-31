# Deploy

This project is **deployed by `dunn.dev/iac`**, not from this repo.
This document is the bidirectional pointer; once you've read it, jump
to `dunn.dev/iac/services/auth/` for the runtime configuration that
actually lands on carmine.

For the full vendor-pin model and the decision record, see
[`ARCHITECTURE.md`](ARCHITECTURE.md) LB-12.

## Promotion path

To ship a change from this repo to production:

```sh
# 1. Tag this repo after CI publishes images.
git tag v0.1.X
git push --tags
# CI fires; consent/portal/ldap-bridge/util images publish to
# registry.gitlab.com/dunn.dev/auth/<name>:v0.1.X

# 2. Sync vendored configs into iac.
cd dunn.dev/iac
make auth-sync-configs
# Review the diff; port desired changes manually.
# Bump provenance SHA + quadlet Image= pins to v0.1.X.

# 3. Provision secrets (if new secrets were added).
make auth-secrets HOST=carmine

# 4. Deploy.
make auth-deploy HOST=carmine

# 5. Apply OIDC clients.
make auth-apply-clients HOST=carmine

# 6. Smoke.
make auth-smoke HOST=carmine
```

## What lives where

| Concern | Lives in | Why |
|---|---|---|
| Application code (consent, ldap-bridge, portal) | `dunn.dev/auth/{consent,ldap-bridge,portal}` | This is the application |
| Container images (consent, portal, ldap-bridge, util) | `registry.gitlab.com/dunn.dev/auth/{consent,portal,ldap-bridge,util}` | Built by `.gitlab-ci.yml` here |
| OIDC client manifests | `dunn.dev/auth/hydra/clients/*.yaml` | Single source; consent + portal + util consume |
| Identity schema | `dunn.dev/auth/kratos/identity.schema.json` | Single source; vendored COPY in `iac/services/auth/kratos/`, pinned to a released auth tag, with a 3-line provenance header |
| Production Kratos config | `dunn.dev/auth/kratos/kratos.yml` | Single authoritative file; vendored COPY in `iac/services/auth/kratos/`, pinned to a released auth tag, with a 3-line provenance header. DSN host + admin host + consent host are env-substituted (`${KRATOS_PG_HOST}` etc.) so the same file works in both topologies. |
| Production Hydra config | `dunn.dev/auth/hydra/hydra.yml` | Same shape as kratos.yml; vendored COPY in `iac/services/auth/hydra/`, pinned to a released auth tag, with a 3-line provenance header. `${HYDRA_PG_HOST}` substitutes. |
| LDAP bridge config | `dunn.dev/auth/ldap-bridge/glauth.cfg` | Single source; vendored COPY in `iac/services/auth/ldap-bridge/`, pinned to a released auth tag, with a 3-line provenance header. `public_url_env` / `admin_url_env` carry the topology delta (lab: `kratos`; production: `auth-kratos`). |
| Postgres init script | `dunn.dev/auth/lab/compose/postgres-init.sh` | Single source, including the defensive `CREATE EXTENSION "uuid-ossp"`. Vendored COPY in `iac/services/auth/postgres/`, pinned to a released auth tag, with a 3-line provenance header. |
| Container quadlets | `dunn.dev/iac/services/auth/.config/containers/systemd/` | The deploy plane owns runtime topology |
| pyinfra orchestration | `dunn.dev/iac/pyinfra/hosts/carmine.py` `SERVICES["auth"]` | Same |
| Secrets (sops) | `dunn.dev/iac/pyinfra/secrets.enc.yaml` | Single source for both this stack and every other carmine service |
| Tile-dashboard apps registry | `dunn.dev/auth/portal/src/content/apps/*.md` | Astro Content Collection; portal reads at runtime |
| Deploy runbook | `dunn.dev/iac/AGENTS.md` + `dunn.dev/iac/DEPLOY.md` | Same |

## Why two repos

`dunn.dev/auth` is the **application**; the team contributing back to
Ory/glauth would extract this repo (or a subset) as the open-source
contribution. `dunn.dev/iac` is the **operator concern** -- secrets,
runtime topology, sops, ZFS pools, every other service that runs on
carmine. Mixing them would couple the open-sourceable application to
the operator's private infrastructure decisions.

## Versioning

`dunn.dev/auth` versions independently of `dunn.dev/iac`. The auth-repo
tag is what gets pinned in iac quadlets. Renovate watches the auth
registry images and proposes bumps in iac.

## Rollback

`make auth-deploy` rolls the substrate. To roll back: revert the iac
quadlet commit (re-pinning the previous v0.1.X-1 tag), `make auth-deploy`
again. Image tags are immutable in the registry; the rollback is purely
an iac change.

`secrets.system` rotation is **NOT** part of normal deploy. See
`docs/runbooks/secrets-rotation.md` for the break-glass procedure.

## Related docs

- `dunn.dev/auth/docs/STATUS.md` -- current release + open items
- `dunn.dev/auth/ARCHITECTURE.md` -- load-bearing decisions map + substrate topology + request flows (for new operators or LLMs picking up this codebase cold)
- `dunn.dev/auth/docs/golden-path.md` -- integration choices that keep us durable on Ory upgrades
- `dunn.dev/iac/AGENTS.md` -- iac estate conventions
- `dunn.dev/iac/services/auth/README.md` -- service-specific deploy notes (in iac)
