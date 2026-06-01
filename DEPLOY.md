# Deploy

This project is **deployed by `dunn.dev/iac`**, not from this repo.
This document is the consumption contract: the deploy shape, the
promotion path, and the env/secret set. For what the application *is*
and the load-bearing decisions behind it, read
[`ARCHITECTURE.md`](ARCHITECTURE.md). For current release/version
state, read [`docs/STATUS.md`](docs/STATUS.md). This file does not
restate either.

## Deploy shape

One auth pod on carmine, fronted by a Caddy edge. The containers:

| Container | Image | Role |
|---|---|---|
| **auth** | `registry.gitlab.com/dunn.dev/othala/auth` | The converged Astro Node SSR app. Renders Kratos self-service flows, serves the Hydra login/consent/logout challenge handlers, runs the access-gate, builds id_token claims, and hosts the loopback admin endpoints. See `ARCHITECTURE.md`. |
| **ldap-bridge** | `registry.gitlab.com/dunn.dev/othala/ldap-bridge` | Go glauth-kratos LDAP bridge. Protocol adapter for non-OAuth clients (Jellyfin native, Apple TV). Stays Go by design. |
| **kratos** | upstream Ory Kratos | Identity (self-service flows, sessions, recovery). |
| **hydra** | upstream Ory Hydra | OAuth2/OIDC. Ships no UI; the auth app is its login+consent provider. |
| **postgres** | `postgres:18-alpine` | Separate `kratos` + `hydra` databases. |
| **caddy** | `registry.gitlab.com/dunn.dev/caddy-estate` | TLS edge for `dag.dunn.dev`. Snippets are volume-mounted, not baked. |

> **Image rename in flight.** The converged app image is named **auth**.
> The repo still builds it as `portal` today (`.gitlab-ci.yml`
> `build-portal`, image tag `portal`); the rename to `auth` happens in
> Wave CP, just after this doc lands. Until that tag publishes, the
> live pin is still `…/auth/portal:<tag>`. Name the target **auth**.

### The dual-listener

The auth container runs **two HTTP listeners in one process**
(`portal/src/server/listen.mjs`):

- **Public SSR port** (`PORT`, container default `8080`, bound on
  `0.0.0.0`). Serves the Astro handler: the Kratos self-service UIs,
  the family UI + `/auth/*` + `/admin/*` pages, and the OAuth2
  challenge providers (`/oauth2/{login,consent,logout}`). This is the
  only handler reachable from the network. Caddy fronts this port.
- **Admin port** (`ADMIN_PORT`, container default `8431`, bound on
  `ADMIN_HOST=127.0.0.1`, loopback / pod-only). A separate server with
  its own disjoint mux: `GET /healthz`, `GET /readyz`,
  `POST /admin/revoke-user`, `POST /admin/recovery-gate`. It never
  delegates to the SSR handler, and the SSR handler never sees these
  paths. The admin surface is off the public mux **by construction**,
  not by routing rule.

Only the public port is `EXPOSE`d. The admin port stays on loopback
inside the pod.

## Promotion path

There is **no submodule and no symlink**. iac vendors auth's
authoritative configs as copies, each pinned to a released auth **tag**
with a short provenance header. The promotion path is edit, tag, sync,
bump, deploy:

```sh
# 1. Tag this repo after CI publishes images.
git tag v0.1.X
git push --tags
# CI fires (.gitlab-ci.yml): images publish to
# registry.gitlab.com/dunn.dev/othala/<name>:v0.1.X
# (auth/ldap-bridge; rename to auth lands in Wave CP).

# 2. Sync vendored configs into iac and bump the pins.
cd dunn.dev/iac
make auth-sync-configs
# Review the diff; port desired changes manually.
# Bump quadlet Image= pins + provenance SHA to v0.1.X.

# 3. Provision secrets (if new secrets were added).
make auth-secrets HOST=carmine

# 4. Deploy.
make auth-deploy HOST=carmine

# 5. Register OIDC clients (see "Client registration" below).
make auth-apply-clients HOST=carmine

# 6. Smoke.
make auth-smoke HOST=carmine
```

Rollback is purely an iac change: revert the quadlet commit (re-pinning
the previous `v0.1.X-1` tag) and `make auth-deploy` again. Registry
tags are immutable, so the rollback is deterministic.

## Environment and secrets

The auth container's runtime env. The Ory upstream URLs are set by the
iac quadlet (`KRATOS_PUBLIC_URL`, `KRATOS_ADMIN_URL`,
`HYDRA_PUBLIC_URL`, `HYDRA_ADMIN_URL`, `HYDRA_ISSUER_URL`); the listener
ports default to `PORT=8080` / `ADMIN_PORT=8431`. The secrets, all
sops-backed in `dunn.dev/iac/pyinfra/secrets.enc.yaml`:

| Secret | Guards / used by |
|---|---|
| `OTHALA_ADMIN_SUBJECTS` | The **sole admin authz**: an allowlist of admin emails. Checked at `requireAdminSession`, the recovery-gate, and the `/admin/*` page gates. The `admin` group is display-only. |
| `OTHALA_ADMIN_ENDPOINT_BEARER` | `POST /admin/revoke-user` on the loopback admin port. Constant-time, fail-closed. |
| `RECOVERY_GATE_SECRET` | `POST /admin/recovery-gate` (the Kratos recovery-hook). Constant-time, fail-closed. |
| `LDAP_BRIDGE_ADMIN_URL` / `LDAP_BRIDGE_ADMIN_TOKEN` | Best-effort LDAP bind-cache flush in the revoke fan-out. |
| `CSRF_SECRET` | CSRF token signing for the self-service flow posts. |

The old secrets are **gone**: `CONSENT_ADMIN_BEARER`,
`CONSENT_ADMIN_URL`, `KRATOS_BRIDGE_ADMIN_TOKEN`, and the overloaded
`auth_internal_bearer` are not part of the converged app. The revoke
fan-out is in-process; there is no portal-to-consent admin HTTP hop.

Back-channel logout is **Hydra-native** (Hydra signs with its own key).
The app holds **no signing key at rest**; the custom private-key signer
was deleted.

## Client registration

OIDC client registration is **shell-driven today**:
`make auth-apply-clients` runs `util/apply-clients.sh` in the `auth-util`
one-shot container against Hydra's admin API. See
[`docs/per-app-oidc.md`](docs/per-app-oidc.md) for the full per-RP
runbook.

The repo also carries an all-TS successor (`portal/src/lib/manifests.ts`
parser + `register-clients.ts` via the Hydra OAuth2Api, plus the full
`validateClients` lint). It is **dormant**: not yet wired live, and it
does **not** supersede `apply-clients.sh` until the E1 cutover.

## E1 cutover (pending)

At the iac E1 cutover the convergence becomes additive: the legacy Go
consent service and the `util` runner are retired, and the auth pod
collapses to auth + ldap-bridge + Ory. The cutover steps that touch
deploy:

- Drop `auth-consent` from the pod; remove `auth-portal`'s
  `After=/Requires=auth-consent` and its `CONSENT_ADMIN_URL` /
  `auth_internal_bearer` wiring.
- Add the dual-listener admin port and its three new secrets
  (`OTHALA_ADMIN_SUBJECTS`, `OTHALA_ADMIN_ENDPOINT_BEARER`,
  `RECOVERY_GATE_SECRET`) to the quadlet.
- **Repoint the Kratos recovery-hook** from the old consent service
  (`consent:4478`) to the auth admin port
  `http://127.0.0.1:8431/admin/recovery-gate`, authenticated with
  `Bearer RECOVERY_GATE_SECRET`.

Until E1, the iac quadlets remain at the pre-cutover shape (auth-portal
still depends on auth-consent). The Go consent + util sources still
exist in-tree, **legacy-pending-removal**, and are not the current
architecture.

## Why two repos

`dunn.dev/othala` is the **application** and its authoritative configs.
`dunn.dev/iac` is the **operator concern**: secrets, runtime topology,
sops, ZFS pools, every other carmine service. iac vendors auth's
configs by tag-pin so the open-sourceable application stays decoupled
from private infrastructure decisions. The auth repo versions
independently; the auth tag is what gets pinned in iac quadlets.

## Related docs

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — what the app is + load-bearing decisions (read this for the architecture; this file does not restate it)
- [`docs/STATUS.md`](docs/STATUS.md) — the only place release/version state is asserted
- [`docs/per-app-oidc.md`](docs/per-app-oidc.md) — per-RP OIDC integration runbook
- `dunn.dev/iac/services/auth/README.md` — service-specific deploy notes (in iac)
- `dunn.dev/iac/AGENTS.md` — iac estate conventions
