# Deploy

Othala is **deployed by a separate vendor-pin config repo** (the deploy
plane), not from this repo. This document is the consumption contract:
the deploy shape, the promotion path, and the env/secret set. For what
the application *is* and the load-bearing decisions behind it, read
[`ARCHITECTURE.md`](ARCHITECTURE.md). For current release/version
state, read [`docs/STATUS.md`](docs/STATUS.md). This file does not
restate either.

Othala is "Ory for your home": a self-hosted Ory substrate for a
personal estate, the on-prem analog to Ory Network. The deployed
instance is **dag.dunn.dev** (dagaz ᛞ, the threshold rune); the login
screen renders ᛞ→ᛟ, "door to home" (dag→othala). In the deploy repo the instance
is grouped under **dag** (`services/dag/`, `dag-*` quadlets,
`dag.network`, `dag_*` sops keys); the functional Ory services keep
their role names (kratos / hydra / postgres).

## Getting started: two entry paths

**Option A — E2E smoke harness (`e2e/`):** The fastest way to validate
Othala locally against a running substrate, without a deploy repo or
sops. See `e2e/README.md` for env reference and smoke verification. The
harness runs the same Othala app image as production; the deploy plane's
differences are quadlets + sops, not the app itself.

**Option B — production deployment (the operator's deploy repo):** The
promotion path documented in the rest of this file. Vendor Othala
configs by tag-pin into your deploy repo, manage secrets with sops +
age, deploy via quadlets. Full details below.

---

## Deploy shape

One Othala pod on carmine, fronted by a Caddy edge. The containers:

| Quadlet | Image | Role |
|---|---|---|
| **dag-portal** | `registry.gitlab.com/dunn.dev/othala` | The converged Astro Node SSR app. Renders the Kratos self-service flows, serves the Hydra login/consent/logout challenge handlers, runs the access-gate, builds id_token claims, and hosts the loopback admin endpoints. See `ARCHITECTURE.md`. |
| **dag-ldap-bridge** | `registry.gitlab.com/dunn.dev/othala/ldap-bridge` | Go glauth-kratos LDAP bridge. Protocol adapter for non-OAuth native clients (Jellyfin / Apple TV). Stays Go by design. |
| **dag-kratos** | upstream Ory Kratos | Identity: self-service flows, sessions, recovery. |
| **dag-hydra** | upstream Ory Hydra | OAuth2/OIDC. Ships no UI by design; the Othala app is its login + consent provider. |
| **dag-postgres** | `postgres:18-alpine` | Separate `kratos` + `hydra` databases. |
| **dag-caddy** | `registry.gitlab.com/dunn.dev/caddy-estate` | TLS edge for `dag.dunn.dev`. Snippets are volume-mounted, not baked. |

> **Image name reconciled (Wave CP).** The converged app image
> publishes at the registry **root**:
> `registry.gitlab.com/dunn.dev/othala` (the oryd/kratos-style
> namespace/name shape, `publish_at_root: true` in `.gitlab-ci.yml`
> `build-othala`). The `dag-portal` quadlet pins this root path. The
> next published tag (`v0.2.0`) is the first to ship under the new name;
> the live pin reads `…/othala/portal:<tag>` only until that tag
> publishes.

### The dual-listener

The Othala container runs **two HTTP listeners in one process**
(`portal/src/server/listen.mjs`):

- **Public SSR port** (`PORT`, container default `8080`, bound on
  `HOST=0.0.0.0`). Serves the Astro handler: the Kratos self-service
  UIs, the family tile dashboard + `/auth/*` + `/admin/*` pages, and the
  OAuth2 challenge providers (`/oauth2/{login,consent,logout}`). This is
  the only handler reachable from the network. Caddy fronts this port.
- **Admin port** (`ADMIN_PORT`, container default `8431`, bound on
  `ADMIN_HOST=127.0.0.1`, loopback / pod-only). A separate
  `http.createServer` with its own disjoint mux: `GET /healthz`,
  `GET /readyz`, `POST /admin/revoke-user`, `POST /admin/recovery-gate`.
  It never delegates to the SSR handler, and the SSR handler never sees
  these paths. The admin surface is off the public mux **by
  construction**, not by routing rule.

Only the public port is `EXPOSE`d. The admin port stays on loopback
inside the pod. Both bearer-guarded admin routes are constant-time and
fail-closed (an unset secret rejects every request).

## Promotion path

There is **no submodule and no symlink**. The deploy repo vendors
Othala's authoritative configs as copies, each pinned to a released
Othala **tag** with a short provenance header. The promotion path is
edit, tag, sync, bump, deploy:

```sh
# 1. Tag this repo after CI publishes images.
git tag v0.1.X
git push --tags
# CI fires (.gitlab-ci.yml): the converged app publishes at the
# registry root, registry.gitlab.com/dunn.dev/othala:v0.1.X, and the
# LDAP bridge as registry.gitlab.com/dunn.dev/othala/ldap-bridge:v0.1.X.

# 2. Sync vendored configs into the deploy repo and review the drift.
# cd <your-deploy-repo>
make dag-sync-configs       # diff vendored configs vs othala HEAD
# Port desired changes manually, then bump each dag-* quadlet Image=
# pin + provenance SHA to v0.1.X.

# 3. Provision secrets (if new secrets were added).
make dag-secrets HOST=carmine

# 4. Pre-deploy validation, then deploy.
make dag-preflight HOST=carmine    # sops keys, registry images, drift, SSH
make dag-deploy HOST=carmine

# 5. Register OIDC clients (see "Client registration" below).
make dag-apply-clients HOST=carmine

# 6. Smoke.
make dag-smoke HOST=carmine
```

Rollback is purely a deploy-repo change: revert the quadlet commit
(re-pinning the previous tag) and `make dag-deploy` again. Registry
tags are immutable, so the rollback is deterministic.

## Environment and secrets

The Othala container's runtime env. The Ory upstream URLs are set by the
deploy quadlet (`KRATOS_PUBLIC_URL`, `KRATOS_ADMIN_URL`, `HYDRA_PUBLIC_URL`,
`HYDRA_ADMIN_URL`, `HYDRA_ISSUER_URL`); the listener ports default to
`PORT=8080` / `ADMIN_PORT=8431`. `MANIFEST_DIR` (default
`/etc/portal/manifests`) is the directory the app reads per-app manifests
from at runtime; the quadlet volume-mounts the synced manifest set there
read-only. The secrets are sops + age backed in the operator's
sops-encrypted secrets store under `carmine.dag_*` keys; the deploy
plane maps each `dag_*` key to the env target below:

| Env target | Guards / used by |
|---|---|
| `OTHALA_ADMIN_SUBJECTS` | The **sole admin authz**: an allowlist of admin emails. Checked at `requireAdminSession`, the recovery-gate, and the `/admin/*` page gates. The `admin` group is display-only. |
| `OTHALA_ADMIN_ENDPOINT_BEARER` | `POST /admin/revoke-user` on the loopback admin port. Constant-time, fail-closed. |
| `RECOVERY_GATE_SECRET` | `POST /admin/recovery-gate` (the Kratos recovery-hook). Constant-time, fail-closed. |
| `LDAP_BRIDGE_ADMIN_URL` / `LDAP_BRIDGE_ADMIN_TOKEN` | Best-effort LDAP bind-cache flush in the revoke fan-out. |
| `CSRF_SECRET` | CSRF token signing for the self-service flow posts. |

The old secrets are **gone**: `CONSENT_ADMIN_BEARER`, `CONSENT_ADMIN_URL`,
`KRATOS_BRIDGE_ADMIN_TOKEN`, and the overloaded `auth_internal_bearer` /
`dag_internal_bearer` are not part of the converged app. The revoke
fan-out is in-process; there is no app-to-consent admin HTTP hop.

Back-channel logout is **Hydra-native** (Hydra signs with its own key,
as it has since 2019). The app holds **no signing key at rest**; the
custom private-key signer was deleted.

## Client registration

OIDC client registration is a deliberate **one-shot**, never run on app
boot or triggered by a route. The deploy repo runs the registrar, e.g.
`make dag-apply-clients`, which invokes a `--rm` one-shot runner on
`dag.network` (the only network that can reach Hydra's admin port)
against the manifests synced into `MANIFEST_DIR`. See
[`docs/per-app-oidc.md`](docs/per-app-oidc.md) for the full per-RP
runbook.

The runner is the converged app's **in-app registrar**
(`portal/src/lib/register-clients.ts` driving the Hydra OAuth2Api, fed by
the `manifests.ts` parser + the full `validateClients` lint), bundled to
`dist/server/register-clients.mjs` and exercised in CI: the `e2e` harness
runs it as a `compose run --rm register-clients` one-shot against the
freshly-built image, reading each `<slug>.yaml` `oidc:` block from
`MANIFEST_DIR` and resolving `<SLUG>_CLIENT_SECRET` from env. The legacy
shell `apply-clients.sh` + Go `util` runner were retired at E1 (source
deleted).

## Deploy cutover (pending)

At the deploy cutover the convergence becomes additive: the legacy Go
consent service and the `util` runner are retired (their source dirs have
been deleted from this repo at E1), and the pod collapses to dag-portal
(the othala app) + dag-ldap-bridge + Ory. The cutover steps that touch
deploy:

- Drop `dag-consent` from the pod; remove `dag-portal`'s
  `After=` / `Requires=dag-consent` and its `CONSENT_ADMIN_BEARER` /
  consent-URL wiring.
- Wire the dual-listener admin port (`ADMIN_PORT=8431` on loopback) and
  the new admin env targets (`OTHALA_ADMIN_SUBJECTS`,
  `OTHALA_ADMIN_ENDPOINT_BEARER`, `RECOVERY_GATE_SECRET`) into the
  `dag-portal` quadlet.
- **Repoint the Kratos recovery-hook** from the old consent service to
  the Othala admin port `http://127.0.0.1:8431/admin/recovery-gate`,
  authenticated with `Bearer RECOVERY_GATE_SECRET`.
- **Regenerate secrets fresh** as `dag_*` sops keys. carmine is being
  reinstalled ahead of the cutover, so the secret material is generated
  fresh, not migrated from any prior instance.

Until the cutover, the deploy quadlets (`dag-*`) remain at the
pre-cutover shape (`dag-portal` still depends on `dag-consent`). The Go
consent + util sources have been removed from this repo at E1; their
behaviour lives in the converged app and they are not the current
architecture.

## Why two repos

`dunn.dev/othala` is the **application** and its authoritative configs.
The **deploy repo** is the operator concern: secrets, runtime topology,
sops + age, ZFS pools, every other host service. The deploy repo is the
primary deployment view; it vendors Othala's configs by tag-pin so the
open-sourceable application stays decoupled from private infrastructure
decisions. Othala versions independently; the Othala tag is what gets
pinned in the `dag-*` quadlets.

## Related docs

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — what the app is + load-bearing decisions (read this for the architecture; this file does not restate it)
- [`docs/STATUS.md`](docs/STATUS.md) — the only place release/version state is asserted
- [`docs/per-app-oidc.md`](docs/per-app-oidc.md) — per-RP OIDC integration runbook
- your deploy repo's docs — service-specific deploy notes and estate conventions
