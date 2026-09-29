# Deploy

Othala ships one container image; a deploy plane is the operator-owned
config, secrets, and runtime topology that turns that image into a running
instance. This document is the consumption contract: what a deploy plane
must provide, not how any particular one provides it. For what the
application *is* and the load-bearing decisions behind it, read
[`ARCHITECTURE.md`](ARCHITECTURE.md). For release/version state, read
[`CHANGELOG.md`](CHANGELOG.md) and git tags. This file does not restate
either.

## Getting started: two entry paths

**Option A — E2E smoke harness (`e2e/`):** The fastest way to validate
Othala locally against a running substrate, without any deploy plane. See
`e2e/README.md` for env reference and smoke verification. The harness runs
the same app image production would; a deploy plane's job is the topology
and secrets around it, not a different app.

**Option B — a real deploy plane:** vendor Othala's configs by tag-pin,
supply the env contract below, and run the containers however your
platform runs containers. The contract is the same regardless of mechanism
— quadlets, compose, Kubernetes.

## Images

One image per release, tagged at the git tag and published at the registry
root (`registry.gitlab.com/dunn.dev/othala:vX.Y.Z`, `publish_at_root: true`
in `.gitlab-ci.yml`). A deploy plane pins by tag or digest; registry tags
are immutable, so pinning by tag is already deterministic. Kratos and Hydra
are upstream Ory images — this repo does not build or publish them.

## The dual-listener

The app runs **two HTTP listeners in one process**
(`portal/src/server/listen.mjs`):

- **Public SSR port** (`PORT`, default `8080`, `HOST=0.0.0.0`). The Astro
  handler: Kratos self-service UIs, the family tile dashboard, `/auth/*` +
  `/admin/*` pages, and the OAuth2 challenge providers
  (`/oauth2/{login,consent,logout}`). The only port a deploy plane should
  expose to the network.
- **Admin port** (`ADMIN_PORT`, default `4431`, `ADMIN_HOST=127.0.0.1`,
  loopback only). A separate `http.createServer` with its own disjoint mux:
  `GET /healthz`, `GET /readyz`, `POST /admin/revoke-user`,
  `POST /admin/{recovery,login-code}-gate`. It never delegates to the SSR
  handler, which never sees these paths — off the public mux **by
  construction**, not by routing rule. The bearer-guarded routes are
  constant-time and fail-closed: an unset secret rejects every request.

A deploy plane that publishes the admin port to the network, or to any
network segment reachable from outside the pod/host, has broken the trust
boundary this app is built around (`ARCHITECTURE.md` § Trust boundary).

## Vendored configs and the drift-check obligation

Four files are byte-canonical here and must be vendored **verbatim**, not
hand-edited, by any deploy plane: `kratos/kratos.yml`, `hydra/hydra.yml`,
`kratos/identity.schema.json`, and `kratos/hooks/recovery-gate.jsonnet`. A
deploy plane that diverges from these has diverged from behavior this repo
tests and documents — the gate handler's own guarantees (Section 3 of
`docs/runbooks/admin-recovery.md`), the identity schema, and the recovery
flow config all assume these bytes. Run a byte-diff check against the
pinned Othala ref on every promotion; treat any diff as something to port
upstream to this repo, never a local patch.

Topology values inside those files (service hostnames, bind addresses) are
expected to be templated (`${ENV}` substitution or equivalent) and
supplied by the deploy plane at render time — that is not divergence.

## Environment contract

[`.env.example`](.env.example) is the full, authoritative variable list —
every var the app reads, annotated. This section covers only what needs
context beyond that file:

- The Ory upstream URLs (`KRATOS_PUBLIC_URL`, `KRATOS_ADMIN_URL`,
  `HYDRA_PUBLIC_URL`, `HYDRA_ADMIN_URL`, `HYDRA_ISSUER_URL`) and the
  listener ports are set by the deploy plane, not baked into the image.
- `MANIFEST_DIR` (default `/etc/portal/manifests`) is the directory the app
  reads per-app manifests from at runtime. A deploy plane mounts its
  synced manifest set there, read-only.
- `KRATOS_ADMIN_BIND_HOST` and `HYDRA_ADMIN_BIND_HOST` have no default: bind each to an address on the internal network the edge is not attached to.
- With `OTHALA_HIBP_ENABLED=true`, an HIBP outage blocks setting a password (registration, settings, the password step after recovery); admin-API and shell break-glass paths are unaffected.
- Secrets come from whatever secret store the deploy plane uses (sops,
  Vault, a platform's native secret objects) — never committed, never baked
  into the image.
- Admin authority is deliberately **not** an env target: it is the
  `metadata_admin.admin` marker on the Kratos identity
  (`docs/runbooks/admin-recovery.md` § 2). A deploy plane that adds an env
  var admin allowlist has reintroduced the exact bypass this design avoids.

## Client registration

The app registers OIDC clients itself: `portal/src/server/registrar.ts` runs
`registerAllClients` (`portal/src/lib/register-clients.ts`, fed by the
`manifests.ts` parser and the full `validateClients` lint) on boot and on
SIGHUP against Hydra's admin port. See
[`per-app-oidc.md`](site/src/content/docs/guides/per-app-oidc.md) for the
full per-RP runbook.

## Promotion path

1. Tag this repo after CI publishes images (`git tag vX.Y.Z && git push
   --tags`).
2. The deploy plane re-vendors the four config files (previous section) at
   the new ref and reviews what changed.
3. Bump the pinned image tag/digest for the app, plus Kratos/Hydra if their
   pins changed.
4. Provision any new secrets, then deploy.
5. SIGHUP the app if manifests changed (previous section).
6. Smoke: `/healthz`, `/readyz`, and the OIDC discovery document all
   answer; a real login round-trips.

Rollback is purely a deploy-plane change: revert to the previous pinned
tag and redeploy. Registry tags are immutable, so rollback is
deterministic.

## Why two repos

`dunn.dev/othala` is the **application** and its authoritative configs. The
deploy plane is the operator concern: secrets, runtime topology, storage,
every other host service. It vendors Othala's configs by tag-pin so the
open-sourceable application stays decoupled from private infrastructure
decisions. Othala versions independently of any instance running it.

## Related docs

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — what the app is + load-bearing
  decisions (this file does not restate it)
- [`CHANGELOG.md`](CHANGELOG.md) and git tags — the only place
  release/version state is asserted
- [`per-app-oidc.md`](site/src/content/docs/guides/per-app-oidc.md) —
  per-RP OIDC integration runbook
- [`docs/runbooks/admin-recovery.md`](docs/runbooks/admin-recovery.md) —
  the admin-authority model and the recovery ladder
- `portal/src/lib/gate.ts` — how entry and role are decided (the model the
  manifests express)
