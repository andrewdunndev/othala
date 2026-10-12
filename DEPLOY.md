# Deploy

Othala ships one container image; a deploy plane is the operator-owned config,
secrets and runtime topology around it. This is the consumption contract: what a
deploy plane must provide. Design decisions are in [`ARCHITECTURE.md`](ARCHITECTURE.md),
version state in [`CHANGELOG.md`](CHANGELOG.md) and git tags.

## Getting started: two entry paths

**Option A, the E2E smoke harness (`e2e/`):** validates Othala locally with no
deploy plane, running the same app image as production. See `e2e/README.md`.

**Option B, a real deploy plane:** vendor Othala's configs by tag-pin, supply the
env contract below, and run the containers however your platform does (quadlets,
compose, Kubernetes).

## Images

One image per release, tagged at the git tag and published at the registry
root (`registry.gitlab.com/dunn.dev/othala:vX.Y.Z`, `publish_at_root: true`
in `.gitlab-ci.yml`). Pin by tag and digest: `v*` registry tags are protected, not immutable. Kratos
and Hydra are upstream Ory images this repo does not build.

Each release image is signed by digest with keyless cosign, from the tag
pipeline's GitLab identity. Verify before pinning:

```sh
cosign verify \
  --certificate-oidc-issuer https://gitlab.com \
  --certificate-identity-regexp '^https://gitlab\.com/dunn\.dev/othala//\.gitlab-ci\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  registry.gitlab.com/dunn.dev/othala@sha256:<digest>
```

## The dual-listener

Expose only the public port, `8080`. The admin port, `4431`, stays on the
internal network; publishing it anywhere reachable from outside the pod or
host breaks the trust boundary
([`ARCHITECTURE.md` § Trust boundary](ARCHITECTURE.md#trust-boundary)).

## Vendored configs and the drift-check obligation

These files are byte-canonical here and must be vendored **verbatim**, not
hand-edited, by any deploy plane: `kratos/kratos.yml`, `hydra/hydra.yml`,
`kratos/identity.schema.json`, `kratos/hooks/recovery-gate.jsonnet`, and the
mail templates in `kratos/courier/`. The recovery gate (`docs/runbooks/admin-recovery.md` § 3) assumes these bytes:
byte-diff them against the pinned ref on every promotion, and port any diff
upstream, never patch locally.

`node dist/server/config.mjs render`, run from the othala image, supplies the
`${VAR}` values; that is not divergence. Render each `kratos/courier/*.gotmpl` to the same file name and
mount the directory at `/etc/config/kratos/courier/`, or code emails fail at send.

## Environment contract

[`.env.example`](.env.example) is the full, authoritative variable list. This
section covers only what needs context beyond that file:

- Service names (`kratos`, `hydra`, `postgres`, `othala`), ports and the Ory
  admin URLs are fixed, and the admin APIs take no bearer: the network is the
  control. A deploy plane mounts its manifests at `/etc/portal/manifests`.
- `KRATOS_ADMIN_BIND_HOST`, `HYDRA_ADMIN_BIND_HOST` and `PORTAL_ADMIN_BIND_HOST` have no production default; the Ory render refuses empty binds, the portal wildcards too. Bind each to an internal-network address the edge cannot reach.
- The breach check is always on: an HIBP outage blocks setting a password (registration, settings, after recovery); admin-API and shell break-glass paths still work.
- Secrets come from the deploy plane's secret store, never the image.
- Admin authority is deliberately **not** an env target: it is the
  `metadata_admin.admin` marker on the Kratos identity
  (`docs/runbooks/admin-recovery.md` § 2). An env var admin allowlist reintroduces the
  bypass this design avoids.

## Client registration

The app registers OIDC clients itself: `portal/src/server/registrar.ts` runs
`registerAllClients` (`portal/src/lib/register-clients.ts`) on boot and on SIGHUP
against Hydra's admin port. See
[`per-app-oidc.md`](site/src/content/docs/guides/per-app-oidc.md).

## Promotion path

1. Tag this repo after CI publishes images (`git tag vX.Y.Z && git push
   --tags`).
2. The deploy plane re-vendors the configs under *Vendored configs* at
   the new ref and reviews what changed.
3. Bump the pinned image tag/digest for the app, plus Kratos/Hydra if their
   pins changed.
4. Provision any new secrets, then deploy.
5. SIGHUP the app if manifests changed (previous section).
6. Smoke: `/healthz`, `/readyz`, and the OIDC discovery document all
   answer; a real login round-trips.

Kratos and Hydra migrations are forward-only: `pg_dump` before any deploy that
changes an Ory pin, and roll back across that change by restoring the dump. An
app-only rollback is a digest revert.
