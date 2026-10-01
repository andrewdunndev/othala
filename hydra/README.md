# hydra

Ory Hydra server configuration in `hydra.yml`.

## CORS allowlist

`serve.public.cors.allowed_origins` is `OTHALA_PUBLIC_URL`. Browser clients on
another origin are unsupported.

## Clients

Client definitions are not stored here. Each manifest's `oidc:` block is
registered on boot and on SIGHUP, with `<SLUG>_CLIENT_SECRET`
from env; a manifest with only `presentation:` is skipped. See
["An app is a manifest"](../README.md#an-app-is-a-manifest),
[`e2e/manifests/`](../e2e/manifests/) for annotated examples,
[`DEPLOY.md`](../DEPLOY.md) "Client registration" and
[`per-app-oidc.md`](../site/src/content/docs/guides/per-app-oidc.md).

## secrets.system non-rotatable

`hydra.yml` references `${HYDRA_SYSTEM_SECRET}`. **Generate once. Store in
sops as `<host>.hydra_system_secret`. Never rotate without rebuilding the
Hydra database.** Break-glass rotation: `docs/runbooks/secrets-rotation.md`.

## Schema migrations

Hydra does not migrate on startup. The production quadlet stack and the e2e
compose stack run a `hydra-migrate` init step (`hydra migrate sql up -e --yes`)
before `hydra serve`.
