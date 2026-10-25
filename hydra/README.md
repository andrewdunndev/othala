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
[`e2e/content/apps/`](../e2e/content/apps/) for annotated examples,
[`per-app-oidc.md`](../site/src/content/docs/guides/per-app-oidc.md).

## secrets.system

`hydra.yml` references `${HYDRA_SYSTEM_SECRET}`. Generate once and keep it in your
secret store. Othala renders a single slot, so changing it rebuilds the Hydra database:
`docs/runbooks/secrets-rotation.md`.

## Schema migrations

Hydra does not migrate on startup. Deployments and the e2e
compose stack run a `hydra-migrate` init step (`hydra migrate sql up -e --yes`)
before `hydra serve`.
