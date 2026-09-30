# hydra

Ory Hydra server configuration in `hydra.yml`.

## CORS allowlist

`serve.public.cors.allowed_origins` is rendered from `OTHALA_CORS_ALLOWED_ORIGINS`
(comma-separated, unquoted origins). A browser-SPA client fetches
`/.well-known/openid-configuration` and `/oauth2/token` from its own origin, so
that origin has to be listed; server-side clients need no entry. With no
browser-SPA client, this is just `OTHALA_PUBLIC_URL`.

## Clients

Client definitions are not stored here. Each manifest's `oidc:` block is
registered from `MANIFEST_DIR` on boot and on SIGHUP, with `<SLUG>_CLIENT_SECRET`
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
