# hydra

Ory Hydra server configuration.

## Files

| File | Purpose |
|---|---|
| `hydra.yml` | Server config: DSN, serve URLs, CORS, login/consent/logout URLs, TTLs, secrets, PKCE off |

## CORS allowlist

`serve.public.cors.allowed_origins` is rendered from `OTHALA_CORS_ALLOWED_ORIGINS`
(comma-separated, unquoted origins), not hardcoded to one origin. A browser-SPA
client fetches `/.well-known/openid-configuration` and `/oauth2/token` from its
own origin, so that origin has to be allowlisted; redirect-flow (server-side)
clients never browser-fetch Hydra and need no entry. With no browser-SPA client
deployed, this is just `OTHALA_PUBLIC_URL`.

OIDC client definitions are **not** stored here — see ["An app is a
manifest"](../README.md#an-app-is-a-manifest) for the three blocks. A manifest with only
`presentation:` (a forward-auth tile, no Hydra client) is skipped by the OIDC loader.
[`e2e/manifests/grafana.yaml`](../e2e/manifests/grafana.yaml) and
[`e2e/manifests/audiobookshelf.yaml`](../e2e/manifests/audiobookshelf.yaml) are the annotated spec for
every field, including the `presentation.access:` (entry) vs `consent.group_role_map:` (role) split;
`validateClients` (`../portal/src/lib/manifests.ts`) and `../portal/src/lib/manifest-lint.ts` are what
is enforced.

For the client catalog and per-RP integration details, see
[`per-app-oidc.md`](../site/src/content/docs/guides/per-app-oidc.md).

## Client registration

The Othala app registers each manifest's `oidc:` block from `MANIFEST_DIR` on
boot and on SIGHUP, resolving `<SLUG>_CLIENT_SECRET` from env.

Full registration runbook: [`DEPLOY.md`](../DEPLOY.md) "Client registration"
and [`per-app-oidc.md`](../site/src/content/docs/guides/per-app-oidc.md).

Adding a new OIDC client: add a `<slug>.yaml` to the manifest directory, add
the secret, and SIGHUP the app.

## secrets.system non-rotatable

`hydra.yml` references `${HYDRA_SYSTEM_SECRET}`. **Generate once. Store in
sops as `<host>.hydra_system_secret`. Never rotate without rebuilding the
Hydra database.** Break-glass rotation: `docs/runbooks/secrets-rotation.md`.

## Schema migrations

Hydra does not run schema migrations on startup. The production quadlet stack and
the e2e compose stack both include a `hydra-migrate` init step
(`hydra migrate sql up -e --yes`) that runs before `hydra serve`.
