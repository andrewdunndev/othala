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

OIDC client definitions are **not** stored here. Clients are unified `<slug>.yaml`
manifests read at runtime from `MANIFEST_DIR` (default `/etc/portal/manifests`).
Each manifest can carry `presentation:` (tile metadata **and the access
binding**), `oidc:` (forwarded to Hydra), and `consent:` (role/claim shape read
by the Othala app) blocks. A manifest with only `presentation:` (a forward-auth
tile, no Hydra client) is skipped by the OIDC loader.

The two group-facing fields do different jobs and are not interchangeable:
`presentation.access:` lists the group(s) that grant **entry** to the app, and
`consent.group_role_map:` maps a group to a **role** inside it. A role mapping
never admits anyone; see [`docs/access-model.md`](../docs/access-model.md).

Generic worked examples live in [`e2e/manifests/`](../e2e/manifests/).

For the client catalog and per-RP integration details, see
[`per-app-oidc.md`](../site/src/content/docs/guides/per-app-oidc.md).

## Client registration

Registration is a deliberate one-shot, never triggered on app boot. On the
deployment side, the operator invokes the Othala in-app registrar
(`portal/src/lib/register-clients.ts`, bundled to
`dist/server/register-clients.mjs`) as a one-shot `--rm` container on `dag.network`.
It reads each manifest's `oidc:` block from `MANIFEST_DIR` and resolves
`<SLUG>_CLIENT_SECRET` from env.

Full registration runbook: [`DEPLOY.md`](../DEPLOY.md) "Client registration"
and [`per-app-oidc.md`](../site/src/content/docs/guides/per-app-oidc.md).

Adding a new OIDC client: add a `<slug>.yaml` to the manifest directory, add
the sops secret, re-run `just dag-reload-clients`.

## secrets.system non-rotatable

`hydra.yml` references `${HYDRA_SYSTEM_SECRET}`. **Generate once. Store in
sops as `<host>.hydra_system_secret`. Never rotate without rebuilding the
Hydra database.** Break-glass rotation: `docs/runbooks/secrets-rotation.md`.

## Schema migrations

Hydra does not run schema migrations on startup. The production quadlet stack and
the e2e compose stack both include a `hydra-migrate` init step
(`hydra migrate sql up -e --yes`) that runs before `hydra serve`.
