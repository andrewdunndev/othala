# hydra

Ory Hydra server configuration.

## Files

| File | Purpose |
|---|---|
| `hydra.yml` | Server config: DSN, serve URLs, CORS, login/consent/logout URLs, TTLs, secrets, PKCE off |

OIDC client definitions are **not** stored here. Clients are unified `<slug>.yaml`
manifests read at runtime from `MANIFEST_DIR` (default `/etc/portal/manifests`).
Each manifest can carry `presentation:` (tile metadata), `oidc:` (forwarded to
Hydra), and `consent:` (role/claim shape read by the Othala app) blocks. A
manifest with only `presentation:` (forward-auth or LDAP tile, no Hydra client)
is skipped by the OIDC loader.

Generic worked examples live in [`e2e/manifests/`](../e2e/manifests/).

For the client catalog and per-RP integration details, see
[`docs/per-app-oidc.md`](../docs/per-app-oidc.md).

## Client registration

Registration is a deliberate one-shot, never triggered on app boot. On the
iac side `just dag-reload-clients` runs the Othala in-app registrar
(`portal/src/lib/register-clients.ts`, bundled to
`dist/server/register-clients.mjs`) as a `--rm` container on `dag.network`.
It reads each manifest's `oidc:` block from `MANIFEST_DIR` and resolves
`<SLUG>_CLIENT_SECRET` from env.

Full registration runbook: [`DEPLOY.md`](../DEPLOY.md) "Client registration"
and [`docs/per-app-oidc.md`](../docs/per-app-oidc.md).

Adding a new OIDC client: add a `<slug>.yaml` to your operator manifest
directory, add the sops secret, re-run `just dag-reload-clients`.

## secrets.system non-rotatable

`hydra.yml` references `${HYDRA_SYSTEM_SECRET}`. **Generate once. Store in
sops as `<host>.hydra_system_secret`. Never rotate without rebuilding the
Hydra database.** Break-glass rotation: `docs/runbooks/secrets-rotation.md`.

## Schema migrations

Hydra does not run schema migrations on startup. The iac quadlet stack and
the e2e compose stack both include a `hydra-migrate` init step
(`hydra migrate sql up -e --yes`) that runs before `hydra serve`.
