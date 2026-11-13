# Deploy

[`deploy/example/`](deploy/example/) is a whole compose deployment.

## The seam

The image owns the Kratos and Hydra configs, identity schema, recovery-gate hook and courier defaults; the
`othala.caddy` snippets (`othala-routes`, `othala-forward-auth`, `othala-oidc-app`); the env names
(`portal/src/lib/env-names.ts`); the content layout; and the topology below.

The deployment owns `othala.env` (values), `secrets.env` (never committed), `content/`, a site Caddyfile
(addresses, TLS and DNS provider, `trusted_proxies`, `proxy_protocol`, listeners), its compose file or
units, and a Caddy build with `caddy-ratelimit` and its DNS provider's module.

Never: an extra Ory `--config` layer, any env on Kratos or Hydra (it overrides the rendered files, unseen by
`check`), edits to rendered output, copies of what the image carries, or renamed topology. A policy need
becomes a typed value in a release.

## Before the first enrolment

Three settings become commitments once anyone enrols a credential:

- **`OTHALA_PUBLIC_URL`**: Hydra's issuer. Every client's discovery and every issued token carry it.
- **`OTHALA_APEX`**: the Kratos cookie domain and the WebAuthn RP id, and the ceiling on which
  hostnames can share the session. Changing it invalidates every enrolled passkey.
- **Hydra's `subject_identifiers`**: `public` subjects mean the subject id is the identity id
  everywhere; switching to pairwise later changes every downstream app's notion of who a user is.

## The deployment directory

Copy the example, then edit `othala.env`, the Caddyfile and `content/` (`apps/`, `groups.yaml`, optional
`courier/<name>.gotmpl` replacing the shipped template of that name) before the rest runs:

```sh
cp -r deploy/example /srv/othala && cd /srv/othala && cp othala.env.example othala.env
IMAGE=registry.gitlab.com/dunn.dev/othala@sha256:<digest>   # the tag in compose.yml, plus its digest
(umask 077; docker run --rm -v "$PWD/content:/etc/othala:ro,z" "$IMAGE" node dist/server/config.mjs gen-secrets > secrets.env)
echo 'OTHALA_SMTP_CONNECTION_URI=smtps://user:pass@smtp.example.org:465' >> secrets.env
docker run --rm --env-file othala.env --env-file secrets.env -v "$PWD/content:/etc/othala:ro,z" "$IMAGE" node dist/server/config.mjs check
docker compose up -d
```

For an OIDC app added later, copy only its `<CLIENT_ID>_CLIENT_SECRET` line from a new `gen-secrets` run.

## The first admin

Registration is disabled, so a new stack has no identities and nobody can sign in. Make the first admin from the
console with the `admin` helper in [`docs/runbooks/admin-recovery.md`](docs/runbooks/admin-recovery.md#console-commands),
run from the compose directory. The marker goes on last, because the recovery gate refuses an identity that already
carries it.

1. Create the identity with no credentials and no marker. The traits are `username` and `email`; `groups` starts empty
   and the admin pages grant them later.

   ```sh
   admin identities POST '{"schema_id":"family","traits":{"username":"first.last","email":"you@example.org"},"metadata_admin":{"groups":[]},"verifiable_addresses":[{"value":"you@example.org","via":"email","verified":true,"status":"completed"}]}'
   ```

2. Issue a recovery code for the returned `id`, open `recovery_link` and enter `recovery_code`. In that session enrol
   what the runbook's first section lists: two passkeys, an authenticator app, backup codes and a security key.

   ```sh
   admin recovery/code POST '{"identity_id":"<id>","expires_in":"1h"}'
   ```

3. Set the marker, then sign in and open the admin pages.

   ```sh
   admin identities/<id> PATCH '[{"op":"add","path":"/metadata_admin/admin","value":true}]'
   ```

## Backups and break-glass

All identity state, every passkey and the Hydra clients included, is in the `postgres-data` volume; `secrets.env`
holds the keys that decrypt part of it. Back up both, together: [`docs/runbooks/postgres-backup.md`](docs/runbooks/postgres-backup.md)
says what and how to restore. The example runs no backup job. If an admin loses access,
[`docs/runbooks/admin-recovery.md`](docs/runbooks/admin-recovery.md) is the ladder, and
[`docs/runbooks/lost-device.md`](docs/runbooks/lost-device.md) is for a member's lost device.

## Your own Ory config

A deployment may own finished `kratos.yml` and `hydra.yml` instead of rendering them, with secrets as any
placeholder. The image's `contract/` pins only what the portal depends on; the identity schema and recovery-gate
hook must equal the image's copies. In CI, after every edit:

```sh
docker run --rm -v "$PWD/ory:/ory:ro,z" "$IMAGE" node dist/server/config.mjs check-ory \
  --kratos /ory/kratos.yml --hydra /ory/hydra.yml --identity-schema /ory/identity.schema.json --jsonnet /ory/recovery-gate.jsonnet
```

An env var or extra `-c` file overriding a contract key is the deployment's to keep right: `check-ory` cannot see it.
`check-ory` verifies the config meets what othala depends on; it does not review instance policy (return URLs, cookie scope, lifespans).
A placeholder may replace only the secret or instance part of a value; the `Bearer ` prefix and the URL paths stay literal. `kratos validate` stays the deployment's job.

## Startup order

The render runs first as uid 10000, the Kratos image's uid. Then come both migrate jobs, Kratos and Hydra
(neither Ory service migrates on startup), and the portal; Caddy waits only for the render.
With quadlets the render is a `Type=oneshot`, `RemainAfterExit=yes` unit writing a host tmpfs `/run/othala`; Kratos, Hydra, both migrate units and Caddy take `Requires=` and `After=` on it and mount `/run/othala/{kratos,hydra,caddy}` read-only at `/etc/config/kratos`, `/etc/config/hydra` and `/etc/caddy/othala`.

## Restart rules

- Image pin, `othala.env`, `secrets.env` or `courier/`: rerun the render and recreate what reads them:
  `docker compose up -d --force-recreate render kratos hydra othala caddy`.
  Under podman a repeated recreate can fail with "address already allocated"; `docker compose down` (volumes kept) then `up -d` clears it.
- `apps/` or `groups.yaml`: `docker compose kill -s SIGHUP othala`. The portal reloads and reconciles its Hydra
  clients.

## Validation

1. `check` runs offline over env names, the whole content tree and a render held in memory, so it reports every
   refusal `render` would make for the values it is given. It stands a placeholder in for any secret left unset and
   reports none missing, so run it with `--env-file secrets.env` as well to hold the real secrets to render's rules.
   Run `check --content <dir>` after every edit to `apps/`.
2. `render` checks only env names and `courier/`, so a bad app sidelines that app and never stops sign-in. It
   refuses a missing or blank secret, a leftover `${`, malformed YAML, a secret of the wrong length and a
   `KRATOS_COOKIE_SECRET_PREVIOUS` equal to its `_CURRENT`. A refusal exits 1 and leaves the last good render in place, so a restart
   still boots the earlier config; the migrate jobs and Caddy wait on the render and stay down until it succeeds.
   That protection holds for the example compose, whose render output lives in named volumes. A deployment that
   renders to tmpfs, or that ties services to the render with a hard dependency, loses it on reboot and should render
   to persistent storage. Only a write that fails partway empties the output. `portal/scripts/render.test.mjs` and
   `e2e/smoke.sh` (section I) pin it.
3. Kratos and Hydra validate their merged config at boot and refuse to start.
4. Caddy refuses an unknown directive or a missing module at boot.

## Topology

Fixed by the image:

| Alias | Port | Listener | Called by |
|---|---|---|---|
| `kratos` | 4433 | Kratos public | edge, portal |
| `kratos` | 4434 | Kratos admin, on `KRATOS_ADMIN_BIND_HOST` | portal |
| `hydra` | 4444 | Hydra public | edge |
| `hydra` | 4445 | Hydra admin, on `HYDRA_ADMIN_BIND_HOST` | portal |
| `othala` | 8080 | portal public | edge |
| `othala` | 4431 | portal admin: health and the Kratos webhooks, on `PORTAL_ADMIN_BIND_HOST` | Kratos |
| `postgres` | 5432 | the `kratos` and `hydra` databases | Kratos, Hydra |

The Kratos and Hydra admin APIs take no bearer: bind each to its address on a network the edge never joins,
resolve its alias to that address for its callers (`extra_hosts` in the example), and publish only the edge
([`ARCHITECTURE.md` § Trust boundary](ARCHITECTURE.md#trust-boundary)).
`internal: true` on that network is the boundary, rootful or rootless; podman needs 5.8 or later.

Browser clients on another origin are unsupported: Hydra's CORS allowlist is `OTHALA_PUBLIC_URL` only.

Both edge rate-limit zones key on `{client_ip}`: behind a load balancer, set `trusted_proxies_strict` beside
`trusted_proxies`, or a client picks its own address.

## Images

One othala image per release, signed by digest with keyless cosign. Pin tag and digest (`v*` tags are
protected, not immutable), and verify first:

```sh
cosign verify \
  --certificate-oidc-issuer https://gitlab.com \
  --certificate-identity-regexp '^https://gitlab\.com/dunn\.dev/othala//\.gitlab-ci\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  registry.gitlab.com/dunn.dev/othala@sha256:<digest>
```

Each release's `deploy/example/compose.yml` pins the upstream Ory digests its e2e ran; run those.

## Upgrading

1. Apply the release's "Config changes" from [`CHANGELOG.md`](CHANGELOG.md).
2. Move the othala, Kratos and Hydra pins to the release's example.
3. Before an Ory pin change, `just backup <dir>` (the compose file is an optional second argument, default `deploy/example/compose.yml`; a `pg_dump` of the kratos and hydra databases, as the backup runbook describes; `secrets.env` is yours to copy): Ory migrations are forward-only, so rolling back restores the dump. An
   othala-only rollback is a digest revert.
4. `docker compose up -d --force-recreate render kratos hydra othala caddy` (a plain `up -d` leaves them on pre-upgrade config); the migrate services run automatically via `depends_on`. Check the OIDC discovery document and a real login.
