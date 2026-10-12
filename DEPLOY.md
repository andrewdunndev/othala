# Deploy

[`deploy/example/`](deploy/example/) is a whole compose deployment; e2e runs it on every MR and tag.

## The seam

The image owns the Kratos and Hydra configs, identity schema, recovery-gate hook and courier defaults; the
`othala.caddy` snippets (`othala-routes`, `othala-forward-auth`, `othala-oidc-app`); the env names
(`RETIRED_NAMES` in `portal/src/lib/env-names.ts`); the content layout; and the topology below.

The deployment owns `othala.env` (values), `secrets.env` (never committed), `content/`, a site Caddyfile
(addresses, TLS and DNS provider, `trusted_proxies`, `proxy_protocol`, listeners), its compose file or
units, and a Caddy build with the `caddy-ratelimit` module and a DNS module for its provider.

Never: an extra Ory `--config` layer, any env on Kratos or Hydra (it overrides the rendered files, unseen by
`check`), edits to rendered output, copies of what the image carries, or renamed topology. A policy need
becomes a typed value in a release.

## The deployment directory

```sh
cp -r deploy/example /srv/othala && cd /srv/othala && cp othala.env.example othala.env   # then edit
IMAGE=registry.gitlab.com/dunn.dev/othala@sha256:<digest>   # the pin in compose.yml
docker run --rm -v "$PWD/content:/etc/othala:ro" "$IMAGE" node dist/server/config.mjs gen-secrets > secrets.env
echo 'OTHALA_SMTP_CONNECTION_URI=smtps://user:pass@smtp.example.org:465' >> secrets.env
docker run --rm --env-file othala.env -v "$PWD/content:/etc/othala:ro" "$IMAGE" node dist/server/config.mjs check
docker compose up -d
```

Then edit the Caddyfile and `content/` (`apps/`, `groups.yaml`, optional `courier/<name>.gotmpl` replacing the
shipped template of that name). For an OIDC app added later, copy only its `<CLIENT_ID>_CLIENT_SECRET` line
from a new `gen-secrets` run.

## Startup order

The render runs first, as uid 10000 (the Kratos and Hydra uid), then both migrate jobs, Kratos and Hydra, and
the portal; Caddy waits only for the render. Compose uses `service_completed_successfully`. With quadlets the
render is a `Type=oneshot`, `RemainAfterExit=yes` unit writing a host tmpfs `/run/othala`; Kratos, Hydra, both
migrate units and Caddy take `Requires=` and `After=` on it and mount `/run/othala/{kratos,hydra,caddy}`
read-only at `/etc/config/kratos`, `/etc/config/hydra` and `/etc/caddy/othala`.

## Restart rules

- Image pin, `othala.env`, `secrets.env` or `courier/`: rerun the render, then restart Kratos (it caches
  templates), Hydra and the portal: `docker compose up -d --force-recreate render kratos hydra othala`.
- `apps/` or `groups.yaml`: `docker compose kill -s SIGHUP othala`. The portal reloads and reconciles its Hydra
  clients (`registerAllClients`, `portal/src/lib/register-clients.ts`).

## Validation

1. `check` runs offline, without secrets, over env names and the whole content tree. Run `check --content <dir>`
   with the non-secret env in CI after every edit to `apps/`.
2. `render` checks only env names and `courier/`, so a bad app sidelines that app and never stops sign-in. It
   refuses a missing or blank secret, a leftover `${` and malformed YAML.
3. Kratos and Hydra validate their merged config at boot and refuse to start.
4. Caddy refuses an unknown directive or a missing module at boot.

## Topology

Fixed by the image (`portal/src/lib/constants.ts`, `PORT` and `ADMIN_PORT` in `portal/src/server/listen.ts`):

| Alias | Port | Listener | Called by |
|---|---|---|---|
| `kratos` | 4433 | Kratos public | edge, portal |
| `kratos` | 4434 | Kratos admin, on `KRATOS_ADMIN_BIND_HOST` | portal |
| `hydra` | 4444 | Hydra public | edge |
| `hydra` | 4445 | Hydra admin, on `HYDRA_ADMIN_BIND_HOST` | portal |
| `othala` | 8080 | portal public | edge |
| `othala` | 4431 | portal admin: health and the Kratos webhooks, on `PORTAL_ADMIN_BIND_HOST` | Kratos |
| `postgres` | 5432 | the `kratos` and `hydra` databases | Kratos, Hydra |

The admin APIs take no bearer: bind each to its address on a network the edge never joins, resolve its alias
to that address for its callers (`extra_hosts` in the example), and publish only the edge
([`ARCHITECTURE.md` § Trust boundary](ARCHITECTURE.md#trust-boundary)).

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

Kratos and Hydra are upstream Ory images. Each release's `deploy/example/compose.yml` pins the digests its e2e
ran; run those.

## Upgrading

1. Apply the release's "Deployment changes" from [`CHANGELOG.md`](CHANGELOG.md).
2. Move the othala pin, and the Kratos and Hydra pins to the release's example.
3. Before an Ory pin change, `pg_dump`: Ory migrations are forward-only, so rolling back restores the dump. An
   othala-only rollback is a digest revert.
4. `docker compose up -d`; check `/readyz` on the admin port, the OIDC discovery document and a real login.
