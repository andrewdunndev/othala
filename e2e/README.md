# Othala end-to-end harness

`docker compose` stack (Postgres, Kratos, Hydra, the othala app, Mailpit) plus a
smoke matrix and Playwright specs. It is the release gate and a worked adopter
example: the same `compose.yml` and `validate.sh` run in CI and on a workstation.
Topology, ports and the check sequence are in the headers of `compose.yml`,
`validate.sh` and `smoke.sh`. There is no TLS or Caddy in the smoke path.

## Run the smoke matrix

```sh
# Requires: podman, docker-compose-compat or podman-compose
cd e2e
AUTH_VERSION=latest bash validate.sh
```

## Running the browser e2e locally (macOS/podman)

The browser profile adds Caddy and a Playwright container.

### Prerequisites

- podman + podman-machine running (`podman machine start` if not)
- docker-compose shim wired to the podman socket (see below)

### Build the othala image from current source

Build from current source; a stale image gives false results.

```sh
# from the repo root
podman build -t registry.gitlab.com/dunn.dev/othala:lab \
  -f portal/Containerfile .
```

Export `AUTH_VERSION=lab` (and `AUTH_REGISTRY=registry.gitlab.com/dunn.dev/othala`)
before the compose commands below.

### Start the stack

```sh
export DOCKER_HOST="unix://$(podman machine inspect \
  --format '{{.ConnectionInfo.PodmanSocket.Path}}')"
export AUTH_REGISTRY=registry.gitlab.com/dunn.dev/othala
export AUTH_VERSION=lab

cd e2e
bash ./gen-secrets.sh > .env
set -a; source ./.env; set +a

bash ../scripts/render-config.sh ../kratos/kratos.yml kratos.rendered.yml
bash ../scripts/render-config.sh ../hydra/hydra.yml   hydra.rendered.yml
chmod 0644 kratos.rendered.yml hydra.rendered.yml

# Base stack (smoke services, with the Caddy edge)
docker-compose --env-file=.env up -d

# Browser run: compose.browser.yml recreates othala with PORTAL_ADMIN_BIND_HOST on a static IP
docker-compose -f compose.yml -f compose.browser.yml \
  --profile browser --env-file=.env up -d --no-deps othala
```

### Run the browser specs

The Playwright container runs inside the compose network (same subnet as
the services) using the official arm64-compatible image:

```sh
NET=$(docker-compose --env-file=.env \
  -f compose.yml -f compose.browser.yml \
  ps -q othala 2>/dev/null | \
  xargs -I{} docker inspect {} --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' \
  | head -1)

# If NET detection is fiddly, use the compose project name:
# NET=$(docker-compose config --format json | jq -r '.name')_default

podman run --rm --platform linux/arm64 \
  --network "$NET" \
  -v "$PWD":/test -w /test \
  -e PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
  -e BASE=http://auth.othala.test \
  -e RECOVERY_ADMIN_EMAIL=admin.recovery@othala.test \
  -e MAILPIT_API=http://mailpit:8025 \
  -e OTHALA_ADMIN_URL=http://othala:4431 \
  -e RECOVERY_GATE_SECRET="$RECOVERY_GATE_SECRET" \
  -e GRAFANA_CLIENT_SECRET="$GRAFANA_CLIENT_SECRET" \
  mcr.microsoft.com/playwright:v1.60.0-noble \
  bash -lc 'npm ci && npx playwright test j-recovery-flow.spec.ts'
```

### Key facts about the browser profile

- **PORTAL_ADMIN_BIND_HOST=10.89.11.12** — `compose.browser.yml` gives `othala` a
  static IP on the `10.89.11.0/24` e2e subnet and binds the admin port to
  it, as production does. `0.0.0.0` is FATAL at startup by design
  (`listen.ts` `assertStartupEnv`).
- **Caddy alias** — `auth.othala.test` resolves to the Caddy container via
  `networks.default.aliases`; the portal and Chromium both use it.
- **Breach check** — `kratos.e2e.yml`, merged after the rendered config, turns it off.
- **Subnet** — defined only in `compose.browser.yml`; the base `compose.yml`
  (smoke path) uses the default dynamic subnet and is unaffected.

## CI

The `e2e` job runs on a QEMU runner selected by the project CI/CD variable
`E2E_RUNNER_TAG` (unprotected, unmasked, no default); set it to your runner's
label or the job sits pending forever.
