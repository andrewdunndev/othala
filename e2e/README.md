# Othala end-to-end harness

This is the canonical, OSS-facing example of **how Othala stands up on
`docker compose`** from the published images — a worked adopter example,
and the project's release gate. The same `compose.yml` + `validate.sh`
that gate every tag in CI run unchanged on an operator workstation.

Othala is "Ory for your home": a self-hosted Ory substrate (Kratos +
Hydra + Postgres) fronted by one converged Astro Node SSR app. This
harness brings the whole substrate up, registers the OIDC clients, and
runs a smoke matrix against it — no Caddy, no TLS, no real DNS, just the
containers on a compose network.

## The converged topology

| Service | Image | Role |
|---|---|---|
| `postgres` | `postgres:18-alpine` | Separate `kratos` + `hydra` DBs |
| `kratos` | `oryd/kratos` | Identity: self-service flows, sessions, recovery (public 4433, admin 4434) |
| `hydra` | `oryd/hydra` | OAuth2/OIDC; ships no UI (public 4444, admin 4445) |
| **`othala`** | `${AUTH_REGISTRY}` (registry **root**) | The converged Astro Node SSR app |
| `mailpit` | `axllent/mailpit` | Dev mail catcher (SMTP + web UI) — proves the Kratos courier and contact-form delivery |

The `othala` app is **one image at the registry root** (no `/portal`
sub-path, no separate `consent` or `util` container — those roles folded
into the app). It runs **two listeners in one process**
(`portal/src/server/listen.mjs`):

- **Public SSR port `8080`** — the family UI, `/auth/*` + `/admin/*`
  pages, and the Hydra login/consent/logout challenge handlers at
  `/oauth2/{login,consent,logout}`. The only port fronted by Caddy in
  production.
- **Loopback admin port `4431`** (`127.0.0.1`, pod-only) — a disjoint
  mux: `GET /healthz`, `GET /readyz`, `POST /admin/revoke-user`,
  `POST /admin/recovery-gate`. Never delegates to the SSR handler. In
  this harness the admin probes run via `compose exec` because the port
  is loopback-only.

`${AUTH_REGISTRY}` is the registry root (the app image). `${AUTH_VERSION}`
is the tag (CI passes the just-built tag; local runs use `latest`).

## How it works

In CI, GitLab dispatches the `e2e` job (tagged `[lodestone, qemu]`) to the
lodestone GitLab Runner, whose Custom Executor spawns a per-job ephemeral
Fedora VM (qcow2 linked clone from the `baser` golden — podman +
podman-docker + skopeo + jq + curl pre-baked). The job runs INSIDE the
VM as `fedora`. `e2e/validate.sh`:

1. Generates per-run substrate secrets (`gen-secrets.sh > .env`)
2. Logs in to the GitLab registry (`$CI_REGISTRY_USER` /
   `$CI_REGISTRY_PASSWORD`, auto-injected)
3. `docker compose up -d` (the podman-docker bridge translates to podman)
4. Waits for healthchecks on postgres + mailpit + kratos + hydra +
   othala (5 long-runners)
5. Runs `smoke.sh`
6. Tears down

VM dies on job end. Total turnaround: ~3-5 minutes including image pulls.

## What it validates

- **Substrate sanity** — postgres up; kratos + hydra DBs exist; uuid-ossp
  on hydra; Kratos admin + public health; Hydra admin health + public
  openid-configuration with issuer byte-match + jwks.json RS256; the
  othala app admin `/healthz` (loopback `:4431`); the public
  `/oauth2/login` challenge handler is mounted on `:8080`; the admin mux
  does NOT leak onto the public port.
- **Client registration** — runs the converged app's **in-app registrar**
  (`registerAllClients`, bundled to `dist/server/register-clients.mjs`)
  as a `compose run --rm register-clients` one-shot on the same othala
  image. It reads manifests from `MANIFEST_DIR=/etc/portal/manifests`
  (mounted from `e2e/manifests/`), resolves each `<SLUG>_CLIENT_SECRET`
  from env, and POST/PUTs every client to Hydra admin; the smoke asserts
  the full set registered (specific checks for `grafana` and
  `audiobookshelf`).
- **Identity admin flow** — create an identity via the Kratos admin API;
  `metadata_admin.groups` round-trips.
- **Recovery-gate** — the converged app's loopback endpoint
  `othala:4431/admin/recovery-gate`, `Authorization: Bearer`. Refusal is
  **marker-based** (`is_admin===true` in the webhook payload, derived from
  `metadata_admin.admin` by `recovery-gate.jsonnet`), NOT group- or UUID-based
  (ADR 08). An identity with `is_admin=true` → 403; `is_admin=false` → 200
  (even if groups includes `admin`); a non-boolean `is_admin` → 403 (fail-closed);
  a missing `identity_id` → 403 (fail-closed); a wrong bearer → 401.

## What it does NOT validate

- TLS / Caddy / production DNS. The substrate runs HTTP-only on the
  compose network. Production-shape TLS validation is manual lab work (or
  a future iteration that wires Caddy with `tls internal`).
- Browser-driven OIDC flows. A Playwright suite is the harness for that;
  this harness focuses on substrate + endpoint health.

## On the in-app registrar (a note for adopters)

The app does **not** self-register clients on boot, and no route triggers
registration. Registration is a deliberate **one-shot**: in production,
the deploy repo runs `just dag-reload-clients` (SIGHUP-driven; also runs
on boot) on the network that can reach Hydra's admin port (see the repo
`DEPLOY.md`). This harness does the same against the freshly-built image,
which is why `register-clients` is a `profiles: [oneshot]` service that
`smoke.sh` invokes explicitly rather than starting in the `up` set.

## Files

| File | Purpose |
|---|---|
| `compose.yml` | docker-compose for the converged substrate |
| `hydra.yml` | Hydra config (harness-shape: HTTP issuer, expose_internal_errors=true) |
| `identity.schema.json` | Production identity schema, vendored |
| `recovery-gate.jsonnet` | Recovery-gate webhook body, vendored |
| `glauth.cfg` | Example LDAP bridge config for `gitlab.com/dunn.dev/kratos-ldap` (not used by the default compose run; kept as a reference for operators adding LDAP) |
| `postgres-init.sh` | DB + extension setup |
| `gen-secrets.sh` | Per-run secret generator |
| `smoke.sh` | Probe matrix (pass/fail counters) |
| `validate.sh` | Top-level orchestrator |

## Local operator invocation

```sh
# Requires: podman, docker-compose-compat or podman-compose, registry login
cd e2e
AUTH_VERSION=latest bash validate.sh
```

If a probe fails, container ps/logs print to STDOUT; the register-clients
(B1) output is also saved to `e2e/logs/apply-clients.log`.

## Running the browser e2e locally (macOS/podman)

The browser profile adds Caddy + a Playwright container. It drives the J
(recovery) and K (login-code) specs against the live compose stack.

### Prerequisites

- podman + podman-machine running (`podman machine start` if not)
- docker-compose shim wired to the podman socket (see below)

### Build the othala image from current source

The browser specs exercise `ADMIN_HOST`-gated startup logic that changed
in recent commits. You **must** build from current source — a stale cached
image predates the `ADMIN_HOST=0.0.0.0` FATAL assert and will give false
results.

```sh
# from the auth repo root
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

# Base stack (smoke services)
docker-compose --env-file=.env up -d

# Browser-profile services (othala + caddy — compose.browser.yml overrides
# KRATOS_PUBLIC_URL and ADMIN_HOST, assigns othala a static IP on subnet
# 10.89.11.0/24, and wires the Caddy edge alias)
docker-compose -f compose.yml -f compose.browser.yml \
  --profile browser --env-file=.env up -d --no-deps othala caddy
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
  -e KRATOS_ADMIN_URL=http://kratos:4434 \
  -e HYDRA_PUBLIC_URL=http://hydra:4444 \
  -e HYDRA_ADMIN_URL=http://hydra:4445 \
  -e RECOVERY_ADMIN_EMAIL=admin.recovery@othala.test \
  -e MAILPIT_API=http://mailpit:8025 \
  -e OTHALA_ADMIN_URL=http://othala:4431 \
  -e RECOVERY_GATE_SECRET="$RECOVERY_GATE_SECRET" \
  -e GRAFANA_CLIENT_SECRET="$GRAFANA_CLIENT_SECRET" \
  mcr.microsoft.com/playwright:v1.60.0-noble \
  bash -lc 'npm ci && npx playwright test j-recovery-flow.spec.ts'
```

### Key facts about the browser profile

- **ADMIN_HOST=10.89.11.12** — `compose.browser.yml` gives `othala` a
  static IP on the `10.89.11.0/24` e2e subnet and binds the admin port to
  that IP, mirroring production (where portal binds to its dag-internal IP
  and Kratos reaches it by hostname). `0.0.0.0` is FATAL at startup by
  design (`listen.mjs:354`).
- **KRATOS_PUBLIC_URL override** — set to `http://auth.othala.test` so the
  portal's SSR browser-flow helpers build URLs that Chromium can resolve
  through the Caddy edge alias. The smoke path keeps `http://kratos:4433`.
- **Caddy alias** — `auth.othala.test` resolves to the Caddy container
  inside the compose network via `networks.default.aliases`.
- **Subnet** — defined only in `compose.browser.yml`; the base `compose.yml`
  (smoke path) uses the default dynamic subnet and is unaffected.

## CI invocation

`.gitlab-ci.yml`'s `e2e` job (stage `e2e`), tagged `[lodestone, qemu]`.
Depends on `build-othala` + `build-e2e-tester` so the just-built images
are pulled at the build tag. Gates the package + release stages.

## When to evolve

When an Ory upgrade lands, this harness validates the substrate in CI
before the bump reaches carmine. Grow the smoke matrix with each
Ory-surface change worth catching — e.g., when a new admin API endpoint
shape lands, add a probe.
