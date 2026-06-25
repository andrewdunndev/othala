#!/usr/bin/env bash
# validate.sh — top-level Othala e2e orchestrator.
#
# Runs INSIDE the per-job Fedora VM the carmine GitLab Runner spawns
# (Custom Executor, tag carmine,qemu). The VM has podman + podman-docker
# bridge baked into the baser golden image (per the deploy repo's
# runner config "What pre-bakes into the baser golden image"), so
# `docker compose` works natively. The same script runs on an operator
# workstation — this is the OSS-facing "stand Othala up on compose"
# example, not a CI-only artifact.
#
# Sequence:
#   1. Generate per-run secrets → e2e/.env
#   2. Login to the registry (CI_REGISTRY_USER + CI_REGISTRY_PASSWORD
#      injected by GitLab into every job)
#   3. `docker compose up -d` (pulls the othala app at $AUTH_VERSION)
#   4. Wait for healthchecks (postgres → migrate → kratos + hydra →
#      othala). Max 4 min total; if any fail the substrate is broken.
#      NOTE: the LDAP bridge is a separate project (gitlab.com/dunn.dev/
#      kratos-ldap); no e2e spec exercises LDAP here.
#   5. Run smoke.sh
#   6. On failure, dump container logs to artifacts
#   7. `docker compose down -v` (ephemeral; VM dies anyway, but be
#      tidy in case the test runs against a longer-lived host)
#
# Required env (set by .gitlab-ci.yml e2e job):
#   CI_REGISTRY_USER, CI_REGISTRY_PASSWORD — for podman login
#   AUTH_REGISTRY — the registry ROOT (the othala app image); defaults to
#                   registry.gitlab.com/dunn.dev/othala.
#   AUTH_VERSION  — defaults to latest; CI passes the just-built tag.
#
# Local operator invocation:
#   cd e2e
#   AUTH_VERSION=latest bash validate.sh
# (you need to be logged in to the registry via your own podman creds)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Rootful container engine, when available. The crucible CI VM exposes the
# system (rootful) podman socket group-accessible to the unprivileged `fedora`
# user. postgres:18-alpine chowns PGDATA as real root, which fails under
# rootless userns ("Operation not permitted") — against the rootful socket the
# container is real root and chown succeeds. The `docker compose` shim reads
# DOCKER_HOST; native podman (login/logs) reads CONTAINER_HOST — set both so
# they share ONE store (else login creds + `podman logs` miss the compose
# containers). Guarded on socket presence so the operator-workstation rootless
# path (above) is unchanged.
if [[ -S /run/podman/podman.sock ]]; then
  export DOCKER_HOST="unix:///run/podman/podman.sock"
  export CONTAINER_HOST="unix:///run/podman/podman.sock"
  echo "  rootful podman socket detected → DOCKER_HOST/CONTAINER_HOST=/run/podman/podman.sock"
fi

AUTH_REGISTRY="${AUTH_REGISTRY:-registry.gitlab.com/dunn.dev/othala}"
AUTH_VERSION="${AUTH_VERSION:-latest}"

echo "=== othala e2e: AUTH_REGISTRY=$AUTH_REGISTRY AUTH_VERSION=$AUTH_VERSION ==="

# Permission sanity: scripts must be executable.
chmod +x ./gen-secrets.sh ./smoke.sh ./postgres-init.sh

# Step 1: per-run secrets. gen-secrets MUST succeed and emit a full env — a
# partial/empty .env silently renders configs with literal ${VAR} placeholders
# that crash Ory at startup (observed as a ~45min hang, pipeline 2574071772,
# when a gen-secrets bug produced an empty .env). Fail fast instead.
if ! AUTH_REGISTRY="$AUTH_REGISTRY" AUTH_VERSION="$AUTH_VERSION" bash ./gen-secrets.sh > .env; then
    echo "  ✗ gen-secrets.sh failed — aborting"; exit 1
fi
env_vars=$(grep -cE '^[A-Z][A-Z_]*=' .env || true)
if [[ "$env_vars" -lt 30 ]]; then
    echo "  ✗ .env has only $env_vars vars (expected >=30) — partial gen-secrets; aborting"; exit 1
fi
echo "  secrets generated (.env, $env_vars vars)"

# Step 2: registry login (skip if CI vars absent for local runs)
if [[ -n "${CI_REGISTRY_USER:-}" && -n "${CI_REGISTRY_PASSWORD:-}" ]]; then
    echo "  podman login to $AUTH_REGISTRY..."
    echo "$CI_REGISTRY_PASSWORD" | podman login --username "$CI_REGISTRY_USER" --password-stdin "${AUTH_REGISTRY%%/*}"
fi

# Render the Ory configs via THE canonical render, scripts/render-config.sh —
# shared with the deploy plane (dunn.dev/iac), so e2e and production use the
# same mechanism and the same template-derived variable contract. Kratos/Hydra
# do NOT interpolate ${VAR} inside their YAML (they only accept
# uppercased-dotted env OVERRIDES); the canonical configs are templates that
# must be rendered before the containers mount them.
# compose.yml mounts the rendered copies (not the canonical sources directly,
# since compose bind-mounts require a path that exists at up-time and the
# canonical sources contain un-expanded placeholders at that point).
# render-config.sh fails fast — listing missing variable NAMES only, never
# rendered content — if any template token is unset/empty, so a partial .env
# cannot reach `compose up` (the old post-render leftover-grep is superseded:
# the pre-check makes leftovers impossible by construction).
set -a
source ./.env
set +a
# render-config.sh runs under set -euo pipefail internally, but validate.sh
# itself omits -e so a bare `bash ...` call would let a render failure continue.
# Explicit fail-fast guards surface the failure immediately rather than letting
# compose up proceed with un-rendered (${VAR}-literal) configs.
bash ../scripts/render-config.sh ../kratos/kratos.yml kratos.rendered.yml \
    || { echo "  ✗ render kratos.yml failed — aborting" >&2; exit 1; }
bash ../scripts/render-config.sh ../hydra/hydra.yml   hydra.rendered.yml \
    || { echo "  ✗ render hydra.yml failed — aborting" >&2; exit 1; }
echo "  canonical configs rendered (kratos.rendered.yml, hydra.rendered.yml)"

# Step 3: compose up — wrapped in a timeout. A never-healthy dependency (e.g. a
# mis-rendered config) makes `up -d` block indefinitely; the health-wait timeout
# below never arms because we never return from `up -d`. Without this wrapper the
# job hangs to the CI wall-clock limit (observed: ~45min, pipeline 2574071772).
echo "  docker compose up (timeout 300s)..."
if ! timeout 300 docker compose --env-file=.env up -d; then
    echo "  ✗ compose up failed or timed out — diagnostics:"
    docker compose ps || true
    docker compose logs --tail=120 || true
    exit 1
fi

# Step 4: wait for healthy
echo "  waiting for healthchecks (max 240s)..."
DEADLINE=$(($(date +%s) + 240))
while true; do
    if [[ $(date +%s) -gt $DEADLINE ]]; then
        echo "  ✗ healthcheck timeout"
        docker compose ps
        # Dump each container's logs to STDOUT (the /tmp file isn't an
        # uploadable CI artifact and the podman-compose `logs` shim is
        # unreliable). Native `podman logs` per container surfaces WHY a
        # service never went healthy directly in the job trace.
        echo "=== container logs (healthcheck timeout) ==="
        for svc in postgres kratos-migrate kratos hydra-migrate hydra othala mailpit; do
            echo "--- lab-$svc ---"
            podman logs --tail=60 "lab-$svc" 2>&1 || true
        done
        exit 1
    fi
    # Count healthy long-running services. podman-compose's
    # `ps --format json` emits a different shape than docker compose (NOT
    # JSON-lines), so a per-line json parser silently counts 0 and this
    # loop times out at 240s even on a fully-healthy substrate (observed
    # 2026-06-02, pipeline 2571487244: all 5 healthy, loop never saw them).
    # The PLAIN `docker compose ps` output reliably shows "(healthy)" in the
    # status column under both engines — count that instead.
    healthy=$(docker compose ps 2>/dev/null | grep -c '(healthy)')
    # Expecting 5 healthy long-runners: postgres, kratos, hydra, othala,
    # mailpit. consent + util are gone (folded into the othala app); the
    # LDAP bridge is now at gitlab.com/dunn.dev/kratos-ldap, no spec here.
    # The othala healthcheck hits its loopback admin /healthz (:4431);
    # mailpit answers `readyz` — gating on all surfaces a broken service.
    if [[ "${healthy:-0}" -ge 5 ]]; then
        echo "  ✓ substrate healthy ($healthy/5 long-runners up)"
        break
    fi
    sleep 5
done

# Step 5: smoke (the API-level suite + browser-free OIDC dance, sections A-G)
echo ""
echo "=== smoke ==="
set -a; source .env; set +a
bash ./smoke.sh
SMOKE_EXIT=$?

# Step 5b: browser e2e (Playwright). Ory-faithful two-phase shape — upstream runs
# `run.sh --only-setup` (stack + client registration up) then `playwright test`.
# Our smoke already did the setup (incl. section B client registration), so now run
# the Playwright specs against the live stack. Bring up the browser Caddy edge, then
# run the playwright service as a ONE-SHOT via `compose run` (podman-compose-safe;
# `up --exit-code-from` is unreliable under podman-compose, same class as --no-color).
echo ""
echo "=== browser e2e (Playwright) ==="
BROWSER_EXIT=0
if docker compose --profile browser --env-file=.env up -d --no-deps caddy; then
    sleep 5  # caddy boots in ~1s; brief settle before the specs hit auth.othala.test
    timeout 360 docker compose --profile browser --env-file=.env run --rm --no-deps -T playwright || BROWSER_EXIT=$?
else
    echo "  ✗ could not start the caddy edge"; BROWSER_EXIT=1
fi
if [[ $BROWSER_EXIT -eq 0 ]]; then echo "  ✓ browser e2e passed"; else echo "  ✗ browser e2e failed (exit $BROWSER_EXIT)"; fi

# Step 6: log dump on failure — STDOUT via native `podman logs` (the podman shim
# rejects `compose logs --no-color`, and /tmp isn't uploadable as a CI artifact).
if [[ $SMOKE_EXIT -ne 0 || $BROWSER_EXIT -ne 0 ]]; then
    echo ""
    echo "=== container ps ==="
    docker compose ps 2>&1 || true
    echo "=== container logs (last 80 each) ==="
    for svc in postgres kratos hydra othala mailpit caddy; do
        echo "--- lab-$svc ---"
        podman logs --tail=80 "lab-$svc" 2>&1 || true
    done
fi

# Step 7: teardown
echo ""
echo "  docker compose down..."
docker compose --profile browser down -v --remove-orphans || true

# Fail the job if EITHER the smoke suite or the browser e2e failed.
if [[ $SMOKE_EXIT -ne 0 || $BROWSER_EXIT -ne 0 ]]; then
    echo "=== e2e FAILED (smoke=$SMOKE_EXIT browser=$BROWSER_EXIT) ==="
    exit 1
fi
echo "=== e2e PASSED (smoke + browser) ==="
exit 0
