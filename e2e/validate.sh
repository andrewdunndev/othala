#!/usr/bin/env bash
# validate.sh: the Othala e2e orchestrator. Runs deploy/example/compose.yml under compose.e2e.yml in the per-job
# VM (podman + docker shim) or on a workstation: cd e2e && AUTH_VERSION=latest bash validate.sh
# Env: CI_REGISTRY_USER/PASSWORD (login), AUTH_REGISTRY, AUTH_VERSION (default latest).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Prefer the rootful podman socket: postgres chowns PGDATA as real root, which fails rootless.
# Set both DOCKER_HOST and CONTAINER_HOST so compose, login and logs share one store.
if [[ -S /run/podman/podman.sock ]]; then
  export DOCKER_HOST="unix:///run/podman/podman.sock"
  export CONTAINER_HOST="unix:///run/podman/podman.sock"
  echo "  rootful podman socket detected → DOCKER_HOST/CONTAINER_HOST=/run/podman/podman.sock"
fi

AUTH_REGISTRY="${AUTH_REGISTRY:-registry.gitlab.com/dunn.dev/othala}"
AUTH_VERSION="${AUTH_VERSION:-latest}"

echo "=== othala e2e: AUTH_REGISTRY=$AUTH_REGISTRY AUTH_VERSION=$AUTH_VERSION ==="

# This directory is the deployment: the shipped compose file and init script, the test's own othala.env,
# Caddyfile and content/, and compose.e2e.yml (outside the contract) on top.
cp ../deploy/example/compose.yml ../deploy/example/postgres-init.sh .
chmod +x ./smoke.sh ./postgres-init.sh
export AUTH_REGISTRY AUTH_VERSION
export COMPOSE_FILE=compose.yml:compose.e2e.yml

# Registry login (skipped when the CI vars are absent, for local runs).
if [[ -n "${CI_REGISTRY_USER:-}" && -n "${CI_REGISTRY_PASSWORD:-}" ]]; then
    echo "  podman login to $AUTH_REGISTRY..."
    echo "$CI_REGISTRY_PASSWORD" | podman login --username "$CI_REGISTRY_USER" --password-stdin "${AUTH_REGISTRY%%/*}"
fi

# A deployer's secrets.env: the image's gen-secrets over the content, which mints each client secret.
if ! (umask 077 && podman run --rm -v "$SCRIPT_DIR/content:/etc/othala:ro,z" "$AUTH_REGISTRY:$AUTH_VERSION" \
        node dist/server/config.mjs gen-secrets > secrets.env); then
    echo "  ✗ gen-secrets failed — aborting"; exit 1
fi
echo "  secrets generated (secrets.env)"

# smoke.sh reads the same values the containers get; read literally, as compose does.
while IFS= read -r line; do export "$line"; done < <(grep -hE '^[A-Za-z_][A-Za-z0-9_]*=' othala.env secrets.env)

# Wrapped in a timeout: a never-healthy dependency makes `up -d` block until the CI limit.
echo "  docker compose up (timeout 300s)..."
if ! timeout 300 docker compose up -d; then
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
        # Native `podman logs`: the compose logs shim is unreliable and /tmp is not an artifact.
        echo "=== container logs (healthcheck timeout) ==="
        for svc in render postgres kratos-migrate kratos hydra-migrate hydra othala mailpit caddy; do
            echo "--- lab-$svc ---"
            podman logs --tail=60 "lab-$svc" 2>&1 || true
        done
        exit 1
    fi
    # Count "(healthy)" in plain `ps` output: podman-compose's JSON shape differs from docker's,
    # so a JSON parser counts 0 and times out.
    healthy=$(docker compose ps 2>/dev/null | grep -c '(healthy)')
    # Expect 5 long-runners: postgres, kratos, hydra, othala, mailpit.
    if [[ "${healthy:-0}" -ge 5 ]]; then
        echo "  ✓ substrate healthy ($healthy/5 long-runners up)"
        break
    fi
    sleep 5
done

# The edge has no healthcheck. Smoke and the browser run enter through it (the portal reaches Kratos and
# Hydra directly on the internal network), so wait until it answers.
for _ in $(seq 1 30); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8088/ || true) != 000 ]] && break
    sleep 2
done

# Step 5: smoke (the API-level suite + browser-free OIDC dance, sections A-G)
echo ""
echo "=== smoke ==="
bash ./smoke.sh
SMOKE_EXIT=$?

# Step 5b: browser e2e against the same stack, as a one-shot `compose run` (`up --exit-code-from` is
# unreliable under podman-compose).
echo ""
echo "=== browser e2e (Playwright) ==="
BROWSER_EXIT=0
timeout 360 docker compose --profile browser run --rm --no-deps -T playwright || BROWSER_EXIT=$?
if [[ $BROWSER_EXIT -eq 0 ]]; then echo "  ✓ browser e2e passed"; else echo "  ✗ browser e2e failed (exit $BROWSER_EXIT)"; fi

# Step 6: log dump on failure via native `podman logs`.
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
