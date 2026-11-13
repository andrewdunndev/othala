#!/usr/bin/env bash
# validate.sh: the Othala e2e orchestrator. Runs deploy/example/compose.yml under compose.e2e.yml in the per-job
# VM (podman + docker shim) or on a workstation: `just e2e` (builds both images first), or
# cd e2e && AUTH_VERSION=<tag> bash validate.sh against a published image
# Env: CI_REGISTRY_USER/PASSWORD (login), AUTH_REGISTRY, AUTH_VERSION (default latest).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

source ./lib.sh

AUTH_REGISTRY="${AUTH_REGISTRY:-registry.gitlab.com/dunn.dev/othala}"
AUTH_VERSION="${AUTH_VERSION:-latest}"

echo "=== othala e2e: AUTH_REGISTRY=$AUTH_REGISTRY AUTH_VERSION=$AUTH_VERSION ==="

# This directory is the deployment: the shipped compose file and init script, the test's own othala.env,
# Caddyfile and content/, and compose.e2e.yml (outside the contract) on top.
cp ../deploy/example/compose.yml ../deploy/example/postgres-init.sh .
chmod +x ./smoke.sh ./postgres-init.sh
export AUTH_REGISTRY AUTH_VERSION
export COMPOSE_FILE=compose.yml:compose.e2e.yml

registry_login
(umask 077 && gen_secrets "$AUTH_VERSION" > secrets.env) || { echo "  ✗ gen-secrets failed — aborting"; exit 1; }
echo "  secrets generated (secrets.env)"
load_env

up_and_wait

# Smoke (the API-level suite + browser-free OIDC dance, sections A-G)
echo ""
echo "=== smoke ==="
bash ./smoke.sh
SMOKE_EXIT=$?

# Browser e2e against the same stack, as a one-shot `compose run` (`up --exit-code-from` is
# unreliable under podman-compose).
echo ""
echo "=== browser e2e (Playwright) ==="
BROWSER_EXIT=0
timeout 360 docker compose --profile browser run --rm --no-deps -T playwright || BROWSER_EXIT=$?
if [[ $BROWSER_EXIT -eq 0 ]]; then echo "  ✓ browser e2e passed"; else echo "  ✗ browser e2e failed (exit $BROWSER_EXIT)"; fi

# Log dump on failure via native `podman logs`.
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

# Teardown
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
