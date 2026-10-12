#!/usr/bin/env bash
# validate.sh: the Othala e2e orchestrator. Runs in the per-job VM (podman + docker
# shim) or on a workstation: cd e2e && AUTH_VERSION=latest bash validate.sh
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

chmod +x ./gen-secrets.sh ./smoke.sh ./postgres-init.sh

# A partial .env fails below: the render refuses a missing variable or secret.
if ! AUTH_REGISTRY="$AUTH_REGISTRY" AUTH_VERSION="$AUTH_VERSION" bash ./gen-secrets.sh > .env; then
    echo "  ✗ gen-secrets.sh failed — aborting"; exit 1
fi
echo "  secrets generated (.env)"

# Step 2: registry login (skip if CI vars absent for local runs)
if [[ -n "${CI_REGISTRY_USER:-}" && -n "${CI_REGISTRY_PASSWORD:-}" ]]; then
    echo "  podman login to $AUTH_REGISTRY..."
    echo "$CI_REGISTRY_PASSWORD" | podman login --username "$CI_REGISTRY_USER" --password-stdin "${AUTH_REGISTRY%%/*}"
fi

# Kratos and Hydra do not interpolate ${VAR}: the image under test renders its own policy from the .env names.
set -a
source ./.env
set +a
ENV_ARGS=()
while IFS= read -r name; do ENV_ARGS+=(-e "$name"); done < <(grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' .env | tr -d '=')
rm -rf config.rendered && mkdir config.rendered
# Rootless podman maps the host user to container root; keep-id makes the render's uid own the mount.
USERNS_ARGS=()
[[ -S /run/podman/podman.sock ]] || USERNS_ARGS=(--userns=keep-id)
podman run --rm --user "$(id -u):$(id -g)" "${USERNS_ARGS[@]}" "${ENV_ARGS[@]}" -v "$SCRIPT_DIR/config.rendered:/run/othala:z" \
    -v "$SCRIPT_DIR/content:/etc/othala:ro,z" \
    "$AUTH_REGISTRY:$AUTH_VERSION" node dist/server/config.mjs render \
    || { echo "  ✗ render failed — aborting" >&2; exit 1; }
# The render writes owner-only, but kratos/hydra run as uid 10000 under cap_drop ALL and could not read the
# bind-mounted configs; they are per-run artifacts, .env keeps the secrets at 0600.
chmod -R go+rX config.rendered
echo "  configs rendered by the image (config.rendered/; world-readable for the in-container ory uid)"

# Wrapped in a timeout: a never-healthy dependency makes `up -d` block until the CI limit.
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
        # Native `podman logs`: the compose logs shim is unreliable and /tmp is not an artifact.
        echo "=== container logs (healthcheck timeout) ==="
        for svc in postgres kratos-migrate kratos hydra-migrate hydra othala mailpit caddy; do
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
set -a; source .env; set +a
bash ./smoke.sh
SMOKE_EXIT=$?

# Step 5b: browser e2e. smoke already did setup (the Caddy edge is part of the stack); run playwright
# as a one-shot `compose run` (`up --exit-code-from` is unreliable under podman-compose).
echo ""
echo "=== browser e2e (Playwright) ==="
# compose.browser.yml is layered only here (smoke keeps the loopback admin bind). It recreates
# othala with PORTAL_ADMIN_BIND_HOST=10.89.11.12 (0.0.0.0 is FATAL in listen.mjs; loopback is unreachable from
# kratos, so the J recovery specs would fail; needs the subnet in compose.yml).
BROWSER_EXIT=0
BROWSER_COMPOSE=(docker compose -f compose.yml -f compose.browser.yml --profile browser --env-file=.env)
if "${BROWSER_COMPOSE[@]}" up -d --no-deps othala; then
    sleep 8  # othala recreate + caddy boot; settle before specs hit auth.othala.test
    timeout 360 "${BROWSER_COMPOSE[@]}" run --rm --no-deps -T playwright || BROWSER_EXIT=$?
else
    echo "  ✗ could not recreate othala for the browser run"; BROWSER_EXIT=1
fi
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
