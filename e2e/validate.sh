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

# gen-secrets must emit a full env: a partial .env renders literal ${VAR} placeholders
# that hang Ory at startup.
if ! AUTH_REGISTRY="$AUTH_REGISTRY" AUTH_VERSION="$AUTH_VERSION" bash ./gen-secrets.sh > .env; then
    echo "  ✗ gen-secrets.sh failed — aborting"; exit 1
fi
env_vars=$(grep -cE '^[A-Z][A-Z_]*=' .env || true)
if [[ "$env_vars" -lt 25 ]]; then
    echo "  ✗ .env has only $env_vars vars (expected >=25) — partial gen-secrets; aborting"; exit 1
fi
echo "  secrets generated (.env, $env_vars vars)"

# Step 2: registry login (skip if CI vars absent for local runs)
if [[ -n "${CI_REGISTRY_USER:-}" && -n "${CI_REGISTRY_PASSWORD:-}" ]]; then
    echo "  podman login to $AUTH_REGISTRY..."
    echo "$CI_REGISTRY_PASSWORD" | podman login --username "$CI_REGISTRY_USER" --password-stdin "${AUTH_REGISTRY%%/*}"
fi

# Render the Ory configs with scripts/render-config.sh (the same renderer as the deploy plane);
# Kratos/Hydra do not interpolate ${VAR}. It fails on any unset template variable, listing names only.
set -a
source ./.env
set +a
# validate.sh omits -e, so each render needs an explicit fail-fast guard.
bash ../scripts/render-config.sh ../kratos/kratos.yml kratos.rendered.yml \
    || { echo "  ✗ render kratos.yml failed — aborting" >&2; exit 1; }
bash ../scripts/render-config.sh ../hydra/hydra.yml   hydra.rendered.yml \
    || { echo "  ✗ render hydra.yml failed — aborting" >&2; exit 1; }
# The renderer writes 0600 but kratos/hydra run as uid 10000 under cap_drop ALL and could not
# read the bind-mounted configs; they are per-run artifacts, .env keeps the secrets at 0600.
chmod 0644 kratos.rendered.yml hydra.rendered.yml
echo "  canonical configs rendered (kratos.rendered.yml, hydra.rendered.yml; 0644 for in-container ory uid)"

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
        for svc in postgres kratos-migrate kratos hydra-migrate hydra othala mailpit; do
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

# Step 4b: seed both admin identities via the Kratos admin API with the
# metadata_admin.admin marker set at creation. No id is supplied: Kratos rejects one
# with 400. Credentials come from .env (gen-secrets.sh), shared with the Playwright fixtures.
echo ""
echo "=== seed phase (admin identities with metadata_admin.admin=true marker) ==="

# Post from the othala container (has Node) to kratos:4434, program on stdin.

# Usage: seed_admin_identity <email> <username> <display_name> <groups_json> <password>
seed_admin_identity() {
    local email="$1" username="$2" display_name="$3" groups_json="$4" password="$5"
    local result
    result=$(printf '%s' "fetch('http://kratos:4434/admin/identities',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schema_id:'family',state:'active',traits:{username:'${username}',email:'${email}',displayName:'${display_name}'},metadata_admin:{admin:true,groups:${groups_json}},credentials:{password:{config:{password:'${password}'}}}})}).then(r=>r.json()).then(j=>{process.stdout.write(j.id||('ERR:'+JSON.stringify(j)));process.exit(0)}).catch(e=>{process.stdout.write('EXC:'+e.message);process.exit(1)})" \
        | docker compose exec -T othala node 2>/dev/null)
    # Strip ANSI resets that podman-compose prepends.
    result=$(printf '%s' "$result" | sed 's/\x1b\[[0-9;]*m//g')
    printf '%s' "$result"
}

ADMIN_EMAIL="${ADMIN_EMAIL:-admin@othala.test}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-othala-testpass-2026}"
RECOVERY_ADMIN_EMAIL="${RECOVERY_ADMIN_EMAIL:-admin.recovery@othala.test}"
RECOVERY_ADMIN_USERNAME="${RECOVERY_ADMIN_USERNAME:-admin.recovery}"
RECOVERY_ADMIN_PASSWORD="${RECOVERY_ADMIN_PASSWORD:-othala-testpass-2026}"

# Access model: an admin holds `<svc>-access` AND `<svc>-admin` explicitly; dropping
# grafana-access locks the admin out (t-access-model.spec.ts T4). metadata_admin.admin
# is portal authority only and is orthogonal to groups.
echo "  seeding primary admin: $ADMIN_EMAIL (admin marker + groups) ..."
ADMIN_ID=$(seed_admin_identity \
    "$ADMIN_EMAIL" "$ADMIN_USERNAME" "Othala Admin" \
    "['grafana-access','grafana-admin']" "$ADMIN_PASSWORD")
if [[ -z "$ADMIN_ID" || "$ADMIN_ID" == ERR:* || "$ADMIN_ID" == EXC:* ]]; then
    echo "  ✗ seed admin failed: $ADMIN_ID"; exit 1
fi
echo "  ✓ admin seeded: id=$ADMIN_ID (metadata_admin.admin=true)"

# The recovery-admin exercises the recovery-gate (marker only), so it holds just grafana-access.
echo "  seeding recovery-admin: $RECOVERY_ADMIN_EMAIL (admin marker + groups) ..."
RECOVERY_ADMIN_ID=$(seed_admin_identity \
    "$RECOVERY_ADMIN_EMAIL" "$RECOVERY_ADMIN_USERNAME" "Admin Recovery Test" \
    "['grafana-access']" "$RECOVERY_ADMIN_PASSWORD")
if [[ -z "$RECOVERY_ADMIN_ID" || "$RECOVERY_ADMIN_ID" == ERR:* || "$RECOVERY_ADMIN_ID" == EXC:* ]]; then
    echo "  ✗ seed recovery-admin failed: $RECOVERY_ADMIN_ID"; exit 1
fi
echo "  ✓ recovery-admin seeded: id=$RECOVERY_ADMIN_ID (metadata_admin.admin=true)"

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
# othala with ADMIN_HOST=10.89.11.12 (0.0.0.0 is FATAL in listen.mjs; loopback is unreachable from
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
