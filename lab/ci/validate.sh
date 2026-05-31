#!/usr/bin/env bash
# validate.sh — top-level CI lab orchestrator.
#
# Runs INSIDE the per-job Fedora VM the carmine GitLab Runner spawns
# (Custom Executor, tag carmine,qemu). The VM has podman + podman-docker
# bridge baked into the baser golden image (per dunn.dev/iac/services/
# runner/README.md "What pre-bakes into the baser golden image"), so
# `docker compose` works natively.
#
# Sequence:
#   1. Generate per-run secrets → lab/ci/.env
#   2. Login to the registry (CI_REGISTRY_USER + CI_REGISTRY_PASSWORD
#      injected by GitLab into every job)
#   3. `docker compose up -d` (pulls auth images at $AUTH_VERSION)
#   4. Wait for healthchecks (postgres → migrate → kratos + hydra →
#      consent + portal). Max 4 min total; if any fail the substrate
#      is broken.
#   5. Run smoke.sh
#   6. On failure, dump container logs to artifacts
#   7. `docker compose down -v` (ephemeral; VM dies anyway, but be
#      tidy in case the test runs against a longer-lived host)
#
# Required env (set by .gitlab-ci.yml lab-validate job):
#   CI_REGISTRY_USER, CI_REGISTRY_PASSWORD — for podman login
#   AUTH_REGISTRY — defaults to registry.gitlab.com/dunn.dev/auth
#   AUTH_VERSION  — defaults to latest; CI should pass $CI_COMMIT_SHA
#
# Local operator invocation:
#   cd lab/ci
#   AUTH_VERSION=latest bash validate.sh
# (you need to be logged in to the registry via your own podman creds)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LAB_DOMAIN="${LAB_DOMAIN:-test.dunn.dev}"
AUTH_REGISTRY="${AUTH_REGISTRY:-registry.gitlab.com/dunn.dev/auth}"
AUTH_VERSION="${AUTH_VERSION:-latest}"

echo "=== lab validate: AUTH_REGISTRY=$AUTH_REGISTRY AUTH_VERSION=$AUTH_VERSION LAB_DOMAIN=$LAB_DOMAIN ==="

# Permission sanity: scripts must be executable.
chmod +x ./gen-secrets.sh ./smoke.sh ./postgres-init.sh

# Step 1: per-run secrets
LAB_DOMAIN="$LAB_DOMAIN" \
AUTH_REGISTRY="$AUTH_REGISTRY" \
AUTH_VERSION="$AUTH_VERSION" \
  bash ./gen-secrets.sh > .env
echo "  secrets generated (.env, $(wc -l < .env) lines)"

# Step 2: registry login (skip if CI vars absent for local runs)
if [[ -n "${CI_REGISTRY_USER:-}" && -n "${CI_REGISTRY_PASSWORD:-}" ]]; then
    echo "  podman login to $AUTH_REGISTRY..."
    echo "$CI_REGISTRY_PASSWORD" | podman login --username "$CI_REGISTRY_USER" --password-stdin "${AUTH_REGISTRY%%/*}"
fi

# envsubst doesn't help with the YAML configs — they're consumed by
# kratos/hydra binaries which already do their own ${VAR} substitution
# from env. Just `docker compose` passes the env vars through.

# Step 3: compose up.
# Set -e here so a failed compose-up aborts before smoke.
set -e
echo "  docker compose up..."
docker compose --env-file=.env up -d
set +e

# Step 4: wait for healthy
echo "  waiting for healthchecks (max 240s)..."
DEADLINE=$(($(date +%s) + 240))
while true; do
    if [[ $(date +%s) -gt $DEADLINE ]]; then
        echo "  ✗ healthcheck timeout"
        docker compose ps
        docker compose logs --tail=200 > /tmp/lab-healthcheck-failure.log
        exit 1
    fi
    # Count healthy long-running services
    healthy=$(docker compose ps --format json 2>/dev/null | \
        python3 -c "import sys,json
n=0
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try: d=json.loads(line)
    except: continue
    if d.get('Health')=='healthy': n+=1
print(n)" 2>/dev/null)
    # Expecting 6 healthy long-runners: postgres, kratos, hydra, consent,
    # portal, ldap-bridge. The bridge has its own /healthz on :6478;
    # gating on it surfaces a broken bridge in the same loop instead of
    # later in smoke.
    if [[ "${healthy:-0}" -ge 6 ]]; then
        echo "  ✓ substrate healthy ($healthy/6 long-runners up)"
        break
    fi
    sleep 5
done

# Step 5: smoke
echo ""
echo "=== smoke ==="
set -a; source .env; set +a
bash ./smoke.sh
SMOKE_EXIT=$?

# Step 6: log dump on failure
if [[ $SMOKE_EXIT -ne 0 ]]; then
    {
        echo "=== docker compose ps ==="
        docker compose ps
        echo ""
        echo "=== docker compose logs (full) ==="
        docker compose logs --no-color
    } > /tmp/lab-smoke-failure.log
    echo "  failure logs in /tmp/lab-smoke-failure.log (CI uploads as artifact)"
fi

# Step 7: teardown
echo ""
echo "  docker compose down..."
docker compose down -v --remove-orphans || true

exit $SMOKE_EXIT
