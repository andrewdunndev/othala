#!/usr/bin/env bash
# shellcheck disable=SC1091
set -euo pipefail

BENCH_DIR="/opt/bench-sso-iac"
COMPOSE_DIR="${BENCH_DIR}/compose"
TOKEN_FILE="${BENCH_DIR}/.ak-token"

echo "=== Deploying bench-sso-iac ==="

# --- Load env ---
if [[ -f "${BENCH_DIR}/.env" ]]; then
    set -a
    source "${BENCH_DIR}/.env"
    set +a
    echo "Loaded .env (DOMAIN=${DOMAIN:-unset})"
else
    echo "ERROR: No .env file at ${BENCH_DIR}/.env" >&2
    exit 1
fi

# --- Validate required vars ---
for var in AUTHENTIK_SECRET_KEY AUTHENTIK_PG_PASS AUTHENTIK_BOOTSTRAP_PASSWORD DOMAIN; do
    if [[ -z "${!var:-}" ]]; then
        echo "ERROR: Required variable ${var} is not set in .env" >&2
        exit 1
    fi
done

cd "$COMPOSE_DIR"

# --- Ensure .env is accessible from compose directory ---
if [[ ! -f "${COMPOSE_DIR}/.env" ]]; then
    ln -sf "${BENCH_DIR}/.env" "${COMPOSE_DIR}/.env"
    echo "Linked .env into compose directory"
fi

# --- Fix blueprint permissions for container UID 1000 ---
chown -R 1000:1000 "${BENCH_DIR}/blueprints" 2>/dev/null || true

# --- Pull images ---
echo "Pulling images (this may take a few minutes)..."
podman-compose pull 2>&1 | tail -10

# --- Start the stack ---
echo "Starting services..."
podman-compose up -d 2>&1

# --- Wait for Authentik ---
echo "Waiting for Authentik to be healthy..."
MAX_WAIT=300
ELAPSED=0
while (( ELAPSED < MAX_WAIT )); do
    if curl -sf http://localhost:9000/-/health/live/ >/dev/null 2>&1; then
        echo "Authentik healthy after ${ELAPSED}s"
        break
    fi
    sleep 10
    ELAPSED=$((ELAPSED + 10))
    if (( ELAPSED % 60 == 0 )); then
        echo "  still waiting... (${ELAPSED}s)"
        # Show last error from server logs
        podman logs authentik-server 2>&1 | grep -i 'error' | tail -1
    fi
done

if (( ELAPSED >= MAX_WAIT )); then
    echo "ERROR: Authentik did not become healthy within ${MAX_WAIT}s" >&2
    echo "--- authentik-server logs ---"
    podman logs authentik-server 2>&1 | tail -30
    exit 1
fi

# --- Generate API token ---
echo "Generating API token via ak create_admin_token..."
AK_TOKEN=""
for attempt in 1 2 3; do
    AK_TOKEN=$(podman exec -e AUTHENTIK_SECRET_KEY="${AUTHENTIK_SECRET_KEY}" \
        -e AUTHENTIK_POSTGRESQL__HOST=postgres \
        -e AUTHENTIK_POSTGRESQL__NAME=authentik \
        -e AUTHENTIK_POSTGRESQL__USER=authentik \
        -e AUTHENTIK_POSTGRESQL__PASSWORD="${AUTHENTIK_PG_PASS}" \
        authentik-server ak create_admin_token 2>/dev/null | grep -v '{' | tr -d '[:space:]')
    if [[ -n "$AK_TOKEN" ]] && [[ ${#AK_TOKEN} -gt 10 ]]; then
        echo "  Token generated (${#AK_TOKEN} chars)"
        echo "$AK_TOKEN" > "$TOKEN_FILE"
        break
    fi
    echo "  Attempt $attempt failed, retrying in 10s..."
    sleep 10
done

if [[ -z "$AK_TOKEN" ]] || [[ ${#AK_TOKEN} -lt 10 ]]; then
    echo "WARNING: Could not generate API token. Manual setup needed." >&2
    echo "  Run: podman exec authentik-server ak create_admin_token"
fi

# --- Wait for blueprints ---
echo "Waiting for worker to process blueprints (60s)..."
sleep 60

# --- Verify blueprints (if we have a token) ---
if [[ -n "$AK_TOKEN" ]]; then
    echo "Checking blueprint results..."
    AK_URL="http://localhost:9000"
    GROUPS=$(curl -sf -H "Authorization: Bearer ${AK_TOKEN}" \
        "${AK_URL}/api/v3/core/groups/" 2>/dev/null | jq '.pagination.count // 0' 2>/dev/null || echo 0)
    APPS=$(curl -sf -H "Authorization: Bearer ${AK_TOKEN}" \
        "${AK_URL}/api/v3/core/applications/" 2>/dev/null | jq '.pagination.count // 0' 2>/dev/null || echo 0)
    PROVIDERS=$(curl -sf -H "Authorization: Bearer ${AK_TOKEN}" \
        "${AK_URL}/api/v3/providers/all/" 2>/dev/null | jq '.pagination.count // 0' 2>/dev/null || echo 0)
    echo "  Groups: ${GROUPS}, Applications: ${APPS}, Providers: ${PROVIDERS}"

    if [[ "$GROUPS" -lt 3 ]] || [[ "$APPS" -lt 1 ]]; then
        echo "WARNING: Fewer objects than expected" >&2
        echo "  Check: podman logs authentik-worker | grep -i blueprint" >&2
    fi
fi

# --- Set test user passwords ---
if [[ -n "$AK_TOKEN" ]]; then
    echo "Setting test user passwords..."
    export AUTHENTIK_BOOTSTRAP_TOKEN="$AK_TOKEN"
    bash "${BENCH_DIR}/scripts/set-passwords.sh" || echo "  WARNING: password setting failed"
fi

# --- Configure apps that need API-based OIDC setup ---
echo "Configuring app OIDC via API..."
bash "${BENCH_DIR}/scripts/configure-apps.sh" || echo "  WARNING: app configuration had failures"

# --- Summary ---
echo ""
echo "=== Deployment complete ==="
echo "  Authentik:     http://localhost:9000"
echo "  Admin login:   akadmin / ${AUTHENTIK_BOOTSTRAP_PASSWORD}"
if [[ -n "$AK_TOKEN" ]]; then
    echo "  API token:     ${AK_TOKEN:0:8}... (saved to ${TOKEN_FILE})"
fi
echo "  Services:      podman-compose ps"
echo ""
echo "  Running containers:"
podman ps --format '  {{.Names}}\t{{.Status}}' 2>/dev/null | sort
echo ""
echo "  Next steps:"
echo "  1. Set *.${DOMAIN} A record to this VM's IP"
echo "  2. Run: make smoke-local"
