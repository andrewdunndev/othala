#!/usr/bin/env bash
set -euo pipefail

# Set passwords for test users via Authentik API
# Run after deploy.sh when blueprints have been applied

BENCH_DIR="/opt/bench-sso-iac"

if [[ -f "${BENCH_DIR}/.env" ]]; then
    set -a
    source "${BENCH_DIR}/.env"
    set +a
fi

AK_TOKEN="${AUTHENTIK_BOOTSTRAP_TOKEN:-}"
AK_URL="http://localhost:9000"
TEST_PASSWORD="${TEST_USER_PASSWORD:-bench-test-pass}"
TOKEN_FILE="${BENCH_DIR}/.ak-token"

# Try token from env, then from file
if [[ -z "$AK_TOKEN" ]] && [[ -f "$TOKEN_FILE" ]]; then
    AK_TOKEN=$(cat "$TOKEN_FILE")
fi

if [[ -z "$AK_TOKEN" ]]; then
    echo "ERROR: No API token. Set AUTHENTIK_BOOTSTRAP_TOKEN or run deploy.sh first." >&2
    exit 1
fi

set_password() {
    local username="$1"
    local password="$2"

    # Find user ID
    local user_id
    user_id=$(curl -sf -H "Authorization: Bearer ${AK_TOKEN}" \
        "${AK_URL}/api/v3/core/users/?search=${username}" | jq -r '.results[0].pk // empty')

    if [[ -z "$user_id" ]]; then
        echo "  SKIP: User ${username} not found"
        return
    fi

    # Set password
    curl -sf -X POST -H "Authorization: Bearer ${AK_TOKEN}" \
        -H "Content-Type: application/json" \
        "${AK_URL}/api/v3/core/users/${user_id}/set_password/" \
        -d "{\"password\": \"${password}\"}" >/dev/null

    echo "  OK: ${username} password set"
}

echo "=== Setting test user passwords ==="
set_password "andrew.dunn" "$TEST_PASSWORD"
set_password "jane.dunn" "$TEST_PASSWORD"
set_password "test.family" "$TEST_PASSWORD"
set_password "test.friend" "$TEST_PASSWORD"
echo "=== Done ==="
echo ""
echo "Test credentials:"
echo "  andrew.dunn / ${TEST_PASSWORD}"
echo "  jane.dunn / ${TEST_PASSWORD}"
echo "  test.family / ${TEST_PASSWORD}"
echo "  test.friend / ${TEST_PASSWORD}"
