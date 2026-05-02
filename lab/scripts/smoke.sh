#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

BENCH_DIR="/opt/bench-sso-iac"

# Load env
if [[ -f "${BENCH_DIR}/.env" ]]; then
    # shellcheck disable=SC1091
    set -a
    source "${BENCH_DIR}/.env"
    set +a
fi

AK_TOKEN="${AUTHENTIK_BOOTSTRAP_TOKEN:-}"
AK_URL="http://localhost:9000"
DOMAIN="${DOMAIN:-test.dunn.dev}"

PASSED=0
FAILED=0
SKIPPED=0

check() {
    local name="$1"
    shift
    printf "  %-50s " "$name"
    local output
    if output=$("$@" 2>&1); then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        [[ -n "${output:-}" ]] && printf "    %s\n" "$output" | head -5
        FAILED=$((FAILED + 1))
    fi
}

skip() {
    local name="$1" reason="$2"
    printf "  %-50s SKIP (%s)\n" "$name" "$reason"
    SKIPPED=$((SKIPPED + 1))
}

# API helper — exits non-zero on HTTP error
api_get() {
    curl -sf -H "Authorization: Bearer ${AK_TOKEN}" "${AK_URL}${1}"
}

# Check that an API search returns at least one result
api_has() {
    local path="$1"
    local count
    count=$(api_get "$path" | jq '.results | length')
    [[ "$count" -gt 0 ]]
}

echo "=== bench-sso-iac Smoke Tests ==="
echo ""

# --- Infrastructure ---
echo "--- Infrastructure ---"
echo ""

check "Authentik server healthy" \
    curl -sf "${AK_URL}/-/health/live/"

check "Authentik API reachable" \
    curl -sf -o /dev/null "${AK_URL}/api/v3/root/config/"

check "Caddy running" \
    podman ps --format '{{.Names}}' --filter name=bench-caddy --noheading

check "Vaultwarden running" \
    podman ps --format '{{.Names}}' --filter name=bench-vaultwarden --noheading

check "Mealie running" \
    podman ps --format '{{.Names}}' --filter name=bench-mealie --noheading

check "Audiobookshelf running" \
    podman ps --format '{{.Names}}' --filter name=bench-audiobookshelf --noheading

check "Jellyfin running" \
    podman ps --format '{{.Names}}' --filter name=bench-jellyfin --noheading

check "Navidrome running" \
    podman ps --format '{{.Names}}' --filter name=bench-navidrome --noheading

check "Immich running" \
    podman ps --format '{{.Names}}' --filter name=bench-immich --noheading

# Service port checks (localhost, no TLS needed)
check "Authentik port 9000 open" \
    curl -sf -o /dev/null "http://localhost:9000/-/health/live/"

check "Caddy port 80 open" \
    curl -sf -o /dev/null -w '' "http://localhost:80/" || true

echo ""

# --- Authentik Configuration ---
if [[ -z "$AK_TOKEN" ]]; then
    skip "Authentik API checks" "AUTHENTIK_BOOTSTRAP_TOKEN not set"
else
    echo "--- Authentik Configuration ---"
    echo ""

    # Groups
    check "Group: admin" \
        api_has '/api/v3/core/groups/?search=admin'

    check "Group: family" \
        api_has '/api/v3/core/groups/?search=family'

    check "Group: friends" \
        api_has '/api/v3/core/groups/?search=friends'

    check "Group: access-keep" \
        api_has '/api/v3/core/groups/?search=access-keep'

    check "Group: access-cinema" \
        api_has '/api/v3/core/groups/?search=access-cinema'

    check "Group: access-tune" \
        api_has '/api/v3/core/groups/?search=access-tune'

    # Users
    check "User: andrew.dunn" \
        api_has '/api/v3/core/users/?search=andrew.dunn'

    check "User: test.family" \
        api_has '/api/v3/core/users/?search=test.family'

    check "User: test.friend" \
        api_has '/api/v3/core/users/?search=test.friend'

    # Providers
    check "OAuth2 provider: keep" \
        api_has '/api/v3/providers/oauth2/?search=keep'

    check "OAuth2 provider: larder" \
        api_has '/api/v3/providers/oauth2/?search=larder'

    check "OAuth2 provider: listen" \
        api_has '/api/v3/providers/oauth2/?search=listen'

    check "OAuth2 provider: memory" \
        api_has '/api/v3/providers/oauth2/?search=memory'

    check "LDAP provider: cinema" \
        api_has '/api/v3/providers/ldap/?search=cinema'

    check "Proxy provider: tune" \
        api_has '/api/v3/providers/proxy/?search=tune'

    # Applications
    check "Application: keep" \
        api_has '/api/v3/core/applications/?search=keep'

    check "Application: larder" \
        api_has '/api/v3/core/applications/?search=larder'

    check "Application: listen" \
        api_has '/api/v3/core/applications/?search=listen'

    check "Application: cinema" \
        api_has '/api/v3/core/applications/?search=cinema'

    check "Application: tune" \
        api_has '/api/v3/core/applications/?search=tune'

    check "Application: memory" \
        api_has '/api/v3/core/applications/?search=memory'

    # Custom config
    check "Scope mapping: email_verified" \
        api_has '/api/v3/propertymappings/scope/?search=email_verified'

    check "Flow: dunn-authentication" \
        api_has '/api/v3/flows/instances/?search=dunn-authentication'

    check "Flow: dunn-passwordless" \
        api_has '/api/v3/flows/instances/?search=dunn-passwordless'
fi

echo ""
echo "=== Results: ${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped ==="

if [[ "$FAILED" -gt 0 ]]; then
    exit 1
fi
