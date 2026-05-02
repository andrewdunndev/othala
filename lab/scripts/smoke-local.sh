#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

# smoke-local.sh -- validate Authentik config via localhost only.
# No DNS, no TLS, no Caddy. Tests the Authentik API and app container ports.

BENCH_DIR="/opt/auth-lab"

if [[ -f "${BENCH_DIR}/.env" ]]; then
    # shellcheck disable=SC1091
    set -a
    source "${BENCH_DIR}/.env"
    set +a
fi

AK_TOKEN="${AUTHENTIK_BOOTSTRAP_TOKEN:-}"
AK_URL="http://localhost:9000"
TOKEN_FILE="${BENCH_DIR}/.ak-token"

# Try token from env, then from file
if [[ -z "$AK_TOKEN" ]] && [[ -f "$TOKEN_FILE" ]]; then
    AK_TOKEN=$(cat "$TOKEN_FILE")
fi

PASSED=0
FAILED=0
SKIPPED=0

check() {
    local name="$1"
    shift
    printf "  %-55s " "$name"
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
    printf "  %-55s SKIP (%s)\n" "$name" "$reason"
    SKIPPED=$((SKIPPED + 1))
}

api_get() {
    curl -sf -H "Authorization: Bearer ${AK_TOKEN}" "${AK_URL}${1}"
}

api_has() {
    local path="$1"
    local count
    count=$(api_get "$path" | jq '.results | length')
    [[ "$count" -gt 0 ]]
}

api_count() {
    local path="$1"
    api_get "$path" | jq '.results | length'
}

echo "=== auth-lab Smoke Local ==="
echo "  Testing via localhost only -- no DNS, no TLS"
echo ""

# --- Infrastructure ---
echo "--- Infrastructure ---"
echo ""

check "Authentik server healthy" \
    curl -sf "${AK_URL}/-/health/live/"

check "Authentik API reachable" \
    curl -sf -o /dev/null "${AK_URL}/api/v3/root/config/"

# Check each container is running
for svc in authentik-server authentik-worker authentik-postgres bench-caddy \
           bench-vaultwarden bench-mealie bench-audiobookshelf bench-jellyfin \
           bench-navidrome bench-immich bench-immich-postgres; do
    check "Container: ${svc}" \
        podman ps --format '{{.Names}}' --filter "name=${svc}" --noheading | grep -q "${svc}"
done

echo ""

# --- App health checks (via container network) ---
echo "--- App Health (internal network) ---"
echo ""

check "Authentik :9000" \
    curl -sf -o /dev/null "${AK_URL}/-/health/live/"

# Check each app via podman exec through caddy (on the compose network)
check "Vaultwarden (keep) HTTP" \
    podman exec bench-caddy wget -q -O /dev/null --timeout=5 "http://vaultwarden:80/" 2>&1

check "Mealie (larder) HTTP" \
    podman exec bench-caddy wget -q -O /dev/null --timeout=5 "http://mealie:9000/" 2>&1

check "Audiobookshelf (listen) HTTP" \
    podman exec bench-caddy wget -q -O /dev/null --timeout=5 "http://audiobookshelf:80/healthcheck" 2>&1

check "Jellyfin (cinema) HTTP" \
    podman exec bench-caddy wget -q -O /dev/null --timeout=5 "http://jellyfin:8096/" 2>&1

check "Navidrome (tune) HTTP" \
    podman exec bench-caddy wget -q -O /dev/null --timeout=5 "http://navidrome:4533/" 2>&1

check "Immich (memory) HTTP" \
    podman exec bench-caddy wget -q -O /dev/null --timeout=5 "http://immich-server:2283/api/server/ping" 2>&1

echo ""

# --- Authentik API checks ---
if [[ -z "$AK_TOKEN" ]]; then
    skip "All Authentik API checks" "AUTHENTIK_BOOTSTRAP_TOKEN not set"
else
    echo "--- Authentik: Groups ---"
    echo ""

    check "Group: admin" \
        api_has '/api/v3/core/groups/?search=admin'
    check "Group: family" \
        api_has '/api/v3/core/groups/?search=family'
    check "Group: friends" \
        api_has '/api/v3/core/groups/?search=friends'
    check "Group: access-keep" \
        api_has '/api/v3/core/groups/?search=access-keep'
    check "Group: access-larder" \
        api_has '/api/v3/core/groups/?search=access-larder'
    check "Group: access-listen" \
        api_has '/api/v3/core/groups/?search=access-listen'
    check "Group: access-cinema" \
        api_has '/api/v3/core/groups/?search=access-cinema'
    check "Group: access-tune" \
        api_has '/api/v3/core/groups/?search=access-tune'
    check "Group: access-memory" \
        api_has '/api/v3/core/groups/?search=access-memory'

    echo ""
    echo "--- Authentik: Users ---"
    echo ""

    check "User: andrew.dunn" \
        api_has '/api/v3/core/users/?search=andrew.dunn'
    check "User: jane.dunn" \
        api_has '/api/v3/core/users/?search=jane.dunn'
    check "User: test.family" \
        api_has '/api/v3/core/users/?search=test.family'
    check "User: test.friend" \
        api_has '/api/v3/core/users/?search=test.friend'

    echo ""
    echo "--- Authentik: Providers ---"
    echo ""

    check "OAuth2 provider: keep (Vaultwarden)" \
        api_has '/api/v3/providers/oauth2/?search=keep'
    check "OAuth2 provider: larder (Mealie)" \
        api_has '/api/v3/providers/oauth2/?search=larder'
    check "OAuth2 provider: listen (Audiobookshelf)" \
        api_has '/api/v3/providers/oauth2/?search=listen'
    check "OAuth2 provider: memory (Immich)" \
        api_has '/api/v3/providers/oauth2/?search=memory'
    check "LDAP provider: cinema (Jellyfin)" \
        api_has '/api/v3/providers/ldap/?search=cinema'
    check "Proxy provider: tune (Navidrome)" \
        api_has '/api/v3/providers/proxy/?search=tune'

    echo ""
    echo "--- Authentik: Applications ---"
    echo ""

    for app in keep larder listen cinema tune memory; do
        check "Application: ${app}" \
            api_has "/api/v3/core/applications/?search=${app}"
    done

    echo ""
    echo "--- Authentik: Flows ---"
    echo ""

    check "Flow: dunn-authentication" \
        api_has '/api/v3/flows/instances/?search=dunn-authentication'
    check "Flow: dunn-passwordless" \
        api_has '/api/v3/flows/instances/?search=dunn-passwordless'

    echo ""
    echo "--- Authentik: Custom Config ---"
    echo ""

    check "Scope mapping: email_verified" \
        api_has '/api/v3/propertymappings/scope/?search=email_verified'
    check "Scope mapping: offline_access" \
        api_has '/api/v3/propertymappings/scope/?search=offline_access'

    echo ""
    echo "--- Authentik: OIDC Well-Known ---"
    echo ""

    for app in keep larder listen memory; do
        check "OIDC well-known: ${app}" \
            curl -sf -o /dev/null "${AK_URL}/application/o/${app}/.well-known/openid-configuration"
    done

    echo ""
    echo "--- Authentik: Policy Evaluation ---"
    echo ""

    # Test that andrew.dunn can access keep (should pass)
    ANDREW_ID=$(api_get '/api/v3/core/users/?search=andrew.dunn' | jq -r '.results[0].pk // empty')
    KEEP_SLUG="keep"
    if [[ -n "$ANDREW_ID" ]]; then
        check "Policy: andrew.dunn can access keep" \
            bash -c "curl -sf -H 'Authorization: Bearer ${AK_TOKEN}' '${AK_URL}/api/v3/core/applications/${KEEP_SLUG}/check_access/?for_user=${ANDREW_ID}' | jq -e '.passing == true'"
    else
        skip "Policy: andrew.dunn can access keep" "user not found"
    fi

    # Test that test.friend cannot access keep (should fail -- not in access-keep)
    FRIEND_ID=$(api_get '/api/v3/core/users/?search=test.friend' | jq -r '.results[0].pk // empty')
    if [[ -n "$FRIEND_ID" ]]; then
        check "Policy: test.friend denied keep" \
            bash -c "curl -sf -H 'Authorization: Bearer ${AK_TOKEN}' '${AK_URL}/api/v3/core/applications/${KEEP_SLUG}/check_access/?for_user=${FRIEND_ID}' | jq -e '.passing == false'"
    else
        skip "Policy: test.friend denied keep" "user not found"
    fi

    echo ""
    echo "--- Authentik: LDAP Outpost ---"
    echo ""

    check "LDAP outpost exists" \
        api_has '/api/v3/outposts/instances/?search=cinema'

    # Test LDAP bind if ldapsearch is available
    if command -v ldapsearch &>/dev/null; then
        check "LDAP bind (anonymous search)" \
            ldapsearch -x -H ldap://localhost:3389 -b "dc=dunn,dc=dev" -s base "(objectClass=*)" 2>&1 | grep -q "result"
    else
        skip "LDAP bind" "ldapsearch not installed"
    fi
fi

echo ""
echo "=== Results: ${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped ==="

if [[ "$FAILED" -gt 0 ]]; then
    exit 1
fi
