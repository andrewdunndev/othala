#!/usr/bin/env bash
# shellcheck disable=SC1091
set -euo pipefail

# configure-apps.sh — post-deploy OIDC configuration for apps that need
# API-based setup (cannot be configured via env vars alone).
#
# Apps configured here:
#   - Audiobookshelf (listen): PATCH /api/auth-settings
#   - Immich (memory): PUT /api/system-config
#
# Apps NOT configured here (env-var based, already set in compose):
#   - Vaultwarden (keep): SSO_* env vars
#   - Mealie (larder): OIDC_* env vars
#   - Navidrome (tune): forward auth (no app config)
#   - Jellyfin (cinema): LDAP plugin requires manual UI setup

BENCH_DIR="/opt/bench-sso-iac"

if [[ -f "${BENCH_DIR}/.env" ]]; then
    set -a
    source "${BENCH_DIR}/.env"
    set +a
fi

DOMAIN="${DOMAIN:-test.dunn.dev}"
AUTH_URL="http://authentik-server:9000"

PASSED=0
FAILED=0
SKIPPED=0

report() {
    local name="$1" status="$2"
    printf "  %-50s %s\n" "$name" "$status"
}

# --- Wait for app to be healthy ---
wait_for_app() {
    local name="$1" url="$2" max="${3:-60}"
    local elapsed=0
    while (( elapsed < max )); do
        if curl -sf -o /dev/null "$url" 2>/dev/null; then
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    echo "  WARNING: ${name} not ready after ${max}s at ${url}" >&2
    return 1
}

echo "=== Configuring app OIDC (post-deploy) ==="
echo ""

# --- Audiobookshelf ---
echo "--- Audiobookshelf (listen) ---"
echo ""

ABS_URL="http://audiobookshelf:80"
ABS_CONFIGURED=false

if wait_for_app "Audiobookshelf" "${ABS_URL}/healthcheck" 30; then
    # ABS needs an initial admin user before API works. On first launch it
    # shows a setup wizard. We create the root user via the API.
    # Check if setup is needed by trying to hit the auth-settings endpoint.
    ABS_TOKEN=""

    # Try to create root user (no-op if already exists)
    ROOT_RESP=$(curl -sf -X POST "${ABS_URL}/api/setup" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"'"${AUTHENTIK_BOOTSTRAP_PASSWORD}"'"}' 2>/dev/null || echo "exists")

    if [[ "$ROOT_RESP" != "exists" ]]; then
        # Extract token from setup response
        ABS_TOKEN=$(echo "$ROOT_RESP" | jq -r '.user.token // empty' 2>/dev/null)
    fi

    # If setup was already done, login instead
    if [[ -z "$ABS_TOKEN" ]]; then
        LOGIN_RESP=$(curl -sf -X POST "${ABS_URL}/login" \
            -H "Content-Type: application/json" \
            -d '{"username":"admin","password":"'"${AUTHENTIK_BOOTSTRAP_PASSWORD}"'"}' 2>/dev/null || true)
        ABS_TOKEN=$(echo "$LOGIN_RESP" | jq -r '.user.token // empty' 2>/dev/null)
    fi

    if [[ -n "$ABS_TOKEN" ]]; then
        # Configure OIDC
        ABS_OIDC=$(curl -sf -X PATCH "${ABS_URL}/api/auth-settings" \
            -H "Authorization: Bearer ${ABS_TOKEN}" \
            -H "Content-Type: application/json" \
            -d '{
                "authActiveAuthMethods": ["local", "openid"],
                "authOpenIDIssuerURL": "'"${AUTH_URL}/application/o/listen/"'",
                "authOpenIDClientID": "bench-listen",
                "authOpenIDClientSecret": "bench-listen-secret",
                "authOpenIDButtonText": "Login with Authentik",
                "authOpenIDAutoLaunch": false,
                "authOpenIDAutoRegister": true,
                "authOpenIDMatchExistingBy": "email",
                "authOpenIDGroupClaim": "groups"
            }' 2>/dev/null || echo "FAIL")

        if [[ "$ABS_OIDC" != "FAIL" ]]; then
            report "Audiobookshelf OIDC configured" "OK"
            ABS_CONFIGURED=true
            PASSED=$((PASSED + 1))
        else
            report "Audiobookshelf OIDC configuration" "FAIL"
            FAILED=$((FAILED + 1))
        fi
    else
        report "Audiobookshelf admin login" "FAIL (no token)"
        FAILED=$((FAILED + 1))
    fi
else
    report "Audiobookshelf" "SKIP (not ready)"
    SKIPPED=$((SKIPPED + 1))
fi

echo ""

# --- Immich ---
echo "--- Immich (memory) ---"
echo ""

IMMICH_URL="http://immich-server:2283"
IMMICH_CONFIGURED=false

if wait_for_app "Immich" "${IMMICH_URL}/api/server/ping" 60; then
    # Immich needs admin setup on first launch.
    # Create admin user via API (no-op if already exists).
    IMMICH_ADMIN_RESP=$(curl -sf -X POST "${IMMICH_URL}/api/auth/admin-sign-up" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Admin",
            "email": "'"${AUTHENTIK_BOOTSTRAP_EMAIL:-admin@dunn.dev}"'",
            "password": "'"${AUTHENTIK_BOOTSTRAP_PASSWORD}"'"
        }' 2>/dev/null || echo "exists")

    # Login to get token
    IMMICH_LOGIN=$(curl -sf -X POST "${IMMICH_URL}/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{
            "email": "'"${AUTHENTIK_BOOTSTRAP_EMAIL:-admin@dunn.dev}"'",
            "password": "'"${AUTHENTIK_BOOTSTRAP_PASSWORD}"'"
        }' 2>/dev/null || true)
    IMMICH_TOKEN=$(echo "$IMMICH_LOGIN" | jq -r '.accessToken // empty' 2>/dev/null)

    if [[ -n "$IMMICH_TOKEN" ]]; then
        # Get current config, merge OAuth settings, PUT back
        CURRENT_CONFIG=$(curl -sf -H "Authorization: Bearer ${IMMICH_TOKEN}" \
            "${IMMICH_URL}/api/system-config" 2>/dev/null || echo "{}")

        if [[ "$CURRENT_CONFIG" != "{}" ]]; then
            UPDATED_CONFIG=$(echo "$CURRENT_CONFIG" | jq '.oauth = {
                "enabled": true,
                "autoLaunch": false,
                "autoRegister": true,
                "buttonText": "Login with Authentik",
                "clientId": "bench-memory",
                "clientSecret": "bench-memory-secret",
                "issuerUrl": "'"${AUTH_URL}/application/o/memory/"'",
                "scope": "openid email profile",
                "signingAlgorithm": "RS256",
                "profileSigningAlgorithm": "none",
                "tokenEndpointAuthMethod": "client_secret_post",
                "timeout": 30000,
                "defaultStorageQuota": 0,
                "storageLabelClaim": "preferred_username",
                "storageQuotaClaim": "immich_quota"
            }' 2>/dev/null)

            IMMICH_RESULT=$(curl -sf -X PUT "${IMMICH_URL}/api/system-config" \
                -H "Authorization: Bearer ${IMMICH_TOKEN}" \
                -H "Content-Type: application/json" \
                -d "$UPDATED_CONFIG" 2>/dev/null || echo "FAIL")

            if [[ "$IMMICH_RESULT" != "FAIL" ]]; then
                report "Immich OIDC configured" "OK"
                IMMICH_CONFIGURED=true
                PASSED=$((PASSED + 1))
            else
                report "Immich OIDC configuration" "FAIL"
                FAILED=$((FAILED + 1))
            fi
        else
            report "Immich config read" "FAIL"
            FAILED=$((FAILED + 1))
        fi
    else
        report "Immich admin login" "FAIL (no token)"
        FAILED=$((FAILED + 1))
    fi
else
    report "Immich" "SKIP (not ready)"
    SKIPPED=$((SKIPPED + 1))
fi

echo ""
echo "=== App configuration: ${PASSED} ok, ${FAILED} failed, ${SKIPPED} skipped ==="

if [[ "$FAILED" -gt 0 ]]; then
    exit 1
fi
