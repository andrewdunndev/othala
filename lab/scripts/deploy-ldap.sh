#!/usr/bin/env bash
# shellcheck disable=SC1091
# Phase 2 lab spike deploy: Kratos + glauth-kratos LDAP bridge.
#
# Builds the bridge image from /opt/auth-lab/ldap-bridge, generates a
# self-signed TLS cert for the LDAPS listener, brings up compose, waits
# for Kratos health, then creates a test identity via the admin API.
#
# This script is idempotent on the build and identity-create steps.

set -euo pipefail

AUTH_DIR="/opt/auth-lab"
COMPOSE_DIR="${AUTH_DIR}/lab/compose"
BRIDGE_DIR="${AUTH_DIR}/ldap-bridge"
TLS_DIR="${COMPOSE_DIR}/tls"

LDAP_TEST_USER="${LDAP_TEST_USER:-ldaptest}"
LDAP_TEST_EMAIL="${LDAP_TEST_EMAIL:-ldaptest@dunn.dev}"
LDAP_TEST_PASS="${LDAP_TEST_PASS:-ldappass1}"
LDAP_TEST_DISPLAY="${LDAP_TEST_DISPLAY:-LDAP Test}"

echo "=== Phase 2 deploy: glauth-kratos lab ==="

if [[ ! -f "${AUTH_DIR}/.env" ]]; then
    echo "ERROR: No .env file at ${AUTH_DIR}/.env" >&2
    exit 1
fi

set -a
source "${AUTH_DIR}/.env"
set +a
echo "Loaded .env (DOMAIN=${DOMAIN:-unset})"

for var in DOMAIN KRATOS_PG_PASS KRATOS_COOKIE_SECRET_CURRENT KRATOS_CIPHER_SECRET_CURRENT \
           KRATOS_UI_COOKIE_SECRET KRATOS_UI_CSRF_SECRET; do
    if [[ -z "${!var:-}" ]]; then
        echo "ERROR: Required variable ${var} is not set" >&2
        exit 1
    fi
done

# Allow _PREVIOUS slots to be empty on first provision.
: "${KRATOS_COOKIE_SECRET_PREVIOUS:=}"
: "${KRATOS_CIPHER_SECRET_PREVIOUS:=}"
export KRATOS_COOKIE_SECRET_PREVIOUS KRATOS_CIPHER_SECRET_PREVIOUS

# Ensure KRATOS_BRIDGE_ADMIN_TOKEN is present in the env file. Kratos OSS
# admin port does not enforce bearer auth (network-isolation only), so any
# non-empty string passes the bridge's config validator.
if ! grep -q '^KRATOS_BRIDGE_ADMIN_TOKEN=' "${AUTH_DIR}/.env"; then
    echo "Adding KRATOS_BRIDGE_ADMIN_TOKEN to .env (Kratos OSS ignores it)"
    {
        echo ""
        echo "KRATOS_BRIDGE_ADMIN_TOKEN=lab-dummy-token-not-checked-by-oss-kratos"
    } >> "${AUTH_DIR}/.env"
    set -a
    source "${AUTH_DIR}/.env"
    set +a
fi

# Force-link .env into compose dir so podman-compose picks it up. The
# rsync from the dev box drops a regular file at compose/.env which can
# go stale relative to /opt/auth-lab/.env; replace it with a symlink.
rm -f "${COMPOSE_DIR}/.env"
ln -sf "${AUTH_DIR}/.env" "${COMPOSE_DIR}/.env"

# 1. Build the bridge image -------------------------------------------------
echo ""
echo "--- Building glauth-kratos image ---"
BUILD_START=$(date +%s)
sudo podman build -t localhost/dunn.dev/glauth-kratos:lab -f "${BRIDGE_DIR}/Containerfile" "${BRIDGE_DIR}"
BUILD_END=$(date +%s)
BUILD_SECS=$((BUILD_END - BUILD_START))

IMAGE_SIZE=$(sudo podman image inspect localhost/dunn.dev/glauth-kratos:lab --format '{{.Size}}')
IMAGE_SIZE_MB=$(( IMAGE_SIZE / 1024 / 1024 ))
echo "Built in ${BUILD_SECS}s (image size: ${IMAGE_SIZE_MB} MB)"

# 2. Generate TLS material for the LDAPS listener ---------------------------
echo ""
echo "--- Generating self-signed TLS cert for LDAPS ---"
mkdir -p "${TLS_DIR}"
if [[ ! -f "${TLS_DIR}/glauth-cert.pem" ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
        -days 30 \
        -keyout "${TLS_DIR}/glauth-key.pem" \
        -out    "${TLS_DIR}/glauth-cert.pem" \
        -subj   "/CN=glauth-kratos.local" \
        -addext "subjectAltName=DNS:glauth-kratos,DNS:glauth-kratos.local,DNS:localhost,IP:127.0.0.1"
    chmod 644 "${TLS_DIR}/glauth-cert.pem"
    chmod 600 "${TLS_DIR}/glauth-key.pem"
    echo "Generated ${TLS_DIR}/glauth-{cert,key}.pem (CN=glauth-kratos.local, valid 30d)"
else
    echo "TLS cert already present: ${TLS_DIR}/glauth-cert.pem"
fi

# 3. Render Kratos config ---------------------------------------------------
echo ""
echo "--- Rendering Kratos config ---"
cd "$COMPOSE_DIR"
KRATOS_VARS='${KRATOS_PG_PASS} ${KRATOS_COOKIE_SECRET_CURRENT} ${KRATOS_COOKIE_SECRET_PREVIOUS} ${KRATOS_CIPHER_SECRET_CURRENT} ${KRATOS_CIPHER_SECRET_PREVIOUS}'
envsubst "$KRATOS_VARS" < kratos.lab.yml > kratos.rendered.yml
echo "Rendered: kratos.rendered.yml ($(wc -l < kratos.rendered.yml) lines)"

# 4. Bring up the stack -----------------------------------------------------
echo ""
echo "--- Pulling base images ---"
sudo podman-compose -f compose-ldap.yml pull 2>&1 | tail -10 || true

echo ""
echo "--- Starting services ---"
sudo podman-compose -f compose-ldap.yml up -d 2>&1

# 5. Wait for Kratos --------------------------------------------------------
echo ""
echo "--- Waiting for Kratos admin API ---"
MAX_WAIT=180
ELAPSED=0
while (( ELAPSED < MAX_WAIT )); do
    if sudo podman exec auth-kratos wget -qO- http://localhost:4434/admin/health/ready >/dev/null 2>&1; then
        echo "Kratos healthy after ${ELAPSED}s"
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done

if (( ELAPSED >= MAX_WAIT )); then
    echo "ERROR: Kratos did not become healthy within ${MAX_WAIT}s" >&2
    sudo podman logs auth-kratos 2>&1 | tail -40
    exit 1
fi

# 6. Create the test identity via Kratos admin API --------------------------
echo ""
echo "--- Creating test identity (${LDAP_TEST_USER}) ---"

# Idempotent: list existing first
EXISTING=$(sudo podman exec auth-kratos wget -qO- "http://localhost:4434/admin/identities" \
    | jq -r ".[] | select(.traits.username==\"${LDAP_TEST_USER}\") | .id" \
    || true)

if [[ -n "$EXISTING" ]]; then
    echo "Identity ${LDAP_TEST_USER} already exists (id=${EXISTING}); skipping create"
else
    PAYLOAD=$(cat <<JSON
{
  "schema_id": "family",
  "traits": {
    "username": "${LDAP_TEST_USER}",
    "email": "${LDAP_TEST_EMAIL}",
    "displayName": "${LDAP_TEST_DISPLAY}"
  },
  "credentials": {
    "password": {
      "config": {
        "password": "${LDAP_TEST_PASS}"
      }
    }
  }
}
JSON
)
    # podman exec doesn't take stdin gracefully here; write into a tmp file in the container.
    TMP_PAYLOAD="/tmp/identity-payload.json"
    echo "$PAYLOAD" | sudo podman exec -i auth-kratos sh -c "cat > ${TMP_PAYLOAD}"
    RESP=$(sudo podman exec auth-kratos wget -qO- \
        --header="Content-Type: application/json" \
        --post-file="${TMP_PAYLOAD}" \
        "http://localhost:4434/admin/identities" 2>&1) || {
        echo "ERROR: identity create failed:" >&2
        echo "$RESP" >&2
        exit 1
    }
    NEW_ID=$(echo "$RESP" | jq -r '.id // ""')
    if [[ -z "$NEW_ID" ]]; then
        echo "ERROR: identity create returned no id; raw response:" >&2
        echo "$RESP" >&2
        exit 1
    fi
    echo "Created ${LDAP_TEST_USER} (id=${NEW_ID})"
fi

# 7. Wait for bridge LDAPS to be reachable ----------------------------------
echo ""
echo "--- Waiting for glauth-kratos LDAPS ---"
ELAPSED=0
while (( ELAPSED < 60 )); do
    if sudo ss -ltn | grep -q ':636 '; then
        echo "Port 636 listening after ${ELAPSED}s"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if (( ELAPSED >= 60 )); then
    echo "ERROR: glauth-kratos LDAPS port 636 never appeared" >&2
    sudo podman logs auth-glauth-kratos 2>&1 | tail -40
    exit 1
fi

# 8. Install ldap-utils for validation --------------------------------------
echo ""
echo "--- Installing openldap-clients (for ldapsearch) ---"
if ! command -v ldapsearch >/dev/null 2>&1; then
    sudo dnf install -y --nodocs --setopt=install_weak_deps=False openldap-clients >/dev/null
fi
ldapsearch -VV 2>&1 | head -3 || true

echo ""
echo "=== Phase 2 deploy complete ==="
echo "  Kratos UI:     https://auth-lab.${DOMAIN}/"
echo "  Test user:     uid=${LDAP_TEST_USER},ou=users,dc=dunn,dc=dev / ${LDAP_TEST_PASS}"
echo "  LDAPS:         ldaps://localhost:636"
echo ""
echo "  Run validation: bash ${AUTH_DIR}/lab/scripts/test-ldap.sh"
echo ""
echo "  Containers:"
sudo podman ps --format '  {{.Names}}\t{{.Status}}' 2>/dev/null | sort
