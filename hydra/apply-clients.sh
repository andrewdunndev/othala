#!/usr/bin/env bash
# Apply OIDC client manifests under hydra/clients/ to a running Hydra.
#
# Usage (in lab or production):
#   HYDRA_ADMIN_URL=http://hydra:4445 ./apply-clients.sh
#
# Reads each YAML, transforms to JSON, calls Hydra admin API.
# Idempotent: existing clients are updated; new clients are created.
# Reads client_secret from environment variable named after the client_id
# in upper-case (e.g., KEEP_CLIENT_SECRET for client_id=keep).

set -euo pipefail

HYDRA_ADMIN_URL="${HYDRA_ADMIN_URL:?HYDRA_ADMIN_URL must be set, e.g. http://hydra:4445}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENTS_DIR="${SCRIPT_DIR}/clients"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required" >&2
    exit 1
fi
if ! command -v yq &>/dev/null; then
    echo "ERROR: yq is required (install via 'pip install yq' or 'brew install yq')" >&2
    exit 1
fi

apply_client() {
    local manifest="$1"
    local client_id
    client_id=$(yq -r '.client_id' "$manifest")

    local secret_var="${client_id^^}_CLIENT_SECRET"
    local secret="${!secret_var:-}"
    if [[ -z "$secret" ]]; then
        echo "ERROR: ${secret_var} not set in environment for ${client_id}" >&2
        return 1
    fi

    # Convert YAML to JSON, inject client_secret
    local body
    body=$(yq -j ". + {\"client_secret\": \"${secret}\"}" "$manifest")

    # Check if client exists
    local exists_status
    exists_status=$(curl -s -o /dev/null -w '%{http_code}' \
        "${HYDRA_ADMIN_URL}/admin/clients/${client_id}")

    if [[ "$exists_status" == "200" ]]; then
        echo "  updating ${client_id}"
        curl -sf -X PUT \
            -H 'Content-Type: application/json' \
            -d "$body" \
            "${HYDRA_ADMIN_URL}/admin/clients/${client_id}" >/dev/null
    elif [[ "$exists_status" == "404" ]]; then
        echo "  creating ${client_id}"
        curl -sf -X POST \
            -H 'Content-Type: application/json' \
            -d "$body" \
            "${HYDRA_ADMIN_URL}/admin/clients" >/dev/null
    else
        echo "ERROR: unexpected status ${exists_status} for ${client_id}" >&2
        return 1
    fi
}

echo "==> Applying Hydra client manifests against ${HYDRA_ADMIN_URL}"
for manifest in "${CLIENTS_DIR}"/*.yaml; do
    [[ -f "$manifest" ]] || continue
    apply_client "$manifest"
done
echo "==> Done"
