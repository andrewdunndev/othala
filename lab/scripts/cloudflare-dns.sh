#!/usr/bin/env bash
# Create / delete auth-lab + keep-lab DNS A records pointing at the lab VM.
# Requires CF_API_TOKEN (Zone:DNS:Edit on dunn.dev) and CF_ZONE_ID.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
STATE_FILE="${PROJECT_DIR}/lab/.gcp-state"

: "${CF_API_TOKEN:?CF_API_TOKEN required (Zone:DNS:Edit on dunn.dev)}"
: "${CF_ZONE_ID:?CF_ZONE_ID required}"

DOMAIN_BASE="${DOMAIN_BASE:-test.dunn.dev}"
RECORDS=("auth-lab.${DOMAIN_BASE}" "keep-lab.${DOMAIN_BASE}")

cf_api() {
    curl -sf -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/$1" \
        "${@:2}"
}

dns_up() {
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "ERROR: No .gcp-state — run 'make lab-up' first" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$STATE_FILE"

    for name in "${RECORDS[@]}"; do
        echo "Creating A record ${name} → ${OUTER_IP}"
        cf_api "dns_records" \
            --data "{\"type\":\"A\",\"name\":\"${name}\",\"content\":\"${OUTER_IP}\",\"ttl\":120,\"proxied\":false}" \
            | jq -r '.success, .errors // empty' || true
    done
}

dns_down() {
    for name in "${RECORDS[@]}"; do
        echo "Looking up DNS record id for ${name}..."
        ID=$(cf_api "dns_records?name=${name}" | jq -r '.result[0].id // empty')
        if [[ -n "$ID" ]]; then
            echo "  Deleting record ${ID}"
            cf_api "dns_records/${ID}" -X DELETE >/dev/null
        else
            echo "  No record to delete"
        fi
    done
}

case "${1:-help}" in
    up)   dns_up ;;
    down) dns_down ;;
    *)
        echo "Usage: $0 {up|down}"
        exit 1 ;;
esac
