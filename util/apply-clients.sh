#!/usr/bin/env bash
# Apply OIDC client manifests to a running Hydra.
#
# v0.1.4: this script ships in the auth-util image
# (registry.gitlab.com/dunn.dev/othala/util:<tag>). It reads manifest
# YAMLs from $CLIENTS_DIR (default /etc/util/manifests/) and
# POSTs/PUTs each to ${HYDRA_ADMIN_URL}/admin/clients.
#
# Invocation patterns:
#
#   1. Operator-driven via iac:
#        cd dunn.dev/iac && make auth-apply-clients HOST=carmine
#      iac wraps:
#        podman run --rm --network=auth ... auth-util:vX
#      with $HYDRA_ADMIN_URL + per-client secrets pulled from sops.
#
#   2. Lab compose end-to-end validation:
#        podman run --rm --network=auth_default \
#          -v $(pwd)/hydra/clients:/etc/util/manifests:ro \
#          -e HYDRA_ADMIN_URL=http://auth-hydra:4445 \
#          -e KEEP_CLIENT_SECRET=... \
#          dunn.dev/othala-util:lab
#
# Namespace separation (per adversarial review C3 / D6):
#   The yaml files have two top-level blocks:
#     oidc:    forwarded to Hydra (client_id, redirect_uris, etc.)
#     consent: read by the consent service only (roles, group_role_map,
#              emit_groups_claim, skip_access_check)
#   This script extracts ONLY the oidc: block and posts that to Hydra.
#   Anything outside oidc: is consent-service-only and must not appear
#   in the Hydra client object.
#
# Optional environment:
#   HYDRA_ADMIN_URL       Default: http://auth-hydra:4445 (the iac
#                         quadlet network name). Override for other
#                         topologies.
#   CLIENTS_DIR           Default: /etc/util/manifests (set by the
#                         Containerfile). Override for non-default
#                         mount points.
#   CONSENT_RELOAD_HOOK   Command to run after a successful apply,
#                         e.g. "kill -HUP $(cat /run/consent.pid)" or
#                         a systemctl reload-or-restart equivalent.
#                         Optional; if unset, the consent service
#                         must be reloaded by hand.
#   DRY_RUN=1             Print the JSON body that would be sent to
#                         Hydra and exit. Useful for diff-checking
#                         the namespace split.
#
# Reads each YAML, transforms to JSON (oidc: block only), calls the
# Hydra admin API. Idempotent: existing clients are updated; new
# clients are created. Reads client_secret from environment variable
# named after the client_id in upper-case (e.g., KEEP_CLIENT_SECRET
# for client_id=keep). The c_c-only llm client does not need a
# redirect URI separately; same env var convention applies.

set -euo pipefail

CLIENTS_DIR="${CLIENTS_DIR:-/etc/util/manifests}"
HYDRA_ADMIN_URL="${HYDRA_ADMIN_URL:-http://auth-hydra:4445}"
DRY_RUN="${DRY_RUN:-0}"

if [[ "$DRY_RUN" != "1" ]]; then
    : "${HYDRA_ADMIN_URL:?HYDRA_ADMIN_URL must be set, e.g. http://hydra:4445}"
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required" >&2
    exit 1
fi
if ! command -v yq &>/dev/null; then
    echo "ERROR: yq is required (install via 'pip install yq' or 'brew install yq')" >&2
    exit 1
fi

# validate_manifest checks the yaml structure before we extract anything.
# Both oidc: and consent: blocks must be present (mappings, possibly
# empty), and oidc.client_id must be non-empty. Apply-clients does not
# lint roles / group_role_map; the consent service does that on load
# (--validate-manifests).
#
# Works with both python-yq (kislyuk) — type returns "object" — and
# mikefarah/yq — type returns "!!map".
validate_manifest() {
    local manifest="$1"
    local has_oidc has_consent client_id

    has_oidc=$(yq -r '.oidc | type' "$manifest" 2>/dev/null || echo "null")
    has_consent=$(yq -r '.consent | type' "$manifest" 2>/dev/null || echo "null")

    case "$has_oidc" in
        object|"!!map") : ;;
        *)
            echo "ERROR: ${manifest}: missing or non-object 'oidc:' block (got: ${has_oidc})" >&2
            return 1
            ;;
    esac
    case "$has_consent" in
        object|"!!map") : ;;
        *)
            echo "ERROR: ${manifest}: missing 'consent:' block (use 'consent: {}' if no role config; got: ${has_consent})" >&2
            return 1
            ;;
    esac

    client_id=$(yq -r '.oidc.client_id' "$manifest")
    if [[ -z "$client_id" || "$client_id" == "null" ]]; then
        echo "ERROR: ${manifest}: oidc.client_id is empty" >&2
        return 1
    fi
}

apply_client() {
    local manifest="$1"
    local client_id
    client_id=$(yq -r '.oidc.client_id' "$manifest")

    # bash 3.2 (macOS default) lacks ${VAR^^}; use tr for portability.
    local secret_var
    secret_var="$(printf '%s' "$client_id" | tr '[:lower:]' '[:upper:]')_CLIENT_SECRET"
    local secret="${!secret_var:-}"
    if [[ -z "$secret" && "$DRY_RUN" != "1" ]]; then
        echo "ERROR: ${secret_var} not set in environment for ${client_id}" >&2
        return 1
    fi

    # Extract ONLY the oidc: block + inject client_secret. Everything
    # under consent: stays out of the body sent to Hydra.
    local body
    if [[ "$DRY_RUN" == "1" ]]; then
        # Skip secret injection so the dry-run output is safe to print.
        body=$(yq -j '.oidc' "$manifest")
    else
        body=$(yq -j ".oidc + {\"client_secret\": \"${secret}\"}" "$manifest")
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        echo "==> ${client_id} (DRY_RUN): would post the following body to Hydra:"
        echo "$body" | jq .
        return 0
    fi

    # Check if client exists.
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

# trigger_consent_reload runs CONSENT_RELOAD_HOOK if set. The consent
# service rereads hydra/clients/*.yaml on SIGHUP; the hook is the
# operator-supplied command that delivers that signal (kill -HUP <pid>,
# systemctl reload, podman kill --signal HUP, etc.).
trigger_consent_reload() {
    if [[ -z "${CONSENT_RELOAD_HOOK:-}" ]]; then
        return 0
    fi
    echo "==> Triggering consent service reload via CONSENT_RELOAD_HOOK"
    if ! eval "$CONSENT_RELOAD_HOOK"; then
        echo "WARN: CONSENT_RELOAD_HOOK exited non-zero. Consent service may still be on the old manifest set; reload by hand." >&2
        return 1
    fi
}

if [[ "$DRY_RUN" == "1" ]]; then
    echo "==> Dry run: validating and printing oidc: blocks for hydra/clients/*.yaml"
else
    echo "==> Applying Hydra client manifests against ${HYDRA_ADMIN_URL}"
fi

for manifest in "${CLIENTS_DIR}"/*.yaml; do
    [[ -f "$manifest" ]] || continue
    validate_manifest "$manifest"
done

for manifest in "${CLIENTS_DIR}"/*.yaml; do
    [[ -f "$manifest" ]] || continue
    apply_client "$manifest"
done

if [[ "$DRY_RUN" != "1" ]]; then
    trigger_consent_reload
fi

echo "==> Done"
