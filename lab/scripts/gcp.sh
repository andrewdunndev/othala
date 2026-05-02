#!/usr/bin/env bash
# shellcheck disable=SC1090
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

GCP_PROJECT="${GCP_PROJECT:-}"
GCP_ZONE="${GCP_ZONE:-us-east1-b}"
GCP_MACHINE_TYPE="${GCP_MACHINE_TYPE:-e2-standard-4}"
GCP_DISK_SIZE="${GCP_DISK_SIZE:-30}"
GCP_IMAGE_FAMILY="${GCP_IMAGE_FAMILY:-centos-stream-10}"
GCP_IMAGE_PROJECT="${GCP_IMAGE_PROJECT:-centos-cloud}"
VM_NAME="${BENCH_VM_NAME:-bench-sso-$(date +%s)}"
MAX_LIFETIME_SEC="${MAX_LIFETIME_SEC:-7200}"

STATE_FILE="${PROJECT_DIR}/.gcp-state"

resolve_image_family() {
    if [[ -n "$GCP_IMAGE_FAMILY" ]]; then
        echo "$GCP_IMAGE_FAMILY"
        return
    fi
    local family
    family=$(gcloud compute images list \
        --project="$GCP_IMAGE_PROJECT" \
        --filter="family~'^fedora-cloud-[0-9]+-x86-64$'" \
        --sort-by="~creationTimestamp" \
        --limit=1 \
        --format='value(family)' 2>/dev/null || true)
    if [[ -z "$family" ]]; then
        family="fedora-cloud-42-x86-64"
        echo "WARNING: Could not query image families, falling back to ${family}" >&2
    fi
    echo "$family"
}

gcp_up() {
    [[ -n "$GCP_PROJECT" ]] || { echo "ERROR: GCP_PROJECT is required" >&2; return 1; }

    local image_family
    image_family=$(resolve_image_family)

    echo "=== Creating bench VM: ${VM_NAME} ==="
    echo "  Project: ${GCP_PROJECT}"
    echo "  Zone:    ${GCP_ZONE}"
    echo "  Type:    ${GCP_MACHINE_TYPE}"
    echo "  Image:   ${GCP_IMAGE_PROJECT}/${image_family}"
    echo "  Disk:    ${GCP_DISK_SIZE}GB pd-standard"
    echo "  TTL:     ${MAX_LIFETIME_SEC}s"

    gcloud compute instances create "$VM_NAME" \
        --project="$GCP_PROJECT" \
        --zone="$GCP_ZONE" \
        --machine-type="$GCP_MACHINE_TYPE" \
        --image-family="$image_family" \
        --image-project="$GCP_IMAGE_PROJECT" \
        --boot-disk-size="${GCP_DISK_SIZE}GB" \
        --boot-disk-type=pd-standard \
        --metadata-from-file=startup-script="${SCRIPT_DIR}/setup-vm.sh"$([ -f "${PROJECT_DIR}/.env" ] && echo ",bench-env=${PROJECT_DIR}/.env") \
        --metadata="max-lifetime-sec=${MAX_LIFETIME_SEC}" \
        --tags=http-server,https-server \
        --scopes=default \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)'

    local outer_ip
    outer_ip=$(gcloud compute instances describe "$VM_NAME" \
        --project="$GCP_PROJECT" \
        --zone="$GCP_ZONE" \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)')

    cat > "$STATE_FILE" <<EOF
VM_NAME=${VM_NAME}
GCP_PROJECT=${GCP_PROJECT}
GCP_ZONE=${GCP_ZONE}
OUTER_IP=${outer_ip}
EOF

    echo "=== VM created: ${outer_ip} ==="

    # Background auto-delete safety net
    local ttl_min=$(( MAX_LIFETIME_SEC / 60 ))
    nohup bash -c "
        sleep ${MAX_LIFETIME_SEC}
        echo 'WARNING: Auto-deleting ${VM_NAME} after ${ttl_min} min TTL'
        gcloud compute instances delete '${VM_NAME}' \
            --project='${GCP_PROJECT}' \
            --zone='${GCP_ZONE}' \
            --quiet 2>/dev/null || true
    " >/dev/null 2>&1 &
    disown

    echo "Waiting for SSH..."
    if ! gcp_wait_ssh; then
        echo "ERROR: VM created but SSH never became available" >&2
        echo "  VM ${VM_NAME} is still running — clean up with: make gcp-down" >&2
        return 1
    fi

    echo "Waiting for startup script to complete..."
    if ! gcp_wait_setup; then
        echo "ERROR: Startup script did not complete" >&2
        echo "  Check: make gcp-ssh then journalctl -u google-startup-scripts" >&2
        return 1
    fi

    echo "=== VM ready ==="
    echo "  IP:  ${outer_ip}"
    echo "  SSH: make gcp-ssh"
    echo "  DNS: Set *.test.dunn.dev A record to ${outer_ip}"
}

gcp_wait_ssh() {
    local max=60 attempt=0
    while (( attempt < max )); do
        if gcloud compute ssh "$VM_NAME" \
            --project="$GCP_PROJECT" \
            --zone="$GCP_ZONE" \
            --command="true" \
            --ssh-flag="-o ConnectTimeout=10" \
            --ssh-flag="-o StrictHostKeyChecking=no" \
            --quiet 2>/dev/null; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 5
    done
    echo "ERROR: SSH timed out after $((max * 5))s" >&2
    return 1
}

gcp_wait_setup() {
    local max=60 attempt=0
    while (( attempt < max )); do
        if gcloud compute ssh "$VM_NAME" \
            --project="$GCP_PROJECT" \
            --zone="$GCP_ZONE" \
            --command="test -f /opt/bench-sso-iac/.setup-complete" \
            --ssh-flag="-o ConnectTimeout=10" \
            --ssh-flag="-o StrictHostKeyChecking=no" \
            --quiet 2>/dev/null; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 5
    done
    echo "ERROR: Startup script timed out after $((max * 5))s" >&2
    return 1
}

gcp_down() {
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "No .gcp-state file — nothing to tear down"
        return 0
    fi
    source "$STATE_FILE"
    echo "=== Deleting VM: ${VM_NAME} ==="
    gcloud compute instances delete "$VM_NAME" \
        --project="$GCP_PROJECT" \
        --zone="$GCP_ZONE" \
        --quiet 2>/dev/null || true
    rm -f "$STATE_FILE"
    echo "=== VM deleted ==="
}

gcp_ssh() {
    [[ -f "$STATE_FILE" ]] || { echo "ERROR: No .gcp-state -- run 'make gcp-up' first" >&2; return 1; }
    source "$STATE_FILE"
    gcloud compute ssh "$VM_NAME" \
        --project="$GCP_PROJECT" \
        --zone="$GCP_ZONE" \
        --ssh-flag="-o StrictHostKeyChecking=no" \
        --ssh-flag="-o ServerAliveInterval=30" \
        --ssh-flag="-o ServerAliveCountMax=10" \
        -- "$@"
}

gcp_scp_to() {
    local src="$1" dst="$2"
    [[ -f "$STATE_FILE" ]] || { echo "ERROR: No .gcp-state -- run 'make gcp-up' first" >&2; return 1; }
    source "$STATE_FILE"
    gcloud compute scp "$src" "${VM_NAME}:${dst}" \
        --project="$GCP_PROJECT" \
        --zone="$GCP_ZONE" \
        --scp-flag="-o StrictHostKeyChecking=no"
}

gcp_ip() {
    [[ -f "$STATE_FILE" ]] || { echo "ERROR: No .gcp-state — run 'make gcp-up' first" >&2; return 1; }
    source "$STATE_FILE"
    echo "$OUTER_IP"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    cmd="${1:-help}"
    shift || true
    case "$cmd" in
        up)   gcp_up ;;
        down) gcp_down ;;
        ssh)  gcp_ssh "$@" ;;
        scp)  gcp_scp_to "$@" ;;
        ip)   gcp_ip ;;
        *)
            echo "Usage: $0 {up|down|ssh|scp|ip}"
            echo "  up   — Create GCP VM"
            echo "  down — Destroy GCP VM"
            echo "  ssh  — SSH to VM (pass commands as args)"
            echo "  scp SRC DST — Copy file to VM"
            echo "  ip   — Print VM external IP"
            exit 1
            ;;
    esac
fi
