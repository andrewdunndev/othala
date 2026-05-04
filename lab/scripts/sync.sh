#!/usr/bin/env bash
# Sync the auth/ repo to the lab VM. Uses plain rsync over the
# gcloud-managed SSH key, bypassing gcloud's wrapper (which mis-parses
# its own ssh-flag arg when invoked from rsync's -e).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
STATE_FILE="${PROJECT_DIR}/lab/.gcp-state"

if [[ ! -f "$STATE_FILE" ]]; then
    echo "ERROR: No .gcp-state at $STATE_FILE — run 'make lab-up' first" >&2
    exit 1
fi
# shellcheck source=/dev/null
source "$STATE_FILE"

REMOTE_DIR="/opt/auth-lab"
SSH_KEY="${HOME}/.ssh/google_compute_engine"
SSH_USER="${USER}"

if [[ ! -f "$SSH_KEY" ]]; then
    echo "ERROR: gcloud SSH key not found at $SSH_KEY — run 'gcloud compute ssh' once first" >&2
    exit 1
fi

SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

echo "=== Syncing $PROJECT_DIR -> ${SSH_USER}@${OUTER_IP}:${REMOTE_DIR} ==="

# Prep dir on VM (ensure user owns it)
ssh $SSH_OPTS "${SSH_USER}@${OUTER_IP}" \
    "sudo mkdir -p $REMOTE_DIR && sudo chown -R \$(id -u):\$(id -g) $REMOTE_DIR"

rsync -azP \
    --exclude='.git' \
    --exclude='.gcp-state' \
    --exclude='node_modules' \
    --exclude='portal/.astro' \
    --exclude='portal/dist' \
    --exclude='lab/.gcp-state' \
    -e "ssh $SSH_OPTS" \
    "${PROJECT_DIR}/" "${SSH_USER}@${OUTER_IP}:${REMOTE_DIR}/"

if [[ -f "${PROJECT_DIR}/lab/compose/.env" ]]; then
    scp $SSH_OPTS \
        "${PROJECT_DIR}/lab/compose/.env" "${SSH_USER}@${OUTER_IP}:${REMOTE_DIR}/.env"
    echo "Synced lab/compose/.env -> ${REMOTE_DIR}/.env"
fi

echo "=== Sync complete ==="
