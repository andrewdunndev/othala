#!/usr/bin/env bash
# GCP VM startup script for Phase 1 lab spike.
# Installs podman + podman-compose, opens firewall, waits for sync.
set -euo pipefail

WORK_DIR="/opt/auth-lab"
MARKER="${WORK_DIR}/.setup-complete"
DEPLOY_MARKER="${WORK_DIR}/.deploy-complete"

# --- Auto-shutdown on GCP ---
is_gcp() {
    curl -sf -m 2 -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/id" >/dev/null 2>&1
}

if is_gcp; then
    shutdown -c 2>/dev/null || true
    TTL_SEC=$(curl -sf -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/max-lifetime-sec" 2>/dev/null || echo "7200")
    TTL_MIN=$(( TTL_SEC / 60 ))
    if (( TTL_MIN > 0 )); then
        shutdown -P "+${TTL_MIN}" "auth-lab: auto-shutdown after ${TTL_MIN}min" &
        echo "Scheduled auto-shutdown in ${TTL_MIN} minutes"
    fi
fi

if [[ -f "$MARKER" ]]; then
    echo "Setup already complete, skipping"
    exit 0
fi

echo "=== auth-lab: VM setup ==="

dnf install -y --nodocs --setopt=install_weak_deps=False \
    podman \
    python3-pip \
    git \
    curl \
    jq

pip3 install podman-compose 2>/dev/null || pip install podman-compose

echo "Installed: podman $(podman --version 2>/dev/null | awk '{print $NF}'), podman-compose $(podman-compose --version 2>/dev/null | awk '{print $NF}')"

systemctl enable --now podman.socket
echo "Podman socket: $(systemctl is-active podman.socket)"

if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    for svc in ssh http https; do
        firewall-cmd --add-service="$svc" 2>/dev/null || true
        firewall-cmd --permanent --add-service="$svc" 2>/dev/null || true
    done
    echo "Firewall: opened ssh, http, https"
fi

mkdir -p "$WORK_DIR"

ENV_DATA=$(curl -sf -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/auth-env" 2>/dev/null || true)
if [[ -n "$ENV_DATA" ]]; then
    echo "$ENV_DATA" > "${WORK_DIR}/.env"
    echo ".env written from metadata"
else
    echo "No auth-env metadata; expecting .env via sync"
fi

touch "$MARKER"
echo "=== Setup complete ==="
echo ""
echo "Next: run 'make sync' from your dev machine to push the auth repo."
echo "Auto-deploy fires once .env and lab/scripts/deploy.sh are present."

# Watch for sync, then auto-deploy
(
    while [[ ! -f "${WORK_DIR}/.env" ]] || [[ ! -f "${WORK_DIR}/lab/scripts/deploy.sh" ]]; do
        sleep 5
    done
    echo "=== Sync detected, starting auto-deploy ==="
    chmod +x "${WORK_DIR}/lab/scripts/"*.sh 2>/dev/null || true
    bash "${WORK_DIR}/lab/scripts/deploy.sh" && touch "$DEPLOY_MARKER" || echo "Deploy failed"
) &
disown
