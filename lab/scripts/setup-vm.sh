#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="/opt/bench-sso-iac"
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
        shutdown -P "+${TTL_MIN}" "bench-sso-iac: auto-shutdown after ${TTL_MIN}min" &
        echo "Scheduled auto-shutdown in ${TTL_MIN} minutes"
    fi
fi

# --- Idempotency ---
if [[ -f "$MARKER" ]]; then
    echo "Setup already complete, skipping"
    exit 0
fi

echo "=== bench-sso-iac: VM setup ==="

# --- Install packages ---
echo "Installing podman and tools..."
dnf install -y --nodocs --setopt=install_weak_deps=False \
    podman \
    python3-pip \
    git \
    curl \
    jq \
    openldap-clients

pip3 install podman-compose 2>/dev/null || pip install podman-compose

echo "Installed: podman $(podman --version 2>/dev/null | awk '{print $NF}'), podman-compose $(podman-compose --version 2>/dev/null | awk '{print $NF}')"

# --- Enable root podman socket ---
systemctl enable --now podman.socket
echo "Podman socket: $(systemctl is-active podman.socket)"

# --- Firewall ---
if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    for svc in ssh http https; do
        firewall-cmd --add-service="$svc" 2>/dev/null || true
        firewall-cmd --permanent --add-service="$svc" 2>/dev/null || true
    done
    for port in 9000/tcp 9443/tcp 636/tcp; do
        firewall-cmd --add-port="$port" 2>/dev/null || true
        firewall-cmd --permanent --add-port="$port" 2>/dev/null || true
    done
    echo "Firewall: opened ssh, http, https, 636, 9000, 9443"
fi

# --- Clone repo ---
echo "Cloning bench-sso-iac..."
mkdir -p "$WORK_DIR"
git clone --depth 1 https://gitlab.com/dunn.dev/bench-sso-iac.git "${WORK_DIR}/repo" 2>/dev/null || true
if [[ -d "${WORK_DIR}/repo" ]]; then
    cp -r "${WORK_DIR}/repo/compose" "${WORK_DIR}/"
    cp -r "${WORK_DIR}/repo/blueprints" "${WORK_DIR}/"
    cp -r "${WORK_DIR}/repo/scripts" "${WORK_DIR}/"
    chmod +x "${WORK_DIR}/scripts/"*.sh
    rm -rf "${WORK_DIR}/repo"
    echo "Repo cloned and files copied"
fi

# --- Write .env from metadata ---
echo "Fetching .env from instance metadata..."
ENV_DATA=$(curl -sf -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/bench-env" 2>/dev/null || true)
if [[ -n "$ENV_DATA" ]]; then
    echo "$ENV_DATA" > "${WORK_DIR}/.env"
    echo ".env written from metadata"
else
    echo "WARNING: No bench-env metadata found. Create .env manually."
fi

# --- Fix blueprint permissions ---
chown -R 1000:1000 "${WORK_DIR}/blueprints" 2>/dev/null || true

touch "$MARKER"
echo "=== Setup complete ==="

# --- Auto-deploy if .env exists ---
if [[ -f "${WORK_DIR}/.env" ]] && [[ -f "${WORK_DIR}/scripts/deploy.sh" ]]; then
    echo "=== Starting auto-deploy ==="
    bash "${WORK_DIR}/scripts/deploy.sh" && touch "$DEPLOY_MARKER" || echo "Deploy failed"
fi
