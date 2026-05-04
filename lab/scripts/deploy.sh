#!/usr/bin/env bash
# shellcheck disable=SC1091
# Phase 1 lab spike deploy: bring up Kratos+Hydra+reference-consent+Vaultwarden,
# wait for health, register the keep-lab OIDC client.

set -euo pipefail

AUTH_DIR="/opt/auth-lab"
COMPOSE_DIR="${AUTH_DIR}/lab/compose"

echo "=== Deploying auth-lab spike ==="

if [[ ! -f "${AUTH_DIR}/.env" ]]; then
    echo "ERROR: No .env file at ${AUTH_DIR}/.env" >&2
    exit 1
fi

set -a
source "${AUTH_DIR}/.env"
set +a
echo "Loaded .env (DOMAIN=${DOMAIN:-unset})"

for var in DOMAIN POSTGRES_PASSWORD KRATOS_PG_PASS HYDRA_PG_PASS \
           KRATOS_COOKIE_SECRET_CURRENT KRATOS_CIPHER_SECRET_CURRENT \
           HYDRA_SYSTEM_SECRET HYDRA_COOKIE_SECRET_CURRENT HYDRA_PAIRWISE_SALT \
           KEEP_CLIENT_SECRET CONSENT_ADMIN_BEARER; do
    if [[ -z "${!var:-}" ]]; then
        echo "ERROR: Required variable ${var} is not set" >&2
        exit 1
    fi
done

# H3 rotation slots: both _CURRENT and _PREVIOUS are populated with
# distinct secrets on first provision (gen-secrets.sh seeds both). If
# any _PREVIOUS slot is empty, abort: an empty entry in Kratos or Hydra
# `secrets.cookie` / `secrets.cipher` is a YAML schema violation and
# the service refuses to boot. Treat this as a misconfigured .env, not
# something to paper over with sed.
for var in KRATOS_COOKIE_SECRET_PREVIOUS KRATOS_CIPHER_SECRET_PREVIOUS HYDRA_COOKIE_SECRET_PREVIOUS; do
    if [[ -z "${!var:-}" ]]; then
        echo "ERROR: ${var} is empty. Re-run lab/scripts/gen-secrets.sh; both _CURRENT and _PREVIOUS rotation slots must carry distinct values." >&2
        exit 1
    fi
done

cd "$COMPOSE_DIR"

if [[ ! -f "${COMPOSE_DIR}/.env" ]]; then
    ln -sf "${AUTH_DIR}/.env" "${COMPOSE_DIR}/.env"
fi

# Pre-render Kratos / Hydra config: substitute ${VAR} placeholders.
# Kratos and Hydra do not natively interpolate ${VAR} in YAML; their config
# loader treats it as a literal string. We render the YAMLs through envsubst
# and mount the rendered version into the containers.
echo "Rendering Kratos + Hydra configs (envsubst)..."
KRATOS_VARS='${DOMAIN} ${KRATOS_PG_PASS} ${KRATOS_COOKIE_SECRET_CURRENT} ${KRATOS_COOKIE_SECRET_PREVIOUS} ${KRATOS_CIPHER_SECRET_CURRENT} ${KRATOS_CIPHER_SECRET_PREVIOUS}'
HYDRA_VARS='${DOMAIN} ${HYDRA_PG_PASS} ${HYDRA_SYSTEM_SECRET} ${HYDRA_COOKIE_SECRET_CURRENT} ${HYDRA_COOKIE_SECRET_PREVIOUS} ${HYDRA_PAIRWISE_SALT}'
envsubst "$KRATOS_VARS" < kratos.lab.yml > kratos.rendered.yml
envsubst "$HYDRA_VARS"  < hydra.lab.yml  > hydra.rendered.yml

echo "Rendered: kratos.rendered.yml ($(wc -l < kratos.rendered.yml) lines), hydra.rendered.yml ($(wc -l < hydra.rendered.yml) lines)"

# Build local images that aren't pulled from a registry. Skip if
# already present (idempotent re-deploy).
echo "Building local images (consent + portal) if needed..."
if ! podman image exists dunn.dev/consent:lab; then
    echo "  building dunn.dev/consent:lab"
    (cd "${AUTH_DIR}/consent" && podman build -t dunn.dev/consent:lab .) | tail -5
fi
if ! podman image exists dunn.dev/auth-portal:lab; then
    echo "  building dunn.dev/auth-portal:lab (context = auth repo root)"
    (cd "${AUTH_DIR}" && podman build -t dunn.dev/auth-portal:lab -f portal/Containerfile .) | tail -5
fi

echo "Pulling registry images..."
podman-compose pull 2>&1 | tail -10 || true

echo "Starting services..."
podman-compose up -d 2>&1

# Wait for Hydra (the slowest dependency before client registration)
echo "Waiting for Hydra admin API..."
MAX_WAIT=180
ELAPSED=0
while (( ELAPSED < MAX_WAIT )); do
    if podman exec auth-hydra wget -qO- http://localhost:4445/health/ready >/dev/null 2>&1; then
        echo "Hydra healthy after ${ELAPSED}s"
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done

if (( ELAPSED >= MAX_WAIT )); then
    echo "ERROR: Hydra did not become healthy within ${MAX_WAIT}s" >&2
    podman logs auth-hydra 2>&1 | tail -30
    exit 1
fi

# Register the keep-lab OIDC client (Vaultwarden's exposed client_id;
# kept registered separately because the lab Vaultwarden uses its own
# host and redirect path).
echo "Registering keep-lab OIDC client in Hydra..."
podman exec auth-hydra hydra create client \
    --endpoint http://localhost:4445 \
    --id keep-lab \
    --secret "${KEEP_CLIENT_SECRET}" \
    --name "Vaultwarden Lab" \
    --grant-type authorization_code,refresh_token \
    --response-type code \
    --scope openid,email,profile,offline_access \
    --redirect-uri "https://keep-lab.${DOMAIN}/identity/connect/oidc-signin" \
    --post-logout-callback "https://keep-lab.${DOMAIN}/" \
    --token-endpoint-auth-method client_secret_basic \
    --skip-consent \
    --format json 2>&1 | tail -20 || \
    echo "  (client may already exist, that's OK)"

# Apply production OIDC client manifests. apply-clients.sh reads
# hydra/clients/*.yaml and POSTs the oidc: block to Hydra. Run from
# the host VM against the published Hydra container IP. The lab VM's
# setup script (setup-vm.sh) installs jq; yq comes from podman-compose
# install since the dnf yq is the wrong yq (kislyuk python-yq is what
# this script targets).
echo "Applying production OIDC client manifests..."
if ! command -v yq >/dev/null 2>&1; then
    echo "  installing yq (python-yq) via pip..."
    pip3 install --quiet yq 2>/dev/null || pip install --quiet yq 2>/dev/null || true
fi
HYDRA_IP=$(podman inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' auth-hydra 2>/dev/null || echo "")
if [[ -n "$HYDRA_IP" ]]; then
    HYDRA_ADMIN_URL="http://${HYDRA_IP}:4445" \
        bash "${AUTH_DIR}/hydra/apply-clients.sh" 2>&1 | tail -30 || \
        echo "  apply-clients had failures (some manifests may have prod-only constraints)"
else
    echo "  WARN: could not resolve auth-hydra container IP; skipping apply-clients"
fi

echo ""
echo "=== Lab deployment complete ==="
echo "  Kratos:    https://auth-lab.${DOMAIN}/self-service/registration/browser"
echo "  Hydra:     https://auth-lab.${DOMAIN}/.well-known/openid-configuration"
echo "  Vaultwarden: https://keep-lab.${DOMAIN}"
echo ""
echo "  Running containers:"
podman ps --format '  {{.Names}}\t{{.Status}}' 2>/dev/null | sort
