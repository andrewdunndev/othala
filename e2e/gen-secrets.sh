#!/usr/bin/env bash
# gen-secrets.sh: emit per-run e2e secrets to stdout in .env format (used by validate.sh).
# Usage: bash e2e/gen-secrets.sh > e2e/.env

set -euo pipefail

gen()       { openssl rand -hex 32; }
gen_short() { openssl rand -hex 16; }
# gen_alnum: exactly 32 alphanumerics; 48 base64 bytes leave >32 survivors, the loop retries the rare miss.
gen_alnum() {
    local s
    while true; do
        s=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 32)
        [[ ${#s} -eq 32 ]] && break
    done
    printf '%s' "$s"
}

# AUTH_REGISTRY is the registry root (the othala app image); AUTH_VERSION is the tag.
AUTH_REGISTRY="${AUTH_REGISTRY:-registry.gitlab.com/dunn.dev/othala}"
AUTH_VERSION="${AUTH_VERSION:-latest}"

# One value per rotation slot, as in production: Ory v26.2.0 enforces uniqueItems on these
# arrays, so never two identical slots and no _PREVIOUS at rest.
kratos_cookie=$(gen)
kratos_cipher=$(gen_short)
hydra_cookie=$(gen)

cat <<EOF
AUTH_REGISTRY=${AUTH_REGISTRY}
AUTH_VERSION=${AUTH_VERSION}

POSTGRES_PASSWORD=$(gen_alnum)
KRATOS_PG_PASS=$(gen_alnum)
HYDRA_PG_PASS=$(gen_alnum)

# SMTP: mailpit catches Kratos courier and portal contact-form mail via one shared URI
# (kratos.yml courier.smtp.connection_uri, lib/mailer.ts). ?disable_starttls=true is required:
# Kratos v26.2.0 defaults to MandatoryStartTLS and abandons every message against plain SMTP.
OTHALA_SMTP_CONNECTION_URI=smtp://mailpit:1025/?disable_starttls=true
OTHALA_CONTACT_RECIPIENT=ops@othala.test

# Instance identity: auth.othala.test is the Caddy edge alias (compose net, no DNS). No tracing
# endpoint is set, so the tracing blocks are dropped from the rendered configs.
OTHALA_PUBLIC_URL=http://auth.othala.test
OTHALA_APEX=othala.test
OTHALA_INSTANCE_NAME='Othala Lab'

# The e2e network is flat, so the admin APIs bind all interfaces; deployments bind them to the
# admin-plane IP.
KRATOS_ADMIN_BIND_HOST=0.0.0.0
HYDRA_ADMIN_BIND_HOST=0.0.0.0

# Kratos cookie + cipher and Hydra cookie: one active secret each.
KRATOS_COOKIE_SECRET_CURRENT=${kratos_cookie}
KRATOS_CIPHER_SECRET_CURRENT=${kratos_cipher}

# Hydra
HYDRA_SYSTEM_SECRET=$(gen)
HYDRA_COOKIE_SECRET_CURRENT=${hydra_cookie}

# Admin credentials, shared by the validate.sh seed and the Playwright fixtures (test-only values).
ADMIN_EMAIL=admin@othala.test
ADMIN_USERNAME=admin
ADMIN_PASSWORD=othala-testpass-2026
RECOVERY_ADMIN_EMAIL=admin.recovery@othala.test
RECOVERY_ADMIN_USERNAME=admin.recovery
RECOVERY_ADMIN_PASSWORD=othala-testpass-2026

# Admin authority is the metadata_admin.admin marker; RECOVERY_GATE_SECRET guards the Kratos
# webhooks on the loopback admin port.
RECOVERY_GATE_SECRET=$(gen)

# App CSRF tokens (HIGH-1)
CSRF_SECRET=$(gen)

# Per-client OIDC secrets: <SLUG>_CLIENT_SECRET for each e2e/manifests fixture with an oidc:
# block (client_id upper-cased; promptdesk.yaml's client_id is "promptdesk").
GRAFANA_CLIENT_SECRET=$(gen)
AUDIOBOOKSHELF_CLIENT_SECRET=$(gen)
PROMPTDESK_CLIENT_SECRET=$(gen)
EOF
