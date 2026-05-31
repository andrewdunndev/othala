#!/usr/bin/env bash
# gen-secrets.sh — emit per-run lab secrets to stdout in .env format.
#
# Used by validate.sh inside the CI lab VM. Every secret is freshly
# generated per run; nothing persists past the VM's lifetime.
#
# Usage:
#   bash lab/ci/gen-secrets.sh > lab/ci/.env

set -euo pipefail

gen()       { openssl rand -hex 32; }
gen_short() { openssl rand -hex 16; }
gen_alnum() { openssl rand -base64 24 | tr -d '+/=' | head -c 32; }

# LAB_DOMAIN is the suffix used in URL emission. Not real DNS; the
# smoke suite hits container ports directly.
LAB_DOMAIN="${LAB_DOMAIN:-test.dunn.dev}"

# AUTH_REGISTRY + AUTH_VERSION resolve which auth-* images to pull.
# In CI: AUTH_REGISTRY=$CI_REGISTRY_IMAGE, AUTH_VERSION=$CI_COMMIT_SHA
# (or :latest for local operator runs).
AUTH_REGISTRY="${AUTH_REGISTRY:-registry.gitlab.com/dunn.dev/auth}"
AUTH_VERSION="${AUTH_VERSION:-latest}"

cat <<EOF
LAB_DOMAIN=${LAB_DOMAIN}
AUTH_REGISTRY=${AUTH_REGISTRY}
AUTH_VERSION=${AUTH_VERSION}

POSTGRES_PASSWORD=$(gen_alnum)
KRATOS_PG_PASS=$(gen_alnum)
HYDRA_PG_PASS=$(gen_alnum)

# Kratos cookie + cipher slots. Two distinct secrets per slot pair
# (Kratos rejects empty list elements). Substrate-secret collapse is a
# production simplification; lab keeps the two-slot model so any
# Kratos schema change that affects slot handling fails loud here.
KRATOS_COOKIE_SECRET_CURRENT=$(gen)
KRATOS_COOKIE_SECRET_PREVIOUS=$(gen)
KRATOS_CIPHER_SECRET_CURRENT=$(gen_short)
KRATOS_CIPHER_SECRET_PREVIOUS=$(gen_short)

# Hydra
HYDRA_SYSTEM_SECRET=$(gen)
HYDRA_COOKIE_SECRET_CURRENT=$(gen)
HYDRA_COOKIE_SECRET_PREVIOUS=$(gen)
HYDRA_PAIRWISE_SALT=$(gen_short)

# Consent + portal cross-auth (MEDIUM-1 admin bearer + MEDIUM-2 recovery-gate)
CONSENT_ADMIN_BEARER=$(gen)
RECOVERY_GATE_SECRET=$(gen)

# Portal CSRF tokens (HIGH-1)
CSRF_SECRET=$(gen)

# Per-client OIDC secrets for apply-clients smoke. Every client_id in
# hydra/clients/*.yaml that the smoke registers needs an env var.
KEEP_CLIENT_SECRET=$(gen)
OBSERVE_CLIENT_SECRET=$(gen)
LARDER_CLIENT_SECRET=$(gen)
LISTEN_CLIENT_SECRET=$(gen)
CINEMA_CLIENT_SECRET=$(gen)
MEMORY_CLIENT_SECRET=$(gen)
VAULT_CLIENT_SECRET=$(gen)
LIBRARY_CLIENT_SECRET=$(gen)
FORGE_CLIENT_SECRET=$(gen)
TAILSCALE_CLIENT_SECRET=$(gen)
LLM_CLIENT_SECRET=$(gen)
EOF
