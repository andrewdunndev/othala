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

# Production (golden-path LB#10) collapses each rotation slot pair to
# a single sops key feeding both _CURRENT and _PREVIOUS env vars: one
# auth_session_secret drives Kratos cookie CURRENT+PREVIOUS, one
# auth_cipher_secret drives Kratos cipher CURRENT+PREVIOUS, and the
# Hydra cookie pair collapses the same way. The lab intentionally
# mirrors that wire shape so the substrate it validates IS the
# substrate that ships — if Ory ever rejects a slot pair with
# byte-identical entries, the CI lab fails before the change reaches
# carmine.
kratos_cookie=$(gen)
kratos_cipher=$(gen_short)
hydra_cookie=$(gen)

cat <<EOF
LAB_DOMAIN=${LAB_DOMAIN}
AUTH_REGISTRY=${AUTH_REGISTRY}
AUTH_VERSION=${AUTH_VERSION}

POSTGRES_PASSWORD=$(gen_alnum)
KRATOS_PG_PASS=$(gen_alnum)
HYDRA_PG_PASS=$(gen_alnum)

# Kratos cookie + cipher + Hydra cookie: production collapsed-key
# shape (LB#10). Same value in both _CURRENT and _PREVIOUS.
KRATOS_COOKIE_SECRET_CURRENT=${kratos_cookie}
KRATOS_COOKIE_SECRET_PREVIOUS=${kratos_cookie}
KRATOS_CIPHER_SECRET_CURRENT=${kratos_cipher}
KRATOS_CIPHER_SECRET_PREVIOUS=${kratos_cipher}

# Hydra
HYDRA_SYSTEM_SECRET=$(gen)
HYDRA_COOKIE_SECRET_CURRENT=${hydra_cookie}
HYDRA_COOKIE_SECRET_PREVIOUS=${hydra_cookie}
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
