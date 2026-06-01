#!/usr/bin/env bash
# gen-secrets.sh — emit per-run e2e secrets to stdout in .env format.
#
# Used by validate.sh inside the e2e VM. Every secret is freshly
# generated per run; nothing persists past the VM's lifetime.
#
# Usage:
#   bash e2e/gen-secrets.sh > e2e/.env

set -euo pipefail

gen()       { openssl rand -hex 32; }
gen_short() { openssl rand -hex 16; }
gen_alnum() { openssl rand -base64 24 | tr -d '+/=' | head -c 32; }

# LAB_DOMAIN is the suffix used in URL emission. Not real DNS; the
# smoke suite hits container ports directly.
LAB_DOMAIN="${LAB_DOMAIN:-test.dunn.dev}"

# AUTH_REGISTRY is the registry ROOT — the converged othala app image
# itself (registry.gitlab.com/dunn.dev/othala). ldap-bridge is the
# ${AUTH_REGISTRY}/ldap-bridge sub-image. AUTH_VERSION is the tag.
# In CI: AUTH_REGISTRY=$CI_REGISTRY_IMAGE, AUTH_VERSION=the just-built
# tag (v-tag or short-SHA). Local operator runs use :latest.
AUTH_REGISTRY="${AUTH_REGISTRY:-registry.gitlab.com/dunn.dev/othala}"
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

# Converged app admin model (CU3). consent is gone; these are the
# othala app's own secrets:
#   OTHALA_ADMIN_SUBJECTS         the SOLE admin authority — a comma-
#                                 separated email allowlist. The smoke
#                                 seeds a known admin email to exercise
#                                 the recovery-gate refuse path.
#   OTHALA_ADMIN_ENDPOINT_BEARER  guards POST /admin/revoke-user (loopback)
#   RECOVERY_GATE_SECRET          guards POST /admin/recovery-gate (loopback)
OTHALA_ADMIN_SUBJECTS=admin@${LAB_DOMAIN}
OTHALA_ADMIN_ENDPOINT_BEARER=$(gen)
RECOVERY_GATE_SECRET=$(gen)

# App CSRF tokens (HIGH-1)
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
