#!/usr/bin/env bash
# Generate fresh secrets for a Phase 1 lab spike .env file.
# Writes to stdout; redirect to lab/compose/.env.
#
# Usage:
#   bash lab/scripts/gen-secrets.sh > lab/compose/.env
#
# Cookie / cipher rotation slot convention (H3):
#   Both _CURRENT and _PREVIOUS are populated with distinct secrets on
#   first provisioning. The _CURRENT slot signs new cookies; the
#   _PREVIOUS slot only verifies. On rotation, _PREVIOUS is set to the
#   prior _CURRENT and a fresh _CURRENT is minted. Always two distinct
#   secrets in flight.
#
#   Why not leave _PREVIOUS empty: Kratos and Hydra both reject empty
#   list elements in `secrets.cookie` / `secrets.cipher` as YAML
#   schema violations after envsubst expansion. Carrying a sentinel
#   _PREVIOUS keeps the YAML well-formed at all times and removes a
#   class of rotation-runbook foot-guns.
#
#   See docs/runbooks/cookie-rotation.md.

set -euo pipefail

gen() { openssl rand -hex 32; }
gen_short() { openssl rand -hex 16; }
gen_alnum() { openssl rand -base64 24 | tr -d '+/=' | head -c 32; }

cat <<EOF
DOMAIN=test.dunn.dev
POSTGRES_PASSWORD=$(gen_alnum)
KRATOS_PG_PASS=$(gen_alnum)
HYDRA_PG_PASS=$(gen_alnum)

# Kratos cookie + cipher rotation slots. _PREVIOUS seeded with a
# distinct sentinel secret so the YAML list never has an empty entry;
# becomes meaningful on first rotation (set to prior _CURRENT).
KRATOS_COOKIE_SECRET_CURRENT=$(gen)
KRATOS_COOKIE_SECRET_PREVIOUS=$(gen)
KRATOS_CIPHER_SECRET_CURRENT=$(gen_short)
KRATOS_CIPHER_SECRET_PREVIOUS=$(gen_short)

# Hydra. _PREVIOUS seeded with a distinct sentinel secret per the
# rotation runbook; becomes meaningful on first rotation.
HYDRA_SYSTEM_SECRET=$(gen)
HYDRA_COOKIE_SECRET_CURRENT=$(gen)
HYDRA_COOKIE_SECRET_PREVIOUS=$(gen)
HYDRA_PAIRWISE_SALT=$(gen)

# Reference Kratos UI (lab-only; production drops kratos-ui)
KRATOS_UI_COOKIE_SECRET=$(openssl rand -hex 16)
KRATOS_UI_CSRF_SECRET=$(openssl rand -hex 16)

# LDAP bridge (compose-ldap.yml only)
KRATOS_BRIDGE_ADMIN_TOKEN=$(gen)

# Per-app OIDC client secrets. KEEP is the only one Vaultwarden uses
# in the lab; the rest are stubs so apply-clients.sh has a value to
# substitute for each manifest.
KEEP_CLIENT_SECRET=$(gen_alnum)
LARDER_CLIENT_SECRET=larder-lab-secret-stub-not-used
LISTEN_CLIENT_SECRET=listen-lab-secret-stub-not-used
CINEMA_CLIENT_SECRET=cinema-lab-secret-stub-not-used
MEMORY_CLIENT_SECRET=memory-lab-secret-stub-not-used
VAULT_CLIENT_SECRET=vault-lab-secret-stub-not-used
LIBRARY_CLIENT_SECRET=library-lab-secret-stub-not-used
FORGE_CLIENT_SECRET=forge-lab-secret-stub-not-used
OBSERVE_CLIENT_SECRET=observe-lab-secret-stub-not-used
TAILSCALE_CLIENT_SECRET=tailscale-lab-secret-stub-not-used
LLM_CLIENT_SECRET=llm-lab-secret-stub-not-used

# Phase 3: consent service admin bearer (D4 force re-login)
CONSENT_ADMIN_BEARER=$(gen)

# Phase 3 security remediation:
# - CSRF_SECRET: portal admin form CSRF tokens (HIGH-1)
# - RECOVERY_GATE_SECRET: HMAC for Kratos -> consent recovery webhook (MEDIUM-2)
# - LDAP_BRIDGE_ADMIN_BEARER: bridge admin endpoint (MEDIUM-5 cache flush)
CSRF_SECRET=$(gen)
RECOVERY_GATE_SECRET=$(gen)
LDAP_BRIDGE_ADMIN_BEARER=$(gen)
EOF
