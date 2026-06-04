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

# AUTH_REGISTRY is the registry ROOT — the converged othala app image
# itself (registry.gitlab.com/dunn.dev/othala). ldap-bridge is the
# ${AUTH_REGISTRY}/ldap-bridge sub-image. AUTH_VERSION is the tag.
# In CI: AUTH_REGISTRY=$CI_REGISTRY_IMAGE, AUTH_VERSION=the just-built
# tag (v-tag or short-SHA). Local operator runs use :latest.
AUTH_REGISTRY="${AUTH_REGISTRY:-registry.gitlab.com/dunn.dev/othala}"
AUTH_VERSION="${AUTH_VERSION:-latest}"

# Production (golden-path LB#10) collapses each rotation slot to a single
# sops key: one auth_session_secret drives the Kratos cookie, one
# auth_cipher_secret the Kratos cipher, one drives the Hydra cookie. Ory
# v26.2.0 enforces uniqueItems on these arrays, so a collapsed key renders
# as a SINGLE-element array — never two identical slots. The lab mirrors
# that shipping wire shape: one value per slot, no _PREVIOUS at rest.
# (Rotation prepends a distinct entry; see the kratos/hydra.yml runbooks.)
kratos_cookie=$(gen)
kratos_cipher=$(gen_short)
hydra_cookie=$(gen)

cat <<EOF
AUTH_REGISTRY=${AUTH_REGISTRY}
AUTH_VERSION=${AUTH_VERSION}

POSTGRES_PASSWORD=$(gen_alnum)
KRATOS_PG_PASS=$(gen_alnum)
HYDRA_PG_PASS=$(gen_alnum)

# ── SMTP stub (no real mail in e2e; Kratos courier uses these) ───────────────
# These are consumed by the expandvars render of kratos.yml (courier.smtp).
# Courier is effectively inert in the e2e (no real SMTP relay), but the config
# must not contain literal \${SMTP_USER}/\${SMTP_PASS} or Kratos rejects the DSN.
SMTP_USER=lab
SMTP_PASS=lab

# ── Instance identity (e2e test host) ────────────────────────────────────────
# auth.othala.test is the generic test host alias used by the browser-profile
# Caddy edge. No real DNS; compose net alias resolves it inside the net.
OTHALA_PUBLIC_URL=http://auth.othala.test
OTHALA_PUBLIC_HOST=auth.othala.test
OTHALA_APEX=othala.test
OTHALA_WEBAUTHN_RP_ID=othala.test
OTHALA_WEBAUTHN_RP_ORIGINS=http://auth.othala.test
OTHALA_INSTANCE_NAME='Othala Lab'
OTHALA_SMTP_FROM_ADDRESS=noreply@othala.test

# ── Password policy: HIBP off for offline VM, min-length 12 ─────────────────
# haveibeenpwned_enabled=false prevents a network call the CI VM cannot make.
# min_password_length=12 keeps length enforcement; e2e uses ≥12-char passwords.
OTHALA_HIBP_ENABLED=false
OTHALA_PASSWORD_MIN_LENGTH=12

# ── Host routing (compose service names; iac quadlets use container names) ───
KRATOS_PG_HOST=postgres
HYDRA_PG_HOST=postgres
KRATOS_ADMIN_HOST=kratos
CONSENT_HOST=othala

# Kratos cookie + cipher + Hydra cookie: single active secret each
# (collapsed-key, LB#10). No _PREVIOUS at rest — v26.2.0 uniqueItems.
KRATOS_COOKIE_SECRET_CURRENT=${kratos_cookie}
KRATOS_CIPHER_SECRET_CURRENT=${kratos_cipher}

# Hydra
HYDRA_SYSTEM_SECRET=$(gen)
HYDRA_COOKIE_SECRET_CURRENT=${hydra_cookie}
HYDRA_PAIRWISE_SALT=$(gen_short)

# ── LDAP bridge ───────────────────────────────────────────────────────────────
LDAP_BASE_DN=dc=othala,dc=test
LDAP_SERVICE_BIND_DN=cn=ldap-reader,dc=othala,dc=test
LDAP_SERVICE_BIND_PASSWORD=$(gen_short)

# Converged app admin model (CU3). consent is gone; these are the
# othala app's own secrets:
#   OTHALA_ADMIN_SUBJECTS         the SOLE admin authority — a comma-
#                                 separated email allowlist. The smoke
#                                 seeds a known admin email to exercise
#                                 the recovery-gate refuse path.
#   OTHALA_ADMIN_ENDPOINT_BEARER  guards POST /admin/revoke-user (loopback)
#   RECOVERY_GATE_SECRET          guards POST /admin/recovery-gate (loopback)
OTHALA_ADMIN_SUBJECTS=admin@othala.test
OTHALA_ADMIN_ENDPOINT_BEARER=$(gen)
RECOVERY_GATE_SECRET=$(gen)

# App CSRF tokens (HIGH-1)
CSRF_SECRET=$(gen)

# Per-client OIDC secrets for the register-clients smoke. Every fixture
# in e2e/manifests/ that carries an oidc: block (and so gets registered
# against Hydra) needs a <SLUG>_CLIENT_SECRET env var. The generic
# example set has two OIDC clients: grafana + audiobookshelf. The
# presentation-only fixtures (jellyfin/proxywatch/statuspage) have no
# oidc: block and need no secret.
GRAFANA_CLIENT_SECRET=$(gen)
AUDIOBOOKSHELF_CLIENT_SECRET=$(gen)
EOF
