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
# gen_alnum: produce exactly 32 alphanumeric characters.
# base64 24 → ~32 chars after stripping +/=, but tr -d on a partial
# pipeline can yield fewer than 32 when deletion runs pull the count below
# the head -c window. 48 bytes → ~64 base64 chars → ~48 alnum survivors,
# comfortably above 32. The assert loop retries on the astronomically rare
# sub-32 output (Bernoulli p≈0.75 per char; P(<32 from 48)≈10⁻⁸).
gen_alnum() {
    local s
    while true; do
        s=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 32)
        [[ ${#s} -eq 32 ]] && break
    done
    printf '%s' "$s"
}

# AUTH_REGISTRY is the registry ROOT — the converged othala app image
# itself (registry.gitlab.com/dunn.dev/othala). AUTH_VERSION is the tag.
# In CI: AUTH_REGISTRY=$CI_REGISTRY_IMAGE, AUTH_VERSION=the just-built
# tag (v-tag or short-SHA). Local operator runs use :latest.
# NOTE: the LDAP bridge is now gitlab.com/dunn.dev/kratos-ldap (separate).
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

# ── SMTP (e2e mail catcher: mailpit) ─────────────────────────────────────────
# The e2e stack runs a real mailpit catcher (compose service `mailpit`,
# SMTP :1025, HTTP API :8025). Both Kratos courier AND the portal contact-form
# mailer point at it via the SHARED connection URI below — so the contact form
# is provably functional in the gate (smoke.sh Section H POSTs /api/request and
# asserts the message lands in mailpit). No auth/TLS: mailpit accepts plain SMTP.
#
# OTHALA_SMTP_CONNECTION_URI is the single source of truth, consumed by:
#   - kratos/kratos.yml  courier.smtp.connection_uri  (rendered by validate.sh)
#   - portal/src/lib/mailer.ts  (read via lib/config.ts at request time)
#
# ?disable_starttls=true is required for mailpit (and any plain-text SMTP relay).
# Kratos v26.2.0 gomail defaults to MandatoryStartTLS even for smtp:// URIs; without
# this flag the courier worker connects successfully but then fails STARTTLS
# negotiation and abandons every message after 6 retries.
SMTP_USER=lab
SMTP_PASS=lab
OTHALA_SMTP_CONNECTION_URI=smtp://mailpit:1025/?disable_starttls=true
# The contact form delivers here; the smoke seeds this as the recipient and
# asserts mailpit received a message addressed to it.
OTHALA_CONTACT_RECIPIENT=ops@othala.test

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

# ── OpenTelemetry tracing (OFF in e2e) ──────────────────────────────────────
# render-config.sh fails on ANY unset \${VAR}, so the kratos/hydra `tracing:`
# blocks need these three set even though tracing is disabled here. OFF-default:
# OTHALA_OTLP_PROVIDER="" makes Ory ignore the otlp provider entirely (no
# collector connection, no spans), so the offline VM never reaches for a
# collector. The endpoint/environment are inert placeholders that satisfy the
# render contract; the deploy plane (iac) overrides all three from sops +
# inventory with provider="otel" to turn tracing on. No ingest token here —
# the emitters send unauthenticated to the host alloy receiver, which adds the
# observe ingest auth and redacts centrally on its forward hop.
OTHALA_OTLP_PROVIDER=""
OTHALA_OTLP_ENDPOINT=localhost:4318
OTHALA_OTLP_ENVIRONMENT=lab

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

# ── Admin-plane bind addresses ────────────────────────────────────────────────
# The e2e harness is single-network, so the admin APIs bind all interfaces.
# Segmented deployments (iac) set these to the admin-plane network IP so the
# unauthenticated admin listeners never answer on the edge interface.
KRATOS_ADMIN_BIND_HOST=0.0.0.0
HYDRA_ADMIN_BIND_HOST=0.0.0.0

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

# Converged app admin model (CU3 / CVP-P1). consent is gone; these are the
# othala app's own secrets:
#   OTHALA_ADMIN_IDS              the SOLE admin authority — a comma-separated
#                                 list of Kratos identity UUIDs. The e2e fixtures
#                                 seed identities with these EXACT UUIDs (via the
#                                 createIdentity `id` field) to exercise the admin
#                                 gate, recovery-gate, and login-gate refuse paths:
#                                   ...0001 = `admin` fixture (admin@othala.test)
#                                   ...0002 = J2 recovery-gate test identity
#                                 PLACEHOLDER for real deployments: replace with the
#                                 real admin identity UUID(s) from `kratos identity
#                                 list` after first boot.
#   OTHALA_ADMIN_ENDPOINT_BEARER  guards POST /admin/revoke-user (loopback)
#   RECOVERY_GATE_SECRET          guards POST /admin/recovery-gate (loopback)
#                                 and POST /admin/login-gate (loopback; CVP-P3)
OTHALA_ADMIN_IDS=00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002
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
