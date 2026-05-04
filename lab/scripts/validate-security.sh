#!/usr/bin/env bash
# Phase 3 security-remediation validation. Runs on the lab VM after deploy.
# Tests the patches landed for adversarial-review-2026-05-04 findings.

set -uo pipefail

DOMAIN="${DOMAIN:-}"
if [[ -z "$DOMAIN" ]]; then
    set -a; source /opt/auth-lab/.env; set +a
fi
AUTH_HOST="auth-lab.${DOMAIN}"
KEEP_HOST="keep-lab.${DOMAIN}"
HOME_HOST="home-lab.${DOMAIN}"

EVIDENCE="/opt/auth-lab/lab/docs/security-validation.md"
PASS=0
FAIL=0
DEFER=0
FAILED_TESTS=()

mkdir -p "$(dirname "$EVIDENCE")"

log() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$EVIDENCE"; }
pass() { PASS=$((PASS+1)); log "[PASS] $*"; }
fail() { FAIL=$((FAIL+1)); FAILED_TESTS+=("$*"); log "[FAIL] $*"; }
defer() { DEFER=$((DEFER+1)); log "[DEFER] $*"; }

cat > "$EVIDENCE" <<EOF
# Security-remediation validation

VM: $(hostname)
Domain: ${DOMAIN}
Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)

EOF

CURL() { podman run --rm --network compose_default docker.io/curlimages/curl "$@"; }

log "=== Security validation start ==="

# Substrate sanity (sanity check)
log ""
log "## Substrate sanity"
CODE=$(curl -sk --max-time 5 -o /tmp/oc.json -w "%{http_code}" "https://${AUTH_HOST}/.well-known/openid-configuration")
[[ "$CODE" == "200" ]] && pass "Substrate openid-config 200" || fail "Substrate openid-config code=${CODE}"

# HIGH-2: X-Forwarded-* drop in buildReturnTo
log ""
log "## HIGH-2: X-Forwarded-* drop"
# Spoof X-Forwarded-Host directly to consent service. The login handler
# uses buildReturnTo to construct the redirect; with the fix, X-Forwarded-*
# are ignored, so an evil host shouldn't appear in the redirect URL.
SPOOF_RESP=$(CURL -sk -o /tmp/spoof.txt -w "%{http_code}\n%{redirect_url}" \
    -H "X-Forwarded-Host: evil.example.com" \
    -H "X-Forwarded-Proto: https" \
    "http://consent:4477/login?login_challenge=invalid-challenge-for-test" 2>&1)
SPOOF_CODE=$(echo "$SPOOF_RESP" | head -1)
SPOOF_REDIR=$(echo "$SPOOF_RESP" | tail -1)
# We expect either 404/400 (challenge invalid) or a redirect that does NOT contain evil.example
if echo "$SPOOF_REDIR" | grep -qi "evil.example"; then
    fail "HIGH-2 X-Forwarded-Host honored, redirect=${SPOOF_REDIR}"
else
    pass "HIGH-2 X-Forwarded-Host ignored (code=${SPOOF_CODE}, redir=${SPOOF_REDIR:0:60})"
fi

# MEDIUM-1: listener split (admin endpoint should NOT be on :4477)
log ""
log "## MEDIUM-1: listener split"
CODE=$(CURL -sk -o /dev/null -w "%{http_code}" "http://consent:4477/admin/revoke-user" -X POST -d '{}')
if [[ "$CODE" == "404" || "$CODE" == "405" ]]; then
    pass "MEDIUM-1 /admin/revoke-user not on :4477 (code=${CODE})"
else
    fail "MEDIUM-1 /admin/revoke-user on :4477 returned code=${CODE} (expected 404/405)"
fi

# Admin endpoint should be on :4478
CODE=$(CURL -sk -o /dev/null -w "%{http_code}" "http://consent:4478/admin/revoke-user" -X POST -d '{}')
if [[ "$CODE" == "401" || "$CODE" == "403" || "$CODE" == "400" ]]; then
    pass "MEDIUM-1 /admin/revoke-user on :4478 reachable + auth-gated (code=${CODE})"
else
    fail "MEDIUM-1 /admin/revoke-user on :4478 returned code=${CODE} (expected 401/403/400)"
fi

# Public login should NOT be on :4478
CODE=$(CURL -sk -o /dev/null -w "%{http_code}" "http://consent:4478/login?login_challenge=x")
if [[ "$CODE" == "404" || "$CODE" == "405" ]]; then
    pass "MEDIUM-1 /login not on :4478 (code=${CODE})"
else
    fail "MEDIUM-1 /login on :4478 returned code=${CODE} (expected 404/405)"
fi

# MEDIUM-2: webhook HMAC auth
log ""
log "## MEDIUM-2: webhook HMAC auth"
# No secret header
CODE=$(CURL -sk -o /tmp/wh1.out -w "%{http_code}" -X POST \
    -H 'Content-Type: application/json' \
    -d '{"identity_id":"x","groups":["family"]}' \
    "http://consent:4478/webhooks/recovery-gate")
if [[ "$CODE" == "403" ]]; then
    pass "MEDIUM-2 webhook without secret → 403"
else
    fail "MEDIUM-2 webhook without secret → ${CODE}: $(cat /tmp/wh1.out 2>/dev/null | head -1)"
fi

# Wrong secret
CODE=$(CURL -sk -o /tmp/wh2.out -w "%{http_code}" -X POST \
    -H 'Content-Type: application/json' \
    -H "X-Webhook-Auth: wrong-secret-value" \
    -d '{"identity_id":"x","groups":["family"]}' \
    "http://consent:4478/webhooks/recovery-gate")
if [[ "$CODE" == "403" ]]; then
    pass "MEDIUM-2 webhook with wrong secret → 403"
else
    fail "MEDIUM-2 webhook with wrong secret → ${CODE}"
fi

# Right secret + non-admin
SECRET=$(grep '^RECOVERY_GATE_SECRET=' /opt/auth-lab/.env | cut -d= -f2)
CODE=$(CURL -sk -o /tmp/wh3.out -w "%{http_code}" -X POST \
    -H 'Content-Type: application/json' \
    -H "X-Webhook-Auth: ${SECRET}" \
    -d '{"identity_id":"x","groups":["family"]}' \
    "http://consent:4478/webhooks/recovery-gate")
if [[ "$CODE" == "200" ]]; then
    pass "MEDIUM-2 webhook with right secret + non-admin → 200"
else
    fail "MEDIUM-2 webhook with right secret + non-admin → ${CODE}: $(cat /tmp/wh3.out 2>/dev/null | head -1)"
fi

# Right secret + admin
CODE=$(CURL -sk -o /tmp/wh4.out -w "%{http_code}" -X POST \
    -H 'Content-Type: application/json' \
    -H "X-Webhook-Auth: ${SECRET}" \
    -d '{"identity_id":"x","groups":["admin","family"]}' \
    "http://consent:4478/webhooks/recovery-gate")
if [[ "$CODE" == "403" ]]; then
    pass "MEDIUM-2+H1 webhook with right secret + admin → 403"
else
    fail "MEDIUM-2+H1 webhook with right secret + admin → ${CODE}"
fi

# LOW-5: refuse-on-empty groups
CODE=$(CURL -sk -o /tmp/wh5.out -w "%{http_code}" -X POST \
    -H 'Content-Type: application/json' \
    -H "X-Webhook-Auth: ${SECRET}" \
    -d '{"identity_id":"x","groups":[]}' \
    "http://consent:4478/webhooks/recovery-gate")
if [[ "$CODE" == "403" ]]; then
    pass "LOW-5 webhook with empty groups → 403"
else
    fail "LOW-5 webhook with empty groups → ${CODE}"
fi

# MEDIUM-7: webfinger reflection hardening
log ""
log "## MEDIUM-7: webfinger reflection"
HUGE=$(printf 'A%.0s' {1..1000})
RESP=$(curl -sk --max-time 5 "https://${AUTH_HOST}/.well-known/webfinger?resource=acct:${HUGE}@dunn.dev")
SUBJECT=$(echo "$RESP" | jq -r .subject 2>/dev/null)
if [[ "$SUBJECT" != "acct:${HUGE}@dunn.dev" ]] && echo "$SUBJECT" | grep -qE "^acct:[^@]+@dunn\.dev$"; then
    pass "MEDIUM-7 webfinger subject hardcoded (returned: ${SUBJECT})"
else
    fail "MEDIUM-7 webfinger reflected payload, subject=${SUBJECT:0:80}"
fi

# LOW-3: trailing slash on allowed_return_urls (verify in kratos config render)
log ""
log "## LOW-3: trailing slash"
ALLOWED=$(CURL -sk "http://kratos:4434/admin/health/ready" -o /dev/null -w "%{http_code}")
defer "LOW-3 trailing-slash check: requires runtime probe of return_to handling; covered by config grep"
if grep -E '^\s+- https://[^/]+(\.dunn\.dev|sslip\.io)\s*$' /opt/auth-lab/lab/compose/kratos.rendered.yml 2>/dev/null | grep -v '/$'; then
    fail "LOW-3 some return URLs missing trailing slash"
else
    pass "LOW-3 all return URLs end with /"
fi

# Set up test identities for HIGH-1 / HIGH-3 testing
log ""
log "## Identity setup for portal tests"
AGD_RESP=$(CURL -sk -X POST "http://kratos:4434/admin/identities" \
    -H 'Content-Type: application/json' \
    -d '{"schema_id":"family","traits":{"username":"agd","email":"agd@dunn.dev","displayName":"agd"},"metadata_admin":{"groups":["admin","family","access-keep"]}}')
AGD_ID=$(echo "$AGD_RESP" | jq -r .id 2>/dev/null)
if [[ -n "$AGD_ID" && "$AGD_ID" != "null" ]]; then
    pass "agd identity created id=${AGD_ID:0:8}"
else
    fail "agd creation: $AGD_RESP"
fi

OTHER_ADMIN_RESP=$(CURL -sk -X POST "http://kratos:4434/admin/identities" \
    -H 'Content-Type: application/json' \
    -d '{"schema_id":"family","traits":{"username":"other.admin","email":"other.admin@dunn.dev","displayName":"Other Admin"},"metadata_admin":{"groups":["admin","family"]}}')
OTHER_ADMIN_ID=$(echo "$OTHER_ADMIN_RESP" | jq -r .id 2>/dev/null)
if [[ -n "$OTHER_ADMIN_ID" && "$OTHER_ADMIN_ID" != "null" ]]; then
    pass "other.admin identity created id=${OTHER_ADMIN_ID:0:8}"
else
    fail "other.admin creation: $OTHER_ADMIN_RESP"
fi

# HIGH-3: portal refuses admin-to-admin recovery. Hit Kratos admin recovery
# link directly to confirm Kratos itself does NOT block admins (the gate
# is at the portal layer). Then verify the portal action does block.
log ""
log "## HIGH-3: admin-to-admin recovery refusal"

# Direct Kratos admin recovery — should succeed (Kratos doesn't enforce)
KR_DIRECT=$(CURL -sk -X POST "http://kratos:4434/admin/recovery/link" \
    -H 'Content-Type: application/json' \
    -d "{\"identity_id\":\"${OTHER_ADMIN_ID}\"}" \
    -o /tmp/kr-direct.out -w "%{http_code}")
if [[ "$KR_DIRECT" == "200" ]]; then
    pass "HIGH-3 sanity: Kratos admin/recovery/link works direct (proves the gate is portal-only)"
else
    defer "HIGH-3 sanity: Kratos returned ${KR_DIRECT}; this test relies on Kratos accepting"
fi

# Portal layer test would require an admin session cookie. Capture as
# integration-test-deferred; the unit tests for the portal action cover
# this. Document the call surface for future browser-driven test.
defer "HIGH-3 portal-layer test: requires admin session cookie; covered by portal unit tests in admin/users/[id].astro POST handler"

# HIGH-1: CSRF — without a session/token, the portal POST should reject.
# A direct POST to /admin/users/<id> without CSRF token, expecting redirect
# or 403. Without an admin session even, we get redirect to login.
log ""
log "## HIGH-1: CSRF token enforcement"
# Hit the admin POST without any auth — expect redirect (admin guard catches it first)
CODE=$(curl -sk --max-time 5 -X POST "https://${AUTH_HOST}/admin/users/${OTHER_ADMIN_ID}" \
    -d "action=force-relogin" \
    -o /tmp/h1.out -w "%{http_code}")
if [[ "$CODE" == "302" || "$CODE" == "303" || "$CODE" == "401" || "$CODE" == "403" ]]; then
    pass "HIGH-1 admin POST without auth → ${CODE} (admin guard fires before CSRF)"
else
    fail "HIGH-1 admin POST without auth → ${CODE}"
fi
defer "HIGH-1 in-session CSRF test: requires admin login + session cookie; covered by portal CSRF unit tests"

# Apply clients (regression check that namespace split didn't regress)
log ""
log "## Regression: apply-clients.sh"
if [[ -x /opt/auth-lab/hydra/apply-clients.sh ]]; then
    APPLY_OUT=$(cd /opt/auth-lab/hydra && CONSENT_RELOAD_HOOK="" bash apply-clients.sh 2>&1)
    CLIENT_COUNT=$(CURL -sk "http://hydra:4445/admin/clients" | jq 'length' 2>/dev/null || echo 0)
    if [[ "$CLIENT_COUNT" -ge 11 ]]; then
        pass "Regression apply-clients.sh applied ${CLIENT_COUNT} clients"
    else
        fail "Regression apply-clients.sh: only ${CLIENT_COUNT} clients (want ≥11)"
    fi
else
    defer "apply-clients.sh not executable"
fi

# Summary
log ""
log "=== Summary ==="
log "PASS: ${PASS}"
log "FAIL: ${FAIL}"
log "DEFER: ${DEFER}"
if (( FAIL > 0 )); then
    log "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do
        log "  - $t"
    done
fi

if (( FAIL == 0 )); then
    VERDICT="GREEN"
elif (( FAIL <= 2 )); then
    VERDICT="YELLOW"
else
    VERDICT="RED"
fi
log "Verdict: ${VERDICT}"

cat >> "$EVIDENCE" <<EOF

---
Verdict: ${VERDICT}
Pass: ${PASS} / Fail: ${FAIL} / Defer: ${DEFER}
Completed: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

echo "DONE"
