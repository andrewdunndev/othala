#!/usr/bin/env bash
# smoke.sh — substrate-up validation matrix.
#
# Runs INSIDE the CI lab VM after `podman compose up -d` brings up the
# auth substrate. Probes each container directly on its compose network
# hostname (postgres, kratos, hydra, consent, portal, ldap-bridge).
#
# Exit 0 on all-green, 1 on any failure. Logs container outputs on
# failure to /tmp/lab-failure.log for CI artifact upload.
#
# Pre-conditions:
#   - `docker compose` (podman-docker bridge) up
#   - All long-running services have hit healthy state
#   - .env present in cwd

set -uo pipefail   # NOT -e: every probe runs even if some fail.

PASS=0
FAIL=0
FAILED_PROBES=()

pass() { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$1"; }
fail() {
    FAIL=$((FAIL+1))
    FAILED_PROBES+=("$1")
    printf "  \033[31m✗\033[0m %s\n" "$1"
    if [[ -n "${2:-}" ]]; then
        printf "      %s\n" "$2"
    fi
}

# Helper: run curl from a transient container on the compose network.
# We can't rely on the runner VM having direct access to the compose
# internal network (podman compose puts it on a private bridge), so
# every probe goes through `docker compose exec`.
curl_in() {
    local container="$1"; shift
    docker compose exec -T "$container" wget -qO- "$@" 2>/dev/null
}

curl_code_in() {
    local container="$1"; shift
    docker compose exec -T "$container" wget -qO /dev/null -S "$@" 2>&1 | awk '/HTTP/ {print $2}' | tail -1
}

echo "=== smoke matrix ==="

# Section A: Substrate sanity
echo ""
echo "A. Substrate sanity"

# A1: postgres reachable + kratos + hydra DBs exist
out=$(docker compose exec -T postgres psql -U postgres -t -A -c "SELECT datname FROM pg_database WHERE datname IN ('kratos','hydra');" 2>/dev/null | sort | tr '\n' ',' )
if [[ "$out" == "hydra,kratos," ]]; then
    pass "A1 postgres: kratos + hydra DBs present"
else
    fail "A1 postgres DBs" "got: $out"
fi

# A2: uuid-ossp on hydra DB
out=$(docker compose exec -T postgres psql -U postgres -d hydra -t -A -c "SELECT extname FROM pg_extension WHERE extname='uuid-ossp';" 2>/dev/null)
if [[ "$out" == "uuid-ossp" ]]; then
    pass "A2 postgres: uuid-ossp on hydra"
else
    fail "A2 uuid-ossp" "missing on hydra; init.sh failed"
fi

# A3: Kratos admin /health/ready
code=$(curl_code_in kratos http://localhost:4434/admin/health/ready)
if [[ "$code" == "200" ]]; then
    pass "A3 kratos admin /health/ready"
else
    fail "A3 kratos admin /health/ready" "code=$code"
fi

# A4: Kratos public /.well-known/ory/webauthn.js (WebAuthn ceremony script)
code=$(curl_code_in kratos http://localhost:4433/.well-known/ory/webauthn.js)
if [[ "$code" == "200" ]]; then
    pass "A4 kratos public WebAuthn ceremony script"
else
    fail "A4 webauthn.js" "code=$code"
fi

# A5: Hydra admin /health/ready
code=$(curl_code_in hydra http://localhost:4445/health/ready)
if [[ "$code" == "200" ]]; then
    pass "A5 hydra admin /health/ready"
else
    fail "A5 hydra admin /health/ready" "code=$code"
fi

# A6: Hydra public /.well-known/openid-configuration + issuer byte-match
oidc=$(curl_in hydra http://localhost:4444/.well-known/openid-configuration)
issuer=$(echo "$oidc" | python3 -c "import sys,json; print(json.load(sys.stdin).get('issuer',''))" 2>/dev/null || echo "")
expected_issuer="http://auth-lab.${LAB_DOMAIN}/"
if [[ "$issuer" == "$expected_issuer" ]]; then
    pass "A6 hydra openid-config issuer byte-match: $issuer"
else
    fail "A6 hydra issuer mismatch" "got=$issuer want=$expected_issuer"
fi

# A7: Hydra jwks.json has RS256 key
jwks=$(curl_in hydra http://localhost:4444/.well-known/jwks.json)
if echo "$jwks" | python3 -c "import sys,json; d=json.load(sys.stdin); assert any(k.get('alg')=='RS256' for k in d.get('keys',[]))" 2>/dev/null; then
    pass "A7 hydra jwks.json has RS256 key"
else
    fail "A7 hydra jwks.json missing RS256 key"
fi

# A8: Consent /healthz
code=$(curl_code_in consent http://localhost:4477/healthz)
if [[ "$code" == "200" ]]; then
    pass "A8 consent /healthz"
else
    fail "A8 consent /healthz" "code=$code"
fi

# A9: Portal /healthz
code=$(curl_code_in portal http://localhost:8080/healthz)
if [[ "$code" == "200" ]]; then
    pass "A9 portal /healthz"
else
    fail "A9 portal /healthz" "code=$code"
fi

# Section B: apply-clients integration
echo ""
echo "B. apply-clients integration (auth-util)"

# B1: Run auth-util via compose. Expect every client manifest in
# hydra/clients/*.yaml to register.
docker compose run --rm util > /tmp/apply-clients.log 2>&1
applycode=$?
if [[ $applycode -eq 0 ]]; then
    pass "B1 apply-clients exited 0"
else
    fail "B1 apply-clients exit code $applycode" "see /tmp/apply-clients.log"
fi

# B2: Hydra admin lists the registered clients
clients_json=$(curl_in hydra http://localhost:4445/admin/clients)
client_count=$(echo "$clients_json" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
if [[ "$client_count" -ge 11 ]]; then
    pass "B2 hydra admin lists $client_count clients (expected >=11 per hydra/clients/*.yaml)"
else
    fail "B2 hydra admin client count" "got=$client_count"
fi

# B3: Specific client check — keep is registered
keep_check=$(curl_code_in hydra http://localhost:4445/admin/clients/keep)
if [[ "$keep_check" == "200" ]]; then
    pass "B3 keep client registered"
else
    fail "B3 keep client missing" "code=$keep_check"
fi

# B4: tailscale registered (NO PKCE; the manifest is unusual)
ts_check=$(curl_code_in hydra http://localhost:4445/admin/clients/tailscale)
if [[ "$ts_check" == "200" ]]; then
    pass "B4 tailscale client registered (no PKCE pre-condition holds)"
else
    fail "B4 tailscale client missing" "code=$ts_check"
fi

# Section C: identity admin flow
echo ""
echo "C. Identity admin flow"

# C1: Create an identity via Kratos admin API
identity_json=$(docker compose exec -T kratos wget -qO- --post-data='{"schema_id":"family","traits":{"username":"lab.test","email":"lab.test@'${LAB_DOMAIN}'","displayName":"Lab Test"},"metadata_admin":{"groups":["family","access-keep","access-observe"]}}' --header='Content-Type: application/json' http://localhost:4434/admin/identities 2>/dev/null)
identity_id=$(echo "$identity_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
if [[ -n "$identity_id" ]]; then
    pass "C1 created identity id=$identity_id"
else
    fail "C1 create identity failed" "response: $identity_json"
fi

# C2: Read identity back, metadata_admin.groups round-tripped
if [[ -n "$identity_id" ]]; then
    rt=$(curl_in kratos "http://localhost:4434/admin/identities/$identity_id")
    groups=$(echo "$rt" | python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join(d.get('metadata_admin',{}).get('groups',[])))" 2>/dev/null || echo "")
    if [[ "$groups" == "family,access-keep,access-observe" ]]; then
        pass "C2 identity round-trip preserves metadata_admin.groups"
    else
        fail "C2 metadata_admin.groups round-trip" "got=$groups"
    fi
fi

# Section D: recovery-gate webhook (MEDIUM-2 + LOW-5)
echo ""
echo "D. Recovery-gate webhook"

# D1: Admin group → 403
admin_code=$(docker compose exec -T consent wget -qO /dev/null -S --post-data='{"identity_id":"x","groups":["admin","family"]}' --header="Content-Type: application/json" --header="X-Webhook-Auth: ${RECOVERY_GATE_SECRET}" http://localhost:4478/webhooks/recovery-gate 2>&1 | awk '/HTTP/ {print $2}' | tail -1)
if [[ "$admin_code" == "403" ]]; then
    pass "D1 recovery-gate refuses admin (HIGH-3)"
else
    fail "D1 recovery-gate admin path" "code=$admin_code"
fi

# D2: Non-admin → 200
nonadmin_code=$(docker compose exec -T consent wget -qO /dev/null -S --post-data='{"identity_id":"x","groups":["family"]}' --header="Content-Type: application/json" --header="X-Webhook-Auth: ${RECOVERY_GATE_SECRET}" http://localhost:4478/webhooks/recovery-gate 2>&1 | awk '/HTTP/ {print $2}' | tail -1)
if [[ "$nonadmin_code" == "200" ]]; then
    pass "D2 recovery-gate allows non-admin"
else
    fail "D2 recovery-gate non-admin path" "code=$nonadmin_code"
fi

# D3: Empty groups → 403 (LOW-5 defensive default)
empty_code=$(docker compose exec -T consent wget -qO /dev/null -S --post-data='{"identity_id":"x","groups":[]}' --header="Content-Type: application/json" --header="X-Webhook-Auth: ${RECOVERY_GATE_SECRET}" http://localhost:4478/webhooks/recovery-gate 2>&1 | awk '/HTTP/ {print $2}' | tail -1)
if [[ "$empty_code" == "403" ]]; then
    pass "D3 recovery-gate refuses on empty groups (LOW-5)"
else
    fail "D3 recovery-gate empty groups" "code=$empty_code"
fi

# D4: Wrong secret → 403 (MEDIUM-2)
wrong_code=$(docker compose exec -T consent wget -qO /dev/null -S --post-data='{"identity_id":"x","groups":["family"]}' --header="Content-Type: application/json" --header="X-Webhook-Auth: wrong-secret" http://localhost:4478/webhooks/recovery-gate 2>&1 | awk '/HTTP/ {print $2}' | tail -1)
if [[ "$wrong_code" == "403" ]]; then
    pass "D4 recovery-gate rejects wrong secret (MEDIUM-2)"
else
    fail "D4 recovery-gate wrong secret" "code=$wrong_code"
fi

# ----- Summary -----
echo ""
TOTAL=$((PASS + FAIL))
if [[ $FAIL -eq 0 ]]; then
    printf "\033[32mALL %d PROBES PASSED\033[0m\n" "$TOTAL"
    exit 0
else
    printf "\033[31m%d/%d FAILED\033[0m\n" "$FAIL" "$TOTAL"
    echo ""
    echo "Failed probes:"
    for p in "${FAILED_PROBES[@]}"; do
        echo "  - $p"
    done
    {
        echo "=== container ps ==="
        docker compose ps
        echo ""
        echo "=== container logs ==="
        for svc in postgres kratos hydra consent portal ldap-bridge; do
            echo "--- $svc ---"
            docker compose logs --tail=50 "$svc"
        done
    } > /tmp/lab-failure.log
    exit 1
fi
