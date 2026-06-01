#!/usr/bin/env bash
# smoke.sh — converged-substrate validation matrix.
#
# Runs INSIDE the e2e VM after `docker compose up -d` brings up the
# converged Othala substrate. Probes each container directly on its
# compose network hostname (postgres, kratos, hydra, othala, ldap-bridge).
#
# The othala app is ONE service: public SSR port 8080 (family UI +
# /auth/* + /admin/* + the /oauth2/{login,consent,logout} challenge
# handlers) and a loopback admin port 8431 (/healthz, /readyz,
# /admin/revoke-user, /admin/recovery-gate). The admin port binds
# 127.0.0.1 inside the container, so admin probes run via `compose exec`
# against localhost:8431; the public port is probed across the network.
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

# A8: Othala app admin /healthz on the loopback admin port (8431).
# /healthz + /readyz live on the admin mux, NOT the public SSR port.
code=$(curl_code_in othala http://127.0.0.1:8431/healthz)
if [[ "$code" == "200" ]]; then
    pass "A8 othala admin /healthz (loopback :8431)"
else
    fail "A8 othala admin /healthz" "code=$code"
fi

# A9: Othala public SSR port (8080) serves a challenge handler. The
# converged app is Hydra's login/consent/logout provider at
# /oauth2/{login,consent,logout}. Hit /oauth2/login WITHOUT a
# login_challenge: the handler is mounted (not 404) and rejects the
# bad/absent challenge. Any served response (not a connection refusal,
# not a 404) proves the public mux is up and the challenge route exists.
code=$(curl_code_in othala http://localhost:8080/oauth2/login)
if [[ -n "$code" && "$code" != "404" ]]; then
    pass "A9 othala public /oauth2/login challenge handler mounted (code=$code)"
else
    fail "A9 othala /oauth2/login handler" "code=$code (expected a served non-404; 404 means the route is missing)"
fi

# A9b: The admin mux is DISJOINT from the public mux — an /admin/* route
# must NOT be reachable on the public SSR port. /admin/recovery-gate on
# 8080 is a public page route (gated), never the loopback admin endpoint;
# the loopback POST handler is unreachable across :8080. Assert the
# loopback admin route is NOT served as the JSON endpoint on the public
# port: a GET on 8080 must not be the admin-port 'not found'/handler.
# (Boundary check — the converged app's by-construction mux split.)
code=$(curl_code_in othala http://localhost:8080/healthz)
if [[ "$code" == "404" || -z "$code" ]]; then
    pass "A9b othala public port does NOT serve admin /healthz (mux split holds)"
else
    fail "A9b admin route leaked onto public port" "code=$code (admin /healthz must be loopback-only)"
fi

# A10: ldap-bridge /healthz on admin port (:6478). The bridge image
# carries curl (UBI 9 minimal base for this exact reason); exec via
# compose. The bridge runs all three listeners (LDAP, LDAPS-optional,
# admin HTTP) off a shared errs channel — if any fails the process
# dies — so a healthy /healthz implies LDAP :389 is also bound.
code=$(docker compose exec -T ldap-bridge curl -s -o /dev/null -w "%{http_code}" http://localhost:6478/healthz 2>/dev/null)
if [[ "$code" == "200" ]]; then
    pass "A10 ldap-bridge /healthz (implies LDAP :389 bound)"
else
    fail "A10 ldap-bridge /healthz" "code=$code"
fi

# Section B: client registration (converged in-app registrar)
echo ""
echo "B. client registration (in-app registrar, one-shot)"

# B1: Run the converged app's in-app registrar as a `compose run` one-shot
# on the SAME othala image (dist/server/register-clients.mjs ->
# registerAllClients). This is the successor to the deleted util/
# apply-clients.sh: it reads hydra/clients/*.yaml from MANIFEST_DIR,
# resolves each <SLUG>_CLIENT_SECRET from env, and POST/PUTs every client
# to Hydra admin. Expect exit 0 with every manifest registered.
docker compose run --rm register-clients > /tmp/apply-clients.log 2>&1
applycode=$?
if [[ $applycode -eq 0 ]]; then
    pass "B1 in-app register-clients exited 0"
else
    fail "B1 register-clients exit code $applycode" "see /tmp/apply-clients.log"
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

# Section D: recovery-gate (converged app loopback admin endpoint)
echo ""
echo "D. Recovery-gate (othala :8431 /admin/recovery-gate)"
#
# CU3 convergence: the gate moved from the consent service (:4478,
# X-Webhook-Auth header, group-based refusal) to the othala app's
# loopback admin port (:8431, Authorization: Bearer, ALLOWLIST-based
# refusal). The app's recoveryGateVerdict refuses recovery iff the
# in-flight identity's traits.email is on OTHALA_ADMIN_SUBJECTS (the
# `admin` metadata_admin group is display-only, NOT consulted). It
# fails closed on a missing email and 401s a bad bearer. We probe via
# `compose exec` because the admin port is loopback-only.

# Helper: POST a recovery-gate body with a bearer, capture HTTP code.
# Runs inside the othala container (the admin port is loopback there).
gate_code() {
    local bearer="$1"; local body="$2"
    docker compose exec -T othala wget -qO /dev/null -S \
        --post-data="$body" \
        --header="Content-Type: application/json" \
        --header="Authorization: Bearer ${bearer}" \
        http://127.0.0.1:8431/admin/recovery-gate 2>&1 \
        | awk '/HTTP/ {print $2}' | tail -1
}

ADMIN_EMAIL="admin@${LAB_DOMAIN}"

# D1: Allowlisted admin subject → 403 (admin recovery is console-only).
admin_code=$(gate_code "${RECOVERY_GATE_SECRET}" '{"traits":{"email":"'"${ADMIN_EMAIL}"'"}}')
if [[ "$admin_code" == "403" ]]; then
    pass "D1 recovery-gate refuses allowlisted admin (HIGH-3, allowlist authority)"
else
    fail "D1 recovery-gate admin path" "code=$admin_code want=403 (email ${ADMIN_EMAIL} on OTHALA_ADMIN_SUBJECTS)"
fi

# D2: Non-admin subject (email NOT on the allowlist) → 200, even if it
# carries the display-only `admin` group.
nonadmin_code=$(gate_code "${RECOVERY_GATE_SECRET}" '{"traits":{"email":"kid@'"${LAB_DOMAIN}"'"},"metadata_admin":{"groups":["admin","family"]}}')
if [[ "$nonadmin_code" == "200" ]]; then
    pass "D2 recovery-gate allows non-allowlisted (group 'admin' is display-only)"
else
    fail "D2 recovery-gate non-admin path" "code=$nonadmin_code want=200"
fi

# D3: Missing/unidentifiable email → 403 (fail-closed on a subject the
# gate can't identify).
empty_code=$(gate_code "${RECOVERY_GATE_SECRET}" '{"traits":{}}')
if [[ "$empty_code" == "403" ]]; then
    pass "D3 recovery-gate fails closed on unidentifiable subject"
else
    fail "D3 recovery-gate missing-email path" "code=$empty_code want=403"
fi

# D4: Wrong bearer → 401 (constant-time, fail-closed bearer check on the
# admin mux; distinct from the 403 verdict refusal).
wrong_code=$(gate_code "wrong-secret" '{"traits":{"email":"kid@'"${LAB_DOMAIN}"'"}}')
if [[ "$wrong_code" == "401" ]]; then
    pass "D4 recovery-gate rejects wrong bearer (401, fail-closed)"
else
    fail "D4 recovery-gate wrong bearer" "code=$wrong_code want=401"
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
        for svc in postgres kratos hydra othala ldap-bridge; do
            echo "--- $svc ---"
            docker compose logs --tail=50 "$svc"
        done
    } > /tmp/lab-failure.log
    exit 1
fi
