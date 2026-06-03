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
#
# podman-compose (1.5.x) prepends an ANSI reset (ESC[0m) to the FIRST line
# of `exec` output; docker emits none. Strip it from every captured value
# or JSON parses + string compares break (observed 2026-06-02: curl_code_in
# read "HTTP/1.1" as the status field). _strip_ansi is a no-op under docker,
# so the harness stays engine-portable.
_strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }

curl_in() {
    local container="$1"; shift
    docker compose exec -T "$container" wget -qO- "$@" 2>/dev/null | _strip_ansi
}

curl_code_in() {
    local container="$1"; shift
    docker compose exec -T "$container" wget -qO /dev/null -S "$@" 2>&1 \
        | _strip_ansi | grep -oE 'HTTP/[0-9.]+ +[0-9]{3}' | tail -1 | grep -oE '[0-9]{3}$'
}

# node_in <container> — run a JS program inside <container>'s node, reading
# the SCRIPT FROM STDIN. podman-compose's `exec` mangles argv elements that
# contain spaces/quotes (e.g. `node -e "...'Bearer X'..."` splits on the
# space and breaks the script); feeding the program on stdin keeps it an
# opaque byte stream. docker handles stdin identically, so this is portable.
# othala has node but no wget/curl, so all its probes route through here.
node_in() {
    local container="$1"
    docker compose exec -T "$container" node 2>/dev/null | _strip_ansi
}

# othala_code <url> — HTTP status code via Node fetch.
othala_code() {
    local url="$1"
    printf '%s' "fetch('${url}').then(r=>{process.stdout.write(String(r.status));process.exit(0)}).catch(()=>{process.stdout.write('0');process.exit(1)})" | node_in othala
}

# othala_get <url> — response body via Node fetch.
othala_get() {
    local url="$1"
    printf '%s' "fetch('${url}').then(r=>r.text()).then(t=>{process.stdout.write(t);process.exit(0)}).catch(()=>process.exit(1))" | node_in othala
}

echo "=== smoke matrix ==="

# Section A: Substrate sanity
echo ""
echo "A. Substrate sanity"

# A1: postgres reachable + kratos + hydra DBs exist
out=$(docker compose exec -T postgres psql -U postgres -t -A -c "SELECT datname FROM pg_database WHERE datname IN ('kratos','hydra');" 2>/dev/null | _strip_ansi | sort | tr '\n' ',' )
if [[ "$out" == "hydra,kratos," ]]; then
    pass "A1 postgres: kratos + hydra DBs present"
else
    fail "A1 postgres DBs" "got: $out"
fi

# A2: uuid-ossp on hydra DB
out=$(docker compose exec -T postgres psql -U postgres -d hydra -t -A -c "SELECT extname FROM pg_extension WHERE extname='uuid-ossp';" 2>/dev/null | _strip_ansi)
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
# Issuer is now the Othala public URL: OTHALA_PUBLIC_URL (set to http://auth.othala.test
# in the e2e env by gen-secrets.sh). The old auth-lab.${LAB_DOMAIN} prefix is retired.
expected_issuer="${OTHALA_PUBLIC_URL}/"
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
code=$(othala_code http://127.0.0.1:8431/healthz)
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
code=$(othala_code http://localhost:8080/oauth2/login)
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
code=$(othala_code http://localhost:8080/healthz)
if [[ "$code" == "404" ]]; then
    pass "A9b othala public port does NOT serve admin /healthz (mux split holds)"
else
    fail "A9b admin route leaked onto public port" "code=$code (expected 404; admin /healthz must be loopback-only)"
fi

# A10: ldap-bridge /healthz on admin port (:6478). The bridge image
# carries curl (UBI 9 minimal base for this exact reason); exec via
# compose. The bridge runs all three listeners (LDAP, LDAPS-optional,
# admin HTTP) off a shared errs channel — if any fails the process
# dies — so a healthy /healthz implies LDAP :389 is also bound.
code=$(docker compose exec -T ldap-bridge curl -s -o /dev/null -w "%{http_code}" http://localhost:6478/healthz 2>/dev/null | _strip_ansi)
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
#
# --no-deps is REQUIRED under podman-compose: a bare `compose run` does an
# `up` reconciliation of the service's deps that RECREATES the whole running
# project (it killed othala + kratos mid-smoke). --no-deps skips that; it is a
# no-op under docker since `up -d` already started the deps.
docker compose --profile oneshot run --rm --no-deps register-clients > /tmp/apply-clients.log 2>&1
applycode=$?
if [[ $applycode -eq 0 ]]; then
    pass "B1 in-app register-clients exited 0"
else
    fail "B1 register-clients exit code $applycode" "register-clients output below"
    echo "  ----- register-clients output (/tmp/apply-clients.log) -----"
    sed 's/^/    | /' /tmp/apply-clients.log 2>/dev/null || true
    echo "  ----- end register-clients output -----"
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

# C1: Create an identity via the Kratos admin API. kratos' busybox wget has
# no --post-data, so POST from othala's node over the compose network (othala
# reaches kratos:4434). Program on stdin (podman-compose-safe).
identity_json=$(printf '%s' "fetch('http://kratos:4434/admin/identities',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schema_id:'family',traits:{username:'lab.test',email:'lab.test@${OTHALA_APEX}',displayName:'Lab Test'},metadata_admin:{groups:['family','access-keep','access-observe']}})}).then(r=>r.text()).then(t=>{process.stdout.write(t);process.exit(0)}).catch(()=>process.exit(1))" | node_in othala)
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
# Uses Node fetch — the ci-runtime-node image has no wget/curl.
gate_code() {
    local bearer="$1"; local body="$2"
    printf '%s' "fetch('http://127.0.0.1:8431/admin/recovery-gate',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer ${bearer}'},body:'${body}'}).then(r=>{process.stdout.write(String(r.status));process.exit(0)}).catch(()=>{process.stdout.write('0');process.exit(1)})" | node_in othala
}

ADMIN_EMAIL="admin@${OTHALA_APEX}"

# D1: Allowlisted admin subject → 403 (admin recovery is console-only).
admin_code=$(gate_code "${RECOVERY_GATE_SECRET}" '{"traits":{"email":"'"${ADMIN_EMAIL}"'"}}')
if [[ "$admin_code" == "403" ]]; then
    pass "D1 recovery-gate refuses allowlisted admin (HIGH-3, allowlist authority)"
else
    fail "D1 recovery-gate admin path" "code=$admin_code want=403 (email ${ADMIN_EMAIL} on OTHALA_ADMIN_SUBJECTS)"
fi

# D2: Non-admin subject (email NOT on the allowlist) → 200, even if it
# carries the display-only `admin` group.
nonadmin_code=$(gate_code "${RECOVERY_GATE_SECRET}" '{"traits":{"email":"kid@'"${OTHALA_APEX}"'"},"metadata_admin":{"groups":["admin","family"]}}')
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
wrong_code=$(gate_code "wrong-secret" '{"traits":{"email":"kid@'"${OTHALA_APEX}"'"}}')
if [[ "$wrong_code" == "401" ]]; then
    pass "D4 recovery-gate rejects wrong bearer (401, fail-closed)"
else
    fail "D4 recovery-gate wrong bearer" "code=$wrong_code want=401"
fi

# Section E: revoke fan-out (admin endpoint, LIVE Kratos + Hydra)
echo ""
echo "E. Revoke fan-out (othala :8431 /admin/revoke-user)"
#
# D3: the admin force-logout endpoint runs revokeSubject() against LIVE Kratos
# + Hydra — delete Kratos sessions + revoke Hydra login/consent sessions
# (closes the ≤24h deactivated-user token gap). The unit tests only STUB the
# SDK; this is the first probe that drives the fan-out end-to-end. Loopback
# admin port, so via node_in. Uses the identity C1 created.

# revoke_body <bearer> <subject> — POST /admin/revoke-user, return JSON body.
revoke_body() {
    local bearer="$1"; local subject="$2"
    printf '%s' "fetch('http://127.0.0.1:8431/admin/revoke-user',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer ${bearer}'},body:JSON.stringify({subject:'${subject}'})}).then(r=>r.text()).then(t=>{process.stdout.write(t);process.exit(0)}).catch(()=>process.exit(1))" | node_in othala
}
# revoke_code <bearer> <body-json> — POST /admin/revoke-user, return HTTP code.
revoke_code() {
    local bearer="$1"; local body="$2"
    printf '%s' "fetch('http://127.0.0.1:8431/admin/revoke-user',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer ${bearer}'},body:'${body}'}).then(r=>{process.stdout.write(String(r.status));process.exit(0)}).catch(()=>{process.stdout.write('0');process.exit(1)})" | node_in othala
}

# E1: wrong bearer → 401 (fail-closed, mirrors D4; bearer checked before body).
e1=$(revoke_code "wrong-secret" '{"subject":"anything"}')
if [[ "$e1" == "401" ]]; then
    pass "E1 revoke-user rejects wrong bearer (401, fail-closed)"
else
    fail "E1 revoke-user wrong bearer" "code=$e1 want=401"
fi

# E2: valid bearer, missing subject → 400.
e2=$(revoke_code "${OTHALA_ADMIN_ENDPOINT_BEARER}" '{}')
if [[ "$e2" == "400" ]]; then
    pass "E2 revoke-user 400 on missing subject"
else
    fail "E2 revoke-user missing subject" "code=$e2 want=400"
fi

# E3: valid bearer + the real C1 subject → 200 + the live fan-out flags. Drives
# revokeSubject against LIVE Kratos + Hydra (the integration the stubs can't prove).
if [[ -n "${identity_id:-}" ]]; then
    rb=$(revoke_body "${OTHALA_ADMIN_ENDPOINT_BEARER}" "$identity_id")
    flags=$(echo "$rb" | python3 -c "import sys,json
d=json.load(sys.stdin)
print('%s,%s,%s' % (d.get('kratosSessionsRevoked'), d.get('hydraLoginRevoked'), d.get('hydraConsentRevoked')))" 2>/dev/null || echo "parse-fail")
    if [[ "$flags" == "True,True,True" ]]; then
        pass "E3 revoke-user fan-out landed (kratos sessions + hydra login + hydra consent revoked)"
    else
        fail "E3 revoke-user fan-out" "flags(kratos,hydraLogin,hydraConsent)=$flags body=$rb"
    fi
else
    fail "E3 revoke-user fan-out" "no identity_id from C1 to revoke"
fi

# Section F: dual-listener boundary (the reverse of A9b)
echo ""
echo "F. Listener boundary"
# A9b proved admin routes don't bleed onto the public port. F1 proves the
# reverse: the loopback admin mux does NOT serve public SSR routes.
f1=$(othala_code http://127.0.0.1:8431/oauth2/login)
if [[ "$f1" == "404" ]]; then
    pass "F1 admin port does NOT serve public /oauth2/login (mux split holds both ways)"
else
    fail "F1 public route leaked onto admin port" "code=$f1 want=404 (admin mux must not serve SSR routes)"
fi

# Section G: full browser-free OIDC dance (login forged via Hydra admin -> the
# app's consent handler -> auth code -> ID token). The converged challenge surface
# end-to-end against LIVE Kratos + Hydra. See oidc-dance.mjs for the mechanics.
echo ""
echo "G. OIDC dance (login -> consent -> ID token; claims + access-gate deny)"

# mk_identity <state> <groups-json> <localpart> -> echoes the new identity id.
mk_identity() {
    printf '%s' "fetch('http://kratos:4434/admin/identities',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schema_id:'family',state:'$1',traits:{username:'$3',email:'$3@${OTHALA_APEX}',displayName:'$3'},metadata_admin:{groups:$2}})}).then(r=>r.json()).then(j=>{process.stdout.write(j.id||'');process.exit(0)}).catch(()=>process.exit(1))" | node_in othala
}
# run_dance <subject> -> the dance result line (OK claims=... / DENIED... / STEP/EXC).
# Substitutes the subject + keep client secret into oidc-dance.mjs and pipes the
# result to the dance-runner oneshot container (playwright image + npm deps).
# Each call starts a fresh container (--rm); npm ci runs every time (~5-10s per
# invocation). This is acceptable for 3 G probes; a future optimisation would
# bake a sub-image with the deps pre-installed.
run_dance() {
    local out res
    out=$(sed "s|__SUBJECT__|$1|g; s|__KEEP_SECRET__|${KEEP_CLIENT_SECRET}|g" ./oidc-dance.mjs \
        | docker compose --profile oneshot run --rm --no-deps -T dance-runner 2>&1 | _strip_ansi)
    res=$(echo "$out" | grep -E '^OK |^DENIED|^STEP|^EXC' | tail -1)
    if [[ -z "$res" ]]; then
        # No result line means the dance crashed (dep install, SDK error, etc.).
        # Surface the full output to the trace instead of swallowing it.
        echo "  ----- dance produced no OK/DENIED/STEP/EXC line; full output: -----" >&2
        echo "$out" | sed 's/^/    | /' | tail -45 >&2
        echo "  ----- end dance output -----" >&2
    fi
    echo "$res"
}

# G1: active member WITH the access-keep group -> dance completes, and the ID token
# carries the manifest-injected role claim (resource_access.keep.roles=[user]).
# This is the integration guard for the claims-injection convergence regression.
g1_id=$(mk_identity active "['family','access-keep']" g1.activekeep)
g1=$(run_dance "$g1_id")
if [[ "$g1" == OK* && "$g1" == *'"keep_roles":["user"]'* ]]; then
    pass "G1 OIDC dance issues an ID token with the injected role claim (keep_roles=[user])"
else
    fail "G1 OIDC dance + claims injection" "got: $g1"
fi

# G2: INACTIVE identity -> access-gate denies at the consent re-gate (state check).
g2_id=$(mk_identity inactive "['family','access-keep']" g2.inactive)
g2=$(run_dance "$g2_id")
if [[ "$g2" == DENIED* && "$g2" == *active* ]]; then
    pass "G2 OIDC dance DENIES an inactive identity (state gate, D3)"
else
    fail "G2 inactive deny" "got: $g2 (want DENIED ... not active)"
fi

# G3: active identity WITHOUT the access-keep group -> denied at consent (group check).
g3_id=$(mk_identity active "['family']" g3.nogroup)
g3=$(run_dance "$g3_id")
if [[ "$g3" == DENIED* && "$g3" == *access-keep* ]]; then
    pass "G3 OIDC dance DENIES a member missing the access-keep group (group gate)"
else
    fail "G3 no-group deny" "got: $g3 (want DENIED ... access-keep group)"
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
    # Dump diagnostics to STDOUT (the CI trace) — /tmp artifacts aren't uploadable
    # (not a subpath of the project dir) and `docker compose logs` fails under the
    # podman shim (it injects --no-color, which podman-compose rejects). Use native
    # `podman logs <container>`; container_name is lab-<svc>.
    echo ""
    echo "=== container ps ==="
    docker compose ps 2>&1 || true
    echo ""
    echo "=== container logs (last 60 each) ==="
    for svc in postgres kratos hydra othala ldap-bridge; do
        echo "--- lab-$svc ---"
        podman logs --tail=60 "lab-$svc" 2>&1 || true
    done
    exit 1
fi
