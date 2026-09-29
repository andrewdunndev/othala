#!/usr/bin/env bash
# smoke.sh — converged-substrate validation matrix.
#
# Runs INSIDE the e2e VM after `docker compose up -d` brings up the
# converged Othala substrate. Probes each container directly on its
# compose network hostname (postgres, kratos, hydra, othala).
#
# The othala app is ONE service: public SSR port 8080 (family UI +
# /auth/* + /admin/* + the /oauth2/{login,consent,logout} challenge
# handlers) and a loopback admin port 4431 (/healthz, /readyz,
# /admin/revoke-user, /admin/recovery-gate). The admin port binds
# 127.0.0.1 inside the container, so admin probes run via `compose exec`
# against localhost:4431; the public port is probed across the network.
#
# Exit 0 on all-green, 1 on any failure. Failure diagnostics (container
# ps/logs) print to STDOUT for the CI job trace; the one on-disk log this
# script produces (register-clients output, B1) lands under LOG_DIR for
# CI artifact upload — see LOG_DIR below for why that can't be /tmp.
#
# Pre-conditions:
#   - `docker compose` (podman-docker bridge) up
#   - All long-running services have hit healthy state
#   - .env present in cwd

set -uo pipefail   # NOT -e: every probe runs even if some fail.

# LOG_DIR: on-disk logs this script writes MUST live inside the project
# checkout. GitLab Runner refuses `artifacts:paths` entries that resolve
# outside $CI_PROJECT_DIR ("artifact path is not a subpath of project
# directory") and drops the WHOLE on-failure artifact archive when it does
# — not just the offending entry (observed live: job 15871403418, every
# e2e failure lost its diagnostics). smoke.sh runs with cwd=e2e/ (validate.sh
# cd's there before sourcing it), so a plain relative path is enough; SCRIPT_DIR
# makes that true for direct/local invocation too. Gitignored via the root
# *.log rule. .gitlab-ci.yml's e2e job artifacts: paths must match this.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"
APPLY_CLIENTS_LOG="$LOG_DIR/apply-clients.log"

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

# A0: healthcheck probes write no access-log line (request_log.
# disable_for_health on the listener each compose healthcheck targets). Runs
# before any probe below touches a health path. Each service fires its own
# healthcheck, then a request that IS logged; once that control line shows,
# the probe's line would show too, so zero health lines is a real zero.
for row in "kratos http://localhost:4433/.well-known/ory/webauthn.js" \
           "hydra http://localhost:4444/.well-known/openid-configuration"; do
    svc="${row%% *}"; control="${row#* }"
    control_path="/${control#http://*/}"
    podman healthcheck run "lab-$svc" >/dev/null 2>&1
    curl_code_in "$svc" "$control" >/dev/null
    seen=0
    for _ in 1 2 3 4 5; do
        logs=$(podman logs "lab-$svc" 2>&1)
        seen=$(grep -cF "\"path\":\"$control_path\"" <<<"$logs")
        [[ "$seen" -gt 0 ]] && break
        sleep 1
    done
    health=$(grep -cE '"path":"(/admin)?/health/(alive|ready)"' <<<"$logs")
    if [[ "$seen" -eq 0 ]]; then
        fail "A0 $svc health probes unlogged" "control $control_path never logged; log unreadable"
    elif [[ "$health" -ne 0 ]]; then
        fail "A0 $svc health probes unlogged" "$health health-path access-log lines"
    else
        pass "A0 $svc health probes unlogged"
    fi
done

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
# Issuer is the Othala public URL: OTHALA_PUBLIC_URL (set to http://auth.othala.test
# in the e2e env by gen-secrets.sh).
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

# A8: Othala app admin /healthz on the loopback admin port (4431).
# /healthz + /readyz live on the admin mux, NOT the public SSR port.
code=$(othala_code http://127.0.0.1:4431/healthz)
if [[ "$code" == "200" ]]; then
    pass "A8 othala admin /healthz (loopback :4431)"
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

# A10: ldap-bridge /healthz — SKIPPED. The LDAP bridge is now a
# separate project (gitlab.com/dunn.dev/kratos-ldap); no bridge
# service is pulled in this compose harness since no e2e spec exercises
# LDAP. Operators who extend this harness with LDAP can add A10 back
# against the kratos-ldap service.
# pass "A10 ldap-bridge /healthz (implies LDAP :389 bound)" -- not wired

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
docker compose --profile oneshot run --rm --no-deps register-clients > "$APPLY_CLIENTS_LOG" 2>&1
applycode=$?
if [[ $applycode -eq 0 ]]; then
    pass "B1 in-app register-clients exited 0"
else
    fail "B1 register-clients exit code $applycode" "register-clients output below"
    echo "  ----- register-clients output ($APPLY_CLIENTS_LOG) -----"
    sed 's/^/    | /' "$APPLY_CLIENTS_LOG" 2>/dev/null || true
    echo "  ----- end register-clients output -----"
fi

# B2: Hydra admin lists EXACTLY the clients with an oidc: block. The count
# is DATA-DRIVEN from the fixtures: grep the manifest dir for files that
# declare a top-level `oidc:` block (presentation-only tiles — filedrop,
# proxywatch, statuspage — have none and register no client). No hardcoded
# number; add/remove an OIDC fixture and this re-derives.
oidc_fixture_count=$(grep -lE '^oidc:' ./manifests/*.yaml 2>/dev/null | wc -l | tr -d ' ')
clients_json=$(curl_in hydra http://localhost:4445/admin/clients)
client_count=$(echo "$clients_json" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
if [[ "$client_count" == "$oidc_fixture_count" ]]; then
    pass "B2 hydra admin lists $client_count clients (== $oidc_fixture_count oidc: fixtures)"
else
    fail "B2 hydra admin client count" "got=$client_count want=$oidc_fixture_count (fixtures with an oidc: block)"
fi

# B3: Specific client check — grafana is registered (the role-mapping client
# the G-series dance drives against).
grafana_check=$(curl_code_in hydra http://localhost:4445/admin/clients/grafana)
if [[ "$grafana_check" == "200" ]]; then
    pass "B3 grafana client registered"
else
    fail "B3 grafana client missing" "code=$grafana_check"
fi

# B4: audiobookshelf registered (the plain generic_oauth client).
abs_check=$(curl_code_in hydra http://localhost:4445/admin/clients/audiobookshelf)
if [[ "$abs_check" == "200" ]]; then
    pass "B4 audiobookshelf client registered"
else
    fail "B4 audiobookshelf client missing" "code=$abs_check"
fi

# Section C: identity admin flow
echo ""
echo "C. Identity admin flow"

# C1: Create an identity via the Kratos admin API. kratos' busybox wget has
# no --post-data, so POST from othala's node over the compose network (othala
# reaches kratos:4434). Program on stdin (podman-compose-safe).
identity_json=$(printf '%s' "fetch('http://kratos:4434/admin/identities',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schema_id:'family',traits:{username:'lab.test',email:'lab.test@${OTHALA_APEX}',displayName:'Lab Test'},metadata_admin:{groups:['grafana-access','audiobookshelf-access']}})}).then(r=>r.text()).then(t=>{process.stdout.write(t);process.exit(0)}).catch(()=>process.exit(1))" | node_in othala)
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
    if [[ "$groups" == "grafana-access,audiobookshelf-access" ]]; then
        pass "C2 identity round-trip preserves metadata_admin.groups"
    else
        fail "C2 metadata_admin.groups round-trip" "got=$groups"
    fi
fi

# Section D: recovery-gate (converged app loopback admin endpoint)
echo ""
echo "D. Recovery-gate (othala :4431 /admin/recovery-gate)"
#
# As hardened for Kratos v26.2.0: the gate does NOT trust the
# payload's `is_admin` field — v26.2.0 omits metadata_admin from ctx.identity
# in after-hook context (confirmed empirically 2026-06-25) — so it re-fetches
# the identity from the Kratos admin API and refuses iff metadata_admin.admin
# === true (fetchAdminMarker, portal/src/server/listen.mjs). ANY lookup
# failure (unknown identity, admin API down) fails CLOSED. The probes must
# therefore use REAL seeded identities: a placeholder UUID 403s via
# fail-closed, which makes an admin-refusal probe pass vacuously and a
# non-admin-allows probe fail spuriously. The retired OTHALA_ADMIN_IDS UUID
# allowlist is no longer consulted. We probe via `compose exec` because the
# admin port is loopback-only.
#
# Payload shape: { identity_id, is_admin, groups, traits } (per
# recovery-gate.jsonnet); only identity_id feeds the decision today.

# Helper: POST a recovery-gate body with a bearer, capture HTTP code.
# Runs inside the othala container (the admin port is loopback there).
# Uses Node fetch — the ci-runtime-node image has no wget/curl.
gate_code() {
    local bearer="$1"; local body="$2"
    printf '%s' "fetch('http://127.0.0.1:4431/admin/recovery-gate',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer ${bearer}'},body:'${body}'}).then(r=>{process.stdout.write(String(r.status));process.exit(0)}).catch(()=>{process.stdout.write('0');process.exit(1)})" | node_in othala
}

# Helper variant: capture "code|body" so a refusal REASON can be asserted
# (distinguishes marker-refusal from fail-closed refusal).
gate_resp() {
    local bearer="$1"; local body="$2"
    printf '%s' "fetch('http://127.0.0.1:4431/admin/recovery-gate',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer ${bearer}'},body:'${body}'}).then(async r=>{const t=await r.text();process.stdout.write(r.status+'|'+t);process.exit(0)}).catch(()=>{process.stdout.write('0|');process.exit(1)})" | node_in othala
}

# D1: seed a REAL identity with metadata_admin.admin=true, then probe. Expect
# 403 WITH the console-only reason (not just any 403 — a fail-closed 403 must
# not satisfy this probe). Payload deliberately says is_admin=false to prove
# the marker outranks the payload field.
admin_identity_json=$(printf '%s' "fetch('http://kratos:4434/admin/identities',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schema_id:'family',traits:{username:'lab.admin',email:'lab.admin@${OTHALA_APEX}',displayName:'Lab Admin'},metadata_admin:{admin:true,groups:['grafana-access','grafana-admin']}})}).then(r=>r.text()).then(t=>{process.stdout.write(t);process.exit(0)}).catch(()=>process.exit(1))" | node_in othala)
admin_identity_id=$(echo "$admin_identity_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
if [[ -n "$admin_identity_id" ]]; then
    admin_resp=$(gate_resp "${RECOVERY_GATE_SECRET}" "{\"identity_id\":\"${admin_identity_id}\",\"is_admin\":false,\"groups\":[\"grafana-admin\"],\"traits\":{}}")
    admin_code="${admin_resp%%|*}"; admin_body="${admin_resp#*|}"
    if [[ "$admin_code" == "403" && "$admin_body" == *"console-only"* ]]; then
        pass "D1 recovery-gate refuses metadata_admin.admin=true identity (console-only; marker outranks payload is_admin=false)"
    else
        fail "D1 recovery-gate admin path" "code=$admin_code body=$admin_body want=403 + console-only reason"
    fi
else
    fail "D1 seed admin identity" "response: $admin_identity_json"
fi

# D2: the REAL non-admin identity from C1 (metadata_admin has groups, no
# admin marker) → 200, even when the PAYLOAD claims an admin-tier group
# ('grafana-admin'). Group membership is app authorization; PORTAL admin
# authority is the metadata_admin.admin marker alone, and a payload cannot
# assert either.
if [[ -n "$identity_id" ]]; then
    nonadmin_code=$(gate_code "${RECOVERY_GATE_SECRET}" "{\"identity_id\":\"${identity_id}\",\"is_admin\":false,\"groups\":[\"grafana-admin\"],\"traits\":{}}")
    if [[ "$nonadmin_code" == "200" ]]; then
        pass "D2 recovery-gate allows non-admin identity (marker absent; no group confers portal admin authority)"
    else
        fail "D2 recovery-gate non-admin path" "code=$nonadmin_code want=200"
    fi
else
    fail "D2 recovery-gate non-admin path" "no C1 identity available to probe with"
fi

# D3: Missing/unidentifiable identity_id → 403 (fail-closed on a subject the
# gate can't identify; is_admin present but id absent).
empty_code=$(gate_code "${RECOVERY_GATE_SECRET}" '{"is_admin":false,"groups":[],"traits":{}}')
if [[ "$empty_code" == "403" ]]; then
    pass "D3 recovery-gate fails closed on unidentifiable subject (missing identity_id)"
else
    fail "D3 recovery-gate missing-identity_id path" "code=$empty_code want=403"
fi

# D4: Wrong bearer → 403 (constant-time, fail-closed bearer check on the admin
# mux). 403 not 401: Kratos webhooks use can_interrupt, so a non-403 risks being
# treated as a skippable webhook error (fail-open); the bearer reject returns 403
# to reliably abort the flow. Bearer check fires before payload inspection.
wrong_code=$(gate_code "wrong-secret" '{"identity_id":"00000000-0000-0000-0000-000000000099","is_admin":false,"traits":{}}')
if [[ "$wrong_code" == "403" ]]; then
    pass "D4 recovery-gate rejects wrong bearer (403, fail-closed)"
else
    fail "D4 recovery-gate wrong bearer" "code=$wrong_code want=403"
fi

# D5: Malformed is_admin (non-boolean) → 403 (fail-closed; jsonnet always
# emits a boolean, so a non-boolean signals tampering or a gate bug).
malformed_code=$(gate_code "${RECOVERY_GATE_SECRET}" '{"identity_id":"00000000-0000-0000-0000-000000000099","is_admin":"true","groups":[],"traits":{}}')
if [[ "$malformed_code" == "403" ]]; then
    pass "D5 recovery-gate refuses malformed is_admin (non-boolean → fail-closed)"
else
    fail "D5 recovery-gate malformed is_admin" "code=$malformed_code want=403 (non-boolean is_admin must be refused)"
fi

# Section E: revoke fan-out (admin endpoint, LIVE Kratos + Hydra)
echo ""
echo "E. Revoke fan-out (othala :4431 /admin/revoke-user)"
#
# D3: the admin force-logout endpoint runs revokeSubject() against LIVE Kratos
# + Hydra — delete Kratos sessions + revoke Hydra login/consent sessions
# (closes the ≤24h deactivated-user token gap). The unit tests only STUB the
# SDK; this is the first probe that drives the fan-out end-to-end. Loopback
# admin port, so via node_in. Uses the identity C1 created.

# revoke_body <bearer> <subject> — POST /admin/revoke-user, return JSON body.
revoke_body() {
    local bearer="$1"; local subject="$2"
    printf '%s' "fetch('http://127.0.0.1:4431/admin/revoke-user',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer ${bearer}'},body:JSON.stringify({subject:'${subject}'})}).then(r=>r.text()).then(t=>{process.stdout.write(t);process.exit(0)}).catch(()=>process.exit(1))" | node_in othala
}
# revoke_code <bearer> <body-json> — POST /admin/revoke-user, return HTTP code.
revoke_code() {
    local bearer="$1"; local body="$2"
    printf '%s' "fetch('http://127.0.0.1:4431/admin/revoke-user',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer ${bearer}'},body:'${body}'}).then(r=>{process.stdout.write(String(r.status));process.exit(0)}).catch(()=>{process.stdout.write('0');process.exit(1)})" | node_in othala
}

# E1: wrong bearer → 403 (fail-closed, mirrors D4; bearer checked before body).
e1=$(revoke_code "wrong-secret" '{"subject":"anything"}')
if [[ "$e1" == "403" ]]; then
    pass "E1 revoke-user rejects wrong bearer (403, fail-closed)"
else
    fail "E1 revoke-user wrong bearer" "code=$e1 want=403"
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
f1=$(othala_code http://127.0.0.1:4431/oauth2/login)
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
# Substitutes the subject + grafana client secret into oidc-dance.mjs and pipes
# the result to the dance-runner oneshot container (playwright image + npm deps).
# The dance drives the grafana client (THE role-mapping example): its registered
# redirect_uri byte-matches the grafana fixture and its consent block emits the
# grafana_role claim asserted below.
# Each call starts a fresh container (--rm); npm ci runs every time (~5-10s per
# invocation). This is acceptable for 3 G probes; a future optimisation would
# bake a sub-image with the deps pre-installed.
run_dance() {
    local out res
    out=$(sed "s|__SUBJECT__|$1|g; s|__GRAFANA_SECRET__|${GRAFANA_CLIENT_SECRET}|g" ./oidc-dance.mjs \
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

# G1: active member holding grafana-access -> dance completes, and the ID token
# carries grafana's manifest-injected role claim (grafana-access -> viewer ->
# grafana_role=[Viewer]). This is the integration guard for the claims-injection
# convergence regression. The admin pairing and its ordering hazard are asserted
# in the browser phase (playwright/tests/t-access-model.spec.ts T2/T3).
g1_id=$(mk_identity active "['grafana-access']" g1.activegrafana)
g1=$(run_dance "$g1_id")
if [[ "$g1" == OK* && "$g1" == *'"grafana_role":["Viewer"]'* ]]; then
    pass "G1 OIDC dance issues an ID token with the injected role claim (grafana_role=[Viewer])"
else
    fail "G1 OIDC dance + claims injection" "got: $g1"
fi

# G2: INACTIVE identity -> access-gate denies at the consent re-gate (state check).
g2_id=$(mk_identity inactive "['grafana-access']" g2.inactive)
g2=$(run_dance "$g2_id")
# error_description is opaque ('access_denied') by design — the precise reason
# ('identity not active') is logged server-side only and asserted in
# oauth2-handlers.test.mjs. The e2e guard is that the inactive identity is DENIED.
if [[ "$g2" == DENIED* && "$g2" == *access_denied* ]]; then
    pass "G2 OIDC dance DENIES an inactive identity (state gate, D3)"
else
    fail "G2 inactive deny" "got: $g2 (want DENIED ... access_denied)"
fi

# G3: active identity holding ONLY grafana-admin -> DENIED at the access gate.
# Admin-implies-access is abolished: entry comes from grafana-access, which this
# identity does not hold, and NOTHING derives entry from an admin group. The
# grafana manifest binds only grafana-access under presentation.access; putting
# grafana-admin back in that list is what would flip this probe.
g3_id=$(mk_identity active "['grafana-admin']" g3.adminonly)
g3=$(run_dance "$g3_id")
# Opaque error_description by design (see G2); precise reason is server-side only.
# The e2e guard is that the admin-group-only identity is DENIED.
if [[ "$g3" == DENIED* && "$g3" == *access_denied* ]]; then
    pass "G3 OIDC dance DENIES an identity holding ONLY grafana-admin (admin does not imply access)"
else
    fail "G3 admin-only deny" "got: $g3 (want DENIED ... access_denied) — admin-implies-access may have been reintroduced"
fi

# Section H: contact / request form (SSR /api/request, signed-in only).
echo ""
echo "H. Contact form (othala :8080 /api/request -> mailpit)"
#
# Probes run from inside the othala container (it has node; reaches :8080
# and mailpit's HTTP API).

# Signed-in behaviour (200 + delivery, validation, rate limit keyed on the
# identity) is covered by Playwright spec z-contact-form; smoke has no session
# cookie, so it holds the signed-out edge.

# H1: a POST without a session is refused (401) and sends nothing.
H_MARKER="smoke-contact-$(date +%s)-$$"
h1=$(printf '%s' "fetch('http://localhost:8080/api/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'Smoke Tester',type:'access',message:'${H_MARKER} please grant access to an app'})}).then(r=>{process.stdout.write(String(r.status));process.exit(0)}).catch(()=>{process.stdout.write('0');process.exit(1)})" | node_in othala)
if [[ "$h1" == "401" ]]; then
    pass "H1 /api/request refuses a submission without a session (401)"
else
    fail "H1 /api/request without a session" "code=$h1 want=401"
fi

# H2: nothing from that submission reached the mail catcher.
h2=$(printf '%s' "fetch('http://mailpit:8025/api/v1/search?query=${H_MARKER}').then(r=>r.json()).then(d=>{process.stdout.write(String(d.messages_count??(d.messages||[]).length));process.exit(0)}).catch(e=>{process.stdout.write('ERR:'+e.message);process.exit(1)})" | node_in othala)
if [[ "$h2" == "0" ]]; then
    pass "H2 the refused submission sent no mail"
else
    fail "H2 refused submission left mail in the catcher" "got=$h2"
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
    for svc in postgres kratos hydra othala mailpit; do
        echo "--- lab-$svc ---"
        podman logs --tail=60 "lab-$svc" 2>&1 || true
    done
    exit 1
fi
