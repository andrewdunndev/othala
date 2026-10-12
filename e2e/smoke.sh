#!/usr/bin/env bash
# smoke.sh: converged-substrate validation matrix, run in the e2e VM after compose up.
# Admin probes run via `compose exec` against the internal-network bind hosts from othala.env; the
# public port is probed across the network. Exit 0 on all-green; diagnostics print to STDOUT.
# Needs validate.sh: the stack up and healthy, othala.env and secrets.env exported.

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

# Every probe goes through `docker compose exec` (the compose network is a private bridge).
# podman-compose prepends an ANSI reset to the first line of exec output, which breaks
# JSON parses and string compares; _strip_ansi is a no-op under docker.
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

# node_in <container>: run a JS program from STDIN inside <container>'s node (podman-compose
# mangles argv with spaces/quotes). othala has no wget/curl, so its probes route here.
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

# A0: health probes write no access-log line (request_log.disable_for_health). Each service
# fires its healthcheck then a logged control request, so zero health lines is a real zero.
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
code=$(curl_code_in kratos http://${KRATOS_ADMIN_BIND_HOST}:4434/admin/health/ready)
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
code=$(curl_code_in hydra http://${HYDRA_ADMIN_BIND_HOST}:4445/health/ready)
if [[ "$code" == "200" ]]; then
    pass "A5 hydra admin /health/ready"
else
    fail "A5 hydra admin /health/ready" "code=$code"
fi

# A6: Hydra public /.well-known/openid-configuration + issuer byte-match
oidc=$(curl_in hydra http://localhost:4444/.well-known/openid-configuration)
issuer=$(echo "$oidc" | python3 -c "import sys,json; print(json.load(sys.stdin).get('issuer',''))" 2>/dev/null || echo "")
# Issuer is OTHALA_PUBLIC_URL (http://auth.othala.test from othala.env).
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

# A8: othala admin /healthz on the bind host :4431 (admin mux, not the public port).
code=$(othala_code http://${PORTAL_ADMIN_BIND_HOST}:4431/healthz)
if [[ "$code" == "200" ]]; then
    pass "A8 othala admin /healthz (bind host :4431)"
else
    fail "A8 othala admin /healthz" "code=$code"
fi

# A9: /oauth2/login without a login_challenge is served (not 404, not refused) and rejects
# the absent challenge.
code=$(othala_code http://localhost:8080/oauth2/login)
if [[ -n "$code" && "$code" != "404" ]]; then
    pass "A9 othala public /oauth2/login challenge handler mounted (code=$code)"
else
    fail "A9 othala /oauth2/login handler" "code=$code (expected a served non-404; 404 means the route is missing)"
fi

# A9b: the admin mux is disjoint from the public mux; a GET of /admin/recovery-gate on 8080
# is a gated page route, never the admin endpoint.
code=$(othala_code http://localhost:8080/healthz)
if [[ "$code" == "404" ]]; then
    pass "A9b othala public port does NOT serve admin /healthz (mux split holds)"
else
    fail "A9b admin route leaked onto public port" "code=$code (expected 404; admin /healthz must be admin-port-only)"
fi

# Section B: client registration (boot reconcile in the othala service)
echo ""
echo "B. client registration (boot reconcile)"

# B2: Hydra admin lists exactly the clients with an oidc: block, counted from the manifest
# fixtures (presentation-only tiles register none).
oidc_fixture_count=$(grep -lE '^oidc:' ./content/apps/*.yaml 2>/dev/null | wc -l | tr -d ' ')
# The boot reconcile runs behind hydra's healthcheck (5 x 2 s), so poll.
client_count=0
for _ in $(seq 1 30); do
    clients_json=$(curl_in hydra http://${HYDRA_ADMIN_BIND_HOST}:4445/admin/clients)
    client_count=$(echo "$clients_json" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    [[ "$client_count" == "$oidc_fixture_count" ]] && break
    sleep 2
done
if [[ "$client_count" == "$oidc_fixture_count" ]]; then
    pass "B2 hydra admin lists $client_count clients (== $oidc_fixture_count oidc: fixtures)"
else
    fail "B2 hydra admin client count" "got=$client_count want=$oidc_fixture_count (fixtures with an oidc: block)"
fi

# B3: grafana is registered (the role-mapping client the G-series drives).
grafana_check=$(curl_code_in hydra http://${HYDRA_ADMIN_BIND_HOST}:4445/admin/clients/grafana)
if [[ "$grafana_check" == "200" ]]; then
    pass "B3 grafana client registered"
else
    fail "B3 grafana client missing" "code=$grafana_check"
fi

# B4: audiobookshelf registered (the plain generic_oauth client).
abs_check=$(curl_code_in hydra http://${HYDRA_ADMIN_BIND_HOST}:4445/admin/clients/audiobookshelf)
if [[ "$abs_check" == "200" ]]; then
    pass "B4 audiobookshelf client registered"
else
    fail "B4 audiobookshelf client missing" "code=$abs_check"
fi

# Section C: identity admin flow
echo ""
echo "C. Identity admin flow"

# C1: create an identity via the Kratos admin API; kratos' wget has no --post-data, so POST
# from othala's node (program on stdin).
identity_json=$(printf '%s' "fetch('http://kratos:4434/admin/identities',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schema_id:'family',traits:{username:'lab.test',email:'lab.test@${OTHALA_APEX}',displayName:'Lab Test'},metadata_admin:{groups:['grafana-access','audiobookshelf-access']}})}).then(r=>r.text()).then(t=>{process.stdout.write(t);process.exit(0)}).catch(()=>process.exit(1))" | node_in othala)
identity_id=$(echo "$identity_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
if [[ -n "$identity_id" ]]; then
    pass "C1 created identity id=$identity_id"
else
    fail "C1 create identity failed" "response: $identity_json"
fi

# C2: Read identity back, metadata_admin.groups round-tripped
if [[ -n "$identity_id" ]]; then
    rt=$(curl_in kratos "http://${KRATOS_ADMIN_BIND_HOST}:4434/admin/identities/$identity_id")
    groups=$(echo "$rt" | python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join(d.get('metadata_admin',{}).get('groups',[])))" 2>/dev/null || echo "")
    if [[ "$groups" == "grafana-access,audiobookshelf-access" ]]; then
        pass "C2 identity round-trip preserves metadata_admin.groups"
    else
        fail "C2 metadata_admin.groups round-trip" "got=$groups"
    fi
fi

# Section D: recovery-gate (the app's admin endpoint)
echo ""
echo "D. Recovery-gate (othala :4431 /admin/recovery-gate)"
# The gate re-fetches the identity from the Kratos admin API and refuses iff
# metadata_admin.admin === true (fetchAdminMarker, listen.mjs); it ignores the payload's
# is_admin, and any lookup failure fails CLOSED. Probes therefore need REAL seeded identities:
# a placeholder UUID 403s via fail-closed, so an admin-refusal probe would pass vacuously.

# Helper: POST a recovery-gate body with a bearer from inside the othala container.
gate_code() {
    local bearer="$1"; local body="$2"
    printf '%s' "fetch('http://${PORTAL_ADMIN_BIND_HOST}:4431/admin/recovery-gate',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer ${bearer}'},body:'${body}'}).then(r=>{process.stdout.write(String(r.status));process.exit(0)}).catch(()=>{process.stdout.write('0');process.exit(1)})" | node_in othala
}

# Variant returning "code|body" so a refusal REASON can be asserted.
gate_resp() {
    local bearer="$1"; local body="$2"
    printf '%s' "fetch('http://${PORTAL_ADMIN_BIND_HOST}:4431/admin/recovery-gate',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer ${bearer}'},body:'${body}'}).then(async r=>{const t=await r.text();process.stdout.write(r.status+'|'+t);process.exit(0)}).catch(()=>{process.stdout.write('0|');process.exit(1)})" | node_in othala
}

# D1: seed a REAL admin-marker identity; expect 403 WITH the console-only reason (a fail-closed
# 403 must not satisfy it). Payload says is_admin=false to prove the marker outranks it.
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

# D2: the non-admin identity from C1 gets 200 even when the payload claims 'grafana-admin':
# portal admin authority is the metadata_admin.admin marker alone.
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

# D3: missing identity_id -> 403 (fail-closed).
empty_code=$(gate_code "${RECOVERY_GATE_SECRET}" '{"is_admin":false,"groups":[],"traits":{}}')
if [[ "$empty_code" == "403" ]]; then
    pass "D3 recovery-gate fails closed on unidentifiable subject (missing identity_id)"
else
    fail "D3 recovery-gate missing-identity_id path" "code=$empty_code want=403"
fi

# D4: wrong bearer -> 403, not 401: Kratos webhooks use can_interrupt, so a non-403 risks a
# skippable (fail-open) webhook error. The bearer check runs before payload inspection.
wrong_code=$(gate_code "wrong-secret" '{"identity_id":"00000000-0000-0000-0000-000000000099","is_admin":false,"traits":{}}')
if [[ "$wrong_code" == "403" ]]; then
    pass "D4 recovery-gate rejects wrong bearer (403, fail-closed)"
else
    fail "D4 recovery-gate wrong bearer" "code=$wrong_code want=403"
fi

# D5: unknown identity -> 403 (fail-closed).
malformed_code=$(gate_code "${RECOVERY_GATE_SECRET}" '{"identity_id":"00000000-0000-0000-0000-000000000099","traits":{}}')
if [[ "$malformed_code" == "403" ]]; then
    pass "D5 recovery-gate refuses an unknown identity (fail-closed)"
else
    fail "D5 recovery-gate unknown identity" "code=$malformed_code want=403"
fi

# Section F: dual-listener boundary (the reverse of A9b)
echo ""
echo "F. Listener boundary"
# The reverse of A9b: the admin mux does not serve public SSR routes.
f1=$(othala_code http://${PORTAL_ADMIN_BIND_HOST}:4431/oauth2/login)
if [[ "$f1" == "404" ]]; then
    pass "F1 admin port does NOT serve public /oauth2/login (mux split holds both ways)"
else
    fail "F1 public route leaked onto admin port" "code=$f1 want=404 (admin mux must not serve SSR routes)"
fi

# Section G: browser-free OIDC dance (login forged via Hydra admin, app consent handler,
# auth code, ID token) against live Kratos + Hydra. See oidc-dance.mjs.
echo ""
echo "G. OIDC dance (login -> consent -> ID token; claims + access-gate deny)"

# mk_identity <state> <groups-json> <localpart> -> echoes the new identity id.
mk_identity() {
    printf '%s' "fetch('http://kratos:4434/admin/identities',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schema_id:'family',state:'$1',traits:{username:'$3',email:'$3@${OTHALA_APEX}',displayName:'$3'},metadata_admin:{groups:$2}})}).then(r=>r.json()).then(j=>{process.stdout.write(j.id||'');process.exit(0)}).catch(()=>process.exit(1))" | node_in othala
}
# run_dance <subject> -> the result line (OK claims=... / DENIED... / STEP/EXC). Pipes
# oidc-dance.mjs with the subject and grafana client secret into the dance-runner oneshot;
# grafana is the role-mapping client whose consent block emits grafana_role.
run_dance() {
    local out res
    out=$(sed "s|__SUBJECT__|$1|g; s|__GRAFANA_SECRET__|${GRAFANA_CLIENT_SECRET}|g" ./oidc-dance.mjs \
        | docker compose --profile oneshot run --rm --no-deps -T dance-runner 2>&1 | _strip_ansi)
    res=$(echo "$out" | grep -E '^OK |^DENIED|^STEP|^EXC' | tail -1)
    if [[ -z "$res" ]]; then
        # No result line means the dance crashed; surface the full output.
        echo "  ----- dance produced no OK/DENIED/STEP/EXC line; full output: -----" >&2
        echo "$out" | sed 's/^/    | /' | tail -45 >&2
        echo "  ----- end dance output -----" >&2
    fi
    echo "$res"
}

# G1: active member with grafana-access -> dance completes, ID token carries grafana_role=[Viewer]
# (claims-injection regression guard; the admin pairing is asserted in t-access-model.spec.ts).
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
# error_description is opaque ('access_denied') by design; the reason is server-side only
# (oauth2-handlers.test.mjs). The guard is that the inactive identity is DENIED.
if [[ "$g2" == DENIED* && "$g2" == *access_denied* ]]; then
    pass "G2 OIDC dance DENIES an inactive identity (state gate, D3)"
else
    fail "G2 inactive deny" "got: $g2 (want DENIED ... access_denied)"
fi

# G3: active identity holding ONLY grafana-admin -> DENIED: entry comes from grafana-access and
# nothing derives entry from an admin group.
g3_id=$(mk_identity active "['grafana-admin']" g3.adminonly)
g3=$(run_dance "$g3_id")
# Opaque error_description (see G2); the guard is that the admin-group-only identity is DENIED.
if [[ "$g3" == DENIED* && "$g3" == *access_denied* ]]; then
    pass "G3 OIDC dance DENIES an identity holding ONLY grafana-admin (admin does not imply access)"
else
    fail "G3 admin-only deny" "got: $g3 (want DENIED ... access_denied) — admin-implies-access may have been reintroduced"
fi

# Section H: contact / request form (SSR /api/request, signed-in only).
echo ""
echo "H. Contact form (othala :8080 /api/request -> mailpit)"
# Probes run from inside the othala container (node; reaches :8080 and mailpit).

# Signed-in behaviour is covered by Playwright z-contact-form; smoke has no session cookie.

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
    # Native `podman logs` (container_name lab-<svc>): /tmp is not an artifact and the podman
    # shim rejects `compose logs --no-color`.
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
