#!/usr/bin/env bash
# Phase 2 LDAP validation suite. Runs from the lab VM against the
# glauth-kratos bridge listening on localhost:636.
#
# Captures stdout/stderr and return codes for each scenario, then dumps
# the bridge container logs so a single tee'd run produces the evidence
# needed for phase2-evidence.md.

set -uo pipefail

LDAP_TEST_USER="${LDAP_TEST_USER:-ldaptest}"
LDAP_TEST_PASS="${LDAP_TEST_PASS:-ldappass1}"
BASE="dc=dunn,dc=dev"
USER_DN="uid=${LDAP_TEST_USER},ou=users,${BASE}"
HOST="ldaps://localhost:636"

# Disable cert validation: we use a self-signed cert with CN=glauth-kratos.local
# and the client connects via "localhost". Trust is established by the deploy
# placing the cert; cert chain validation is out of scope for this lab.
export LDAPTLS_REQCERT=never

run() {
    local name="$1"
    shift
    echo ""
    echo "===== ${name} ====="
    echo "+ $*"
    "$@"
    local rc=$?
    echo "exit=${rc}"
    return $rc
}

# Mark the start of this run in the bridge log so we can extract just the
# relevant block at the end.
MARK="lab-test-$(date +%s)"
sudo podman exec auth-glauth-kratos sh -c "echo === ${MARK} === >&2" 2>/dev/null || true

run "1. BIND success (correct password) + base SEARCH" \
    ldapsearch -H "$HOST" -x \
    -D "$USER_DN" -w "$LDAP_TEST_PASS" \
    -b "$BASE" -s sub "(uid=${LDAP_TEST_USER})" \
    dn uid cn sn mail objectClass

run "2. BIND failure (wrong password)" \
    ldapsearch -H "$HOST" -x \
    -D "$USER_DN" -w "definitely-wrong-password" \
    -b "$BASE" -s sub "(uid=${LDAP_TEST_USER})"

run "3. BIND success, search nonexistent user" \
    ldapsearch -H "$HOST" -x \
    -D "$USER_DN" -w "$LDAP_TEST_PASS" \
    -b "$BASE" -s sub "(uid=nosuchuser)"

run "4. BIND success, filter (objectClass=inetOrgPerson)" \
    ldapsearch -H "$HOST" -x \
    -D "$USER_DN" -w "$LDAP_TEST_PASS" \
    -b "$BASE" -s sub "(objectClass=inetOrgPerson)" \
    dn uid mail

run "5. BIND with malformed DN (cn= prefix)" \
    ldapsearch -H "$HOST" -x \
    -D "cn=${LDAP_TEST_USER},ou=users,${BASE}" -w "$LDAP_TEST_PASS" \
    -b "$BASE" -s sub "(uid=${LDAP_TEST_USER})"

run "6. Anonymous BIND attempt" \
    ldapsearch -H "$HOST" -x \
    -b "$BASE" -s sub "(uid=${LDAP_TEST_USER})"

run "7. BIND success, retrieve specific attributes only" \
    ldapsearch -H "$HOST" -x \
    -D "$USER_DN" -w "$LDAP_TEST_PASS" \
    -b "$BASE" -s sub "(uid=${LDAP_TEST_USER})" \
    uid mail

# Repeat scenario 1 to confirm bind cache hit
run "8. BIND success again (should hit bind cache)" \
    ldapsearch -H "$HOST" -x \
    -D "$USER_DN" -w "$LDAP_TEST_PASS" \
    -b "$BASE" -s base "(uid=${LDAP_TEST_USER})" \
    uid

echo ""
echo "===== glauth-kratos container logs (tail since ${MARK}) ====="
sudo podman logs auth-glauth-kratos 2>&1 | awk -v mark="${MARK}" '
    BEGIN { show=0 }
    index($0, mark) { show=1; next }
    show { print }
'
echo ""
echo "===== Full bridge log tail (last 80 lines) ====="
sudo podman logs auth-glauth-kratos 2>&1 | tail -80
