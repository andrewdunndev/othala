#!/usr/bin/env bash
# verify-webfinger.sh — validate a WebFinger endpoint against Tailscale's
# KB-1240 contract.
#
# Usage:
#   bash verify-webfinger.sh dunn.dev
#   bash verify-webfinger.sh https://dunn.dev   # https:// is auto-stripped
#
# Exit 0 if the response satisfies every Tailscale-relevant assertion;
# 1 on any mismatch. Prints the response body for inspection.

set -uo pipefail

domain="${1:-dunn.dev}"
domain="${domain#https://}"
domain="${domain#http://}"
domain="${domain%/}"

url="https://${domain}/.well-known/webfinger?resource=acct%3Auser%40${domain}"
EXPECTED_ISSUER="https://auth.dunn.dev/"

echo "=== verify-webfinger ==="
echo "URL:           $url"
echo "Expected iss:  $EXPECTED_ISSUER"
echo ""

# Fetch with header capture
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

http_code=$(curl -sk -o "$tmp" -w '%{http_code}' \
    -D /tmp/wf-headers \
    -H 'Accept: application/jrd+json' \
    "$url")

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s — %s\n" "$1" "${2:-}"; }

# 1. Status 200
if [[ "$http_code" == "200" ]]; then
    ok "HTTP 200"
else
    bad "HTTP status" "got $http_code"
fi

# 2. Content-Type application/jrd+json
ct=$(grep -i '^content-type:' /tmp/wf-headers 2>/dev/null | sed 's/^[Cc]ontent-[Tt]ype:[[:space:]]*//' | tr -d '\r')
if [[ "$ct" == *"application/jrd+json"* ]]; then
    ok "Content-Type: application/jrd+json"
else
    bad "Content-Type" "got '$ct' (Tailscale's parser is strict; plain application/json is rejected)"
fi

# 3. Access-Control-Allow-Origin: *
acao=$(grep -i '^access-control-allow-origin:' /tmp/wf-headers 2>/dev/null | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
if [[ "$acao" == "*" ]]; then
    ok "Access-Control-Allow-Origin: *"
else
    bad "Access-Control-Allow-Origin" "got '$acao' (RFC 7033 §5 expects *)"
fi

# 4. JSON parses
if python3 -c "import sys,json; json.load(sys.stdin)" < "$tmp" 2>/dev/null; then
    ok "Body is well-formed JSON"
else
    bad "Body is not JSON" "see body below"
fi

# 5. Top-level `subject` is a string
subject=$(python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('subject',''))" < "$tmp" 2>/dev/null || echo "")
if [[ -n "$subject" && "$subject" == acct:* ]]; then
    ok "subject: \"$subject\""
else
    bad "subject field" "got '$subject' (Tailscale tolerates any acct:* string; informational)"
fi

# 6. links[0].rel byte-equals "http://openid.net/specs/connect/1.0/issuer"
rel=$(python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('links',[{}])[0].get('rel',''))" < "$tmp" 2>/dev/null || echo "")
if [[ "$rel" == "http://openid.net/specs/connect/1.0/issuer" ]]; then
    ok "links[0].rel: openid.net issuer"
else
    bad "links[0].rel" "got '$rel'"
fi

# 7. links[0].href byte-equals expected issuer
href=$(python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('links',[{}])[0].get('href',''))" < "$tmp" 2>/dev/null || echo "")
if [[ "$href" == "$EXPECTED_ISSUER" ]]; then
    ok "links[0].href byte-matches expected: \"$href\""
else
    bad "links[0].href mismatch" "got '$href' want '$EXPECTED_ISSUER'"
fi

# 8. Cross-check: Hydra's own openid-configuration emits the same issuer
echo ""
echo "=== Cross-check: Hydra issuer at $EXPECTED_ISSUER.well-known/openid-configuration ==="
hydra_oidc=$(curl -sk "${EXPECTED_ISSUER}.well-known/openid-configuration" 2>/dev/null)
if [[ -n "$hydra_oidc" ]]; then
    hydra_iss=$(echo "$hydra_oidc" | python3 -c "import sys,json; print(json.load(sys.stdin).get('issuer',''))" 2>/dev/null || echo "")
    if [[ "$hydra_iss" == "$href" ]]; then
        ok "Hydra issuer byte-matches WebFinger href: \"$hydra_iss\""
    else
        bad "Hydra issuer drift" "hydra='$hydra_iss' webfinger='$href'"
    fi
else
    printf "  \033[33m–\033[0m Hydra unreachable; skipped cross-check (not a webfinger problem)\n"
fi

echo ""
echo "=== response body ==="
cat "$tmp"
echo ""

TOTAL=$((PASS + FAIL))
if [[ $FAIL -eq 0 ]]; then
    printf "\033[32mALL %d CHECKS PASSED — safe to point Tailscale at this domain.\033[0m\n" "$TOTAL"
    exit 0
else
    printf "\033[31m%d/%d FAILED — fix before pointing Tailscale.\033[0m\n" "$FAIL" "$TOTAL"
    echo ""
    echo "Reminder: Tailscale reads WebFinger ONCE during tenant setup."
    echo "Changing the issuer post-setup requires Tailscale support."
    exit 1
fi
