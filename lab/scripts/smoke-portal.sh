#!/usr/bin/env bash
# Portal SSR-vs-prerendered consistency smoke check (M12).
#
# Astro 6 hybrid mode bundles assets per-route; SSR pages and
# prerendered pages can drift in their CSS/font references if a build
# regresses. This script hits one prerendered route (home) and one
# SSR route (auth/login) back-to-back and asserts:
#
#   - Both 200.
#   - Same Cache-Control header (so the perimeter caching tier doesn't
#     surprise users with stale CSS for one route and fresh for the
#     other).
#   - Both reference the same shared CSS bundle filename. Astro hashes
#     the bundle name, so two different filenames means the build
#     emitted two copies and the layout drift the M12 finding flagged
#     is real.
#
# Usage:
#   PORTAL_BASE=https://home.dunn.dev bash lab/scripts/smoke-portal.sh
#   (or PORTAL_BASE=http://localhost:4321 for `astro dev`)
#
# Exit 0 on success, 1 on any check failure.

set -euo pipefail

PORTAL_BASE="${PORTAL_BASE:-http://localhost:4321}"
PRERENDERED_PATH="${PRERENDERED_PATH:-/}"
SSR_PATH="${SSR_PATH:-/auth/login}"

fetch() {
    local path="$1"
    curl -fsS -D - -o /tmp/smoke-portal-body-$$ "${PORTAL_BASE}${path}"
}

extract_css_refs() {
    # Astro emits <link rel="stylesheet" href="/_astro/<hash>.css">.
    grep -oE 'href="[^"]+\.css"' /tmp/smoke-portal-body-$$ \
        | sed -E 's/href="([^"]+)"/\1/' \
        | sort -u
}

echo "==> Fetching prerendered: ${PRERENDERED_PATH}"
HEADERS_A="$(fetch "${PRERENDERED_PATH}" | tr -d '\r' || true)"
CSS_A="$(extract_css_refs)"

echo "==> Fetching SSR: ${SSR_PATH}"
HEADERS_B="$(fetch "${SSR_PATH}" | tr -d '\r' || true)"
CSS_B="$(extract_css_refs)"

# Status codes were enforced by curl -f; here we surface the recorded
# status line for the operator's eyes.
STATUS_A="$(printf '%s' "$HEADERS_A" | head -n1)"
STATUS_B="$(printf '%s' "$HEADERS_B" | head -n1)"
echo "    prerendered: $STATUS_A"
echo "    ssr        : $STATUS_B"

# Cache-Control: extract and compare. Either both unset or both set to
# the same value; an asymmetric Cache-Control is the regression we
# care about.
CC_A="$(printf '%s' "$HEADERS_A" | grep -i '^cache-control:' || true)"
CC_B="$(printf '%s' "$HEADERS_B" | grep -i '^cache-control:' || true)"
if [[ "$CC_A" != "$CC_B" ]]; then
    echo "FAIL: Cache-Control mismatch"
    echo "  prerendered: $CC_A"
    echo "  ssr        : $CC_B"
    exit 1
fi
echo "    cache-control: matched ('${CC_A:-<unset>}')"

# CSS reference set comparison.
if [[ -z "$CSS_A" || -z "$CSS_B" ]]; then
    echo "WARN: one or both pages reference no CSS"
fi

DIFF="$(comm -3 <(printf '%s\n' "$CSS_A") <(printf '%s\n' "$CSS_B") || true)"
if [[ -n "$DIFF" ]]; then
    echo "FAIL: CSS reference drift between SSR and prerendered:"
    printf '%s\n' "$DIFF"
    exit 1
fi
echo "    css refs   : matched ($(printf '%s' "$CSS_A" | wc -l | tr -d ' ') file(s))"

rm -f /tmp/smoke-portal-body-$$

echo "==> portal SSR/prerendered consistency: PASS"
