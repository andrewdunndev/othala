#!/usr/bin/env bash
# check-purity.sh — OSS purity + no-deprecated + dated-debt detection gate.
#
# Detects three families of violations:
#
#   Othala-purity:        instance-specific strings leaked into configs/tests/docs
#   No-referenced-deprecated: references to deleted commands / DORMANT markers
#   Dated-debt:           intentional-failure markers that should have been removed
#
# Usage:
#   bash scripts/check-purity.sh
#
# Exit 0 if all checks pass; exit 1 if any fail.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || exit 1

PASS=0; FAIL=0; FAILED_STEPS=()

step_pass() { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$1"; }
step_fail() {
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("$1")
    printf "  \033[31m✗\033[0m %s\n" "$1"
    if [[ -n "${2:-}" ]]; then
        printf "      %s\n" "$2"
    fi
}

echo "=== check-purity ==="
echo ""

# =================================================================
# Othala-purity family
# =================================================================
echo "Purity:"

# no-dunn-dev-in-configs: no instance domain in Hydra/Kratos config files.
# portal/src/ is excluded — it has legitimate @dunn.dev/reference package imports.
if hits=$(grep -n 'dunn\.dev' hydra/hydra.yml kratos/kratos.yml 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-dunn-dev-in-configs" "$(echo "$hits" | head -3)"
else
    step_pass "no-dunn-dev-in-configs"
fi

# no-dunn-dev-in-tests: no instance domain in portal test scripts.
if hits=$(grep -rn 'dunn\.dev' portal/scripts/ 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-dunn-dev-in-tests" "$(echo "$hits" | head -3)"
else
    step_pass "no-dunn-dev-in-tests"
fi

# no-instance-identity-in-runbooks: no carmine hostname or personal login names in runbooks.
if hits=$(grep -rEn '\bcarmine\b|agd@|andrew\.dunn|ashley\.dunn' docs/runbooks/ 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-instance-identity-in-runbooks" "$(echo "$hits" | head -3)"
else
    step_pass "no-instance-identity-in-runbooks"
fi

# no-personal-names-in-docs: no real operator names in any doc or diagram.
if hits=$(grep -rn 'andrew\.dunn\|ashley\.dunn' docs/ 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-personal-names-in-docs" "$(echo "$hits" | head -3)"
else
    step_pass "no-personal-names-in-docs"
fi

# no-dunn-dev-in-e2e-manifests: no instance domain leaked into compose manifests.
if hits=$(grep -rn 'dunn\.dev' e2e/manifests/ 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-dunn-dev-in-e2e-manifests" "$(echo "$hits" | head -3)"
else
    step_pass "no-dunn-dev-in-e2e-manifests"
fi

# no-stale-llm-client-id: stale llm client_id from pre-redesign client list.
if hits=$(grep -rn 'client_id: llm' portal/scripts/ 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-stale-llm-client-id" "$(echo "$hits" | head -3)"
else
    step_pass "no-stale-llm-client-id"
fi

# no-personal-name-in-help: family-help.md must not address operator by first name.
if hits=$(grep -n '\bAndrew\b' docs/family-help.md 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-personal-name-in-help" "$(echo "$hits" | head -3)"
else
    step_pass "no-personal-name-in-help"
fi

echo ""

# =================================================================
# No-referenced-deprecated family
# =================================================================
echo "No-referenced-deprecated:"

# no-deleted-commands-in-docs: dag-apply-clients and dag-sync-manifests were
# removed; their names must not survive in docs or source.
DEPRECATED_CMD_FILES=(
    DEPLOY.md
    hydra/README.md
    ARCHITECTURE.md
    e2e/README.md
    portal/src/server/register-clients-cli.ts
)
if hits=$(grep -rn 'dag-apply-clients\|dag-sync-manifests' \
    "${DEPRECATED_CMD_FILES[@]}" docs/runbooks/ portal/src/ portal/scripts/ 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-deleted-commands-in-docs" "$(echo "$hits" | head -3)"
else
    step_pass "no-deleted-commands-in-docs"
fi

# no-dormant-cutover-comment: DORMANT marker was a transitional note; must be gone.
if hits=$(grep -rn '\bDORMANT\b' \
    portal/src/server/register-clients-cli.ts e2e/compose.yml 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-dormant-cutover-comment" "$(echo "$hits" | head -3)"
else
    step_pass "no-dormant-cutover-comment"
fi

# no-pending-cutover-section: (pending) markers in DEPLOY.md must be resolved.
if hits=$(grep -n '(pending)' DEPLOY.md 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-pending-cutover-section" "$(echo "$hits" | head -3)"
else
    step_pass "no-pending-cutover-section"
fi

echo ""

# =================================================================
# Dated-debt family
# =================================================================
echo "Dated-debt:"

# no-intentionally-fails-comment: CI jobs must not be intentionally-failing stubs.
if hits=$(grep -n 'INTENTIONALLY FAILS' .gitlab-ci.yml 2>/dev/null) && [[ -n "$hits" ]]; then
    step_fail "no-intentionally-fails-comment" "$(echo "$hits" | head -3)"
else
    step_pass "no-intentionally-fails-comment"
fi

echo ""

# =================================================================
# Summary
# =================================================================
TOTAL=$((PASS + FAIL))
if [[ $FAIL -eq 0 ]]; then
    printf "\033[32mALL %d CHECKS PASSED — purity clean.\033[0m\n" "$TOTAL"
    exit 0
else
    printf "\033[31m%d/%d FAILED — fix violations before tagging.\033[0m\n" "$FAIL" "$TOTAL"
    echo ""
    echo "Failed:"
    for s in "${FAILED_STEPS[@]}"; do
        echo "  - $s"
    done
    exit 1
fi
