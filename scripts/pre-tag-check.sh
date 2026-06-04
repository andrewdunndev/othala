#!/usr/bin/env bash
# pre-tag-check.sh — local gate run before tagging a release.
#
# Runs every test + lint + build that CI runs, locally. If this is
# green, the tag pipeline is unlikely to surprise. If anything fails,
# fix before tagging.
#
# What it runs:
#   - ldap-bridge: go test ./...
#   - portal: npm test
#   - portal: npm run check (Astro typecheck)
#   - portal: npm run build (full SSR build)
#   - e2e shell-scripts: bash -n syntax check
#   - .gitlab-ci.yml: python yaml parse
#   - hydra/clients/*.yaml: yaml parse
#   - portal/src/content/apps/*.md: frontmatter yaml parse
#
# Usage:
#   bash scripts/pre-tag-check.sh
#
# Exit 0 on all-green; 1 on first failure.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || exit 1

PASS=0
FAIL=0
FAILED_STEPS=()

step_pass() { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$1"; }
step_fail() {
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("$1")
    printf "  \033[31m✗\033[0m %s\n" "$1"
    if [[ -n "${2:-}" ]]; then
        printf "      see: %s\n" "$2"
    fi
}

echo "=== pre-tag-check ==="
echo ""
echo "Repo: $REPO_ROOT"
echo "Branch: $(git branch --show-current)"
echo "HEAD: $(git log -1 --oneline)"
echo ""

# ----- Go: ldap-bridge -----
echo "Go tests:"
if cd ldap-bridge && go test ./... >/tmp/pre-tag-ldap.log 2>&1; then
    step_pass "ldap-bridge go test"
else
    step_fail "ldap-bridge go test" "/tmp/pre-tag-ldap.log"
fi
cd "$REPO_ROOT" || exit 1
echo ""

# ----- Portal: tests -----
echo "Portal:"
if cd portal && npm test >/tmp/pre-tag-portal-test.log 2>&1; then
    step_pass "portal npm test ($(grep -c '^✔' /tmp/pre-tag-portal-test.log) passed)"
else
    step_fail "portal npm test" "/tmp/pre-tag-portal-test.log"
fi
cd "$REPO_ROOT" || exit 1

# ----- Portal: typecheck -----
if cd portal && npm run check >/tmp/pre-tag-portal-check.log 2>&1; then
    # check exit-zeros even with warnings; assert "0 errors"
    if grep -q "0 errors" /tmp/pre-tag-portal-check.log; then
        warns=$(grep -oE "[0-9]+ warnings" /tmp/pre-tag-portal-check.log | head -1)
        step_pass "portal astro check (0 errors, ${warns:-? warnings})"
    else
        step_fail "portal astro check (errors present)" "/tmp/pre-tag-portal-check.log"
    fi
else
    step_fail "portal astro check (non-zero exit)" "/tmp/pre-tag-portal-check.log"
fi
cd "$REPO_ROOT" || exit 1

# ----- Portal: build -----
if cd portal && npm run build >/tmp/pre-tag-portal-build.log 2>&1; then
    step_pass "portal astro build"
else
    step_fail "portal astro build" "/tmp/pre-tag-portal-build.log"
fi
cd "$REPO_ROOT" || exit 1
echo ""

# ----- Shell scripts: syntax + shellcheck -----
echo "Shell syntax + lint:"
SHELL_SCRIPTS=(e2e/*.sh)
SYNTAX_BAD=0
for s in "${SHELL_SCRIPTS[@]}"; do
    [[ -f "$s" ]] || continue
    if ! bash -n "$s" 2>/dev/null; then
        step_fail "bash -n $s"
        SYNTAX_BAD=1
    fi
done
if [[ $SYNTAX_BAD -eq 0 ]]; then
    step_pass "bash -n on $(printf '%s\n' "${SHELL_SCRIPTS[@]}" | wc -l | tr -d ' ') scripts"
fi

# shellcheck if available; non-fatal if not installed (CI installs it).
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck --severity=warning "${SHELL_SCRIPTS[@]}" >/tmp/pre-tag-shellcheck.log 2>&1; then
        step_pass "shellcheck --severity=warning"
    else
        step_fail "shellcheck warnings" "/tmp/pre-tag-shellcheck.log"
    fi
else
    printf "  \033[33m–\033[0m shellcheck not on PATH; skipped (install via mise)\n"
fi
echo ""

# ----- YAML parse: .gitlab-ci.yml -----
echo "YAML parse:"
if python3 -c "import yaml; yaml.safe_load(open('.gitlab-ci.yml'))" 2>/dev/null; then
    step_pass ".gitlab-ci.yml parses"
else
    step_fail ".gitlab-ci.yml parse" "(stderr above)"
fi

# ----- YAML parse: hydra/clients/*.yaml -----
CLIENT_BAD=0
for f in hydra/clients/*.yaml; do
    [[ -f "$f" ]] || continue
    if ! python3 -c "import yaml,sys; yaml.safe_load(open('$f'))" 2>/dev/null; then
        step_fail "hydra/clients/$(basename "$f")" "yaml parse"
        CLIENT_BAD=1
    fi
done
if [[ $CLIENT_BAD -eq 0 ]]; then
    count=$(ls hydra/clients/*.yaml 2>/dev/null | wc -l | tr -d ' ')
    step_pass "hydra/clients/ ($count yamls parse)"
fi

# ----- Frontmatter parse: portal/src/content/apps/*.md -----
APPS_BAD=0
for f in portal/src/content/apps/*.md; do
    [[ -f "$f" ]] || continue
    fm=$(awk '/^---$/{flag++; next} flag==1{print}' "$f")
    if ! python3 -c "import yaml,sys; yaml.safe_load(sys.stdin.read())" <<< "$fm" 2>/dev/null; then
        step_fail "portal/src/content/apps/$(basename "$f")" "frontmatter parse"
        APPS_BAD=1
    fi
done
if [[ $APPS_BAD -eq 0 ]]; then
    count=$(ls portal/src/content/apps/*.md 2>/dev/null | wc -l | tr -d ' ')
    step_pass "portal apps registry ($count MDs parse)"
fi
echo ""

# ----- Summary -----
TOTAL=$((PASS + FAIL))
if [[ $FAIL -eq 0 ]]; then
    printf "\033[32mALL %d STEPS PASSED — tagging-safe.\033[0m\n" "$TOTAL"
    echo ""
    echo "Next: git tag vX.X.X && git push --tags"
    exit 0
else
    printf "\033[31m%d/%d FAILED — fix before tagging.\033[0m\n" "$FAIL" "$TOTAL"
    echo ""
    echo "Failed:"
    for s in "${FAILED_STEPS[@]}"; do
        echo "  - $s"
    done
    exit 1
fi
