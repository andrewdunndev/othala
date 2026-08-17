#!/usr/bin/env bash
# pre-tag-check.sh — local gate run before tagging a release.
#
# Runs every test + lint + build that CI runs, locally. If this is
# green, the tag pipeline is unlikely to surprise. If anything fails,
# fix before tagging.
#
# What it runs:
#   - portal: npm test
#   - portal: npm run check (Astro typecheck)
#   - portal: npm run build (full SSR build)
#   - e2e shell-scripts: bash -n syntax check + shellcheck
#   - tracked plain-YAML: python yaml parse
#   - scripts/check-purity.sh
#
# Usage:
#   bash scripts/pre-tag-check.sh
#
# Exit 0 on all-green; 1 if anything fails or could not be checked.
#
# -----------------------------------------------------------------------
# ANTI-VACUITY CONTRACT — read before adding a step.
#
# This is the LAST gate before a tag, so a step that reports PASS without
# having looked at anything is the most expensive kind of lie this repo can
# tell. Two such steps were found here and removed: they globbed
# hydra/clients/*.yaml and portal/src/content/apps/*.md, directories that no
# longer exist in the index, so the loop bodies never ran, the *_BAD flags
# stayed 0, and the gate printed `PASS (0 yamls parse)` release after
# release. `ls <gone>/*.yaml | wc -l` returning 0 was rendered as a count,
# not as an error.
#
# Every file-driven step therefore goes through tracked_set(), which:
#
#   * enumerates from `git ls-files` — the index, so the set is the same
#     here and in CI, where a worktree glob is not;
#   * asserts the set is NON-EMPTY, and calls step_error (never step_pass)
#     when it is;
#   * asserts every member is present and readable before any tool runs.
#
# And every step decides its verdict from RESULTS, not merely from an exit
# status of 0: a test run reporting zero tests and a YAML file parsing to an
# empty document are both step_error, because neither is evidence of health.
# A tool that is absent is a SKIP that the summary names — never a pass.
# -----------------------------------------------------------------------

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || exit 1

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ERROR=0
SKIP=0
FAILED_STEPS=()
SKIPPED_STEPS=()

# Number of steps that must execute. Bump it in the same commit that adds or
# removes a step; see the step-inventory assertion at the end.
EXPECTED_STEPS=7
STEPS_RUN=0
# step_begin: called once at the top of every step block, so deleting a block
# deletes its increment and the inventory assertion below catches the shortfall.
step_begin() { STEPS_RUN=$((STEPS_RUN+1)); }

step_pass() { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$1"; }
step_fail() {
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("$1")
    printf "  \033[31m✗\033[0m %s\n" "$1"
    if [[ -n "${2:-}" ]]; then
        printf "      see: %s\n" "$2"
    fi
}
# step_error: the step could not be performed honestly — an empty or
# unreadable file set, a tool that produced no evidence of having done work.
# This is NEVER a pass, and it counts toward FAIL so the gate exits non-zero.
step_error() {
    ERROR=$((ERROR+1))
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("$1 [VACUOUS/ERROR: step did not run honestly]")
    printf "  \033[33m‼\033[0m %s \033[33m(ERROR — no evidence of work, or an incomplete corpus)\033[0m\n" "$1"
    if [[ -n "${2:-}" ]]; then
        printf "      %s\n" "$2"
    fi
}
# step_skip: a step that genuinely did not run. Counted and named in the
# summary so an all-green line can never imply a skipped step was clean.
step_skip() {
    SKIP=$((SKIP+1))
    SKIPPED_STEPS+=("$1${2:+ — $2}")
    printf "  \033[33m–\033[0m %s (SKIPPED%s)\n" "$1" "${2:+: $2}"
}

# ---------------------------------------------------------------------
# tracked_set <step-name> <pathspec>...
#
# Populates the global array TRACKED with the tracked files under the given
# pathspecs, asserts the set is non-empty, and asserts every member is
# present and readable. Returns 1 (having recorded step_error) otherwise, so
# callers gate on it before running any tool over the set.
# ---------------------------------------------------------------------
TRACKED=()
tracked_set() {
    local name="$1"; shift
    TRACKED=()

    local rc f
    git ls-files -z -- "$@" >"$TMP/set" 2>"$TMP/err"
    rc=$?
    if (( rc != 0 )); then
        step_error "$name" "git ls-files exited $rc for [$*]: $(head -1 "$TMP/err")"
        return 1
    fi

    while IFS= read -r -d '' f; do
        TRACKED+=("$f")
    done <"$TMP/set"

    if (( ${#TRACKED[@]} == 0 )); then
        step_error "$name" \
            "file set is EMPTY — 0 tracked files under [$*]; the step would have examined nothing"
        return 1
    fi

    local bad=()
    for f in "${TRACKED[@]}"; do
        [[ -f "$f" && -r "$f" ]] || bad+=("$f")
    done
    if (( ${#bad[@]} > 0 )); then
        step_error "$name" \
            "${#bad[@]}/${#TRACKED[@]} tracked file(s) missing from the worktree or unreadable, e.g. ${bad[0]}"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------
# count_from <file> <ERE-for-the-metric-word>
#
# Prints the integer that precedes the metric word, e.g. the 10 in
# "- 10 errors". The form this replaces, `grep -q "0 errors"`, is a SUBSTRING
# test: under probe it matched "10 errors", "20 errors" and "100 errors", so
# every error count ending in a zero read as a clean run. Comparing the VALUE
# rather than testing for a shape is what closes that, and it does not depend
# on where in the line the count sits.
#
# Prints nothing and returns 1 when no integer can be extracted, so callers
# route an unparseable summary to step_error rather than to zero.
# ---------------------------------------------------------------------
count_from() {
    local file="$1" word="$2" n
    n=$(grep -oE "[0-9]+ ${word}" "$file" 2>/dev/null | head -1 | grep -oE '^[0-9]+')
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    printf '%s' "$((10#$n))"
}

echo "=== pre-tag-check ==="
echo ""
echo "Repo: $REPO_ROOT"
echo "Branch: $(git branch --show-current)"
echo "HEAD: $(git log -1 --oneline)"
echo ""

# NOTE: the ldap-bridge (glauth-kratos) has been extracted to the
# standalone gitlab.com/dunn.dev/kratos-ldap project; its Go tests are
# no longer part of this pre-tag check.

# ----- Portal: tests -----
echo "Portal:"
step_begin
if cd portal && npm test >/tmp/pre-tag-portal-test.log 2>&1; then
    # A runner that matched no test files exits 0. Exit status alone is
    # therefore not evidence the suite ran; the count of reported passes is.
    passed=$(grep -c '^✔' /tmp/pre-tag-portal-test.log)
    if [[ ! "$passed" =~ ^[0-9]+$ ]]; then
        step_error "portal npm test" \
            "no pass count could be extracted from the runner output — an uncountable result is not a green suite; see /tmp/pre-tag-portal-test.log"
    elif (( passed > 0 )); then
        step_pass "portal npm test ($passed passed)"
    else
        step_error "portal npm test" \
            "exited 0 but reported 0 passing tests — a suite that ran nothing is not a green suite; see /tmp/pre-tag-portal-test.log"
    fi
else
    step_fail "portal npm test" "/tmp/pre-tag-portal-test.log"
fi
cd "$REPO_ROOT" || exit 1

# ----- Portal: typecheck -----
step_begin
if cd portal && npm run check >/tmp/pre-tag-portal-check.log 2>&1; then
    # check exit-zeros even with warnings, so the summary counts — not the
    # exit status — decide this step. Both are read as NUMBERS: see count_from.
    errs=$(count_from /tmp/pre-tag-portal-check.log 'errors?')
    warns=$(count_from /tmp/pre-tag-portal-check.log 'warnings?')
    if [[ -z "$errs" || -z "$warns" ]]; then
        step_error "portal astro check" \
            "exited 0 but its summary yielded no error/warning count — an unparseable result is not a zero result; see /tmp/pre-tag-portal-check.log"
    elif (( errs == 0 )); then
        step_pass "portal astro check ($errs errors, $warns warnings)"
    else
        step_fail "portal astro check ($errs errors)" "/tmp/pre-tag-portal-check.log"
    fi
else
    step_fail "portal astro check (non-zero exit)" "/tmp/pre-tag-portal-check.log"
fi
cd "$REPO_ROOT" || exit 1

# ----- Portal: build -----
step_begin
if cd portal && npm run build >/tmp/pre-tag-portal-build.log 2>&1; then
    step_pass "portal astro build"
else
    step_fail "portal astro build" "/tmp/pre-tag-portal-build.log"
fi
cd "$REPO_ROOT" || exit 1
echo ""

# ----- Shell scripts: syntax + shellcheck -----
echo "Shell syntax + lint:"
# The previous form was `SHELL_SCRIPTS=(e2e/*.sh)`: an unmatched glob stays
# literal, `[[ -f ]]` skips it, and the pass line counted the unexpanded
# pattern as one script. Enumerating from the index makes an empty set an
# error instead of a count.
SHELL_SCRIPTS=()
step_begin
if tracked_set "bash -n (e2e shell scripts)" 'e2e/*.sh'; then
    SHELL_SCRIPTS=("${TRACKED[@]}")
    SYNTAX_BAD=0
    for s in "${SHELL_SCRIPTS[@]}"; do
        if ! bash -n "$s" 2>/dev/null; then
            step_fail "bash -n $s"
            SYNTAX_BAD=1
        fi
    done
    if [[ $SYNTAX_BAD -eq 0 ]]; then
        step_pass "bash -n on ${#SHELL_SCRIPTS[@]} scripts"
    fi
fi

# Lint, if the linter is available. Absent, this is a SKIP the summary
# names — CI installs it, so a local run without it has simply not linted.
step_begin
if (( ${#SHELL_SCRIPTS[@]} == 0 )); then
    step_skip "shellcheck" "no shell scripts enumerated"
elif command -v shellcheck >/dev/null 2>&1; then
    if shellcheck --severity=warning "${SHELL_SCRIPTS[@]}" >/tmp/pre-tag-shellcheck.log 2>&1; then
        step_pass "shellcheck --severity=warning (${#SHELL_SCRIPTS[@]} scripts)"
    else
        step_fail "shellcheck warnings" "/tmp/pre-tag-shellcheck.log"
    fi
else
    step_skip "shellcheck" "not on PATH (install via mise)"
fi
echo ""

# ----- YAML parse -----
#
# One index-driven parse replaces three globbed ones. Two of those globbed
# corpora (hydra/clients/*.yaml, portal/src/content/apps/*.md) have no
# tracked files at all and were passing on an empty loop.
#
# kratos/kratos.yml and hydra/hydra.yml are deliberately NOT in this set:
# render-config.sh documents them as "TEMPLATES whose ${VAR} tokens must be
# substituted before a container mounts them", and an unsubstituted token
# inside a flow sequence is not parseable YAML. Their rendering is covered by
# render-config.sh's own contract, not by a plain parse here.
#
# .deviations.yaml is the third tracked YAML deliberately outside this set, and
# the exclusion is named here rather than left silent: the file currently holds
# only comments, so safe_load returns None and the non-empty-document rule below
# would fail it. "No declared deviations" is a legitimate state for that file,
# not a parse defect, so it is excluded rather than the rule being weakened.
echo "YAML parse:"
step_begin
if ! command -v python3 >/dev/null 2>&1; then
    step_error "yaml parse" "python3 not on PATH — no YAML was parsed"
elif tracked_set "yaml parse" .gitlab-ci.yml 'e2e/compose*.yml' 'e2e/manifests/*.yaml'; then
    # An empty file safe_loads to None and exits 0. Requiring a non-empty
    # document means "it parsed" cannot mean "there was nothing to parse".
    cat >"$TMP/yamlcheck.py" <<'PY'
import sys, yaml
try:
    doc = yaml.safe_load(open(sys.argv[1]))
except Exception as exc:
    print(exc, file=sys.stderr)
    sys.exit(1)
sys.exit(0 if isinstance(doc, (dict, list)) and doc else 3)
PY
    YAML_BAD=0
    for f in "${TRACKED[@]}"; do
        python3 "$TMP/yamlcheck.py" "$f" 2>"$TMP/yamlerr"
        yrc=$?
        case "$yrc" in
            0) ;;
            3) step_fail "$f" "parsed to an EMPTY document"
               YAML_BAD=1 ;;
            1) step_fail "$f" "$(head -1 "$TMP/yamlerr")"
               YAML_BAD=1 ;;
            *) step_error "$f" "yaml parse exited $yrc (not a parse verdict): $(head -1 "$TMP/yamlerr")"
               YAML_BAD=1 ;;
        esac
    done
    if (( YAML_BAD == 0 )); then
        step_pass "${#TRACKED[@]} tracked YAML files parse to non-empty documents"
    fi
fi
echo ""

# ----- Purity + hygiene -----
echo "Purity + hygiene:"
step_begin
bash scripts/check-purity.sh >/tmp/pre-tag-purity.log 2>&1
purity_rc=$?
case "$purity_rc" in
    0) step_pass "check-purity (no violations)" ;;
    1) step_fail "check-purity" "/tmp/pre-tag-purity.log"
       cat /tmp/pre-tag-purity.log ;;
    # check-purity exits 0 or 1 and nothing else. Any other status means it
    # did not reach its own verdict — it was not found, not executable, or
    # died — which is not a content verdict about this repo.
    *) step_error "check-purity" "exited $purity_rc — the gate did not run; see /tmp/pre-tag-purity.log"
       cat /tmp/pre-tag-purity.log ;;
esac
echo ""

# ----- Summary -----
# Step inventory, the same guard scripts/check-purity.sh applies to its checks.
# Without it, deleting a whole step block shrinks the checklist silently and the
# gate still prints an all-passed line — over six steps instead of seven.
# Two assertions, because a step can go missing in two ways: the block can be
# deleted (STEPS_RUN falls short of the constant), or it can run and return
# without reaching any verdict (fewer verdicts than steps).
VERDICTS=$((PASS + FAIL + SKIP))
if (( STEPS_RUN != EXPECTED_STEPS )); then
    step_error "step-inventory" \
        "$STEPS_RUN steps executed, expected $EXPECTED_STEPS — a step was added or removed without updating EXPECTED_STEPS"
elif (( VERDICTS < STEPS_RUN )); then
    step_error "step-inventory" \
        "$STEPS_RUN steps executed but only $VERDICTS verdicts were reported — a step returned without a verdict"
fi

TOTAL=$((PASS + FAIL))
if [[ $FAIL -eq 0 ]]; then
    printf "\033[32mALL %d STEPS PASSED\033[0m" "$TOTAL"
    # A skipped step is not a passed step, so it is named here rather than
    # absorbed into an unqualified "tagging-safe".
    if (( SKIP > 0 )); then
        printf " \033[33m(%d SKIPPED — not checked here)\033[0m\n" "$SKIP"
        for s in "${SKIPPED_STEPS[@]}"; do
            echo "  – $s"
        done
    else
        printf " — tagging-safe.\n"
    fi
    echo ""
    echo "Next: git tag vX.X.X && git push --tags"
    exit 0
else
    printf "\033[31m%d/%d FAILED\033[0m" "$FAIL" "$TOTAL"
    if (( ERROR > 0 )); then
        printf " \033[33m(%d errored — incomplete corpus or no evidence of work, not a content verdict)\033[0m" "$ERROR"
    fi
    printf " — fix before tagging.\n"
    echo ""
    echo "Failed:"
    for s in "${FAILED_STEPS[@]}"; do
        echo "  - $s"
    done
    if (( SKIP > 0 )); then
        echo "Skipped:"
        for s in "${SKIPPED_STEPS[@]}"; do
            echo "  - $s"
        done
    fi
    exit 1
fi
