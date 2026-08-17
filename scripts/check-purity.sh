#!/usr/bin/env bash
# check-purity.sh — OSS purity + no-deprecated + dated-debt detection gate.
#
# Detects families of violations:
#
#   Othala-purity:        instance-specific strings leaked into configs/tests/docs
#   No-referenced-deprecated: references to deleted commands / DORMANT markers
#   Dated-debt:           intentional-failure markers that should have been removed
#
# Usage:
#   bash scripts/check-purity.sh
#
# Exit 0 if all checks pass; exit 1 if any check fails or errors.
#
# -----------------------------------------------------------------------
# ANTI-VACUITY CONTRACT — read before adding a check.
#
# A detection gate is only worth its green when it is impossible for the
# gate to report clean without having actually looked. Failure modes
# were demonstrated against earlier revisions of this script by probe:
#
#   1. A check whose target DIRECTORY existed but held no files reported
#      PASS. Existence is not scanning.
#   2. A check decided pass/fail from grep's EXIT STATUS. `chmod 000` on a
#      scanned path made grep exit 2 (I/O error) with a real hit already on
#      stdout, and exit 2 was read as "no match" — a violation reported as
#      clean.
#   3. A check scanned a full, readable corpus with a PATTERN that could no
#      longer match anything. A typo'd or over-escaped regex matches zero
#      lines, grep exits 1, and the check reports PASS forever. Vacuity at
#      the pattern level rather than the corpus level.
#   4. A check carried one canary per alternative but nothing tied a canary
#      to the branch it proved. Deleting the `agd@` canary from the
#      five-branch runbook check left the other four canaries matched, so
#      the positive control still passed — and the now-unproven branch could
#      then be typo'd to match nothing, still passing, while a real
#      `ssh agd@bastion` line in docs/runbooks/ went undetected. An
#      unproven branch is a dead branch that has not been noticed yet.
#
# This file therefore enforces:
#
#   * A check's pattern is declared as a list of BRANCHES paired
#     index-for-index with a list of CANARIES. Branch i must match canary i,
#     and must match NO OTHER canary. The second half is what closes failure
#     mode 4: if a branch also fires on another branch's canary, deleting
#     either one leaves every canary matched and the loss goes unreported,
#     so an overlapping or superset branch is itself an ERROR.
#   * The branch count is asserted against an expected constant passed at
#     the call site, so removing a branch TOGETHER with its canary — which
#     leaves the pairing internally consistent — still errors. Since the
#     canary count is asserted equal to the branch count, this pins the
#     canary count too.
#   * A branch with no canary is a hard ERROR. There is no such thing as an
#     unproven-but-passing branch.
#   * The pattern actually grepped is the join of the proven branches, built
#     inside the assertion. A branch cannot be scanned without being proven,
#     and the two cannot drift apart.
#   * The scan set is enumerated FIRST and its size asserted > 0. Zero
#     files is step_error, never step_pass.
#   * Every file in the set is asserted present and readable BEFORE grep
#     runs, so an unreadable target cannot masquerade as a clean one.
#   * The verdict is decided from the captured hits, with grep's exit status
#     split three ways: 0 = hits (FAIL), 1 = genuinely clean (PASS),
#     anything else = ERROR. Exit 2 is never treated as exit 1.
#   * The scan set comes from `git ls-files`, i.e. the index — so the set
#     of files examined is identical locally and in CI. A worktree walk is
#     not: site/dist/ and node_modules/ exist on a developer machine and
#     not in a fresh CI clone.
#   * The number of checks that reported a verdict is asserted against
#     EXPECTED_CHECKS, so deleting a check (and with it its canaries) cannot
#     quietly shrink the gate while leaving it green.
#
# A canary is a violating string, so it must not itself become a violation:
# no check's pathspec covers scripts/, which is why the canaries below can
# be written as literals. The one exception is the ADR check, whose corpus
# is the whole index including this file; its canaries are assembled at
# runtime so no resolvable pointer appears in this source.
# -----------------------------------------------------------------------

# NOTE ON `set -e`: it is deliberately NOT enabled. Every check here must
# capture a non-zero exit status from grep and classify it (1 = clean,
# 2 = error); under `set -e` those statuses would abort the script instead
# of being classified, and the gate would report nothing at all.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || exit 1

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0; ERROR=0; FAILED_STEPS=()

# Number of checks that must report a verdict. Bump it in the same commit
# that adds or removes a check; see the check-inventory assertion at the end.
EXPECTED_CHECKS=12

step_pass() {
    PASS=$((PASS+1))
    printf "  \033[32m✓\033[0m %s \033[2m(%s files scanned)\033[0m\n" "$1" "${2:-?}"
}
step_fail() {
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("$1")
    printf "  \033[31m✗\033[0m %s\n" "$1"
    if [[ -n "${2:-}" ]]; then
        printf "      %s\n" "$2"
    fi
}
# step_error: the check could not be performed honestly — one of its branches
# no longer matches its own canary, a branch has no canary of its own, the
# branch set changed size unannounced, its scan set was empty, a target was
# missing or unreadable, or grep failed with an I/O or usage error. This is
# NEVER a pass: neither an unexamined corpus nor an unproven pattern is a
# clean result. Counts toward FAIL so the gate still exits non-zero.
step_error() {
    ERROR=$((ERROR+1))
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("$1 [VACUOUS/ERROR: check did not run honestly]")
    printf "  \033[33m‼\033[0m %s \033[33m(ERROR — unproven pattern, or an incomplete/unreadable corpus)\033[0m\n" "$1"
    if [[ -n "${2:-}" ]]; then
        printf "      %s\n" "$2"
    fi
}

# ---------------------------------------------------------------------
# split_lines <newline-separated string>
#
# Splits into the global array SPLIT_OUT. Used for the branch and canary
# lists, which are passed as newline-separated arguments because bash
# cannot pass arrays. A trailing empty element is impossible: the herestring
# supplies the final newline, and empty elements are rejected by the caller.
# ---------------------------------------------------------------------
SPLIT_OUT=()
split_lines() {
    local line
    SPLIT_OUT=()
    while IFS= read -r line; do
        SPLIT_OUT+=("$line")
    done <<<"$1"
}

# ---------------------------------------------------------------------
# assert_fires <check-name> <expected-branch-count> <branches> <canaries>
#
# The positive control, and the only place PATTERN is built. <branches> and
# <canaries> are newline-separated lists paired index-for-index: branch i is
# proven by canary i.
#
# It answers three distinct failure modes:
#
#   * A pattern that has been typo'd, over-escaped or narrowed scans the
#     right files, matches nothing, and reports clean forever — caught by
#     requiring branch i to match canary i.
#   * A branch whose canary was deleted becomes unprovable while the control
#     still passes on the surviving canaries, and can then be broken freely —
#     caught by requiring the two lists to be the same length and by
#     requiring branch i to match NO canary other than its own, which is what
#     makes "one canary went missing" visible as "one branch fires nothing".
#   * A branch deleted together with its canary shrinks the gate while
#     leaving the pairing consistent — caught by <expected-branch-count>.
#
# On success, PATTERN holds the branches joined with `|`; callers grep that
# and nothing else, so an unproven branch cannot reach the corpus.
# ---------------------------------------------------------------------
PATTERN=""
assert_fires() {
    local name="$1" expected="$2" branches_raw="$3" canaries_raw="$4"
    local -a B=() C=()
    local i j n m rc matched hits total unmatched unproven anyhit

    split_lines "$branches_raw"; B=("${SPLIT_OUT[@]}")
    split_lines "$canaries_raw"; C=("${SPLIT_OUT[@]}")
    n=${#B[@]}; m=${#C[@]}

    # An empty branch is an empty alternative, which matches every line and
    # would turn the whole gate into a permanent FAIL; an empty canary proves
    # nothing. Both mean the list was mis-assembled.
    for (( i = 0; i < n; i++ )); do
        if [[ -z "${B[i]}" ]]; then
            step_error "$name" "branch $i is empty — an empty alternative matches every line; the branch list was mis-assembled"
            return 1
        fi
    done
    for (( i = 0; i < m; i++ )); do
        if [[ -z "${C[i]}" ]]; then
            step_error "$name" \
                "canary $i is empty — an empty canary proves nothing, so branch ${i}${B[i]+ (/${B[i]}/)} is left unproven"
            return 1
        fi
    done

    PATTERN="$(IFS='|'; printf '%s' "${B[*]}")"

    # Unequal lists: the pairing is broken, so name the branches that no
    # surviving canary fires. That is the branch whose canary was deleted.
    if (( m != n )); then
        unproven=""
        for (( i = 0; i < n; i++ )); do
            anyhit=0
            for (( j = 0; j < m; j++ )); do
                printf '%s\n' "${C[j]}" | grep -qE -e "${B[i]}" && anyhit=1
            done
            if (( anyhit == 0 )); then
                unproven="${unproven}${unproven:+, }/${B[i]}/"
            fi
        done
        step_error "$name" \
            "$n pattern branch(es) but $m canary/canaries — each branch is proven by the canary at its own index, so add and remove them together${unproven:+; NO canary now fires branch: $unproven}"
        return 1
    fi

    if (( n != expected )); then
        step_error "$name" \
            "$n pattern branch(es), expected $expected — a branch was added or removed without updating the expected count at the call site; the gate changed size unannounced"
        return 1
    fi

    # Branch i must fire on canary i (it is not dead) and on no other canary
    # (it is discriminating, so the loss of any single branch or canary is
    # visible rather than covered by an overlapping neighbour).
    for (( i = 0; i < n; i++ )); do
        for (( j = 0; j < n; j++ )); do
            printf '%s\n' "${C[j]}" | grep -qE -e "${B[i]}"
            rc=$?
            if (( rc > 1 )); then
                step_error "$name" \
                    "positive-control grep exited $rc (usage or I/O error) for branch /${B[i]}/"
                return 1
            fi
            matched=0
            (( rc == 0 )) && matched=1

            if (( i == j && matched == 0 )); then
                step_error "$name" \
                    "POSITIVE CONTROL FAILED: branch /${B[i]}/ no longer fires on its own canary: ${C[j]} — a pattern that cannot match a known violation cannot prove the corpus clean"
                return 1
            fi
            if (( i != j && matched == 1 )); then
                step_error "$name" \
                    "POSITIVE CONTROL NOT DISCRIMINATING: branch /${B[i]}/ also matches the canary for branch /${B[j]}/ (${C[j]}) — deleting branch /${B[j]}/ would leave every canary matched and the loss unreported"
                return 1
            fi
        done
    done

    # The assembled PATTERN, not only its parts: a broken join matches nothing
    # while every individual branch still passes the loop above.
    total=$m
    hits=$(printf '%s\n' "${C[@]}" | grep -cE -e "$PATTERN")
    rc=$?
    if (( rc > 1 )); then
        step_error "$name" \
            "positive-control grep exited $rc (usage or I/O error) for pattern /$PATTERN/"
        return 1
    fi
    if (( hits != total )); then
        unmatched=$(printf '%s\n' "${C[@]}" | grep -vE -e "$PATTERN" | head -1)
        step_error "$name" \
            "POSITIVE CONTROL FAILED: assembled pattern /$PATTERN/ matched $hits/$total canaries — it no longer fires on: $unmatched"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------
# build_scan_set <check-name> <pathspec>...
#
# Populates the global array SCAN_FILES with the tracked files under the
# given pathspecs, then asserts the set is non-empty and every member is
# present and readable on disk. Returns 1 (having recorded step_error) if
# any of that fails, so callers gate on it before grepping.
#
# `git ls-files` (the index) rather than a worktree walk: the index is the
# same object in CI and locally, so a check cannot scan a different corpus
# in the two places.
# ---------------------------------------------------------------------
SCAN_FILES=()
build_scan_set() {
    local name="$1"; shift
    SCAN_FILES=()

    local rc f
    git ls-files -z -- "$@" >"$TMP/scanset" 2>"$TMP/err"
    rc=$?
    if (( rc != 0 )); then
        step_error "$name" "git ls-files exited $rc for [$*]: $(head -1 "$TMP/err")"
        return 1
    fi

    while IFS= read -r -d '' f; do
        SCAN_FILES+=("$f")
    done <"$TMP/scanset"

    if (( ${#SCAN_FILES[@]} == 0 )); then
        step_error "$name" \
            "scan set is EMPTY — 0 tracked files under [$*]; the check would have examined nothing"
        return 1
    fi

    # A tracked file absent from the worktree, or present but unreadable, would
    # make grep exit 2 — which scan() classifies as an error anyway. Catching it
    # here names the offending file instead of leaving a bare "grep exited 2".
    # Note the asymmetry this deliberately keeps: dropping such files from the
    # set instead would let 32 of 33 files vanish and the check still report
    # clean on the one survivor. Partial corpora are not clean corpora.
    local absent=() unreadable=()
    for f in "${SCAN_FILES[@]}"; do
        if [[ ! -e "$f" ]]; then
            absent+=("$f")
        elif [[ ! -f "$f" || ! -r "$f" ]]; then
            unreadable+=("$f")
        fi
    done
    if (( ${#absent[@]} > 0 )); then
        step_error "$name" \
            "${#absent[@]}/${#SCAN_FILES[@]} file(s) are in the git index but absent from the worktree, e.g. ${absent[0]} — stage the deletion (git rm) or restore the file"
        return 1
    fi
    if (( ${#unreadable[@]} > 0 )); then
        step_error "$name" \
            "${#unreadable[@]}/${#SCAN_FILES[@]} tracked file(s) unreadable, e.g. ${unreadable[0]}"
        return 1
    fi

    return 0
}

# ---------------------------------------------------------------------
# scan <check-name> <expected-branch-count> <branches> <canaries> <pathspec>...
#
# The only sanctioned way to run a content check. Proves every branch fires
# on its own canary and no other, builds and validates the scan set, greps
# the explicit file list with the branch set assembled by assert_fires, and
# decides the verdict from the captured hits with grep's exit status
# classified three ways — hits / clean / error.
#
# The branch-count, branch and canary arguments are positional and mandatory.
# Omitting any of them shifts a pathspec into its place, and a pathspec is
# neither a count nor a violating string, so the check errors instead of
# quietly running without a positive control.
# ---------------------------------------------------------------------
scan() {
    local name="$1" expected="$2" branches="$3" canaries="$4"; shift 4
    assert_fires "$name" "$expected" "$branches" "$canaries" || return 1
    build_scan_set "$name" "$@" || return 1

    local out rc
    # Declaration and assignment are split: `local out=$(...)` would make
    # $? the exit status of `local`, not of grep, and the classification
    # below would read a constant 0.
    out=$(grep -nHE -e "$PATTERN" -- "${SCAN_FILES[@]}" 2>"$TMP/greperr")
    rc=$?

    if (( rc > 1 )); then
        # An exit that is neither 0 nor 1 means grep could not complete: an
        # unreadable file, a bad pattern, an I/O fault. Reading this as
        # "no match" is exactly the hole this classification closes.
        step_error "$name" \
            "grep exited $rc (I/O or usage error, NOT 'no match'): $(head -1 "$TMP/greperr")"
    elif [[ -n "$out" ]]; then
        step_fail "$name" "$(printf '%s\n' "$out" | head -3)"
    elif (( rc == 0 )); then
        step_error "$name" "grep reported a match but emitted no output"
    else
        step_pass "$name" "${#SCAN_FILES[@]}"
    fi
    return 0
}

echo "=== check-purity ==="
echo ""

# =================================================================
# Othala-purity family
# =================================================================
echo "Purity:"

# no-dunn-dev-in-configs: no instance domain in Hydra/Kratos config files.
# portal/src/ is excluded — it has legitimate @dunn.dev/reference package imports.
scan "no-dunn-dev-in-configs" 1 \
    'dunn\.dev' \
    'issuer: https://auth.dunn.dev/' \
    hydra/hydra.yml kratos/kratos.yml

# no-dunn-dev-in-tests: no instance domain in portal test scripts.
scan "no-dunn-dev-in-tests" 1 \
    'dunn\.dev' \
    'fetch("https://portal.dunn.dev/api/health")' \
    portal/scripts/

# no-instance-identity-in-runbooks: no instance hostname (lodestone, or stale
# carmine) or personal login names, in either the internal runbooks (docs/runbooks/)
# or the public docs site content tree (site/src/content/docs/) — both are
# published doc surfaces content can land in.
#
# Five branches, five canaries, paired by index: each canary is fired by exactly
# one branch, so deleting either half of a pair is reported rather than absorbed
# by the other four.
scan "no-instance-identity-in-runbooks" 5 \
    $'\\bcarmine\\b\n\\blodestone\\b\nagd@\nandrew\\.dunn\nashley\\.dunn' \
    $'the retired carmine host\nreboot lodestone after the upgrade\nssh agd@bastion\naccount andrew.dunn\naccount ashley.dunn' \
    docs/runbooks/ site/src/content/docs/

# no-personal-names-in-docs: no real operator names in any doc or diagram,
# across both the internal docs tree (docs/) and the public docs site content
# tree (site/src/content/docs/). Matches bare first names, not just the
# dotted andrew.dunn/ashley.dunn form — a bare name is exactly what "no real
# operator names" means. The bare-name and dotted-name branches stay
# discriminating because grep is case-sensitive here: \bAndrew\b does not fire
# on the lowercase andrew.dunn canary, and vice versa.
scan "no-personal-names-in-docs" 4 \
    $'\\bAndrew\\b\n\\bAshley\\b\nandrew\\.dunn\nashley\\.dunn' \
    $'reviewed by Andrew before merge\nAshley approved the change\naccount andrew.dunn\naccount ashley.dunn' \
    docs/ site/src/content/docs/

# no-dunn-dev-in-e2e-manifests: no instance domain leaked into compose manifests.
scan "no-dunn-dev-in-e2e-manifests" 1 \
    'dunn\.dev' \
    '  redirect_uri: https://app.dunn.dev/callback' \
    e2e/manifests/

# no-stale-llm-client-id: stale llm client_id from pre-redesign client list.
scan "no-stale-llm-client-id" 1 \
    'client_id: llm' \
    'client_id: llm' \
    portal/scripts/

# no-personal-name-in-help: family-help.md must not address operator by first
# name. Lives in the public docs site content tree, not docs/.
scan "no-personal-name-in-help" 1 \
    '\bAndrew\b' \
    'ask Andrew if you get stuck' \
    site/src/content/docs/guides/family-help.md

echo ""

# =================================================================
# No-referenced-deprecated family
# =================================================================
echo "No-referenced-deprecated:"

# no-deleted-commands-in-docs: dag-apply-clients and dag-sync-manifests were
# removed; their names must not survive in docs or source. The sibling gate
# iac/deploy/checks/check_deleted_commands.sh carries the same branch/canary
# pairing over the same two commands; keep the idiom aligned when either
# side changes.
scan "no-deleted-commands-in-docs" 2 \
    $'dag-apply-clients\ndag-sync-manifests' \
    $'run dag-apply-clients on the host\nrun dag-sync-manifests afterwards' \
    DEPLOY.md hydra/README.md ARCHITECTURE.md e2e/README.md \
    portal/src/server/register-clients-cli.ts \
    docs/runbooks/ portal/src/ portal/scripts/

# no-dormant-cutover-comment: DORMANT marker was a transitional note; must be gone.
scan "no-dormant-cutover-comment" 1 \
    '\bDORMANT\b' \
    '// DORMANT until the cutover lands' \
    portal/src/server/register-clients-cli.ts e2e/compose.yml

# no-pending-cutover-section: (pending) markers in DEPLOY.md must be resolved.
# Parens are escaped: the pattern is ERE, where bare parens would group.
scan "no-pending-cutover-section" 1 \
    '\(pending\)' \
    '## Cutover (pending)' \
    DEPLOY.md

echo ""

# =================================================================
# Dated-debt family
# =================================================================
echo "Dated-debt:"

# no-intentionally-fails-comment: CI jobs must not be intentionally-failing stubs.
scan "no-intentionally-fails-comment" 1 \
    'INTENTIONALLY FAILS' \
    '  # INTENTIONALLY FAILS until the job is wired' \
    .gitlab-ci.yml

echo ""

# =================================================================
# Decision-marker resolution family
# =================================================================
echo "Decision-marker resolution:"

# adr-pointers-resolve: every ADR pointer anywhere in the tree — space,
# hyphen or underscore separated, with or without leading zeroes, or written as
# a docs/adr path — must resolve to a tracked file under docs/adr/ whose
# basename starts NN- and ends .md, NN zero-padded to two digits. The resolver
# matches on basename, so an ADR filed in a subdirectory of docs/adr/ resolves
# too.
#
# The prose here deliberately spells no concrete ADR number: this file is
# itself part of the citation corpus, and an example number in a comment would
# be indistinguishable from a real pointer.
adr_pointers_resolve() {
    local name="adr-pointers-resolve"

    # The separator forms are split into one branch per LEADING separator
    # character rather than left as a single character class, so each form has
    # a canary that only it fires. The union is unchanged: a pointer either has
    # no separator or begins with a space, a hyphen or an underscore, and each
    # of those branches still accepts the full run of separators after the
    # first. The zero-separator form gains a canary it never had.
    #
    # The canaries are built by concatenation because this file is inside the
    # citation corpus: a literal pointer here would be indistinguishable from a
    # real one and would demand a matching ADR file.
    local a="AD" d="adr"
    assert_fires "$name" 5 \
        $'ADR[[:space:]][[:space:]_-]*[0-9]+\nADR-[[:space:]_-]*[0-9]+\nADR_[[:space:]_-]*[0-9]+\nADR[0-9]+\ndocs/adr/[0-9]+-' \
        "see ${a}R 07 for rationale"$'\n'"superseded by ${a}R-07"$'\n'"noted in ${a}R_07"$'\n'"tracked as ${a}R07 today"$'\n'"defined in docs/${d}/07-example-decision.md" \
        || return 1

    # Citation corpus: every tracked file. Deliberately the index and not a
    # worktree walk — site/dist/ and site/node_modules/ exist locally and not
    # in a fresh CI clone, so a walk would scan a different corpus in the two
    # places. docs/adr/ is included: an ADR citing another ADR must resolve too.
    build_scan_set "$name" . || return 1

    # -I skips binary files (the repo carries PNG brand artwork): without it,
    # grep emits "Binary file ... matches" and the number extractor below would
    # read digits out of that sentence. The reported file count is therefore the
    # corpus offered to grep, of which the binaries contribute no citations. A
    # corpus that yielded no citation at all is caught as an error below, so
    # this cannot degrade into a silent no-op.
    #
    # PATTERN is the join assert_fires just proved, so the citations extracted
    # here are exactly the forms with a live canary — the extractor cannot drift
    # away from the control.
    local cites rc
    cites=$(grep -IhoE -e "$PATTERN" -- "${SCAN_FILES[@]}" 2>"$TMP/greperr")
    rc=$?
    case "$rc" in
        0) : ;;
        1)  step_error "$name" \
                "no ADR citation matched across ${#SCAN_FILES[@]} tracked files — the resolver would have verified nothing"
            return 1 ;;
        *)  step_error "$name" \
                "citation grep exited $rc (I/O or usage error, NOT 'no match'): $(head -1 "$TMP/greperr")"
            return 1 ;;
    esac

    # Normalise every captured number to two digits BEFORE de-duplicating, so a
    # four-digit-padded citation and a two-digit one collapse to one lookup.
    # 10# forces base-10: without it, a leading zero would be read as octal.
    local raw nums=""
    while IFS= read -r raw; do
        [[ -n "$raw" ]] || continue
        nums+="$(printf '%02d' "$((10#$raw))")"$'\n'
    done < <(printf '%s\n' "$cites" | grep -oE '[0-9]+')
    nums=$(printf '%s' "$nums" | sort -u)
    if [[ -z "$nums" ]]; then
        step_error "$name" "citations matched but no ADR number could be extracted"
        return 1
    fi

    # Resolution corpus: tracked files under docs/adr/.
    local adr_index
    adr_index=$(git ls-files -- docs/adr/)
    if [[ -z "$adr_index" ]]; then
        step_error "$name" "no tracked files under docs/adr/ — resolver has no corpus"
        return 1
    fi

    local nn missing="" grc
    for nn in $nums; do
        printf '%s\n' "$adr_index" | grep -qE "(^|/)${nn}-[^/]*\.md$"
        grc=$?
        case "$grc" in
            0) : ;;
            1) missing="${missing}${missing:+ }${nn}" ;;
            *) step_error "$name" "resolver grep exited $grc while looking up ADR ${nn}"
               return 1 ;;
        esac
    done

    if [[ -n "$missing" ]]; then
        step_fail "$name" "cited but no tracked docs/adr file for: $missing"
    else
        step_pass "$name" "${#SCAN_FILES[@]}"
    fi
    return 0
}
adr_pointers_resolve

echo ""

# =================================================================
# Summary
# =================================================================
# Check inventory. Every check reports exactly one verdict, so the number of
# verdicts is fixed. Without this, deleting a check — and with it the canaries
# that proved its branches still fire — would shrink the gate silently and
# still print an all-passed line.
RAN=$((PASS + FAIL))
if (( RAN != EXPECTED_CHECKS )); then
    step_error "check-inventory" \
        "$RAN checks reported a verdict, expected $EXPECTED_CHECKS — a check was added or removed without updating EXPECTED_CHECKS"
fi

TOTAL=$((PASS + FAIL))
if [[ $FAIL -eq 0 ]]; then
    printf "\033[32mALL %d CHECKS PASSED — purity clean.\033[0m\n" "$TOTAL"
    exit 0
else
    printf "\033[31m%d/%d FAILED\033[0m" "$FAIL" "$TOTAL"
    if [[ $ERROR -gt 0 ]]; then
        printf " \033[33m(%d errored — incomplete or unreadable scan, not a content verdict)\033[0m" "$ERROR"
    fi
    printf " — fix before tagging.\n"
    echo ""
    echo "Failed:"
    for s in "${FAILED_STEPS[@]}"; do
        echo "  - $s"
    done
    exit 1
fi
