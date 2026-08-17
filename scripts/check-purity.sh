#!/usr/bin/env bash
# check-purity.sh — OSS purity + no-deprecated + dated-debt + prose-budget gate.
#
# Detects families of violations:
#
#   Othala-purity:        instance-specific strings leaked into configs/tests/docs
#   No-referenced-deprecated: references to deleted commands / DORMANT markers
#   Dated-debt:           intentional-failure markers that should have been removed
#   Vendored-citation:    line-number pins into the byte-vendored config files
#   Prose-budget:         tracked documentation past its byte ceiling
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
#      to the branch it proved. Deleting one canary from a five-branch check
#      left the other four canaries matched, so the positive control still
#      passed — and the now-unproven branch could then be typo'd to match
#      nothing, still passing, while a real violation of that branch went
#      undetected. An unproven branch is a dead branch that has not been
#      noticed yet.
#   5. A check scanned a real corpus with a proven pattern, and the corpus was
#      a fraction of the surface the rule was written about. The purity family
#      greped docs/runbooks/, site/src/content/docs/, two config files and
#      portal/scripts/ — nothing looked at ARCHITECTURE.md, AGENTS.md,
#      README.md, .gitlab-ci.yml, e2e/ or caddy/, and the instance-name branch
#      list named two hosts out of ten. A clone reported ALL 12 CHECKS PASSED
#      with an instance name sitting in .gitlab-ci.yml and a private-stack
#      application name sitting in DEPLOY.md, docs/runbooks/ and two published
#      diagrams. Narrowness is the fourth vacuity: honest scanning of the wrong
#      corpus is still a green that means nothing. The three whole-tree checks
#      below take the ENTIRE index as their pathspec for exactly this reason,
#      and every path exemption is written with the assertion that bounds it.
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
#   * The BYTES offered to grep are counted and asserted > 0, and any member
#     that contributes zero bytes is itself an ERROR. A file count is a count
#     of things that exist; emptying a scanned file leaves the count intact
#     while the corpus goes silent, so presence is asserted by weight.
#   * The verdict is decided from the captured hits, with grep's exit status
#     split three ways: 0 = hits (FAIL), 1 = genuinely clean (PASS),
#     anything else = ERROR. Exit 2 is never treated as exit 1.
#   * The scan set comes from `git ls-files`, i.e. the index — so the set
#     of files examined is identical locally and in CI. A worktree walk is
#     not: site/dist/ and node_modules/ exist on a developer machine and
#     not in a fresh CI clone.
#   * The CONTENT grepped comes from the index too: the blobs are checked
#     out into a scratch tree with `git checkout-index` and grep reads those.
#     Naming files from the index and then reading their bytes from the
#     worktree is two different corpora wearing one file list — a violation
#     staged but not written to the worktree is in what CI will see and was
#     invisible to a worktree read.
#   * The number of checks that reported a verdict is asserted against
#     EXPECTED_CHECKS, so deleting a check (and with it its canaries) cannot
#     quietly shrink the gate while leaving it green.
#
# A canary is a violating string, so it must not itself become a violation.
# Four checks now take the whole index as their corpus — this file included —
# so their canaries are assembled from fragments at runtime by jn(), and their
# branches are written so that no branch matches its own source text: each
# spells a literal as something that is not itself, an escaped dot for the
# vendored paths and a bracketed first letter for the names. If that ever
# stops holding, the gate fails on its own source, which is the safe
# direction to fail in. Only the narrowly-scoped checks, whose pathspecs do
# not reach scripts/, still spell their canaries as literals.
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
EXPECTED_CHECKS=13

# step_pass <name> <file-count> <byte-count>. Both numbers are reported: a
# file count alone cannot distinguish a scanned corpus from an empty one.
step_pass() {
    PASS=$((PASS+1))
    printf "  \033[32m✓\033[0m %s \033[2m(%s files / %s bytes scanned)\033[0m\n" "$1" "${2:-?}" "${3:-?}"
}
# step_fail <name> <detail>. <detail> may be multi-line; every line is indented,
# because a detail block whose first line alone is indented reads as one hit
# with noise after it.
step_fail() {
    local l
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("$1")
    printf "  \033[31m✗\033[0m %s\n" "$1"
    if [[ -n "${2:-}" ]]; then
        while IFS= read -r l; do printf "      %s\n" "$l"; done <<<"$2"
    fi
}
# step_error: the check could not be performed honestly — one of its branches
# no longer matches its own canary, a branch has no canary of its own, the
# branch set changed size unannounced, its scan set was empty, its corpus
# weighed zero bytes, a target was missing or unreadable, or grep failed with
# an I/O or usage error. This is NEVER a pass: neither an unexamined corpus nor
# an unproven pattern is a clean result. Counts toward FAIL so the gate still
# exits non-zero.
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
# ---------------------------------------------------------------------
# jn <fragment>...
#
# Joins its arguments with no separator. Every banned name in the whole-tree
# checks is spelled in FRAGMENTS and rejoined here, because this file is
# inside the corpus those checks scan: a canary written as a literal would be
# the exact leak it exists to detect, and the gate would fail on its own
# source. The fragments are meaningless apart; the join happens in memory and
# never reaches the tree.
# ---------------------------------------------------------------------
jn() { local IFS=''; printf '%s' "$*"; }

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
# Populates three globals and asserts the corpus is real:
#
#   SCAN_FILES  repo-relative paths of the tracked files under <pathspec>...
#   SCAN_BLOBS  the same files materialised from the INDEX under $TMP/idx,
#               index-for-index with SCAN_FILES. These are what callers grep.
#   SCAN_BYTES  the total size of SCAN_BLOBS, i.e. the bytes grep is offered.
#
# Returns 1 (having recorded step_error) if the set is empty, if any member
# is absent or unreadable in the worktree, if the index blobs cannot be
# materialised, or if any member — or the corpus as a whole — weighs zero
# bytes. Callers gate on it before grepping.
#
# `git ls-files` (the index) rather than a worktree walk: the index is the
# same object in CI and locally, so a check cannot scan a different corpus
# in the two places. `git checkout-index` for the CONTENT, for the same
# reason carried one step further: the file list and the bytes must come from
# one source, or a violation that is staged and not yet written to the
# worktree is named by the list and missed by the read.
# ---------------------------------------------------------------------
SCAN_FILES=()
SCAN_BLOBS=()
SCAN_BYTES=0
SCAN_ROOT="$TMP/idx/"
build_scan_set() {
    local name="$1"; shift
    SCAN_FILES=()
    SCAN_BLOBS=()
    SCAN_BYTES=0

    local rc f i
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

    # Materialise the INDEX content of exactly those files into a scratch tree
    # and hand grep that. The list above came from the index; reading the
    # worktree instead would let a staged violation — the very bytes CI is
    # about to check out — go unread, and a worktree edit that is not staged
    # be reported against a file list that does not describe it.
    rm -rf "$TMP/idx"
    git checkout-index -f -z --stdin --prefix="$SCAN_ROOT" <"$TMP/scanset" 2>"$TMP/err"
    rc=$?
    if (( rc != 0 )); then
        step_error "$name" \
            "git checkout-index exited $rc materialising ${#SCAN_FILES[@]} indexed file(s) for [$*]: $(head -1 "$TMP/err")"
        return 1
    fi

    for (( i = 0; i < ${#SCAN_FILES[@]}; i++ )); do
        SCAN_BLOBS+=("${SCAN_ROOT}${SCAN_FILES[i]}")
    done

    local absent_blob=()
    for (( i = 0; i < ${#SCAN_BLOBS[@]}; i++ )); do
        if [[ ! -f "${SCAN_BLOBS[i]}" || ! -r "${SCAN_BLOBS[i]}" ]]; then
            absent_blob+=("${SCAN_FILES[i]}")
        fi
    done
    if (( ${#absent_blob[@]} > 0 )); then
        step_error "$name" \
            "${#absent_blob[@]}/${#SCAN_FILES[@]} indexed file(s) did not materialise, e.g. ${absent_blob[0]} — the corpus grep would read is not the corpus that was listed"
        return 1
    fi

    # Weight, not headcount. A file that exists and holds nothing is a file the
    # count claims was scanned and grep read nothing from; the asymmetry the
    # absent-file check keeps applies here for the same reason — a corpus where
    # 32 of 33 members went empty is not a clean corpus, it is an unread one.
    local empty=()
    for (( i = 0; i < ${#SCAN_BLOBS[@]}; i++ )); do
        [[ -s "${SCAN_BLOBS[i]}" ]] || empty+=("${SCAN_FILES[i]}")
    done
    if (( ${#empty[@]} > 0 )); then
        step_error "$name" \
            "${#empty[@]}/${#SCAN_FILES[@]} file(s) in the scan set are ZERO BYTES in the index, e.g. ${empty[0]} — grep would read nothing from them while the file count still counted them as scanned"
        return 1
    fi

    cat -- "${SCAN_BLOBS[@]}" >"$TMP/corpus" 2>"$TMP/err"
    rc=$?
    if (( rc != 0 )); then
        step_error "$name" \
            "could not read the materialised index corpus (cat exited $rc): $(head -1 "$TMP/err")"
        return 1
    fi
    SCAN_BYTES=$(wc -c <"$TMP/corpus")
    SCAN_BYTES=${SCAN_BYTES//[^0-9]/}

    # The corpus-level assertion, kept alongside the per-file one: if the
    # per-file rule is ever relaxed, "the check examined zero bytes" must still
    # be an error rather than a pass.
    if [[ -z "$SCAN_BYTES" ]] || (( SCAN_BYTES == 0 )); then
        step_error "$name" \
            "scan corpus is ZERO BYTES across ${#SCAN_FILES[@]} tracked file(s) under [$*] — the files exist but there is nothing in them to scan"
        return 1
    fi

    return 0
}

# ---------------------------------------------------------------------
# scan <check-name> <expected-branch-count> <branches> <canaries> <pathspec>...
#
# The only sanctioned way to run a content check. Proves every branch fires
# on its own canary and no other, builds and validates the scan set, greps
# the index content of that explicit file list with the branch set assembled
# by assert_fires, and decides the verdict from the captured hits with grep's
# exit status classified three ways — hits / clean / error.
#
# The branch-count, branch and canary arguments are positional and mandatory.
# Omitting any of them shifts a pathspec into its place, and a pathspec is
# neither a count nor a violating string, so the check errors instead of
# quietly running without a positive control.
#
# ON REPORTING THE SIZE OF A FINDING. A failing check states its TOTAL hit
# count, always; the listing is capped for readability only, with the cap named
# in the same line ("showing the first N of M"). Not cosmetic: an earlier
# revision piped the hits through `head -3` and printed no total, so a run that
# found ELEVEN private-stack application names — seven of them in one diagram —
# reported three and swallowed eight. An operator fixes what the gate shows and
# believes they are done. Misreporting the size of a finding is the same defect
# class as scanning nothing: both hand back a number that is not about the
# corpus.
# ---------------------------------------------------------------------
# How many hit lines a failing check lists before it stops. The total is always
# reported regardless, so raising or lowering this changes readability only.
HIT_CAP=25
scan() {
    local name="$1" expected="$2" branches="$3" canaries="$4"; shift 4
    assert_fires "$name" "$expected" "$branches" "$canaries" || return 1
    build_scan_set "$name" "$@" || return 1

    local out rc nhits
    # Declaration and assignment are split: `local out=$(...)` would make
    # $? the exit status of `local`, not of grep, and the classification
    # below would read a constant 0.
    out=$(grep -nHE -e "$PATTERN" -- "${SCAN_BLOBS[@]}" 2>"$TMP/greperr")
    rc=$?
    # Report the repo-relative path, not the scratch path the blobs were
    # materialised at.
    out=${out//"$SCAN_ROOT"/}

    if (( rc > 1 )); then
        # An exit that is neither 0 nor 1 means grep could not complete: an
        # unreadable file, a bad pattern, an I/O fault. Reading this as
        # "no match" is exactly the hole this classification closes.
        step_error "$name" \
            "grep exited $rc (I/O or usage error, NOT 'no match'): $(head -1 "$TMP/greperr")"
    elif [[ -n "$out" ]]; then
        nhits=$(grep -c '' <<<"$out")
        if (( nhits > HIT_CAP )); then
            step_fail "$name" \
                "$nhits hit(s) — showing the first $HIT_CAP of $nhits:"$'\n'"$(head -n "$HIT_CAP" <<<"$out")"
        else
            step_fail "$name" "$nhits hit(s):"$'\n'"$out"
        fi
    elif (( rc == 0 )); then
        step_error "$name" "grep reported a match but emitted no output"
    else
        step_pass "$name" "${#SCAN_FILES[@]}" "$SCAN_BYTES"
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

# ---------------------------------------------------------------------
# THE THREE WHOLE-TREE CHECKS
#
# These replace three narrower checks that scanned docs/runbooks/,
# site/src/content/docs/ and one guide page. Their corpus is `.` — every
# tracked file — because the rule they enforce has no path qualifier: a
# stranger reading this repo to learn Ory patterns must not be able to
# reconstruct one maintainer's network from it, and the reconstruction works
# just as well from a CI runner tag or an SVG label as from a runbook.
#
# On the pathspec being `.` and not a list: a list is a claim about where
# violations can appear, and that claim was wrong. The names below leaked into
# .gitlab-ci.yml and into two published diagrams, neither of which any earlier
# pathspec named. There is no file in this repo it would be acceptable to find
# them in, so there is no file to leave out.
#
# ON THE FOUR BYTE-VENDORED FILES, which the widening was expected to have to
# exempt: they are NOT exempt, because the reason for exempting them does not
# hold. The expectation was that they carry the deployment's public URL. They
# do not — kratos/kratos.yml and hydra/hydra.yml carry ${OTHALA_PUBLIC_URL},
# a token substituted at deploy time, and identity.schema.json and
# recovery-gate.jsonnet carry no host at all. All four scan clean against all
# three checks. An exemption written for a reason that turns out to be false
# is just a hole, so none was added; do not add one back without first
# checking what is actually in the files.
#
# On the branches being bracketed rather than grep -i: case-insensitivity is
# written into the PATTERN, not passed as a flag, for two reasons. It keeps
# assert_fires' discrimination rule meaningful — a flag would apply to the
# positive control too, collapsing branches that differ only by case — and it
# is what stops each branch from matching its own source text, since `[Ll]`
# is not the letter it accepts.
# ---------------------------------------------------------------------

# no-instance-names: the hosts in the maintainer's private estate. None of them
# means anything to an adopter, and each one is a line on somebody's network
# map. Ten branches, ten canaries, paired by index.
#
# THE PUBLIC PORTAL'S OWN NAME IS NOT HERE, and the omission is recorded so it
# is not "fixed" by the next reader. This project IS that portal; naming it is
# the showcase working, not a leak, and the recorded posture for this repo is a
# clean showcase rather than an anonymisation. A branch for it was written and
# removed: three letters that sit inside ordinary English words needed a
# hand-chosen boundary instead of `\b`, and it fired on this gate's own
# deleted-command branches below, which had to be de-literalised to survive it.
# Both costs bought nothing. Private hosts are what this check is for.
scan "no-instance-names" 10 \
    "$(printf '%s\n' \
        '\b[Ll]odestone\b' \
        '\b[Cc]armine\b' \
        '\b[Cc]orbel\b' \
        '\b[Cc]rimson\b' \
        '\b[Ss]torr\b' \
        '\b[Oo]aktimbers\b' \
        '\b[Tt]yr\b' \
        '\b[Aa]nvil\b' \
        '\b[Cc]rucible\b' \
        '\b[Nn]orn\b' \
        )" \
    "$(printf '%s\n' \
        "reboot $(jn lode stone) after the upgrade" \
        "the retired $(jn car mine) host" \
        "deployed to $(jn cor bel) last week" \
        "$(jn crim son) holds the replica" \
        "rsync from $(jn sto rr) nightly" \
        "the $(jn oak timbers) box is the spare" \
        "$(jn ty r) runs the QEMU executor" \
        "the $(jn an vil) runner is tagged" \
        "$(jn cru cible) builds the images" \
        "$(jn no rn) serves the metrics" \
        )" \
    .

# no-personal-names: real people. LICENSE is the single path exemption in this
# gate, and it is bounded rather than trusted — a copyright notice is a legal
# instrument that must name its holder, which is not what "no personal names"
# was ever about, but an exempted path is a hole unless something asserts what
# may live in it. license_exemption_is_bounded() below asserts that every
# personal-name hit in LICENSE sits on a copyright line, so the exemption
# cannot widen into a place to put prose.
#
# The dotted first.last login forms get no branch of their own: a dot is a word
# boundary, so the bare-name branches already fire on them. Adding them back
# would break assert_fires' discrimination rule, which is the rule doing the
# real work here.
personal_names() {
    local name="no-personal-names" rc unbounded
    local pat='\b[Aa]ndrew\b|\b[Aa]shley\b|agd[@]'

    # The exemption, bounded. LICENSE is read from the INDEX for the same
    # reason every other corpus here is, and a LICENSE that is missing,
    # unreadable or empty is an ERROR rather than a vacuously-satisfied
    # assertion: "nothing in it violates the rule" is not a claim you can make
    # about a file you could not read.
    if ! git show :LICENSE >"$TMP/license" 2>"$TMP/err"; then
        step_error "$name" \
            "LICENSE is exempted from this check but could not be read from the index ($(head -1 "$TMP/err")) — an exemption over an unreadable file asserts nothing"
        return 0
    fi
    if [[ ! -s "$TMP/license" ]]; then
        step_error "$name" \
            "LICENSE is exempted from this check and is ZERO BYTES in the index — an exemption over an empty file is an unguarded hole"
        return 0
    fi
    # Every personal-name hit in the exempted file must sit on a copyright
    # line. That is the whole of what the exemption is for; anything else in
    # there is prose hiding behind a legal notice.
    unbounded=$(grep -E -e "$pat" "$TMP/license" | grep -vE '^Copyright ')
    rc=$?
    if (( rc > 1 )); then
        step_error "$name" "bounding grep over LICENSE exited $rc (I/O or usage error)"
        return 0
    fi
    if [[ -n "$unbounded" ]]; then
        step_error "$name" \
            "LICENSE is exempted only for the copyright notice, but carries a personal name off a copyright line: $(printf '%s' "$unbounded" | head -1)"
        return 0
    fi

    scan "$name" 3 \
        "$(printf '%s\n' \
            '\b[Aa]ndrew\b' \
            '\b[Aa]shley\b' \
            'agd[@]' \
            )" \
        "$(printf '%s\n' \
            "reviewed by $(jn And rew) before merge" \
            "$(jn Ash ley) approved the change" \
            "ssh $(jn agd '@' bastion)" \
            )" \
        . ':!LICENSE'
}
personal_names

# no-private-stack-apps: the applications running on that private stack. They
# are not example applications; they are an inventory of what one household
# runs. Grafana and Audiobookshelf are the only sanctioned examples, and they
# are already the e2e fixtures under e2e/manifests/, so the docs and the tests
# agree by construction rather than by anyone remembering to keep them aligned.
#
# GitLab is deliberately NOT a branch here, and the omission is named rather
# than left to be rediscovered: this repo is hosted on GitLab and built by
# GitLab CI, so `.gitlab-ci.yml`, `registry.gitlab.com` and "GitLab Runner" are
# structural facts of the project, not leaked inventory. A bare-string ban on
# the word cannot tell the forge from an example app. The constraint that
# matters — GitLab must not appear as an example APPLICATION — is carried by
# the manifest fixtures being Grafana and Audiobookshelf, not by this pattern.
scan "no-private-stack-apps" 10 \
    "$(printf '%s\n' \
        '\b[Ii]mmich\b' \
        '\b[Jj]ellyfin\b' \
        '\b[Cc]inema\b' \
        '\b[Vv]aultwarden\b' \
        '\b[Nn]avidrome\b' \
        '\b[Ss]onarr\b' \
        '\b[Rr]adarr\b' \
        '\b[Mm]ealie\b' \
        '[Oo]pen ?[Ww]eb ?UI' \
        '[Ll]ite[Ll][Ll][Mm]' \
        )" \
    "$(printf '%s\n' \
        "photos live in $(jn Imm ich)" \
        "$(jn Jelly fin) uses the LDAP path" \
        "the $(jn cin ema) tile is gated" \
        "$(jn Vault warden) issues the client" \
        "$(jn Navi drome) streams over forward-auth" \
        "$(jn Son arr) polls the indexer" \
        "$(jn Rad arr) polls the same one" \
        "$(jn Mea lie) holds the recipes" \
        "$(jn Open ' ' WebUI) proxies the model" \
        "$(jn Lite LLM) fronts the inference" \
        )" \
    .

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

# A fourth purity check lived here — no-personal-name-in-help, one branch over
# site/src/content/docs/guides/family-help.md. That page was deleted in the
# convergence, so the check's scan set became empty and it would have reported
# step_error forever. It is gone rather than repointed: no-personal-names above
# already covers every path it covered, and every other path besides.

echo ""

# =================================================================
# No-referenced-deprecated family
# =================================================================
echo "No-referenced-deprecated:"

# no-deleted-commands-in-docs: the two removed client-reconciliation commands,
# whose names carried the instance prefix; they must not survive in docs or
# source. The sibling gate in the deploy repo carries the same branch/canary
# pairing over the same two commands; keep the idiom aligned when either side
# changes.
#
# Branches and canaries are plain literals here, unlike the whole-tree checks.
# They can be: this check's pathspec does not reach scripts/, so its canaries
# are not inside its own corpus, and no whole-tree branch fires on these
# strings. (They were briefly written as bracketed first letters and jn()
# fragments, purely to survive an instance-name branch that has since been
# removed. A literal is easier to read, so the literal is back.)
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
# Vendored-citation family
# =================================================================
echo "Vendored-citation:"

# no-line-pins-into-vendored-files: nothing anywhere in the tree may cite a
# byte-vendored file by LINE NUMBER — neither the single-line form nor the
# range form.
#
# The four vendored files are byte-enforced by the sibling deploy repo's drift
# check, so this repo cannot edit them; their line numbers move under any
# upstream bump, and a citation that carries one is a value that goes stale
# without anything noticing. The rot is demonstrable, and it happened during the
# pass that added this check: a document cited ARCHITECTURE.md's "mTLS gap (A7)"
# paragraph by line range, a concurrent edit in the same diff added five lines
# above it, and the range was wrong before the pass ended. The estate rule is
# that a stale value is replaced by a pointer to the enforcing artifact, never
# by a fresher value — so cite the file, name the key or heading, and drop the
# number.
#
# Four branches, four canaries, paired by index: each canary names exactly one
# of the four vendored paths, so no branch fires on another branch's canary and
# dropping either half of a pair is reported rather than absorbed by a
# neighbour.
#
# The canaries are assembled from fragments at runtime because the corpus here
# is the whole index, this file included, so a pinned citation written out as a literal would be a violation
# of the rule it is meant to prove. The branch patterns are safe as literals
# because each spells its dot as an escaped dot, which is a backslash in this
# source text and so does not match itself.
vendored_line_pins() {
    local name="no-line-pins-into-vendored-files"
    local c=":" k="kratos/kratos" h="hydra/hydra" i="kratos/identity"
    local g="kratos/hooks/recovery-gate" y=".yml" s=".schema.json" j=".jsonnet"

    # The range form needs no branch of its own: a range begins with a number,
    # so the single-number branch already fires on it.
    scan "$name" 4 \
        $'kratos/kratos\\.yml:[0-9]+\nhydra/hydra\\.yml:[0-9]+\nkratos/identity\\.schema\\.json:[0-9]+\nkratos/hooks/recovery-gate\\.jsonnet:[0-9]+' \
        "session block at ${k}${y}${c}264-272"$'\n'"DSN comment at ${h}${y}${c}135"$'\n'"trait at ${i}${s}${c}12"$'\n'"branch at ${g}${j}${c}7" \
        .
}
vendored_line_pins

echo ""

# =================================================================
# Prose-budget family
# =================================================================
echo "Prose-budget:"

# ---------------------------------------------------------------------
# prose-budget — total tracked documentation, capped in bytes.
#
# WHY THERE IS A CEILING AT ALL, recorded here because a number with no
# reason attached gets raised the first time it is inconvenient:
#
# This corpus reached 504,832 bytes across 50 files. At that size, orienting
# in the documentation cost more context than doing the work the documentation
# described — every task began by spending the budget it needed to finish.
# Nearly 20% of one week's model budget went to curating it rather than to
# building anything. Half of it was deleted in a single pass, including a
# 16-document decision corpus and the 243-node citation web that held it
# together, roughly a third of whose line pins were already wrong.
#
# "Keep the documentation short" is an intention, and intentions lose to the
# next plausible page. A ceiling is a build failure, which does not. The rule
# it makes operational is the one in AGENTS.md: adding documentation means
# removing documentation, in the same commit.
#
# RAISING IT is a legitimate act and deliberately an awkward one — it is an
# edit to this constant, in a commit whose message has to say what grew and
# why it earned the room. That is the whole mechanism. What must not happen is
# the ceiling drifting upward one convenient commit at a time, which is why it
# is a literal here and not a high-water mark computed from the tree.
#
# The CHANGELOG is inside the budget, and that is a choice rather than an
# oversight: an agent orienting in this repo reads it like anything else, so
# it costs what everything else costs. It grows monotonically, so it will one
# day be the thing pushing against the ceiling. When it is, trim the old
# entries — releases are in the tags — or raise the ceiling on purpose.
# ---------------------------------------------------------------------

# The ceiling, in bytes. Set to the surviving corpus plus 10% headroom at the
# convergence that created this check.
PROSE_CEILING_BYTES=191957

# What the corpus weighed when it became unmanageable. The ceiling is asserted
# below to be under this, so "raise the ceiling" cannot quietly become "restore
# the state that made the ceiling necessary".
PROSE_HIGH_WATER_BYTES=504832

# THE DEFINITION OF PROSE, kept as data because it is printed on every run:
# a future maintainer reading a failure must be able to see what was counted
# without reading this file.
PROSE_GLOBS=('*.md' '*.mdx' '*.markdown')

# Doc trees whose every tracked file must be counted by the globs above. This
# is the coverage assertion: renaming a page out of the counted extensions is
# the obvious way to dodge a byte budget, and it would otherwise look like the
# corpus shrinking. A file here that the definition does not count is an ERROR
# that names the file, so widening the definition — or moving the file — is a
# deliberate act rather than an accident.
PROSE_COVERED_TREES=(docs/ site/src/content/docs/)

# over_budget <bytes> — the single comparison this check makes. It exists as a
# function so the positive control below can exercise the same code the verdict
# uses; a control that re-implements the comparison proves nothing about it.
over_budget() { (( $1 > PROSE_CEILING_BYTES )); }

prose_budget() {
    local name="prose-budget" rc f i
    local defn total ceiling headroom pct
    local -a missing=()

    defn="$(printf '%s ' "${PROSE_GLOBS[@]}")"
    defn="${defn% }"

    # --- the constants are sane ---------------------------------------
    if [[ ! "$PROSE_CEILING_BYTES" =~ ^[0-9]+$ ]] || (( PROSE_CEILING_BYTES == 0 )); then
        step_error "$name" \
            "PROSE_CEILING_BYTES is '$PROSE_CEILING_BYTES' — a ceiling that is not a positive integer is not a ceiling"
        return 0
    fi
    if (( PROSE_CEILING_BYTES >= PROSE_HIGH_WATER_BYTES )); then
        step_error "$name" \
            "PROSE_CEILING_BYTES ($PROSE_CEILING_BYTES) is at or above the $PROSE_HIGH_WATER_BYTES bytes this corpus weighed when it became unmanageable — a ceiling set there permits exactly the state it exists to prevent"
        return 0
    fi
    if (( ${#PROSE_GLOBS[@]} == 0 )); then
        step_error "$name" "PROSE_GLOBS is empty — the check would define prose as nothing and pass forever"
        return 0
    fi

    # --- positive control ---------------------------------------------
    # The budget analogue of a canary. A comparison hard-wired to "under", or
    # inverted, or reading a variable that is no longer the one being set, is
    # the exact vacuity the pattern checks guard against with canaries: it
    # scans a real corpus and always reports clean. So the comparator is fired
    # at a value that must be over and a value that must not be.
    if ! over_budget $((PROSE_CEILING_BYTES + 1)); then
        step_error "$name" \
            "POSITIVE CONTROL FAILED: over_budget() reports $((PROSE_CEILING_BYTES + 1)) bytes as within a $PROSE_CEILING_BYTES-byte ceiling — the comparison cannot fail, so its green means nothing"
        return 0
    fi
    if over_budget "$PROSE_CEILING_BYTES"; then
        step_error "$name" \
            "POSITIVE CONTROL FAILED: over_budget() reports exactly $PROSE_CEILING_BYTES bytes as over a $PROSE_CEILING_BYTES-byte ceiling — the comparison is off by one against the corpus it is supposed to admit"
        return 0
    fi

    # --- the corpus, from the index, weighed ---------------------------
    # build_scan_set does the whole anti-vacuity job here: empty set, absent or
    # unreadable member, zero-byte member and zero-byte corpus are all ERROR,
    # and SCAN_BYTES is measured over blobs materialised from the index rather
    # than over the worktree.
    build_scan_set "$name" "${PROSE_GLOBS[@]}" || return 0

    # --- coverage ------------------------------------------------------
    printf '%s\n' "${SCAN_FILES[@]}" >"$TMP/proseset"
    git ls-files -z -- "${PROSE_COVERED_TREES[@]}" >"$TMP/covered" 2>"$TMP/err"
    rc=$?
    if (( rc != 0 )); then
        step_error "$name" \
            "git ls-files exited $rc enumerating the covered doc trees [${PROSE_COVERED_TREES[*]}]: $(head -1 "$TMP/err")"
        return 0
    fi
    i=0
    while IFS= read -r -d '' f; do
        i=$((i+1))
        grep -qxF -- "$f" "$TMP/proseset" || missing+=("$f")
    done <"$TMP/covered"
    if (( i == 0 )); then
        step_error "$name" \
            "0 tracked files under the covered doc trees [${PROSE_COVERED_TREES[*]}] — the coverage assertion has nothing to assert, so either a tree moved or this list is stale"
        return 0
    fi
    if (( ${#missing[@]} > 0 )); then
        step_error "$name" \
            "${#missing[@]}/$i file(s) in the covered doc trees are NOT counted as prose, e.g. ${missing[0]} — either it was renamed out of [$defn] to dodge the budget, or the definition needs widening; both are deliberate acts, so make one"
        return 0
    fi

    # --- the numbers, printed on every run -----------------------------
    # Passing or failing. A budget nobody can see is a budget nobody manages,
    # and the run where the headroom went from comfortable to thin is the run
    # worth noticing — not the one after it, where the gate is already red.
    total=$SCAN_BYTES
    ceiling=$PROSE_CEILING_BYTES
    headroom=$((ceiling - total))
    pct=$(( total * 100 / ceiling ))
    printf "      \033[2mprose = tracked %s over the whole index (%s files)\033[0m\n" \
        "$defn" "${#SCAN_FILES[@]}"
    printf "      \033[2mcurrent %s B / ceiling %s B (%s%%) — headroom %s B\033[0m\n" \
        "$total" "$ceiling" "$pct" "$headroom"

    if over_budget "$total"; then
        step_fail "$name" \
            "tracked prose is $total bytes, over the $ceiling-byte ceiling by $((-headroom)) — remove documentation, or raise PROSE_CEILING_BYTES in scripts/check-purity.sh in a commit that says what grew and why"
    else
        step_pass "$name" "${#SCAN_FILES[@]}" "$total"
    fi
    return 0
}
prose_budget

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
