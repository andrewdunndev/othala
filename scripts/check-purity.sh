#!/usr/bin/env bash
# check-purity.sh — OSS purity + no-deprecated gate.
# Data-driven: each check is a ROW (branches/canaries/pathspec) in the table
# below; scan() plus the loop over it is the whole runner. no-personal-names
# needs one extra rule (a bounded exemption), so it stays a small function
# routed through the same build_scan_set/run_scan primitives as every row.
# Reads the git INDEX, not the worktree, so CI sees what this sees, and a
# staged-not-written violation is caught (build_scan_set). Deps: git, bash,
# grep, sed, coreutils only.
# Anti-vacuity, why: a gate that cannot fail proves nothing. Each branch proves itself on its own canary before
# it scans anything — selftest(), the inline successor to the retired
# probe-check-purity.sh mutation harness. Scanned files/bytes are asserted >
# 0; a verdict is read off grep's captured HITS, never its bare exit status.
# Usage: bash scripts/check-purity.sh — exit 0 clean, 1 on any FAIL/ERROR.
set -uo pipefail  # NOT -e: every check classifies grep's exit itself (0/1/>1).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || exit 1  # pathspecs below are repo-root-relative
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0; ERROR=0; FAILED_STEPS=()

step_pass() {  # <name> <files> <bytes> — both counts, so an empty corpus can't hide behind a nonzero file count
    PASS=$((PASS+1))
    printf '  \033[32m\xe2\x9c\x93\033[0m %s \033[2m(%s files / %s bytes scanned)\033[0m\n' "$1" "${2:-?}" "${3:-?}"
}
step_fail() {  # <name> <detail, multi-line ok> — every detail line indented, so a multi-hit block reads as one finding
    local l
    FAIL=$((FAIL+1)); FAILED_STEPS+=("$1")
    printf '  \033[31m\xe2\x9c\x97\033[0m %s\n' "$1"
    if [[ -n "${2:-}" ]]; then while IFS= read -r l; do printf '      %s\n' "$l"; done <<<"$2"; fi
}
step_error() {  # <name> <reason> — an unproven pattern or unreadable corpus is NEVER a pass; counts toward FAIL too
    ERROR=$((ERROR+1)); FAIL=$((FAIL+1))
    FAILED_STEPS+=("$1 [VACUOUS/ERROR: check did not run honestly]")
    printf '  \033[33m\xe2\x80\xbc\033[0m %s \033[33m(ERROR)\033[0m\n' "$1"
    [[ -n "${2:-}" ]] && printf '      %s\n' "$2"
}

# jn <fragment>... — join with no separator. Every self-referential canary
# below is spelled in fragments and rejoined here at runtime: four checks scan
# the WHOLE index, this file included, so a canary written as one literal
# would be the exact leak it exists to prove detectable.
jn() { local IFS=''; printf '%s' "$*"; }

PATTERN=""
# selftest <name> <expected-branches> <branches\n..> <canaries\n..> — branch i
# must fire ONLY on canary i: proves the pattern catches a known violation
# (not typo'd/over-escaped into matching nothing) and that no branch covers
# for a deleted neighbour. Builds PATTERN, the `|`-join scan() greps.
selftest() {
    local name="$1" expected="$2" i j rc hits
    local -a B C
    mapfile -t B <<<"$3"; mapfile -t C <<<"$4"
    if (( ${#B[@]} != expected || ${#C[@]} != expected )); then
        step_error "$name" "${#B[@]} branch(es) / ${#C[@]} canary/canaries, expected $expected — a row changed size unannounced"
        return 1
    fi
    for i in "${!B[@]}"; do
        [[ -n "${B[i]}" && -n "${C[i]}" ]] || { step_error "$name" "branch or canary $i is empty — an empty branch matches every line, an empty canary proves nothing"; return 1; }
    done
    PATTERN="$(IFS='|'; printf '%s' "${B[*]}")"
    for i in "${!B[@]}"; do
        for j in "${!C[@]}"; do
            printf '%s\n' "${C[j]}" | grep -qE -e "${B[i]}"; rc=$?
            (( rc > 1 )) && { step_error "$name" "canary grep exited $rc (I/O or usage error) for branch /${B[i]}/"; return 1; }
            if (( i == j )); then
                (( rc == 0 )) || { step_error "$name" "SELF-TEST FAILED: branch /${B[i]}/ does not fire on its own canary"; return 1; }
            elif (( rc == 0 )); then
                step_error "$name" "branch /${B[i]}/ also fires canary $j — not discriminating, a deleted neighbour would go unreported"; return 1
            fi
        done
    done
    hits=$(printf '%s\n' "${C[@]}" | grep -cE -e "$PATTERN")
    (( hits == expected )) || { step_error "$name" "assembled pattern matched $hits/$expected canaries — the join is broken though every branch passed alone"; return 1; }
    return 0
}

SCAN_FILES=(); SCAN_BLOBS=(); SCAN_BYTES=0; SCAN_ROOT="$TMP/idx/"
# build_scan_set <name> <pathspec...> — indexed file list, and the CONTENT of
# those files materialised from the index (not read off the worktree), so a
# staged-not-written violation is seen. Empty set, an absent/unreadable
# worktree member, a failed checkout, a zero-byte member, or a zero-byte
# corpus are all ERROR — never an empty PASS.
build_scan_set() {
    local name="$1"; shift
    SCAN_FILES=(); SCAN_BLOBS=(); SCAN_BYTES=0
    git ls-files -z -- "$@" >"$TMP/scanset" 2>"$TMP/err" || { step_error "$name" "git ls-files: $(head -1 "$TMP/err")"; return 1; }
    mapfile -d '' -t SCAN_FILES <"$TMP/scanset"
    (( ${#SCAN_FILES[@]} > 0 )) || { step_error "$name" "scan set is EMPTY — 0 tracked files under [$*]"; return 1; }
    local f absent=() unreadable=()
    for f in "${SCAN_FILES[@]}"; do
        [[ -e "$f" ]] || absent+=("$f")
        [[ -e "$f" && ( ! -f "$f" || ! -r "$f" ) ]] && unreadable+=("$f")
    done
    # Named, not dropped: silently scanning fewer files would let 9/10 pass on the one survivor.
    (( ${#absent[@]} == 0 )) || { step_error "$name" "${#absent[@]} indexed file(s) absent from the worktree, e.g. ${absent[0]} — git rm or restore it"; return 1; }
    (( ${#unreadable[@]} == 0 )) || { step_error "$name" "${#unreadable[@]} indexed file(s) unreadable, e.g. ${unreadable[0]}"; return 1; }
    rm -rf "$TMP/idx"
    git checkout-index -f -z --stdin --prefix="$SCAN_ROOT" <"$TMP/scanset" 2>"$TMP/err" || { step_error "$name" "git checkout-index: $(head -1 "$TMP/err")"; return 1; }
    local empty=()
    for f in "${SCAN_FILES[@]}"; do
        SCAN_BLOBS+=("$SCAN_ROOT$f")
        [[ -f "$SCAN_ROOT$f" && -r "$SCAN_ROOT$f" ]] || { step_error "$name" "indexed file did not materialise: $f"; return 1; }
        [[ -s "$SCAN_ROOT$f" ]] || empty+=("$f")
    done
    (( ${#empty[@]} == 0 )) || { step_error "$name" "${#empty[@]} file(s) are ZERO BYTES in the index, e.g. ${empty[0]} — counted as scanned, read nothing"; return 1; }
    cat -- "${SCAN_BLOBS[@]}" >"$TMP/corpus" 2>"$TMP/err" || { step_error "$name" "cat over the materialised corpus: $(head -1 "$TMP/err")"; return 1; }
    SCAN_BYTES=$(wc -c <"$TMP/corpus"); SCAN_BYTES=${SCAN_BYTES//[^0-9]/}
    (( SCAN_BYTES > 0 )) || { step_error "$name" "scan corpus is ZERO BYTES across ${#SCAN_FILES[@]} file(s)"; return 1; }
    return 0
}

HIT_CAP=25  # hits beyond this are still counted in the total, just not printed
# scan <name> <expected-branches> <branches> <canaries> <pathspec...> — the
# only sanctioned way to run a check: prove the pattern (selftest), build the
# scan set, grep it, verdict from the captured HITS — grep's exit status is
# classified 0=hit 1=clean >1=ERROR, never read as pass/fail directly.
scan() {
    local name="$1" expected="$2" branches="$3" canaries="$4"; shift 4
    selftest "$name" "$expected" "$branches" "$canaries" || return 0
    run_scan "$name" "$@"
}
# run_scan <name> <pathspec...> — grep the global PATTERN over the scan set.
run_scan() {
    local name="$1"; shift
    build_scan_set "$name" "$@" || return 0
    local out rc nhits
    out=$(grep -nHE -e "$PATTERN" -- "${SCAN_BLOBS[@]}" 2>"$TMP/greperr")
    rc=$?
    out=${out//"$SCAN_ROOT"/}  # report repo-relative paths, not the scratch checkout path
    if (( rc > 1 )); then
        step_error "$name" "grep exited $rc (I/O or usage error, NOT 'no match'): $(head -1 "$TMP/greperr")"
    elif [[ -n "$out" ]]; then
        nhits=$(grep -c '' <<<"$out")
        if (( nhits > HIT_CAP )); then
            step_fail "$name" "$nhits hit(s) — showing first $HIT_CAP of $nhits:"$'\n'"$(head -n "$HIT_CAP" <<<"$out")"
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

# THE TABLE. row() only appends; the loop after it is the entire run phase.
ROW_NAME=(); ROW_N=(); ROW_BR=(); ROW_CAN=(); ROW_PATH=()
row() { ROW_NAME+=("$1"); ROW_N+=("$2"); ROW_BR+=("$3"); ROW_CAN+=("$4"); ROW_PATH+=("$5"); }

echo "=== check-purity ==="
echo ""

# Purity: instance-specific strings must not leak into a public repo.
row "no-dunn-dev-in-configs" 1 'dunn\.dev' 'issuer: https://auth.dunn.dev/' 'hydra/hydra.yml kratos/kratos.yml'
row "no-dunn-dev-in-tests" 1 'dunn\.dev' 'fetch("https://portal.dunn.dev/api/health")' 'portal/scripts/'
row "no-dunn-dev-in-e2e-manifests" 1 'dunn\.dev' '  redirect_uri: https://app.dunn.dev/callback' 'e2e/content/'

# Vendored-citation: no LINE NUMBER may cite a byte-vendored file (rots under
# any upstream bump) anywhere in the tree — pathspec "." reaches this file
# too, so canaries are jn()-built rather than literal, same as above.
row "no-line-pins-into-vendored-files" 4 \
    "$(printf '%s\n' 'kratos/kratos\.yml:[0-9]+' 'hydra/hydra\.yml:[0-9]+' 'kratos/identity\.schema\.json:[0-9]+' 'kratos/hooks/recovery-gate\.jsonnet:[0-9]+')" \
    "$(printf '%s\n' "session block at $(jn kratos/kratos .yml : 264-272)" "DSN comment at $(jn hydra/hydra .yml : 135)" "trait at $(jn kratos/identity .schema.json : 12)" "branch at $(jn kratos/hooks/recovery-gate .jsonnet : 7)")" \
    .

for i in "${!ROW_NAME[@]}"; do
    # shellcheck disable=SC2086 # ROW_PATH is a space-joined field of plain repo paths; none contain spaces
    scan "${ROW_NAME[i]}" "${ROW_N[i]}" "${ROW_BR[i]}" "${ROW_CAN[i]}" ${ROW_PATH[i]}
done
echo ""

# no-personal-names — special-cased: LICENSE may name its copyright holder, so
# it is excluded from the row above and checked here as BOUNDED first (any
# hit off a "Copyright " line is prose hiding behind the legal notice) before
# the same scan() runs over everything else.
personal_names() {
    local name="no-personal-names" pat='\b[Aa]ndrew\b|\b[Aa]shley\b|agd[@]' unbounded
    git show :LICENSE >"$TMP/license" 2>"$TMP/err" || { step_error "$name" "LICENSE unreadable in the index: $(head -1 "$TMP/err")"; return; }
    [[ -s "$TMP/license" ]] || { step_error "$name" "LICENSE is ZERO BYTES in the index — an exemption over an empty file is a hole"; return; }
    unbounded=$(grep -E -e "$pat" "$TMP/license" | grep -v '^Copyright ')
    [[ -z "$unbounded" ]] || { step_error "$name" "LICENSE carries a personal name off a copyright line: $(head -1 <<<"$unbounded")"; return; }
    scan "$name" 3 \
        "$(printf '%s\n' '\b[Aa]ndrew\b' '\b[Aa]shley\b' 'agd[@]')" \
        "$(printf '%s\n' "reviewed by $(jn And rew) before merge" "$(jn Ash ley) approved the change" "ssh $(jn agd '@' bastion)")" \
        . ':!LICENSE'
}
personal_names
echo ""

# private_names — the host/instance and private-app denylists live in the file
# named by PURITY_PRIVATE_NAMES (sections [no-instance-names] and
# [no-private-stack-apps], one ERE per line), so a public repo does not carry them.
private_names() {
    local file="${PURITY_PRIVATE_NAMES:-}" rule line
    local -a pats
    for rule in no-instance-names no-private-stack-apps; do
        if [[ -z "$file" || ! -r "$file" ]]; then
            if [[ "${CI:-}" == true ]]; then step_fail "$rule" "PURITY_PRIVATE_NAMES unset"
            else printf '  - %s skipped (PURITY_PRIVATE_NAMES unset)\n' "$rule"; fi
            continue
        fi
        pats=()
        while IFS= read -r line; do pats+=("$line"); done < <(awk -v s="[$rule]" '/^\[/{on=($0==s);next} on&&NF' "$file")
        (( ${#pats[@]} > 0 )) || { step_error "$rule" "no patterns under [$rule] in $file"; continue; }
        for line in "${pats[@]}"; do
            printf '' | grep -qE -e "$line"; (( $? > 1 )) && { step_error "$rule" "invalid pattern in $file"; continue 2; }
        done
        PATTERN="$(IFS='|'; printf '%s' "${pats[*]}")"
        run_scan "$rule" .
    done
}
private_names
echo ""

TOTAL=$((PASS + FAIL))
if [[ $FAIL -eq 0 ]]; then
    printf '\033[32mALL %d CHECKS PASSED — purity clean.\033[0m\n' "$TOTAL"
    exit 0
else
    printf '\033[31m%d/%d FAILED\033[0m' "$FAIL" "$TOTAL"
    if [[ $ERROR -gt 0 ]]; then
        printf ' \033[33m(%d errored — incomplete or unreadable scan, not a content verdict)\033[0m' "$ERROR"
    fi
    printf ' — fix before tagging.\n'
    echo ""
    echo "Failed:"
    for s in "${FAILED_STEPS[@]}"; do
        echo "  - $s"
    done
    exit 1
fi
