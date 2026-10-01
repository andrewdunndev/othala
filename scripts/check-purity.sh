#!/usr/bin/env bash
# check-purity.sh — OSS purity + no-deprecated + dated-debt + prose-budget gate.
# Data-driven: each check is a ROW (branches/canaries/pathspec) in the table
# below; scan() plus the loop over it is the whole runner. no-personal-names
# and prose-budget need one extra rule each (a bounded exemption, a byte
# comparator), so they stay small functions routed through the same
# build_scan_set/scan primitives as every row.
# Reads the git INDEX, not the worktree, so CI sees what this sees, and a
# staged-not-written violation is caught (build_scan_set). Deps: git, bash,
# grep, sed, coreutils only.
# Anti-vacuity, why: DECISIONS.md "Cite the artifact that holds the value;
# never restate the value". Each branch proves itself on its own canary before
# it scans anything — selftest(), the inline successor to the retired
# probe-check-purity.sh mutation harness. Scanned files/bytes are asserted >
# 0; a verdict is read off grep's captured HITS, never its bare exit status;
# EXPECTED_CHECKS is asserted against verdicts reported, so a deleted row
# cannot shrink the gate and stay green.
# Usage: bash scripts/check-purity.sh — exit 0 clean, 1 on any FAIL/ERROR.
set -uo pipefail  # NOT -e: every check classifies grep's exit itself (0/1/>1).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || exit 1  # pathspecs below are repo-root-relative
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
EXPECTED_CHECKS=12  # bump in the same commit that adds/removes a row or special check
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
# Whole-index (pathspec "."): the rule has no path qualifier — a private host
# leaked from .gitlab-ci.yml and two diagrams before these three checks were
# widened past docs/. Bracketed first letter, not `grep -i`: a flag would
# apply to the positive control too and collapse selftest()'s discrimination.
row "no-instance-names" 10 \
    "$(printf '%s\n' '\b[Ll]odestone\b' '\b[Cc]armine\b' '\b[Cc]orbel\b' '\b[Cc]rimson\b' '\b[Ss]torr\b' '\b[Oo]aktimbers\b' '\b[Tt]yr\b' '\b[Aa]nvil\b' '\b[Cc]rucible\b' '\b[Nn]orn\b')" \
    "$(printf '%s\n' "reboot $(jn lode stone) after the upgrade" "the retired $(jn car mine) host" "deployed to $(jn cor bel) last week" "$(jn crim son) holds the replica" "rsync from $(jn sto rr) nightly" "the $(jn oak timbers) box is the spare" "$(jn ty r) runs the QEMU executor" "the $(jn an vil) runner is tagged" "$(jn cru cible) builds the images" "$(jn no rn) serves the metrics")" \
    .
# LICENSE is exempted (copyright holder) below, bounded — see personal_names().
# Branches 11-18 are the historical private-catalog CODENAMES a pre-tag pass
# found leaked as fixture data (larder, and the app-shaped hits among
# candidates keep/observe/tune/vault/forge/gather/memory — branch 3 above
# already covered a tenth; listen/library never fired as codenames, only as
# real filenames/products/verbs, so they stay out). Unlike branches 1-10 these
# are
# ordinary English words, so a bare `\bword\b` would fail on every legitimate
# use (e.g. "keep in sync"); scoped instead to the violation SHAPE itself —
# `<word>-access`/`access-<word>`/`<word>-admin` group names or a
# `<word>.dunn.dev`/`<word>.othala.test`/`<word>.example.test` hostname —
# which prose never produces by accident.
row "no-private-stack-apps" 18 \
    "$(printf '%s\n' '\b[Ii]mmich\b' '\b[Jj]ellyfin\b' '\b[Cc]inema\b' '\b[Vv]aultwarden\b' '\b[Nn]avidrome\b' '\b[Ss]onarr\b' '\b[Rr]adarr\b' '\b[Mm]ealie\b' '[Oo]pen ?[Ww]eb ?UI' '[Ll]ite[Ll][Ll][Mm]' '\b[Ll]arder-access\b|\baccess-[Ll]arder\b|\b[Ll]arder-admin\b|\b[Ll]arder\.(dunn\.dev|othala\.test|example\.test)\b' '\b[Kk]eep-access\b|\baccess-[Kk]eep\b|\b[Kk]eep-admin\b|\b[Kk]eep\.(dunn\.dev|othala\.test|example\.test)\b' '\b[Oo]bserve-access\b|\baccess-[Oo]bserve\b|\b[Oo]bserve-admin\b|\b[Oo]bserve\.(dunn\.dev|othala\.test|example\.test)\b' '\b[Tt]une-access\b|\baccess-[Tt]une\b|\b[Tt]une-admin\b|\b[Tt]une\.(dunn\.dev|othala\.test|example\.test)\b' '\b[Vv]ault-access\b|\baccess-[Vv]ault\b|\b[Vv]ault-admin\b|\b[Vv]ault\.(dunn\.dev|othala\.test|example\.test)\b' '\b[Ff]orge-access\b|\baccess-[Ff]orge\b|\b[Ff]orge-admin\b|\b[Ff]orge\.(dunn\.dev|othala\.test|example\.test)\b' '\b[Gg]ather-access\b|\baccess-[Gg]ather\b|\b[Gg]ather-admin\b|\b[Gg]ather\.(dunn\.dev|othala\.test|example\.test)\b' '\b[Mm]emory-access\b|\baccess-[Mm]emory\b|\b[Mm]emory-admin\b|\b[Mm]emory\.(dunn\.dev|othala\.test|example\.test)\b')" \
    "$(printf '%s\n' "photos live in $(jn Imm ich)" "$(jn Jelly fin) uses the code path" "the $(jn cin ema) tile is gated" "$(jn Vault warden) issues the client" "$(jn Navi drome) streams over forward-auth" "$(jn Son arr) polls the indexer" "$(jn Rad arr) polls the same one" "$(jn Mea lie) holds the recipes" "$(jn Open ' ' WebUI) proxies the model" "$(jn Lite LLM) fronts the inference" "granted entry via access-$(jn lar der)" "the tile binds $(jn ke ep)-access for entry" "reachable once the identity holds access-$(jn ob serve)" "the manifest grants access-$(jn tu ne) to members" "the client resolves $(jn va ult)-access from the group map" "the manifest binds access-$(jn for ge) for entry" "the tile carries $(jn gat her)-access as its binding" "the identity already holds access-$(jn mem ory)")" \
    .
row "no-dunn-dev-in-e2e-manifests" 1 'dunn\.dev' '  redirect_uri: https://app.dunn.dev/callback' 'e2e/manifests/'
row "no-stale-llm-client-id" 1 'client_id: llm' 'client_id: llm' 'portal/scripts/'

# No-referenced-deprecated
row "no-deleted-commands-in-docs" 2 \
    "$(printf '%s\n' 'dag-apply-clients' 'dag-sync-manifests')" \
    "$(printf '%s\n' 'run dag-apply-clients on the host' 'run dag-sync-manifests afterwards')" \
    'DEPLOY.md hydra/README.md ARCHITECTURE.md e2e/README.md docs/runbooks/ portal/src/ portal/scripts/'
row "no-pending-cutover-section" 1 '\(pending\)' '## Cutover (pending)' 'DEPLOY.md'

# Dated-debt
row "no-intentionally-fails-comment" 1 'INTENTIONALLY FAILS' '  # INTENTIONALLY FAILS until the job is wired' '.gitlab-ci.yml'

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

# prose-budget — tracked docs capped in bytes; a build failure, not an
# intention (AGENTS.md "The prose budget"). Raising it is a deliberate edit to
# the constant, in a commit saying what grew and why — never a high-water mark
# computed live.
PROSE_CEILING_BYTES=165000
PROSE_HIGH_WATER_BYTES=504832  # size when the corpus became unmanageable; ceiling must stay under this
PROSE_GLOBS=('*.md' '*.mdx' '*.markdown')
PROSE_COVERED_TREES=(docs/ site/src/content/docs/)  # every tracked file here must be counted by the globs above
over_budget() { (( $1 > PROSE_CEILING_BYTES )); }  # own function, so the positive control below exercises real code

prose_budget() {
    local name="prose-budget" rc f i total headroom pct
    local -a missing=()
    if [[ ! "$PROSE_CEILING_BYTES" =~ ^[0-9]+$ ]] || (( PROSE_CEILING_BYTES == 0 )); then
        step_error "$name" "PROSE_CEILING_BYTES is '$PROSE_CEILING_BYTES', not a positive integer"; return
    fi
    if (( PROSE_CEILING_BYTES >= PROSE_HIGH_WATER_BYTES )); then
        step_error "$name" "PROSE_CEILING_BYTES ($PROSE_CEILING_BYTES) is at/above the historical high-water ($PROSE_HIGH_WATER_BYTES) — that permits the state this check exists to prevent"; return
    fi
    (( ${#PROSE_GLOBS[@]} > 0 )) || { step_error "$name" "PROSE_GLOBS is empty — prose would be defined as nothing"; return; }
    # Positive control, both directions: the comparator must be ABLE to fail.
    if ! over_budget $((PROSE_CEILING_BYTES + 1)); then
        step_error "$name" "over_budget() admits $((PROSE_CEILING_BYTES + 1)) bytes under a $PROSE_CEILING_BYTES ceiling — POSITIVE CONTROL FAILED"; return
    fi
    if over_budget "$PROSE_CEILING_BYTES"; then
        step_error "$name" "over_budget() rejects exactly $PROSE_CEILING_BYTES bytes — off by one against the ceiling it should admit"; return
    fi
    build_scan_set "$name" "${PROSE_GLOBS[@]}" || return
    # Coverage: every tracked doc-tree file must be one the globs above counted —
    # renaming a page out of *.md/*.mdx/*.markdown is the obvious way to dodge the budget.
    printf '%s\n' "${SCAN_FILES[@]}" >"$TMP/proseset"
    git ls-files -z -- "${PROSE_COVERED_TREES[@]}" >"$TMP/covered" 2>"$TMP/err" || { step_error "$name" "git ls-files over covered trees: $(head -1 "$TMP/err")"; return; }
    i=0
    while IFS= read -r -d '' f; do
        i=$((i+1))
        grep -qxF -- "$f" "$TMP/proseset" || missing+=("$f")
    done <"$TMP/covered"
    (( i > 0 )) || { step_error "$name" "0 tracked files under [${PROSE_COVERED_TREES[*]}] — nothing to assert coverage over"; return; }
    if (( ${#missing[@]} > 0 )); then
        step_error "$name" "${#missing[@]}/$i covered file(s) not counted as prose, e.g. ${missing[0]} — renamed to dodge the budget, or the glob needs widening; both are deliberate acts"; return
    fi
    total=$SCAN_BYTES; headroom=$((PROSE_CEILING_BYTES - total)); pct=$(( total * 100 / PROSE_CEILING_BYTES ))
    printf '      \033[2mprose = %s over the whole index (%s files)\033[0m\n' "${PROSE_GLOBS[*]}" "${#SCAN_FILES[@]}"
    printf '      \033[2mcurrent %s B / ceiling %s B (%s%%) — headroom %s B\033[0m\n' "$total" "$PROSE_CEILING_BYTES" "$pct" "$headroom"
    if over_budget "$total"; then
        step_fail "$name" "tracked prose is $total bytes, over the ceiling by $((-headroom)) — remove documentation, or raise PROSE_CEILING_BYTES in a commit that says what grew and why"
    else
        step_pass "$name" "${#SCAN_FILES[@]}" "$total"
    fi
}
prose_budget
echo ""

# Check inventory: verdicts reported must equal EXPECTED_CHECKS, so deleting a
# row (and its canaries) cannot shrink the gate and stay green.
RAN=$((PASS + FAIL))
if (( RAN != EXPECTED_CHECKS )); then
    step_error "check-inventory" "$RAN checks reported a verdict, expected $EXPECTED_CHECKS — a check was added or removed without updating EXPECTED_CHECKS"
fi

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
