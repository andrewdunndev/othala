#!/usr/bin/env bash
# probe-check-purity.sh — mutation probe for scripts/check-purity.sh.
#
# Usage:
#   bash scripts/probe-check-purity.sh
#
# Exit 0 if every probe got the verdict it expected; exit 1 otherwise.
#
# -----------------------------------------------------------------------
# WHAT A PROBE IS HERE, AND WHY IT COMPARES TWO SCRIPTS
#
# check-purity.sh reports green. That is not evidence that it would report
# anything else. Each probe below plants ONE defect into a throwaway clone and
# asserts the gate's verdict changes in a named way — the mutation test the
# anti-vacuity contract in check-purity.sh is written against.
#
# Most probes run the mutated fixture through TWO scripts:
#
#   CANDIDATE  scripts/check-purity.sh as it stands in this worktree
#   BASELINE   scripts/check-purity.sh as of HEAD
#
# A probe that only asserts the candidate's verdict cannot tell a hole that was
# closed from a hole that was never open. Recording both verdicts makes each
# probe state a delta: what the gate used to say about this defect, and what it
# says now.
#
# THE BASELINE IS RECORDED, AND ONLY SOMETIMES ASSERTED. This is the one thing
# about the two-script design that has to be got right, and getting it wrong
# turns the suite into a landmine that arms itself on commit. The delta only
# exists while the worktree differs from HEAD. The moment this work is
# committed — which is the state CI always runs in — the baseline IS the
# candidate, every "baseline said PASS, candidate says ERROR" expectation
# becomes false by construction, and a suite full of them goes red on a tree
# where nothing is wrong. So the candidate expectation is always asserted; the
# baseline expectation is asserted only when the two scripts actually differ,
# and is otherwise printed as context with the equality called out. `cmp` at
# startup decides which world we are in.
#
# THE FIXTURE IS BUILT FROM THE GIT INDEX, NOT FROM HEAD. That is the
# difference between a pre-commit gate and a post-commit one.
#
# check-purity.sh is defined over the index — the file list AND the bytes — so
# a fixture cloned from HEAD probes a corpus the gate does not speak for. While
# a large change is staged and uncommitted, a HEAD fixture is the tree as it was
# BEFORE that change: every probe reports on a corpus nobody is about to commit,
# and the suite is useless in precisely the moment it is wanted. Committing
# first does not rescue it, because "commit and see" is what a gate replaces.
#
# So `git checkout-index` materialises the index into a temp dir, a throwaway
# repo is initialised over it and committed once, and `git reset --hard HEAD`
# inside the fixture restores THE INDEX. The parent repo is never written to —
# no ref, object, index or worktree file — because probes stage violations and
# empty files, which must never happen to a real tree.
#
# The two SCRIPTS are the exception, copied in from the worktree and staged in
# the fixture: the corpus under test is what a commit would contain, the gate
# under test is the one you just edited. A startup notice flags that gap.
#
# VIOLATING STRINGS ARE ASSEMBLED AT RUNTIME, never written as literals. This
# file is tracked, so the whole-tree purity checks scan it; a probe that spelled
# out the name it plants would be caught by the check it is probing. jn() below
# is the same device check-purity.sh uses for its own canaries.
# -----------------------------------------------------------------------

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || exit 1

# Hard dependencies, asserted up front, and deliberately the same set the gate
# itself needs: git plus the POSIX text tools.
#
# An earlier revision rewrote fixture files with perl, because BSD and GNU sed
# disagree about `-i`. That put an interpreter nobody had confirmed into a CI
# job on a Node base image — a missing perl there is a red pipeline on the
# first push after merge. The disagreement is only about `-i`, so the fix is to
# stop editing in place, not to change tools: rewrite() below runs sed to a
# temp file and copies it back, portable to both, and gen_bytes() builds its
# payload in bash rather than shelling out at all.
#
# A missing dependency must stop the harness loudly and non-zero: a probe suite
# that quietly skips itself is precisely the vacuity it exists to catch.
for dep in git sed grep cmp; do
    command -v "$dep" >/dev/null 2>&1 || {
        printf 'FATAL: probe harness requires `%s`, which is not on PATH — refusing to report on probes that did not run.\n' \
            "$dep" >&2
        exit 1
    }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FIX="$TMP/fixture"
PROBES=0; MISMATCHES=0; MISMATCH_NAMES=()

# jn <fragment>... — joins with no separator. See the header: every banned name
# this harness plants is spelled in fragments and rejoined here, because this
# file is inside the corpus the whole-tree checks scan.
jn() { local IFS=''; printf '%s' "$*"; }

printf '=== probe-check-purity ===\n\n'

# --- the fixture, materialised from the index -------------------------
# See the header. `git checkout-index -a --prefix=` writes exactly the indexed
# paths, at their indexed modes, into an empty directory; the throwaway repo is
# then initialised over it (with an empty template, so no user hook or config
# from the developer's machine can perturb a probe) and committed once, so the
# fixture's HEAD *is* the parent's index.
mkdir -p "$FIX" "$TMP/empty-template" || exit 1
git checkout-index -a -f --prefix="$FIX/" || {
    echo "could not materialise the index into the fixture"; exit 1; }
git -c init.defaultBranch=main init -q --template="$TMP/empty-template" "$FIX" || {
    echo "could not init the fixture repo"; exit 1; }
# -f so that a .gitignore inside the tree cannot drop a file the parent's index
# tracks: the fixture must be the index, not a filtered view of it.
git -C "$FIX" add -A -f . || { echo "could not stage the fixture"; exit 1; }
git -C "$FIX" -c user.name=probe -c user.email=probe@invalid \
    -c commit.gpgsign=false commit -q --no-verify \
    -m 'fixture: the git index of the repo under probe' || {
    echo "could not commit the fixture"; exit 1; }

# The fixture is the index, asserted rather than assumed. A silently partial
# materialisation would leave every probe below reporting on a corpus smaller
# than the one being committed — the narrowness vacuity, one level up.
if [ "$(git ls-files | git hash-object --stdin)" != "$(git -C "$FIX" ls-files | git hash-object --stdin)" ]; then
    printf 'FATAL: the fixture file list differs from the index it was built from — the probes\n' >&2
    printf '       would be reporting on a corpus that is not the one about to be committed.\n' >&2
    exit 1
fi

git show HEAD:scripts/check-purity.sh >"$TMP/baseline.sh" || {
    echo "could not extract the HEAD baseline"; exit 1; }

# The gate under test comes from the worktree, the corpus from the index. When
# the two disagree about the gate itself, say so: running the staged gate while
# the author is reading their unstaged edits is the kind of quiet mismatch this
# whole suite exists to refuse.
for s in check-purity probe-check-purity; do
    if [ "$(git show ":scripts/$s.sh" 2>/dev/null | git hash-object --stdin)" != "$(git hash-object "$REPO_ROOT/scripts/$s.sh")" ]; then
        printf '  \033[33mscripts/%s.sh is not staged as it stands in the worktree.\033[0m\n' "$s"
        printf '      The fixture CORPUS is the index; the SCRIPTS are copied in from the worktree,\n'
        printf '      so this run probes your unstaged edits against the staged tree.\n\n'
    fi
done

# Is there a delta to assert at all? See the header. When the worktree copy of
# the gate is byte-identical to HEAD's — every CI run, and every local run on a
# clean tree — the "baseline" column is the same script answering the same
# question, so the baseline expectations are recorded rather than asserted.
BASELINE_IS_CANDIDATE=0
if [ "$(git hash-object "$REPO_ROOT/scripts/check-purity.sh")" = "$(git hash-object "$TMP/baseline.sh")" ]; then
    BASELINE_IS_CANDIDATE=1
    printf '  \033[33mbaseline == candidate\033[0m — the worktree gate is byte-identical to HEAD.\n'
    printf '      Baseline verdicts are printed for context and NOT asserted; there is no delta\n'
    printf '      to measure against a script that is the same script. Candidate expectations,\n'
    printf '      which are the actual claims, are asserted as always.\n\n'
fi

# reset_fixture: fixture back to a pristine checkout of the index (which is
# what the fixture's HEAD holds), then re-install both scripts. `git reset
# --hard` would otherwise restore the indexed copy of check-purity.sh over the
# candidate, and `git clean -fd` would delete the baseline, so both are
# re-installed after every reset rather than once.
#
# The baseline is written into scripts/ and left untracked. Both scripts derive
# their corpus from the index, so an untracked file in scripts/ is in neither
# one's scan set and cannot perturb a probe.
# The candidate is also STAGED, not merely written to the worktree. The
# whole-tree purity checks scan the index, and this file is in it; leaving the
# fixture's own copy of the gate staged would mean every probe ran against a
# corpus containing a different version of the very script under test. Staging
# it makes the corpus and the script agree.
reset_fixture() {
    git -C "$FIX" reset --hard -q HEAD || return 1
    git -C "$FIX" clean -fdq || return 1
    cp "$REPO_ROOT/scripts/check-purity.sh" "$FIX/scripts/check-purity.sh" || return 1
    git -C "$FIX" add -- scripts/check-purity.sh || return 1
    cp "$REPO_ROOT/scripts/probe-check-purity.sh" "$FIX/scripts/probe-check-purity.sh" || return 1
    git -C "$FIX" add -- scripts/probe-check-purity.sh || return 1
    cp "$TMP/baseline.sh" "$FIX/scripts/baseline-purity.sh" || return 1
}

# ---------------------------------------------------------------------
# rewrite <file> <sed-expr>...   — apply sed to a file in place.
# strip_lines <file> <ere>       — delete every line matching <ere>, in place.
# gen_bytes <n>                  — emit n bytes on stdout.
#
# The three mutations this harness makes, using only what the gate already
# depends on. sed is never given `-i` — BSD wants an argument to it and GNU does
# not, which is the whole of the portability problem — so these write to a temp
# file and copy back, which works on both.
#
# strip_lines refuses to remove nothing: a mutation probe whose mutation did not
# apply asserts the gate's behaviour on an UNMUTATED fixture and passes for the
# wrong reason, which is the vacuity this suite is written against.
# ---------------------------------------------------------------------
rewrite() {
    local f="$1"; shift
    sed "$@" "$f" >"$TMP/rewrite" || return 1
    cat "$TMP/rewrite" >"$f"
}
strip_lines() {
    local f="$1" re="$2" n
    n=$(grep -cE -e "$re" "$f")
    if (( n == 0 )); then
        printf 'FATAL: mutation matched no line in %s (/%s/) — the probe would test an unmutated fixture.\n' \
            "$f" "$re" >&2
        exit 1
    fi
    grep -vE -e "$re" "$f" >"$TMP/rewrite"
    cat "$TMP/rewrite" >"$f"
}
gen_bytes() {
    local s
    printf -v s '%*s' "$1" ''
    printf '%s' "${s// /x}"
}

# NOTHING NORMALISES THE FIXTURE, which is now a property of the tree rather
# than an omission. An earlier revision stripped pre-existing line-number pins
# out of the clone, because HEAD carried pins the vendored-citation check fails
# on and a fixture already failing a check cannot host a probe for it. The index
# carries none. If they come back, the pristine-fixture banner reports them and
# the probes aimed at that check mismatch — the honest outcome, and better than
# a harness quietly editing the corpus it is measuring.

# run_gate <candidate|baseline> — runs one gate over the fixture as it stands
# and leaves its output in $TMP/<which>.log. Echoes the exit status.
run_gate() {
    local which="$1" script rc
    case "$which" in
        candidate) script="$FIX/scripts/check-purity.sh" ;;
        baseline)  script="$FIX/scripts/baseline-purity.sh" ;;
    esac
    bash "$script" >"$TMP/$which.log" 2>&1
    rc=$?
    printf '%s' "$rc"
}

# verdict_of <log> <check-name> — the one word the gate said about that check.
#
# Read from the "Failed:" list rather than the per-check line, because that list
# is where the gate distinguishes a content verdict from a vacuity verdict:
# step_error appends "[VACUOUS/ERROR: ...]" to the name and step_fail does not.
# ERROR and FAIL are deliberately NOT collapsed — "the check ran and found a
# violation" and "the check could not run honestly" are different claims, and a
# probe that accepted either would not notice one turning into the other.
verdict_of() {
    local log="$1" check="$2"
    if grep -qF -- "  - $check [VACUOUS/ERROR" "$log"; then
        printf 'ERROR'
    elif grep -qxF -- "  - $check" "$log"; then
        printf 'FAIL'
    elif grep -qF -- " $check " "$log"; then
        printf 'PASS'
    else
        printf 'ABSENT'
    fi
}

# probe <name> <check> <expected-candidate-verdict> <expected-baseline-verdict>
#       <expected-candidate-exit> <required-substring-in-candidate-log>
#
# The mutation is applied by the caller before this runs. The required
# substring pins WHY the candidate reached its verdict: a check that errored
# for an unrelated reason would otherwise satisfy an expectation of ERROR and
# the probe would certify a hole it never closed.
probe() {
    local name="$1" check="$2" want_c="$3" want_b="$4" want_exit="$5" want_msg="$6"
    local rc_c got_c got_b bad=""

    PROBES=$((PROBES+1))
    rc_c=$(run_gate candidate)
    # The baseline is run for its LOG, not its exit status: only the candidate's
    # exit is a claim this suite makes.
    run_gate baseline >/dev/null
    got_c=$(verdict_of "$TMP/candidate.log" "$check")
    got_b=$(verdict_of "$TMP/baseline.log" "$check")

    [[ "$got_c" == "$want_c" ]] || bad="${bad}${bad:+; }candidate said $got_c for $check, expected $want_c"
    # See the header: the baseline expectation is a claim about a DELTA, and a
    # delta only exists while the two scripts differ.
    if (( BASELINE_IS_CANDIDATE == 0 )); then
        [[ "$got_b" == "$want_b" ]] || bad="${bad}${bad:+; }baseline said $got_b for $check, expected $want_b"
    fi
    [[ "$rc_c" == "$want_exit" ]] || bad="${bad}${bad:+; }candidate exited $rc_c, expected $want_exit"
    if [[ -n "$want_msg" ]] && ! grep -qF -- "$want_msg" "$TMP/candidate.log"; then
        bad="${bad}${bad:+; }candidate log does not contain the expected reason: $want_msg"
    fi

    if [[ -z "$bad" ]]; then
        printf '  \033[32m✓\033[0m %s\n      candidate: %s   baseline: %s\n' "$name" "$got_c" "$got_b"
    else
        MISMATCHES=$((MISMATCHES+1))
        MISMATCH_NAMES+=("$name")
        printf '  \033[31m✗\033[0m %s\n      %s\n' "$name" "$bad"
    fi
}

# =====================================================================
# NOTE ON THE PROBE TARGET FILE. Several probes below need one tracked file
# in one check's scan set to empty, delete or make unreadable. That was
# site/src/content/docs/guides/family-help.md, which the convergence deleted
# along with the single-file check that scanned it. DEPLOY.md replaces it:
# no-pending-cutover-section scans exactly that one file, which is the
# property these probes need — a one-file corpus makes "the corpus went
# empty" and "the corpus is clean" impossible to confuse.
# =====================================================================

# =====================================================================
# P0 — control. An unmutated fixture must be clean under both scripts,
# so every later verdict is attributable to the mutation and not to the
# fixture.
# =====================================================================
reset_fixture || exit 1
run_gate candidate >/dev/null
cp "$TMP/candidate.log" "$TMP/pristine.log"
if grep -q '^Failed:' "$TMP/pristine.log"; then
    printf '  \033[33mPRISTINE FIXTURE IS NOT CLEAN\033[0m — the gate already reports these on an unmutated clone:\n'
    sed -n '/^Failed:/,$p' "$TMP/pristine.log" | sed '1d;s/^/      /'
    printf '      Every probe below plants ONE defect and attributes the verdict change to it.\n'
    printf '      A check that is already failing cannot host that attribution, so the probes\n'
    printf '      aimed at it will mismatch. Fix the tree; the probes are reporting honestly.\n\n'
fi

probe "control: pristine fixture is clean" \
    "no-pending-cutover-section" PASS PASS 0 ""

# =====================================================================
# HOLE 1 — a corpus of files that exist and hold nothing.
#
# P1 empties a scanned file in BOTH the index and the worktree. The scan set
# still resolves to one present, readable file, so a check that asserts
# presence has nothing to complain about and reports "1 files scanned" over
# zero bytes.
# =====================================================================
reset_fixture || exit 1
: >"$FIX/DEPLOY.md"
git -C "$FIX" add DEPLOY.md
probe "hole 1: scanned file emptied in index and worktree" \
    "no-pending-cutover-section" ERROR PASS 1 "ZERO BYTES"

# =====================================================================
# P2 empties the file in the INDEX ONLY — the worktree copy keeps its bytes.
# This is both holes at once: the corpus CI would check out is empty, while a
# worktree read still finds a full file to scan and reports clean on content
# that is not what is staged.
#
# `git update-index --cacheinfo` against the empty blob mutates the index
# without touching the worktree, which `git add` cannot do.
# =====================================================================
reset_fixture || exit 1
EMPTY_BLOB=$(printf '' | git -C "$FIX" hash-object -w --stdin)
git -C "$FIX" update-index --cacheinfo "100644,$EMPTY_BLOB,DEPLOY.md"
probe "hole 1+2: scanned file emptied in the index only, worktree untouched" \
    "no-pending-cutover-section" ERROR PASS 1 "ZERO BYTES"

# =====================================================================
# HOLE 2 — the index/worktree split.
#
# P3 stages a real violation and then restores the worktree copy. The file
# list comes from the index and names DEPLOY.md; the bytes CI will check out
# carry "(pending)"; a worktree read sees the clean copy and reports PASS on
# a violation that is already staged for commit.
# =====================================================================
reset_fixture || exit 1
cp "$FIX/DEPLOY.md" "$TMP/DEPLOY.clean"
printf '\n## Cutover (pending)\n' >>"$FIX/DEPLOY.md"
git -C "$FIX" add DEPLOY.md
cp "$TMP/DEPLOY.clean" "$FIX/DEPLOY.md"
probe "hole 2: violation staged, worktree clean" \
    "no-pending-cutover-section" FAIL PASS 1 "Cutover (pending)"

# =====================================================================
# P4 — the converse, recorded rather than asserted silently.
#
# A violation written to the worktree and NOT staged is not in the corpus this
# gate is defined over. Both the file list and the bytes now come from the
# index, which is what CI checks out and what a tag will carry; unstaged text
# is in neither. Staging it — the only way it can reach CI — is P3, which is
# caught. The baseline caught this case by reading the worktree, and that is
# the same read that made P3 invisible: the two cannot both be had from one
# corpus, and the corpus that CI executes is the one the gate speaks for.
# =====================================================================
reset_fixture || exit 1
printf '\n## Cutover (pending)\n' >>"$FIX/DEPLOY.md"
probe "boundary: violation in worktree only, never staged (gate speaks for the index)" \
    "no-pending-cutover-section" PASS FAIL 0 ""

# =====================================================================
# P5 — the pre-existing index/worktree assertion, which P3's fix must not
# have displaced: a file in the index and absent from the worktree is still
# an ERROR, not a check that quietly scans one file fewer.
# =====================================================================
reset_fixture || exit 1
rm "$FIX/DEPLOY.md"
probe "regression: indexed file deleted from worktree still ERRORs" \
    "no-pending-cutover-section" ERROR ERROR 1 "absent from the worktree"

# =====================================================================
# P6 — the branch/canary pairing, spot-checked from outside, in the two ways
# it can be broken. The check it is aimed at is no-instance-names, the widest
# of the whole-tree checks.
#
# P6a deletes a CANARY only. The pairing goes uneven, and the gate must not
# merely notice the count — it must name the branch that no surviving canary
# fires, because "one canary went missing" is only actionable as "this branch
# is now unproven".
#
# P6b deletes a branch AND its canary together, which leaves the pairing
# internally consistent and invisible to everything except the
# expected-branch-count argument at the call site. This is the failure the
# whole index-pairing design exists for, and widening the gate must not have
# loosened it.
#
# Both mutations are applied by line-matching on the fragments the names are
# assembled from, which is why check-purity.sh writes one branch per line.
# =====================================================================
reset_fixture || exit 1
strip_lines "$FIX/scripts/check-purity.sh" 'jn no rn'
git -C "$FIX" add -- scripts/check-purity.sh
probe "regression: a deleted canary names the branch it left unproven" \
    "no-instance-names" ERROR ABSENT 1 "NO canary now fires branch"

reset_fixture || exit 1
strip_lines "$FIX/scripts/check-purity.sh" 'jn no rn|\[Nn\]orn'
git -C "$FIX" add -- scripts/check-purity.sh
probe "regression: a deleted branch still trips the expected-branch-count" \
    "no-instance-names" ERROR ABSENT 1 "expected 10"

# =====================================================================
# P7 — the unreadable-target assertion, which reading the index could
# plausibly have neutralised: grep now reads a scratch copy checked out at the
# index's own mode, so a `chmod 000` on the worktree file no longer reaches it.
# The readability assertion must therefore still be made against the worktree,
# and must still be an ERROR rather than a check that scans a readable copy of
# a file nobody can open.
# =====================================================================
reset_fixture || exit 1
chmod 000 "$FIX/DEPLOY.md"
probe "regression: unreadable worktree target still ERRORs" \
    "no-pending-cutover-section" ERROR ERROR 1 "unreadable"
chmod 644 "$FIX/DEPLOY.md"

# =====================================================================
# CHECK 13 — line-number pins into the byte-vendored files.
#
# The three probes a new check owes: it fires on the violation, it does NOT
# fire on the sanctioned form, and it cannot report clean over nothing. The
# baseline says ABSENT to all three, which is the delta being recorded: this
# constraint had no enforcer at HEAD, which is why it kept coming back.
#
# The violating string is assembled from fragments at runtime, never written
# out: this file is tracked, so a literal pin here would be caught by the very
# check it probes.
# =====================================================================
V_PATH="kratos/kratos"; V_EXT=".yml"; V_SEP=":"
PIN="${V_PATH}${V_EXT}${V_SEP}264-272"

# P8 — the positive case. A pin planted in a tracked, staged file must FAIL,
# and the required substring is the pin itself, so a failure for any other
# reason cannot satisfy this probe.
reset_fixture || exit 1
printf '\nThe session block is at `%s` in the vendored config.\n' "$PIN" >>"$FIX/DEPLOY.md"
git -C "$FIX" add DEPLOY.md
probe "check 13: a line-number pin into a vendored file FAILS" \
    "no-line-pins-into-vendored-files" FAIL ABSENT 1 "$PIN"

# P9 — the negative case, which is what stops the check from being a blanket
# ban on naming the file at all. The same sentence with the number dropped —
# the pointer form the estate rule asks for — must PASS, and the whole gate
# must exit 0, so this also re-confirms the check adds no false positive to the
# twelve that were already green.
reset_fixture || exit 1
printf '\nThe session block is in `%s%s`, key `session.whoami.required_aal`.\n' \
    "$V_PATH" "$V_EXT" >>"$FIX/DEPLOY.md"
git -C "$FIX" add DEPLOY.md
probe "check 13: the de-pinned pointer form PASSES" \
    "no-line-pins-into-vendored-files" PASS ABSENT 0 ""

# P10 — vacuity. The check's corpus is the whole index; emptying the index
# leaves it with nothing to read, and nothing-scanned must be an ERROR rather
# than the PASS an exit-status verdict would have produced. `--cached` empties
# the index only, so the worktree still holds every file a walk would have
# found — which is the point: the gate speaks for the index, and the index is
# empty.
reset_fixture || exit 1
git -C "$FIX" rm -r -q --cached . >/dev/null 2>&1
probe "check 13: an empty corpus ERRORs, never passes" \
    "no-line-pins-into-vendored-files" ERROR ABSENT 1 "scan set is EMPTY"

# =====================================================================
# THE WHOLE-TREE CHECKS — one probe per branch, planted on a real surface.
#
# assert_fires already proves, on every gate run, that each branch fires on its
# own canary and no other. That is a proof about STRINGS. What it cannot prove
# is that the branch reaches a FILE: a branch can be perfect and its check
# still blind, which is exactly the defect these three checks were added to
# fix — the old purity family greped five paths and reported ALL 12 CHECKS
# PASSED over an instance name in .gitlab-ci.yml and application names in
# DEPLOY.md, a runbook and two published diagrams.
#
# So each branch gets a probe that plants its violation in a real tracked file,
# and the plant targets CYCLE across the surfaces nothing used to scan —
# ARCHITECTURE.md, AGENTS.md, README.md, .gitlab-ci.yml, e2e/, caddy/,
# portal/src/ — so the branch proof and the reach proof are the same probe.
#
# These run the candidate only. The baseline column is a delta and there is no
# delta to state here: at HEAD these checks do not exist, so the baseline says
# ABSENT to all of them, which the check-13 probes above already record once.
# Running it 23 more times to hear the same word costs half the suite's wall
# clock and says nothing.
# =====================================================================

# probe_branch <label> <check> <violation> <target> <line-prefix>
#
# Plants ONE violating line in ONE tracked file, stages it, and asserts the
# named check FAILS with that exact string in its output. The required
# substring is the violation itself: a check that failed for some other reason
# — a pre-existing leak, a broken corpus — does not satisfy this probe, which
# is what makes it a proof about this branch rather than about this check.
probe_branch() {
    local label="$1" check="$2" violation="$3" target="$4" prefix="$5"
    local rc_c got_c bad=""

    PROBES=$((PROBES+1))
    reset_fixture || { echo "could not reset fixture"; exit 1; }
    printf '%s%s\n' "$prefix" "$violation" >>"$FIX/$target"
    git -C "$FIX" add -- "$target" || { echo "could not stage $target"; exit 1; }

    rc_c=$(run_gate candidate)
    got_c=$(verdict_of "$TMP/candidate.log" "$check")

    [[ "$got_c" == "FAIL" ]] || bad="candidate said $got_c for $check, expected FAIL"
    [[ "$rc_c" == "1" ]] || bad="${bad}${bad:+; }candidate exited $rc_c, expected 1"
    if ! grep -qF -- "$violation" "$TMP/candidate.log"; then
        bad="${bad}${bad:+; }the gate did not report the planted string, so its FAIL is not attributable to this branch"
    fi

    if [[ -z "$bad" ]]; then
        printf '  \033[32m✓\033[0m %s \033[2m(planted in %s)\033[0m\n' "$label" "$target"
    else
        MISMATCHES=$((MISMATCHES+1))
        MISMATCH_NAMES+=("$label")
        printf '  \033[31m✗\033[0m %s\n      %s\n' "$label" "$bad"
    fi
}

# A probe_no_fire() stood here — the negative half of a boundary rule, asserting
# a branch does NOT fire on innocent text. Its one caller was a branch for the
# public portal's own three-letter name, whose boundary was hand-chosen rather
# than `\b` and so needed both halves proven. That branch is gone (see
# check-purity.sh: the portal is what this project publishes, not a private
# host), and every surviving branch is a long name fenced by `\b` on both sides.
# Restore the helper alongside the next branch whose boundary must be argued
# for, not before.

printf '\n  \033[1mno-instance-names — ten branches, ten surfaces\033[0m\n'
probe_branch "instance branch 1 reaches ARCHITECTURE.md" "no-instance-names" \
    "reboot $(jn lode stone) after the upgrade" ARCHITECTURE.md ""
probe_branch "instance branch 2 reaches AGENTS.md" "no-instance-names" \
    "the retired $(jn car mine) host" AGENTS.md ""
probe_branch "instance branch 3 reaches README.md" "no-instance-names" \
    "deployed to $(jn cor bel) last week" README.md ""
probe_branch "instance branch 4 reaches .gitlab-ci.yml" "no-instance-names" \
    "$(jn crim son) holds the replica" .gitlab-ci.yml "# "
probe_branch "instance branch 5 reaches e2e/compose.yml" "no-instance-names" \
    "rsync from $(jn sto rr) nightly" e2e/compose.yml "# "
probe_branch "instance branch 6 reaches caddy/snippets/oidc-app.caddy" "no-instance-names" \
    "the $(jn oak timbers) box is the spare" caddy/snippets/oidc-app.caddy "# "
probe_branch "instance branch 7 reaches portal/src/lib/gate.ts" "no-instance-names" \
    "$(jn ty r) runs the QEMU executor" portal/src/lib/gate.ts "// "
probe_branch "instance branch 8 reaches e2e/README.md" "no-instance-names" \
    "the $(jn an vil) runner is tagged" e2e/README.md ""
probe_branch "instance branch 9 reaches caddy/README.md" "no-instance-names" \
    "$(jn cru cible) builds the images" caddy/README.md ""
probe_branch "instance branch 10 reaches the Makefile" "no-instance-names" \
    "$(jn no rn) serves the metrics" Makefile "# "

printf '\n  \033[1mno-personal-names — three branches, three surfaces\033[0m\n'
probe_branch "personal branch 1 reaches .gitlab-ci.yml" "no-personal-names" \
    "reviewed by $(jn And rew) before merge" .gitlab-ci.yml "# "
probe_branch "personal branch 2 reaches ARCHITECTURE.md" "no-personal-names" \
    "$(jn Ash ley) approved the change" ARCHITECTURE.md ""
probe_branch "personal branch 3 reaches e2e/validate.sh" "no-personal-names" \
    "ssh $(jn agd '@' bastion)" e2e/validate.sh "# "

printf '\n  \033[1mno-private-stack-apps — ten branches, ten surfaces\033[0m\n'
probe_branch "app branch 1 reaches README.md" "no-private-stack-apps" \
    "photos live in $(jn Imm ich)" README.md ""
probe_branch "app branch 2 reaches caddy/snippets/ldap-app.caddy" "no-private-stack-apps" \
    "$(jn Jelly fin) uses the LDAP path" caddy/snippets/ldap-app.caddy "# "
probe_branch "app branch 3 reaches site content" "no-private-stack-apps" \
    "the $(jn cin ema) tile is gated" site/src/content/docs/guides/hardening.md ""
probe_branch "app branch 4 reaches caddy/snippets/oidc-app.caddy" "no-private-stack-apps" \
    "$(jn Vault warden) issues the client" caddy/snippets/oidc-app.caddy "# "
probe_branch "app branch 5 reaches caddy/snippets/forward-auth.caddy" "no-private-stack-apps" \
    "$(jn Navi drome) streams over forward-auth" caddy/snippets/forward-auth.caddy "# "
probe_branch "app branch 6 reaches AGENTS.md" "no-private-stack-apps" \
    "$(jn Son arr) polls the indexer" AGENTS.md ""
probe_branch "app branch 7 reaches DEPLOY.md" "no-private-stack-apps" \
    "$(jn Rad arr) polls the same one" DEPLOY.md ""
probe_branch "app branch 8 reaches e2e/manifests/grafana.md" "no-private-stack-apps" \
    "$(jn Mea lie) holds the recipes" e2e/manifests/grafana.md ""
probe_branch "app branch 9 reaches .gitlab-ci.yml" "no-private-stack-apps" \
    "$(jn Open ' ' WebUI) proxies the model" .gitlab-ci.yml "# "
probe_branch "app branch 10 reaches hydra/README.md" "no-private-stack-apps" \
    "$(jn Lite LLM) fronts the inference" hydra/README.md ""

# =====================================================================
# THE LICENSE EXEMPTION — the one path this gate exempts, probed on both
# sides. An exemption that is never exercised is indistinguishable from a
# hole nobody has walked through yet.
# =====================================================================
printf '\n  \033[1mthe LICENSE exemption is real, and bounded\033[0m\n'

# The exemption works: a copyright notice may name its holder, and the gate
# must stay green over it — otherwise the rule is unshippable, since a repo
# with no copyright holder is not a licensed repo.
reset_fixture || exit 1
printf 'Copyright (c) 2026 %s Example\n' "$(jn And rew)" >>"$FIX/LICENSE"
git -C "$FIX" add LICENSE
probe "LICENSE: a personal name on a copyright line PASSES" \
    "no-personal-names" PASS ABSENT 0 ""

# And it is bounded: the exempted path is exempt for the copyright notice and
# nothing else, so prose smuggled into it is an ERROR rather than a quiet pass.
reset_fixture || exit 1
printf 'Reviewed by %s before merge\n' "$(jn And rew)" >>"$FIX/LICENSE"
git -C "$FIX" add LICENSE
probe "LICENSE: a personal name OFF a copyright line ERRORs" \
    "no-personal-names" ERROR ABSENT 1 "off a copyright line"

# =====================================================================
# THE PROSE BUDGET.
#
# A byte ceiling has a different vacuity surface from a pattern check, so it
# gets its own probes rather than borrowing the pattern ones:
#
#   * it must FAIL when the corpus grows past the ceiling (it fires at all);
#   * it must PASS at exactly the ceiling (it is not off by one, so "the
#     budget is full" and "the budget is blown" stay distinguishable);
#   * it must ERROR when a counted file is renamed out of the definition
#     (the obvious dodge, which would otherwise read as the corpus shrinking);
#   * it must ERROR over an empty corpus (nothing-counted is never under
#     budget);
#   * it must ERROR if the ceiling is raised past the size that made the rule
#     necessary (the slow dodge);
#   * it must ERROR if the comparison itself stops being able to fail.
#
# The growth probes take the ceiling and the current total from the gate's own
# printed line rather than restating the constant here — a probe carrying its
# own copy of the number it is testing proves the copy, not the number.
# =====================================================================
printf '\n  \033[1mprose budget\033[0m\n'

reset_fixture || exit 1
run_gate candidate >/dev/null
PROSE_LINE=$(grep -F 'headroom' "$TMP/candidate.log" | head -1)
PROSE_HEADROOM=$(printf '%s' "$PROSE_LINE" | grep -oE 'headroom -?[0-9]+ B' | grep -oE '\-?[0-9]+')
if [[ ! "$PROSE_HEADROOM" =~ ^-?[0-9]+$ ]]; then
    printf 'FATAL: could not read the headroom from the gate output — the budget probes below\n' >&2
    printf '       would be testing a number they invented. Line was: %s\n' "${PROSE_LINE:-<none>}" >&2
    exit 1
fi
# A corpus already over the ceiling cannot host these probes: both grow the
# fixture BY the headroom, and there is no such thing as growing a file by a
# negative number of bytes. Say that, in the terms the operator has to act on.
# (The previous revision passed the negative straight to a generator, which read
# it as a command-line switch and died with a parser error — a real failure
# reported as a syntax error is a failure nobody fixes.)
if (( PROSE_HEADROOM < 0 )); then
    printf 'FATAL: the prose corpus in the index is already %s bytes OVER the ceiling.\n' \
        "$(( -PROSE_HEADROOM ))" >&2
    printf '       The budget probes grow the fixture BY the headroom, which cannot be done with\n' >&2
    printf '       a negative one. Bring the corpus under the ceiling — or raise the ceiling on\n' >&2
    printf '       purpose, in a commit that says what grew — and re-run. The gate itself already\n' >&2
    printf '       reports this as a prose-budget FAIL; this harness cannot probe past it.\n' >&2
    exit 1
fi
printf '      \033[2mheadroom on the unmutated fixture: %s bytes\033[0m\n' "$PROSE_HEADROOM"

# Growth past the ceiling FAILS. One byte past, so the probe proves the
# boundary and not merely that a very large file is noticed.
reset_fixture || exit 1
gen_bytes "$((PROSE_HEADROOM + 1))" >>"$FIX/README.md"
git -C "$FIX" add README.md
probe "prose budget: one byte over the ceiling FAILS" \
    "prose-budget" FAIL ABSENT 1 "over the"

# Growth to exactly the ceiling PASSES. Without this the check could be a
# strict-greater/greater-or-equal muddle and nothing would say so.
reset_fixture || exit 1
gen_bytes "$PROSE_HEADROOM" >>"$FIX/README.md"
git -C "$FIX" add README.md
probe "prose budget: exactly at the ceiling PASSES" \
    "prose-budget" PASS ABSENT 0 ""

# Renaming a doc-tree page out of the counted extensions is the obvious way to
# make the corpus look smaller than it is. The coverage assertion must call it
# out by name rather than record a shrink.
reset_fixture || exit 1
git -C "$FIX" mv docs/runbooks/lost-device.md docs/runbooks/lost-device.txt
probe "prose budget: a doc-tree file renamed out of the definition ERRORs" \
    "prose-budget" ERROR ABSENT 1 "NOT counted as prose"

# Nothing counted is not under budget.
reset_fixture || exit 1
git -C "$FIX" rm -r -q --cached -- '*.md' >/dev/null 2>&1
probe "prose budget: an empty prose corpus ERRORs, never passes" \
    "prose-budget" ERROR ABSENT 1 "scan set is EMPTY"

# The ceiling cannot be raised back to the size that made the rule necessary.
reset_fixture || exit 1
rewrite "$FIX/scripts/check-purity.sh" \
    -e 's/^PROSE_CEILING_BYTES=[0-9]*/PROSE_CEILING_BYTES=600000/'
git -C "$FIX" add -- scripts/check-purity.sh
probe "prose budget: a ceiling above the historical high-water ERRORs" \
    "prose-budget" ERROR ABSENT 1 "became unmanageable"

# The comparison itself must be able to fail. This is the budget's canary: a
# comparator wired to "under" scans a real corpus, reports a real byte count,
# and is green forever.
reset_fixture || exit 1
rewrite "$FIX/scripts/check-purity.sh" \
    -e 's/^over_budget().*$/over_budget() { false; }/'
git -C "$FIX" add -- scripts/check-purity.sh
probe "prose budget: a comparison that cannot fail ERRORs" \
    "prose-budget" ERROR ABSENT 1 "POSITIVE CONTROL FAILED"

# =====================================================================
# Summary
# =====================================================================
printf '\n'
if (( MISMATCHES == 0 )); then
    printf '\033[32mALL %d PROBES MATCHED — the gate fails the way it claims to.\033[0m\n' "$PROBES"
    exit 0
else
    printf '\033[31m%d/%d PROBES MISMATCHED\033[0m\n\n' "$MISMATCHES" "$PROBES"
    for s in "${MISMATCH_NAMES[@]}"; do
        echo "  - $s"
    done
    exit 1
fi
