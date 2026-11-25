#!/usr/bin/env bash
# The gate behind CONTRACT O12 and O13. `confine.sh DIR` checks a tree; `confine.sh --self-test` plants
# each evasion in a copy of this tree and requires the check to flag it.
set -euo pipefail

silence="testkit/src/store.rs testkit/src/fixture.rs base/tests/conformance.rs base/tests/lint_canary.rs"
mint="base/src/effect.rs testkit/src/store.rs base/tests/conformance.rs base/tests/lint_canary.rs"
read="base/src/secret.rs base/tests/lint_canary.rs"
members="base testkit"

check() (
    cd "$1"
    rs=$(find . -name target -prune -o -name '*.rs' -print | sed 's|^\./||' | sort)
    outside() { grep -vxF -f <(tr ' ' '\n' <<< "$1") || true; }
    label() { sed "s|\$|: $1|"; }
    # shellcheck disable=SC2086
    found=$(
        { grep -lE 'disallowed_method' $rs || true; } | outside "$silence" | label "names disallowed_methods outside the store modules"
        { grep -lw 'host_applied' $rs || true; } | outside "$mint" | label "names host_applied outside the store modules"
        { grep -lw 'expose' $rs || true; } | outside "$read" | label "names expose outside the modules CONTRACT.md names"
        perl -0ne 'print "$ARGV\n" if /#!?\[[^\]]*\b(allow|expect)\s*\([^\]]*(\bwarnings\b|clippy::(style|all)\b)/s' $rs |
            label "silences a lint group that holds disallowed_methods"
        for m in $members; do
            if grep -qE 'disallowed_method|^\[lints\.' "$m/Cargo.toml"; then echo "$m/Cargo.toml: overrides the workspace lints"; fi
            awk '/^\[lints\]/ { getline; ok = ($0 == "workspace = true") } END { exit !ok }' "$m/Cargo.toml" ||
                echo "$m/Cargo.toml: does not inherit the workspace lints"
        done
    )
    [ -z "$found" ] || { echo "$found"; return 1; }
)

self_test() {
    local here tmp n=0
    here=$(pwd)
    tmp=$(mktemp -d)
    trap "rm -rf '$tmp'" EXIT
    find . -name target -prune -o \( -name '*.rs' -o -name Cargo.toml \) -print | tar cf "$tmp/tree.tar" -T -
    plant() { # $1: file; $2: text appended
        rm -rf "$tmp/t" && mkdir "$tmp/t" && tar xf "$tmp/tree.tar" -C "$tmp/t"
        printf '%b\n' "$2" >> "$tmp/t/$1"
        n=$((n + 1))
        if check "$tmp/t" > /dev/null; then echo "self-test $n: $1 with a planted evasion passed"; exit 1; fi
    }
    check "$here" > /dev/null || { echo "self-test: the clean tree fails"; exit 1; }
    plant testkit/src/race.rs '#[expect(\n    clippy::disallowed_methods,\n    reason = "probe"\n)]\nfn probe() {}'
    plant testkit/src/race.rs '#![allow(\n    clippy::unwrap_used,\n    clippy::disallowed_methods\n)]'
    plant testkit/src/race.rs '#[allow(dead_code, clippy::style)]\nfn probe() {}'
    plant testkit/src/race.rs '#![cfg_attr(test, allow(\n    warnings\n))]'
    plant testkit/src/race.rs '#[allow(clippy::all)]\nfn probe() {}'
    plant testkit/src/fixture.rs 'fn m(e: &base::Effect<u8, u8>) -> base::Receipt {\n    e.host_applied()\n}'
    plant testkit/src/fixture.rs 'fn x(s: &base::Secret<4>) -> &[u8; 4] {\n    s.expose()\n}'
    plant testkit/src/store.rs 'fn x(s: &base::SecretBytes) -> usize {\n    s.expose().len()\n}'
    plant testkit/Cargo.toml '[lints.clippy]\ndisallowed_methods = "allow"'
    rm -rf "$tmp/t" && mkdir "$tmp/t" && tar xf "$tmp/tree.tar" -C "$tmp/t"
    sed -i.bak '/^\[lints\]/,$d' "$tmp/t/base/Cargo.toml"
    n=$((n + 1))
    if check "$tmp/t" > /dev/null; then echo "self-test $n: a member without workspace lints passed"; exit 1; fi
    echo "confine self-test: $n planted evasions flagged"
}

case "${1:-.}" in
    --self-test) self_test ;;
    *) check "${1:-.}" ;;
esac
