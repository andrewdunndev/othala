#!/usr/bin/env bash
# The gate behind CONTRACT O12, O13 and R10. `confine.sh DIR` checks a tree; `confine.sh --self-test` plants
# each evasion in a copy of this tree and requires the check to flag it; `confine.sh --canary` proves each
# clippy.toml path is an error at the workspace lint level, with the canary's expects removed.
set -euo pipefail

silence="testkit/src/store.rs testkit/src/fixture.rs base/tests/conformance.rs base/tests/lint_canary.rs"
mint="base/src/effect.rs testkit/src/store.rs base/tests/conformance.rs base/tests/lint_canary.rs"
read="base/src/secret.rs base/tests/lint_canary.rs"
# dev-only members: their src may expect a deny-list lint with a reason
harness="testkit"
denied="unsafe_code missing_docs unreachable_pub clippy::unwrap_used clippy::expect_used clippy::panic clippy::indexing_slicing
    clippy::as_conversions clippy::print_stdout clippy::dbg_macro clippy::disallowed_methods clippy::disallowed_types"
groups="warnings unfulfilled_lint_expectations clippy clippy::all clippy::style clippy::restriction"

# every lint-level attribute as "file<TAB>level<TAB>lint", read past strings, comments and whitespace
levels() {
    perl -0ne '
        s{ ((?<![A-Za-z0-9_])b?r(\#*)".*?"\2) | (b?"(?:\\.|[^\\"])*") | (\x27(?:\\.|[^\\\x27])\x27) | (//[^\n]*) | (/\*.*?\*/) }
         { defined $1 || defined $3 ? q("") : defined $4 ? q( ) : q( ) }gsex;
        s/\s+//g;
        while (/#!?(\[(?:[^\[\]]++|(?1))*\])/g) {
            my $attr = $1;
            while ($attr =~ /\b(allow|expect|warn)(\((?:[^()]++|(?2))*\))/g) {
                my ($level, $args) = ($1, $2);
                $args =~ s/\breason=""//g;
                print "$ARGV\t$level\t$_\n" for map { s/^:://r } $args =~ /((?:::)?[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)/g;
            }
        }' "$@"
}

# the workspace members, read from the root manifest's members array
members() {
    perl -0ne 'print "$1\n" while /^\s*members\s*=\s*\[([^\]]*)\]/msg' Cargo.toml | grep -oE '"[^"]+"' | tr -d '"'
}

check() (
    cd "$1"
    rs=$(find . -name target -prune -o -name '*.rs' -print | sed 's|^\./||' | sort)
    listed() { grep -qxF -e "$1" <(tr ' ' '\n' <<< "$2"); }
    outside() { grep -vxF -f <(tr ' ' '\n' <<< "$1") || true; }
    label() { sed "s|\$|: $1|"; }
    ms=$(members)
    excluded=$(perl -0ne 'print "$1\n" while /^\s*exclude\s*=\s*\[([^\]]*)\]/msg' Cargo.toml | grep -oE '"[^"]+"' | tr -d '"' || true)
    # shellcheck disable=SC2086
    found=$(
        { grep -lE 'disallowed_(method|type)' $rs || true; } | outside "$silence" | label "names disallowed_methods or disallowed_types outside the store modules"
        { grep -lw 'host_applied' $rs || true; } | outside "$mint" | label "names host_applied outside the store modules"
        { grep -lw 'expose' $rs || true; } | outside "$read" | label "names expose outside the modules CONTRACT.md names"
        levels $rs | while IFS=$'\t' read -r file level lint; do
            if listed "$lint" "$groups"; then echo "$file: silences the lint group $lint"
            elif listed "$lint" "$(echo $denied)"; then
                if [ "$level" != expect ]; then echo "$file: ${level}s the deny-list lint $lint (expect it, with a reason)"
                elif [[ $file == */src/* ]] && ! listed "${file%%/*}" "$harness"; then echo "$file: expects the deny-list lint $lint in shipped source"
                fi
            fi
        done | sort -u
        bodies=$(perl -0ne 'while (/\bfn ct_eq\b[^{]*(\{(?:[^{}]++|(?1))*\})/g) { print(($1 =~ s/\s+//gr), "\n") }' base/src/secret.rs)
        if [ "$(grep -c . <<< "$bodies")" -lt 2 ] || grep -vxE '\{self\.0\.as_slice\(\)\.ct_eq\(other\.0\.as_slice\(\)\)\.into\(\)\}' <<< "$bodies" | grep -q .; then
            echo "base/src/secret.rs: a ct_eq body is not subtle's ConstantTimeEq over both byte slices"
        fi
        for lint in $denied; do
            table=$([[ $lint == clippy::* ]] && echo clippy || echo rust)
            perl -0ne 'exit !(/^\[workspace\.lints\.'"$table"'\]\n(?:(?!\[)[^\n]*\n)*?\Q'"${lint#clippy::}"'\E\s*=\s*"(deny|forbid)"/m)' Cargo.toml ||
                echo "Cargo.toml: $lint is not deny or forbid in [workspace.lints.$table]"
        done
        while read -r toml; do
            dir=${toml%/Cargo.toml}
            listed "$dir" "$ms $excluded" || echo "$toml: not a workspace member and not excluded"
        done < <(find . -name target -prune -o -name Cargo.toml -print | sed 's|^\./||' | grep -vx Cargo.toml)
        for m in $ms; do
            if grep -qE 'disallowed_|^\[lints\.' "$m/Cargo.toml"; then echo "$m/Cargo.toml: overrides the workspace lints"; fi
            awk '/^\[lints\]/ { getline; ok = ($0 == "workspace = true") } END { exit !ok }' "$m/Cargo.toml" ||
                echo "$m/Cargo.toml: does not inherit the workspace lints"
        done
        find . -name target -prune -o \( -name clippy.toml -o -name .clippy.toml \) -print | sed 's|^\./||' | grep -vx clippy.toml |
            label "replaces the workspace clippy.toml for its crate" || true
        here=$(pwd)
        configs=$(find . -name target -prune -o -path '*/.cargo/config*' -print; echo rust-toolchain.toml Cargo.toml
            while [ "$here" != / ]; do here=$(dirname "$here"); echo "$here/.cargo/config" "$here/.cargo/config.toml"; done
            echo "${CARGO_HOME:-$HOME/.cargo}/config" "${CARGO_HOME:-$HOME/.cargo}/config.toml")
        for f in $configs; do
            [ -f "$f" ] && grep -qE '(^|[^A-Za-z])(-A|-W|--cap-lints|--force-warn)' "$f" && echo "$f: passes rustc a lint level"
        done
        for v in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS $(compgen -e | grep -E '^CARGO_TARGET_.*_RUSTFLAGS$' || true); do
            grep -qE -- '-A|-W|--cap-lints|--force-warn' <<< "${!v:-}" && echo "\$$v: passes rustc a lint level"
        done
        [ -z "${CLIPPY_CONF_DIR:-}" ] || echo "\$CLIPPY_CONF_DIR: points clippy at another clippy.toml"
        true
    )
    [ -z "$found" ] || { echo "$found"; return 1; }
)

self_test() {
    local here tmp n=0
    here=$(pwd)
    tmp=$(mktemp -d)
    trap "rm -rf '$tmp'" EXIT
    find . -name target -prune -o \( -name '*.rs' -o -name Cargo.toml -o -name clippy.toml -o -path './.cargo/*' -o -name rust-toolchain.toml \) -print |
        tar cf "$tmp/tree.tar" -T -
    fresh() { rm -rf "$tmp/t" && mkdir "$tmp/t" && tar xf "$tmp/tree.tar" -C "$tmp/t"; }
    flagged() { # $1: what was planted
        n=$((n + 1))
        if check "$tmp/t" > /dev/null; then echo "self-test $n: $1 passed"; exit 1; fi
    }
    plant() { fresh && mkdir -p "$(dirname "$tmp/t/$1")" && printf '%b\n' "$2" >> "$tmp/t/$1" && flagged "$1 with a planted evasion"; }
    mutate() { fresh && perl -0pi -e "$2" "$tmp/t/$1" && flagged "$1 mutated by $2"; }
    check "$here" > /dev/null || { echo "self-test: the clean tree fails"; exit 1; }
    plant testkit/src/race.rs '#[expect(\n    clippy::disallowed_methods,\n    reason = "probe"\n)]\nfn probe() {}'
    plant testkit/src/race.rs '#![allow(\n    clippy::unwrap_used,\n    clippy::disallowed_methods\n)]'
    plant testkit/src/race.rs '#[allow(dead_code, clippy::style)]\nfn probe() {}'
    plant testkit/src/race.rs '#![cfg_attr(test, allow(\n    warnings\n))]'
    plant testkit/src/race.rs '#[allow(clippy::all)]\nfn probe() {}'
    plant testkit/src/race.rs '#[cfg_attr(all(), doc = "[a]", allow(dead_code, clippy::style))]\nfn probe() {}'
    plant testkit/src/race.rs '#[allow(clippy :: style)]\nfn probe() {}'
    plant testkit/src/race.rs '#[allow(clippy::\nstyle)]\nfn probe() {}'
    plant testkit/src/race.rs '#![allow(clippy::restriction)]'
    plant testkit/src/race.rs '#![allow(unfulfilled_lint_expectations)]'
    plant testkit/src/race.rs '#![allow(clippy::unwrap_used)]'
    plant testkit/src/race.rs '#![allow(missing_docs)]'
    plant testkit/src/race.rs '#![warn(unreachable_pub)]'
    plant base/tests/golden.rs '#[allow(clippy::panic)]\nfn probe() {}'
    plant base/src/time.rs '#[expect(clippy::indexing_slicing, reason = "probe")]\nfn probe() {}'
    plant testkit/src/fixture.rs 'fn m(e: &base::Effect<u8, u8>) -> base::Receipt {\n    e.host_applied()\n}'
    plant testkit/src/fixture.rs 'fn x(s: &base::Secret<4>) -> &[u8; 4] {\n    s.expose()\n}'
    plant testkit/src/store.rs 'fn x(s: &base::SecretBytes) -> usize {\n    s.expose().len()\n}'
    plant testkit/Cargo.toml '[lints.clippy]\ndisallowed_methods = "allow"'
    plant .cargo/config.toml '[build]\nrustflags = ["-Aclippy::disallowed_methods"]'
    plant .cargo/config.toml '[target.x86_64-unknown-linux-gnu]\nrustflags = ["--cap-lints", "warn"]'
    plant testkit/clippy.toml 'disallowed-methods = []'
    plant extra/Cargo.toml '[package]\nname = "extra"'
    fresh && perl -0pi -e 's/members = \[/members = ["extra", /' "$tmp/t/Cargo.toml" && mkdir "$tmp/t/extra" &&
        printf '[package]\nname = "extra"\n[lints.clippy]\ndisallowed_methods = "allow"\n' > "$tmp/t/extra/Cargo.toml" &&
        flagged "an extra member that allows the lint"
    mutate Cargo.toml 's/^panic = "deny"/panic = "allow"/m'
    mutate Cargo.toml 's/^missing_docs = "deny"\n//m'
    mutate base/Cargo.toml 's/\[lints\].*//s'
    mutate base/src/secret.rs 's/self\.0\.as_slice\(\)\.ct_eq\(other\.0\.as_slice\(\)\)\.into\(\)/self.0 == other.0/'
    fresh && n=$((n + 1)) && if RUSTFLAGS=-Aclippy::all check "$tmp/t" > /dev/null; then echo "self-test $n: RUSTFLAGS passed"; exit 1; fi
    echo "confine self-test: $n planted evasions flagged"
}

# with every canary expect removed, clippy at the configured levels (no -D warnings) must error once per listed path
canary() {
    local here tmp want got
    here=$(pwd -P)
    tmp=$(mktemp -d)
    trap "rm -rf '$tmp'" EXIT
    tar cf - --exclude target --exclude 'mutants.out*' . | tar xf - -C "$tmp"
    perl -ni -e 'print unless /^\s*#\[expect\(clippy::disallowed_(methods|types), reason = "canary"\)\]$/' "$tmp/base/tests/lint_canary.rs"
    want=$(grep -cE '^\s*\{ path = ' clippy.toml)
    got=$( (cd "$tmp" && CARGO_TARGET_DIR="$here/target" cargo clippy -p base --all-features --test lint_canary --message-format=json 2> /dev/null || true) |
        jq -r 'select(.reason == "compiler-message" and .message.level == "error")
            | select(.message.code.code // "" | test("^clippy::disallowed_(methods|types)$"))
            | .message.spans[0].line_start' | sort -u | grep -c . || true)
    [ "$got" = "$want" ] || { echo "canary: $got of $want clippy.toml paths are errors at the workspace level"; exit 1; }
    echo "canary: $want of $want clippy.toml paths are errors at the workspace level"
}

case "${1:-.}" in
    --self-test) self_test ;;
    --canary) canary ;;
    *) check "${1:-.}" ;;
esac
