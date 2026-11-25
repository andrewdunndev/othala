#!/usr/bin/env bash
# The gate behind CONTRACT O12, O13 and R10. `confine.sh DIR` checks a tree; `confine.sh --self-test` plants
# each evasion in a copy of this tree and requires the check to flag it; `confine.sh --canary` proves each
# clippy.toml path and each deny-list lint is an error at the workspace lint level, with the canary's expects removed.
set -euo pipefail

# no source relaxes these, so rustc rejects any allow of them, macro-generated ones included
forbidden="unsafe_code missing_docs unreachable_pub clippy::indexing_slicing clippy::as_conversions clippy::print_stdout clippy::dbg_macro"
denied="$forbidden clippy::unwrap_used clippy::expect_used clippy::panic clippy::disallowed_methods clippy::disallowed_types"
groups="warnings unfulfilled_lint_expectations clippy clippy::all clippy::style clippy::restriction"
flag='^(-A|-W|--allow|--warn|--cap-lints|--force-warn)'

# one array of confine.toml, space-separated
table() {
    KEY=$1 perl -0ne 'print join " ", $1 =~ /"([^"]*)"/g if /^\Q$ENV{KEY}\E\s*=\s*\[([^\]]*)\]/m' confine.toml
}

# the find expression that skips cargo's target dirs: the workspace's and each excluded package's
pruned() {
    local x
    echo "-path ./target"
    for x in $(excluded); do echo "-o -path ./$x/target"; done
}

excluded() {
    perl -0ne 'print "$1\n" while /^\s*exclude\s*=\s*\[([^\]]*)\]/msg' Cargo.toml | grep -oE '"[^"]+"' | tr -d '"' || true
}

# every lint-level attribute as "file<TAB>level<TAB>lint", read past strings, comments and whitespace
levels() {
    perl -0ne '
        s{ ((?<![A-Za-z0-9_])b?r(\#*)".*?"\2) | (b?"(?:\\.|[^\\"])*") | (\x27(?:\\.|[^\\\x27])\x27) | (//[^\n]*) | (/\*.*?\*/) }
         { defined $1 || defined $3 ? q("") : defined $4 ? q( ) : q( ) }gsex;
        s/\s+//g;
        while (/#!?(\[(?:[^\[\]]++|(?1))*\])/g) {
            my $attr = $1;
            print "$ARGV\tmacro\t\n" if $attr =~ /^\[\$/;
            while ($attr =~ /\b(allow|expect|warn)(\((?:[^()]++|(?2))*\))/g) {
                my ($level, $args) = ($1, $2);
                $args =~ s/\breason=""//g;
                print "$ARGV\t$level\t$_\n" for map { s/^:://r } $args =~ /((?:\$|::)?[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)/g;
            }
        }' "$@"
}

# the workspace members, read from the root manifest's members array
members() {
    perl -0ne 'print "$1\n" while /^\s*members\s*=\s*\[([^\]]*)\]/msg' Cargo.toml | grep -oE '"[^"]+"' | tr -d '"'
}

check() (
    cd "$1"
    # shellcheck disable=SC2046
    files() { find . \( $(pruned) \) -prune -o "$@" -print | sed 's|^\./||' | sort; }
    rs=$(files -name '*.rs')
    silence=$(table silence) mint=$(table mint) read=$(table read) harness=$(table harness) unlinted=$(table unlinted)
    listed() { grep -qxF -e "$1" <(tr ' ' '\n' <<< "$2"); }
    outside() { grep -vxF -f <(tr ' ' '\n' <<< "$1") || true; }
    label() { sed "s|\$|: $1|"; }
    ms=$(members)
    excluded=$(excluded)
    # shellcheck disable=SC2086
    found=$(
        { grep -lE 'disallowed_(method|type)' $rs || true; } | outside "$silence" | label "names disallowed_methods or disallowed_types outside the store modules"
        { grep -lw 'host_applied' $rs || true; } | outside "$mint" | label "names host_applied outside the store modules"
        { grep -lw 'expose' $rs || true; } | outside "$read" | label "names expose outside the modules CONTRACT.md names"
        levels $rs | while IFS=$'\t' read -r file level lint; do
            if [ "$level" = macro ]; then echo "$file: an attribute that is a macro metavariable"
            elif [[ $lint == \$* ]]; then echo "$file: a lint level whose lint is a macro metavariable"
            elif listed "$lint" "$groups"; then echo "$file: silences the lint group $lint"
            elif listed "$lint" "$(echo $denied)"; then
                if [ "$level" != expect ]; then echo "$file: ${level}s the deny-list lint $lint (expect it, with a reason)"
                elif [[ $file == */src/* ]] && ! listed "${file%%/*}" "$harness"; then echo "$file: expects the deny-list lint $lint in shipped source"
                fi
            fi
        done | sort -u
        # include! is never needed; a #[path] must name a .rs file inside this tree, so the scan reads it too
        perl -0ne '
            use Cwd qw(abs_path);
            (my $code = $_) =~ s{//[^\n]*|/\*.*?\*/}{}gs;
            s{ ((?<![A-Za-z0-9_])b?r(\#*)".*?"\2) | (b?"(?:\\.|[^\\"])*") | (\x27(?:\\.|[^\\\x27])\x27) | (//[^\n]*) | (/\*.*?\*/) }
             { defined $1 || defined $3 ? q("") : q( ) }gsex;
            print "$ARGV: pulls in code with include!\n" if /\binclude\s*!/;
            my $paths = () = /#!?\[[^\]]*\bpath\s*=/g;
            my ($root, $dir) = (abs_path("."), $ARGV =~ s{[^/]*\z}{}r);
            my @inside = grep {
                my $p = abs_path("$dir$_");
                /\.rs\z/ && defined $p && -f $p && index($p, "$root/") == 0
            } $code =~ /#!?\[[^\]]*?\bpath\s*=\s*"([^"\\]*)"/g;
            print "$ARGV: a #[path] that is not a .rs file in this tree\n" if $paths != @inside' $rs
        bodies=$(perl -0ne 'while (/\bfn ct_eq\b[^{]*(\{(?:[^{}]++|(?1))*\})/g) { print(($1 =~ s/\s+//gr), "\n") }' base/src/secret.rs)
        if [ "$(grep -c . <<< "$bodies")" -lt 2 ] || grep -vxE '\{self\.0\.as_slice\(\)\.ct_eq\(other\.0\.as_slice\(\)\)\.into\(\)\}' <<< "$bodies" | grep -q .; then
            echo "base/src/secret.rs: a ct_eq body is not subtle's ConstantTimeEq over both byte slices"
        fi
        for lint in $denied; do
            lints=$([[ $lint == clippy::* ]] && echo clippy || echo rust)
            want=$(listed "$lint" "$(echo $forbidden)" && echo forbid || echo 'deny|forbid')
            perl -0ne 'exit !(/^\[workspace\.lints\.'"$lints"'\]\n(?:(?!\[)[^\n]*\n)*?\Q'"${lint#clippy::}"'\E\s*=\s*"('"$want"')"/m)' Cargo.toml ||
                echo "Cargo.toml: $lint is not ${want/|/ or } in [workspace.lints.$lints]"
        done
        while read -r toml; do
            dir=${toml%/Cargo.toml}
            listed "$dir" "$ms $excluded" || echo "$toml: not a workspace member and not excluded"
        done < <(files -name Cargo.toml | grep -vx Cargo.toml)
        DENIED=$(echo $denied) perl -ne '
            BEGIN { %ok = map { /^clippy::(.*)/ ? ("clippy.$1" => 1) : ("rust.$_" => 1) } split " ", $ENV{DENIED} }
            if (/^\s*\[/) {
                ($t) = /^\[workspace\.lints\.(rust|clippy)\]\s*$/;
                $in = /lints/;
                print "Cargo.toml:$.: a lint table other than [workspace.lints.rust] or [workspace.lints.clippy]\n" if $in && !defined $t;
                next;
            }
            next if /^\s*(#.*)?$/;
            if ($in) { print "Cargo.toml:$.: not a deny-list lint = \"deny\" or \"forbid\"\n" unless defined $t && /^([a-z_]+) = "(deny|forbid)"$/ && $ok{"$t.$1"} }
            elsif (/lints/) { print "Cargo.toml:$.: sets lints outside the workspace lint tables\n" }' Cargo.toml
        for m in $ms; do
            if [ -e "$m/build.rs" ] || grep -qE '^\s*build\s*=' "$m/Cargo.toml"; then echo "$m: has a build script"; fi
            if listed "$m" "$unlinted"; then
                for o in $ms; do
                    [ "$o" = "$m" ] || ! grep -qE "^\s*$m\s*=" "$o/Cargo.toml" || echo "$o/Cargo.toml: depends on the unlinted member $m"
                done
                continue
            fi
            if grep -qE 'disallowed_|^\[lints\.' "$m/Cargo.toml"; then echo "$m/Cargo.toml: overrides the workspace lints"; fi
            awk '/^\[lints\]/ { getline; ok = ($0 == "workspace = true") } END { exit !ok }' "$m/Cargo.toml" ||
                echo "$m/Cargo.toml: does not inherit the workspace lints"
        done
        files \( -name clippy.toml -o -name .clippy.toml \) | grep -vx clippy.toml |
            label "replaces the workspace clippy.toml for its crate" || true
        here=$(pwd)
        configs=$(files -path '*/.cargo/config*'; echo rust-toolchain.toml Cargo.toml
            while [ "$here" != / ]; do here=$(dirname "$here"); echo "$here/.cargo/config" "$here/.cargo/config.toml"; done
            echo "${CARGO_HOME:-$HOME/.cargo}/config" "${CARGO_HOME:-$HOME/.cargo}/config.toml")
        for f in $configs; do
            # each quoted string split into arguments, so a lint flag counts only at an argument's start
            [ -f "$f" ] && FLAG=$flag perl -ne 'for (/"((?:\\.|[^"\\])*)"|\x27([^\x27]*)\x27/g) { $bad ||= defined $_ && grep { /$ENV{FLAG}/ } split } END { exit !$bad }' "$f" &&
                echo "$f: passes rustc a lint level"
        done
        for v in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS $(compgen -e | grep -E '^CARGO_TARGET_.*_RUSTFLAGS$' || true); do
            FLAG=$flag V=${!v:-} perl -e 'exit !grep { /$ENV{FLAG}/ } split /[\s\x1f]+/, $ENV{V}' && echo "\$$v: passes rustc a lint level"
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
    # shellcheck disable=SC2046
    find . \( $(pruned) \) -prune -o \( -name '*.rs' -o -name '*.toml' -o -path './.cargo/*' \) -print |
        tar cf "$tmp/tree.tar" -T -
    fresh() { rm -rf "$tmp/t" && mkdir "$tmp/t" && tar xf "$tmp/tree.tar" -C "$tmp/t"; }
    flagged() { # $1: what was planted
        n=$((n + 1))
        if check "$tmp/t" > /dev/null; then echo "self-test $n: $1 passed"; exit 1; fi
    }
    plant() { fresh && mkdir -p "$(dirname "$tmp/t/$1")" && printf '%b\n' "$2" >> "$tmp/t/$1" && flagged "$1 with a planted evasion"; }
    mutate() { fresh && perl -0pi -e "$2" "$tmp/t/$1" && flagged "$1 mutated by $2"; }
    passes() { # a planted line that is not an evasion
        fresh && mkdir -p "$(dirname "$tmp/t/$1")" && printf '%b\n' "$2" >> "$tmp/t/$1" &&
            check "$tmp/t" > /dev/null || { echo "self-test: $1 with $2 is flagged"; exit 1; }
    }
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
    plant .cargo/config.toml '[build]\nrustflags = ["--allow", "clippy::disallowed_methods"]'
    plant .cargo/config.toml '[build]\nrustflags = ["--warn=clippy::unwrap_used"]'
    plant base/tests/probe.rs 'include!("probe.txt");'
    plant base/tests/probe.rs '#[path = "probe.txt"]\nmod probe;'
    plant base/tests/probe.rs '#[path = "../../../outside.rs"]\nmod probe;'
    plant base/tests/probe.rs '#[cfg_attr(all(), path = "probe.txt")]\nmod probe;'
    plant base/build.rs 'fn main() {}'
    plant base/src/time.rs 'macro_rules! lint_off {\n    ($($m:tt)*) => {\n        #[$($m)*]\n        fn probe() {}\n    };\n}\nlint_off!(allow(clippy::unwrap_used));'
    plant base/src/time.rs 'macro_rules! lint_off {\n    ($l:path) => {\n        #[allow($l)]\n        fn probe() {}\n    };\n}\nlint_off!(clippy::unwrap_used);'
    plant base/src/target/mod.rs '#![allow(clippy::unwrap_used, clippy::panic)]'
    plant Cargo.toml 'restriction = { level = "allow", priority = 1 }'
    plant Cargo.toml 'style = "deny"'
    plant Cargo.toml '[workspace.lints]\nclippy.unwrap_used = "allow"'
    plant testkit/clippy.toml 'disallowed-methods = []'
    plant extra/Cargo.toml '[package]\nname = "extra"'
    fresh && perl -0pi -e 's/members = \[/members = ["extra", /' "$tmp/t/Cargo.toml" && mkdir "$tmp/t/extra" &&
        printf '[package]\nname = "extra"\n[lints.clippy]\ndisallowed_methods = "allow"\n' > "$tmp/t/extra/Cargo.toml" &&
        flagged "an extra member that allows the lint"
    mutate Cargo.toml 's/^panic = "deny"/panic = "allow"/m'
    mutate Cargo.toml 's/^missing_docs = "forbid"\n//m'
    mutate Cargo.toml 's/^dbg_macro = "forbid"/dbg_macro = "deny"/m'
    mutate base/Cargo.toml 's/\[lints\].*//s'
    mutate base/src/secret.rs 's/self\.0\.as_slice\(\)\.ct_eq\(other\.0\.as_slice\(\)\)\.into\(\)/self.0 == other.0/'
    mutate base/Cargo.toml 's/^(\[package\]\n)/$1build = "probe.rs"\n/m'
    for flags in -Aclippy::all "--allow clippy::unwrap_used" --warn=clippy::panic; do
        fresh && n=$((n + 1)) && if RUSTFLAGS=$flags check "$tmp/t" > /dev/null; then echo "self-test $n: RUSTFLAGS=$flags passed"; exit 1; fi
    done
    passes .cargo/config.toml '[build]\nrustflags = ["-C", "link-arg=-Wl,-z,relro"]'
    fresh && RUSTFLAGS="-C link-arg=-Wl,-z,relro" check "$tmp/t" > /dev/null || { echo "self-test: RUSTFLAGS with a linker flag is flagged"; exit 1; }
    echo "confine self-test: $n planted evasions flagged, 2 linker flags passed"
}

# with every canary expect removed, clippy at the configured levels (no -D warnings) must error once per listed path,
# and a lib probe per deny-list lint must error; the copy sits inside this tree so every ancestor cargo config applies
canary() {
    local here tmp want got missing lib
    here=$(pwd -P)
    mkdir -p "$here/target"
    tmp=$(mktemp -d "$here/target/canary.XXXXXX")
    trap "rm -rf '$tmp'" EXIT
    tar cf - --exclude ./target --exclude 'mutants.out*' . | tar xf - -C "$tmp"
    errors() { # code<TAB>line<TAB>message per distinct error
        (cd "$tmp" && CARGO_TARGET_DIR="$here/target" cargo clippy -p base --all-features "$@" --message-format=json 2> /dev/null || true) |
            jq -r 'select(.reason == "compiler-message" and .message.level == "error")
                | "\(.message.code.code // "")\t\(.message.spans[0].line_start)\t\(.message.message)"' | sort -u
    }
    perl -ni -e 'print unless /^\s*#\[expect\(clippy::disallowed_(methods|types), reason = "canary"\)\]$/' "$tmp/base/tests/lint_canary.rs"
    # the set of paths clippy names must be the set clippy.toml lists, so a path canaried twice does not stand in for another
    want=$(perl -ne 'print "$1\n" if /^\s*\{ path = "([^"]+)"/' clippy.toml | sort -u)
    got=$(errors --test lint_canary | perl -F'\t' -lane 'print $1 if $F[0] =~ /^clippy::disallowed_(methods|types)$/ && $F[2] =~ /`([^`]+)`/' | sort -u)
    missing=$(comm -23 <(echo "$want") <(echo "$got"))
    [ -z "$missing" ] || { echo "canary: not an error at the workspace level:" $missing; exit 1; }
    cat >> "$tmp/base/src/lib.rs" << 'PROBES'
/// canary
pub fn canary_unwrap(x: Option<u8>) -> u8 {
    x.unwrap()
}
/// canary
pub fn canary_expect(x: Option<u8>) -> u8 {
    x.expect("canary")
}
/// canary
pub fn canary_panic() {
    panic!("canary")
}
/// canary
pub fn canary_index(x: &[u8]) -> u8 {
    x[0]
}
/// canary
pub fn canary_as(x: u16) -> u8 {
    x as u8
}
/// canary
pub fn canary_print() {
    std::println!("canary")
}
/// canary
pub fn canary_dbg(x: u8) -> u8 {
    std::dbg!(x)
}
/// canary
pub fn canary_unsafe() {
    unsafe {}
}
pub fn canary_undocumented() {}
mod canary_hidden {
    pub fn unreachable() {}
}
PROBES
    lib=$(errors --lib | cut -f1)
    # shellcheck disable=SC2086
    missing=$(for lint in $denied; do
        [[ $lint == clippy::disallowed_* ]] || grep -qxF "$lint" <<< "$lib" || echo "$lint"
    done)
    [ -z "$missing" ] || { echo "canary: not an error at the workspace level:" $missing; exit 1; }
    echo "canary: each of the $(grep -c . <<< "$want") clippy.toml paths and every deny-list lint are errors at the workspace level"
}

case "${1:-.}" in
    --self-test) self_test ;;
    --canary) canary ;;
    *) check "${1:-.}" ;;
esac
