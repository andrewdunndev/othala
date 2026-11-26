#!/usr/bin/env bash
# `canary.sh [CRATE...]` (default: every crate its gates.json marks published): in a copy of this tree inside target/, so every cargo config and env var applies, append
# each of canary/levels.rs and canary/lints.rs to each crate's src/lib.rs and require each `want:` line's error; copy canary/paths.rs into its tests/
# and require the set of paths clippy names to be the set clippy.toml lists.
set -euo pipefail
crates=$(./crates.sh)
if [ $# -eq 0 ]; then
    published=$(jq -r 'select(.published) | .name' <<< "$crates")
    # shellcheck disable=SC2086 # one crate name per line
    set -- $published
fi
[ $# -gt 0 ] || { echo "canary: no published crate"; exit 1; }
here=$(pwd -P)
mkdir -p "$here/target"
tmp=$(mktemp -d "$here/target/canary.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
find . -mindepth 1 -maxdepth 1 ! -name target ! -name 'mutants.out*' -exec cp -a {} "$tmp"/ \;
errors() { # crate, then cargo args: code<TAB>file<TAB>line<TAB>message per error
    local c=$1
    shift
    (cd "$tmp" && CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$here/target}" cargo clippy -p "$c" --all-features "$@" --message-format=json 2> /dev/null || true) |
        jq -r 'select(.reason == "compiler-message" and .message.level == "error")
            | .message as $m | $m.spans[] | select(.is_primary)
            | "\($m.code.code // "")\t\(.file_name)\t\(.line_start)\t\($m.message)"' | sort -u
}
# R-j: the packages in the resolve graph that enable base/expose (a dependency feature, a forward in a feature list, possibly through a renamed key or a base feature that implies it) must be the ones gates.json gives `expose` modules
exposers() { # tree: one package name per line
    (cd "$1" && cargo metadata --offline --format-version 1) | jq -r '
        (.packages[] | select(.name == "base") | .features) as $bf
        | (reduce range(0; 8) as $_ (["expose"]; . as $f | ($f + [$bf | to_entries[] | select(any(.value[]; . as $v | $f | index($v))) | .key]) | unique)) as $F
        | .packages[] | select(.name != "base")
        | [.dependencies[] | select(.name == "base")] as $deps
        | select(any($deps[]; any(.features[]; . as $x | $F | index($x))) or any($deps[]; .uses_default_features and ($F | index("default")))
            or any(.features[][]; . as $v | any($deps[]; (.rename // .name) as $k | $v | test("^" + $k + "\\??/(" + ($F | join("|")) + ")$"))))
        | .name' | sort -u
}
declared=$(jq -r 'select(.expose) | .name' <<< "$crates" | sort -u)
[ "$(exposers "$here")" = "$declared" ] || { echo "canary: base/expose is enabled by [$(exposers "$here" | xargs)] but declared by [$(echo $declared)]"; exit 1; }
for c in $declared; do
    for m in $(jq -r '.expose[]' "$c/gates.json"); do [ -f "$c/src/$m.rs" ] || [ -f "$c/src/$m/mod.rs" ] || { echo "canary $c: expose module $m has no source"; exit 1; }; done
done
# the checks must catch an undeclared use: each plant in a scratch copy of a probe member is the only difference they may report
probe=$(jq -r 'select((.expose | not) and .name != "base") | .name' <<< "$crates" | head -n 1)
planted() { # a manifest plant, then the exposers it adds
    cp "$probe/Cargo.toml" "$tmp/$probe/Cargo.toml"
    printf '%s\n' "$1" >> "$tmp/$probe/Cargo.toml"
    comm -23 <(exposers "$tmp") <(echo "$declared") || true
    cp "$probe/Cargo.toml" "$tmp/$probe/Cargo.toml"
}
for form in 'direct:[target.'"'cfg(all())'"'.dependencies]
base = { path = "../base", features = ["expose"] }' 'renamed forward:[target.'"'cfg(all())'"'.dependencies]
b = { path = "../base", package = "base", optional = true }
[features]
leak = ["b/expose"]'; do
    caught=$(planted "${form#*:}")
    [ "$caught" = "$probe" ] || { echo "canary: an undeclared base/expose ($(echo "${form%%:*}")) in $probe went unreported (got [$caught])"; exit 1; }
done
# a feature-unified check (--all-features) lets any member borrow a declaring one's feature, so each undeclared member is checked on its own; a member that depends on a declaring crate gets expose transitively and is covered by the grep alone
undeclared=$(jq -r 'select((.expose | not) and .name != "base") | .name' <<< "$crates")
call() { grep -rnE '\bexpose[[:space:]]*\(' --include='*.rs' "$@" 2> /dev/null || true; }
for c in $undeclared; do
    [ -z "$(call "$c")" ] || { echo "canary $c: expose() is called but gates.json declares no expose module:"; call "$c"; exit 1; }
    (cd "$tmp" && cargo check --offline -p "$c" --all-targets 2> /dev/null) || { echo "canary $c: cargo check without --all-features fails"; exit 1; }
done
printf '\npub fn planted_leak(s: &base::SecretBytes) -> usize { s.expose().len() }\n' >> "$tmp/$probe/src/lib.rs"
[ -n "$(call "$tmp/$probe")" ] || { echo "canary: the expose( grep missed a call planted in $probe"; exit 1; }
(cd "$tmp" && cargo check --offline -p "$probe" --all-targets 2>&1 || true) | grep -q 'no method named `expose`' || { echo "canary: an expose() call planted in $probe was not refused for want of base/expose"; exit 1; }
cp "$probe/src/lib.rs" "$tmp/$probe/src/lib.rs"
echo "canary: base/expose only in [$(echo $declared)]; undeclared use in [$(echo $undeclared)] is caught as a direct enable, a renamed forward and a call"
want_paths=$(sed -nE 's/^[[:space:]]*\{ path = "([^"]+)".*/\1/p' clippy.toml | sort -u)
for c in "$@"; do
    offset=$(wc -l < "$c/src/lib.rs")
    n=0
    for probe in canary/levels.rs canary/lints.rs; do
        cp "$c/src/lib.rs" "$tmp/$c/src/lib.rs"
        cat "$probe" >> "$tmp/$c/src/lib.rs"
        want=$(awk -v o="$offset" '/\/\/ want: / { print FNR + o "\t" $NF }' "$probe" | sort -u)
        [ -n "$want" ] || { echo "canary $c: $probe wants nothing"; exit 1; }
        got=$(errors "$c" --lib | awk -F'\t' -v f="$c/src/lib.rs" '$2 ~ f"$" { print $3 "\t" $1 }' | sort -u)
        missing=$(comm -23 <(echo "$want") <(echo "$got"))
        [ -z "$missing" ] || { echo "canary $c: these $probe lines (offset by $offset) lack their error:"; echo "$missing"; exit 1; }
        n=$((n + $(grep -c . <<< "$want")))
    done
    cp "$c/src/lib.rs" "$tmp/$c/src/lib.rs"
    cp canary/paths.rs "$tmp/$c/tests/canary_paths.rs"
    got=$(errors "$c" --test canary_paths | awk -F'\t' '$1 ~ /^clippy::disallowed_(methods|types|macros)$/ { split($4, p, "`"); print p[2] }' | sort -u)
    missing=$(comm -23 <(echo "$want_paths") <(echo "$got"))
    [ -z "$missing" ] || { echo "canary $c: not an error:" $missing; exit 1; }
    echo "canary $c: $n probes and $(grep -c . <<< "$want_paths") clippy.toml paths are errors"
done
