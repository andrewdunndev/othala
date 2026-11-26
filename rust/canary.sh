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
# R-j: only a crate with a direct dependency (of any kind, renamed or under a target table) on `expose` can name the read, so the members with such an edge, base apart, must be the ones gates.json gives `expose` modules
exposers() { # tree: one package name per line
    (cd "$1" && cargo metadata --offline --no-deps --format-version 1) | jq -r '
        .packages[] | select(.name != "base" and any(.dependencies[]; .name == "expose")) | .name' | sort -u
}
declared=$(jq -r 'select(.expose) | .name' <<< "$crates" | sort -u)
[ "$(exposers "$here")" = "$declared" ] || { echo "canary: expose is a dependency of [$(exposers "$here" | xargs)] but declared by [$(echo $declared)]"; exit 1; }
for c in $declared; do
    for m in $(jq -r '.expose[]' "$c/gates.json"); do [ -f "$c/src/$m.rs" ] || [ -f "$c/src/$m/mod.rs" ] || { echo "canary $c: expose module $m has no source"; exit 1; }; done
done
# a build script can pass `-L crate=` and name a crate that is not a dependency
builds=$(cargo metadata --offline --no-deps --format-version 1 | jq -r '.packages[] | select(any(.targets[]; .kind | index("custom-build"))) | .name')
[ -z "$builds" ] || { echo "canary: build script in [$(echo $builds)]"; exit 1; }
# the checks must catch an undeclared use: each plant in a scratch copy of a probe member is the only difference they may report
undeclared=$(jq -r 'select((.expose | not) and .name != "base") | .name' <<< "$crates")
probe=$(cargo metadata --offline --no-deps --format-version 1 | jq -r --arg u "$undeclared" '
    ($u | split("\n") | map(select(. != "" and . != "expose"))) as $U
    | .packages[] | select(.name as $n | $U | index($n)) | select(any(.dependencies[]; .name == "base" and .kind == null)) | .name' | head -n 1)
[ -n "$probe" ] || { echo "canary: no undeclared member to probe"; exit 1; }
planted() { # a dependency table; the exposers it adds
    local m="$tmp/$probe/Cargo.toml"
    cp "$probe/Cargo.toml" "$m"
    printf '\n%s\n' "$1" >> "$m"
    comm -23 <(exposers "$tmp") <(echo "$declared") || true
    cp "$probe/Cargo.toml" "$m"
}
plant_edge() { # what, then a dependency table
    local caught
    caught=$(planted "$2")
    [ "$caught" = "$probe" ] || { echo "canary: an undeclared expose edge ($1) in $probe went unreported (got [$caught])"; exit 1; }
}
plant_edge direct '[dependencies.expose]
path = "../expose"'
plant_edge renamed '[dependencies.e]
path = "../expose"
package = "expose"'
plant_edge "target dev" "[target.'cfg(all())'.dev-dependencies]
expose = { path = \"../expose\" }"
plant_edge build '[build-dependencies.expose]
path = "../expose"'
# unsafe is forbidden workspace-wide; only wipe may allow it
for c in $undeclared; do
    [ "$c" != wipe ] || continue
    printf '\npub fn planted_unsafe() { unsafe {} }\n' >> "$tmp/$c/src/lib.rs"
    errors "$c" --lib | cut -f1 | grep -qx unsafe_code || { echo "canary: unsafe {} planted in $c was not an unsafe_code error"; exit 1; }
    cp "$c/src/lib.rs" "$tmp/$c/src/lib.rs"
done
# the read is refused to a crate without the edge, and a path through include! does not name the crate either
printf '\npub fn planted_leak(s: &base::SecretBytes) -> usize { s.expose().len() }\n' >> "$tmp/$probe/src/lib.rs"
errors "$probe" --lib | cut -f1 | grep -qx E0599 || { echo "canary: an expose() call planted in $probe was not an E0599"; exit 1; }
cp "$probe/src/lib.rs" "$tmp/$probe/src/lib.rs"
echo 'use expose::Expose;' > "$tmp/$probe/src/planted_use.rs"
printf '\ninclude!("planted_use.rs");\n' >> "$tmp/$probe/src/lib.rs"
errors "$probe" --lib | cut -f1 | grep -qx E0432 || { echo "canary: use expose::Expose planted in $probe was not an E0432"; exit 1; }
cp "$probe/src/lib.rs" "$tmp/$probe/src/lib.rs"
rm "$tmp/$probe/src/planted_use.rs"
echo "canary: expose is a dependency of [$(echo $declared)] only; undeclared plants in [$(echo $undeclared)] are caught (edges in $probe, unsafe, E0599, E0432)"
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
