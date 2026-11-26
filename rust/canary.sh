#!/usr/bin/env bash
# `canary.sh [CRATE...]` (default: every crate its gates.json marks published): in a copy of this tree inside target/, so every cargo config and env var applies, append
# each of canary/levels.rs and canary/lints.rs to each crate's src/lib.rs and require each `want:` line's error; copy canary/paths.rs into its tests/
# and require the set of paths clippy names to be the set clippy.toml lists. It also enforces R-j (the expose crate: direct edges, no build script, no public item that names it, no cargo config or CI flag, wipe dev-only) and proves each gate with a plant.
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
# no cargo config or CI env may inject a crate, a wrapper or a flag: the only file under .cargo is cargo-mutants' own
cargo_cfg() { # root: cargo config files under it
    find "$1" \( -name target -o -name .git \) -prune -o -path '*/.cargo/*' \( -name config -o -name config.toml \) -print
}
env_flags() { # files: lines that set a rustc wrapper or flag variable
    grep -nE 'RUSTFLAGS|RUSTC_(WORKSPACE_)?WRAPPER|CARGO_BUILD_RUSTC|CARGO_ENCODED|CARGO_TARGET_[A-Z0-9_]*_(RUSTFLAGS|LINKER|RUNNER)|CARGO_UNSTABLE' "$@" 2> /dev/null || true
}
ci_files=(../.gitlab-ci.yml ../justfile justfile ../mise.toml ../scripts)
cfgs=$(cargo_cfg .. | sort -u)
[ -z "$cfgs" ] || { echo "canary: cargo config can inject crates or flags, refused: $(echo $cfgs)"; exit 1; }
envs=$(env_flags -r "${ci_files[@]}")
[ -z "$envs" ] || { echo "canary: CI sets a rustc wrapper or flag variable: $envs"; exit 1; }
# base implements the read and never re-exports it, and no member names the expose crate in its public surface (a use, glob or extern crate, a supertrait, a dyn or bound, a signature): rustdoc JSON resolves renames
nightly=${NIGHTLY:-nightly-2026-11-24}
exposed() { # crate: the public items of it, in the scratch copy, that name the expose crate
    local j="${CARGO_TARGET_DIR:-$here/target}/doc/${1//-/_}.json"
    rm -f "$j"
    (cd "$tmp" && cargo "+$nightly" rustdoc -p "$1" --lib --all-features -- -Z unstable-options --output-format json > /dev/null 2>&1 || true)
    [ -f "$j" ] || { echo "canary: rustdoc JSON of $1 failed to build" >&2; return 1; }
    jq -r -f exposed.jq "$j"
}
api_names_expose() { # dir: public-api.txt lines naming Expose, other than base's two impls and the trait's own file
    local f
    for f in "$1"/*/public-api.txt; do
        [ "$f" != "$1/expose/public-api.txt" ] || continue
        grep -wH Expose "$f" | grep -vE ':impl Expose for (Secret<N>|SecretBytes)$' || true
    done
}
for c in $(jq -r 'select(.name != "expose") | .name' <<< "$crates"); do
    leaks=$(exposed "$c") || exit 1
    [ -z "$leaks" ] || { echo "canary: $c re-exports or exposes the read: $leaks"; exit 1; }
done
leaks=$(api_names_expose .)
[ -z "$leaks" ] || { echo "canary: Expose in a public-api.txt beyond base's two impls: $leaks"; exit 1; }
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
# wipe stays dev-only: no member depends on it for a normal or build target
wipers() { # tree: members with a non-dev dependency on wipe
    (cd "$1" && cargo metadata --offline --no-deps --format-version 1) | jq -r '
        .packages[] | select(any(.dependencies[]; .name == "wipe" and .kind != "dev")) | .name' | sort -u
}
[ -z "$(wipers "$here")" ] || { echo "canary: wipe is a normal dependency of [$(wipers "$here" | xargs)]"; exit 1; }
printf '\n[dependencies.wipe]\npath = "../wipe"\n' >> "$tmp/$probe/Cargo.toml"
[ "$(wipers "$tmp")" = "$probe" ] || { echo "canary: a normal wipe dependency planted in $probe went unreported"; exit 1; }
cp "$probe/Cargo.toml" "$tmp/$probe/Cargo.toml"
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
printf '\nuse base::Expose as _;\n' >> "$tmp/$probe/src/lib.rs"
errors "$probe" --lib | cut -f1 | grep -qx E0432 || { echo "canary: base::Expose resolved in $probe, so base re-exports the read"; exit 1; }
cp "$probe/src/lib.rs" "$tmp/$probe/src/lib.rs"
# the S1/S3 gates catch what a source grep would miss: a renamed re-export, a glob-free pub use in another member, a dyn read and a public subtrait
plant_leak() { # what, crate, source appended to its lib.rs
    printf '\n%s\n' "$3" >> "$tmp/$2/src/lib.rs"
    local caught
    caught=$(exposed "$2") || exit 1
    cp "$2/src/lib.rs" "$tmp/$2/src/lib.rs"
    [ -n "$caught" ] || { echo "canary: $1 planted in $2 went unreported"; exit 1; }
}
plant_leak "extern crate with a renamed pub use" base 'extern crate expose as e; /// planted
pub use e::Expose as Reveal;'
plant_leak "pub use of expose" factor '/// planted
pub use expose::Expose;'
plant_leak "pub glob of expose" factor '/// planted
pub use expose::*;'
plant_leak "&dyn Expose" factor '/// planted
pub fn planted_dyn(_: &dyn expose::Expose<Bytes = [u8]>) {}'
plant_leak "public subtrait of Expose" factor '/// planted
pub trait PlantedSub: expose::Expose {}'
mkdir -p "$tmp/planted"
cp -a base factor "$tmp/planted/"
echo 'fn x(_: &dyn Expose<Bytes = [u8]>)' >> "$tmp/planted/factor/public-api.txt"
[ -n "$(api_names_expose "$tmp/planted")" ] || { echo "canary: Expose planted in a public-api.txt went unreported"; exit 1; }
rm -rf "$tmp/planted"
# a cargo config or CI wrapper variable is refused
mkdir -p "$tmp/.cargo"
printf '[build]\nrustc-wrapper = "x"\n' > "$tmp/.cargo/config.toml"
[ -n "$(cargo_cfg "$tmp")" ] || { echo "canary: a planted .cargo/config.toml went unreported"; exit 1; }
rm "$tmp/.cargo/config.toml"
printf '[build]\nrustflags = []\n' > "$tmp/.cargo/config"
[ -n "$(cargo_cfg "$tmp")" ] || { echo "canary: a planted .cargo/config went unreported"; exit 1; }
rm "$tmp/.cargo/config"
[ -z "$(cargo_cfg "$tmp")" ] || { echo "canary: the scratch copy has a cargo config"; exit 1; }
printf 'variables:\n  RUSTC_WORKSPACE_WRAPPER: x\n' > "$tmp/planted_ci.yml"
[ -n "$(env_flags "$tmp/planted_ci.yml")" ] || { echo "canary: a planted wrapper variable went unreported"; exit 1; }
rm "$tmp/planted_ci.yml"
echo "canary: expose is a dependency of [$(echo $declared)] only; undeclared plants in [$(echo $undeclared)] are caught (edges in $probe, unsafe, E0599, E0432, re-export and dyn and subtrait leaks, cargo config, CI flags, wipe)"
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
