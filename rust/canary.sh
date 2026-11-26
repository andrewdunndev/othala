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
cleanup() { # the scratch copy, and the rustdoc JSON of the plants (they would pass for the real one)
    rm -rf "$tmp"
    local c
    for c in $(jq -r .name <<< "$crates"); do rm -f "${CARGO_TARGET_DIR:-$here/target}/doc/${c//-/_}.json"; done
}
trap cleanup EXIT
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
# no cargo config, mise file or CI env may inject a crate, a wrapper or a flag: the only file under .cargo is cargo-mutants' own. Only tracked files count (CI's CARGO_HOME holds the config files bundled in registry crates), so the tracked tree must not hold any CARGO_HOME
tracked() { git -C "$1" ls-files; }
cargo_cfg() { # stdin: tracked paths; the cargo config files among them
    grep -E '(^|/)\.cargo/config(\.toml)?$' | grep -vx 'rust/\.cargo/mutants\.toml' || true
}
home_files() { # stdin: tracked paths; any file under a .cargo-home
    grep -E '(^|/)\.cargo-home/' || true
}
mise_files() { # stdin: tracked paths; every file mise reads for an [env]
    grep -E '(^|/)(\.?mise(\.[A-Za-z0-9_-]+)?\.toml|\.config/mise(/[^/]*)?\.toml|\.mise/[^/]*\.toml)$' || true
}
env_flags() { # files: uncommented lines that set a rustc wrapper or flag, in any case or spelling, a bare RUSTC, a --config of them, or mise's _.file and _.source
    {
        grep -HniE 'rustflags|rustc[-_](workspace[-_])?wrapper|CARGO_BUILD_RUSTC|CARGO_ENCODED|CARGO_TARGET_[A-Z0-9_]*_(RUSTFLAGS|LINKER|RUNNER)|CARGO_UNSTABLE|--config[ =].*(build\.rustc|target\..*(rustflags|linker|runner))' "$@" 2> /dev/null
        grep -HnE '(^|[^A-Za-z0-9_])RUSTC([^A-Za-z0-9_]|$)|^[[:space:]"]*_\.(file|source)' "$@" 2> /dev/null
    } | grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' | sort -u || true
}
home_vars() { # files: uncommented CARGO_HOME settings other than CI's own, in-tree .cargo-home
    grep -HnE 'CARGO_HOME' "$@" 2> /dev/null | grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' | grep -vF 'CARGO_HOME: "$CI_PROJECT_DIR/.cargo-home"' || true
}
home_ok() { # path, repo root: a CARGO_HOME outside the repo, or the .cargo-home at its top
    local h r
    h=$(realpath -m "$1")
    r=$(realpath -m "$2")
    case "$h" in "$r/.cargo-home" | "$r/.cargo-home"/*) return 0 ;; "$r" | "$r"/*) return 1 ;; *) return 0 ;; esac
}
root=$(git -C .. rev-parse --show-toplevel)
cfgs=$(tracked .. | cargo_cfg)
[ -z "$cfgs" ] || { echo "canary: cargo config can inject crates or flags, refused: $(echo $cfgs)"; exit 1; }
homes=$(tracked .. | home_files)
[ -z "$homes" ] || { echo "canary: files tracked under .cargo-home, refused: $(echo $homes)"; exit 1; }
home_ok "${CARGO_HOME:-$HOME/.cargo}" "$root" || { echo "canary: CARGO_HOME=$CARGO_HOME is inside the repository but is not its .cargo-home"; exit 1; }
ci_files=(../.gitlab-ci.yml ../justfile justfile crates.sh ../mise.toml ../scripts)
mapfile -t mises < <(tracked .. | mise_files | sed 's|^|../|')
envs=$(env_flags -r "${ci_files[@]}" "${mises[@]}")
[ -z "$envs" ] || { echo "canary: CI or mise sets a rustc wrapper or flag variable: $envs"; exit 1; }
homev=$(home_vars -r "${ci_files[@]}" "${mises[@]}")
[ -z "$homev" ] || { echo "canary: CARGO_HOME is set other than to CI's .cargo-home: $homev"; exit 1; }
# a rustdoc doc cfg hides items from the JSON the check reads
doc_cfg() { # files: those whose cfg or cfg_attr tests `doc`, or sets `doc(...)` (`doc = "..."` is a plain attribute)
    grep -lPz '(?s)cfg(_attr)?!?\s*\((?:(?!\]).)*?(?<![\"\w-])doc\b(?![\"\w-]|\s*=)' "$@" 2> /dev/null || true
}
mapfile -t srcs < <(tracked .. | grep -E '^rust/.*\.rs$' | grep -vE '^rust/canary/' | sed 's|^rust/||')
docs=$(doc_cfg "${srcs[@]}")
[ -z "$docs" ] || { echo "canary: cfg or cfg_attr tests doc in [$(echo $docs)]"; exit 1; }
# base implements the read and never re-exports it, and no member names the expose crate in its public surface (a use, glob or extern crate, a supertrait, a dyn or bound, a signature): rustdoc JSON resolves renames
nightly=${NIGHTLY:-nightly-2026-11-24}
exposed() { # crate: the public items of it, in the scratch copy, that name the expose crate
    local j="${CARGO_TARGET_DIR:-$here/target}/doc/${1//-/_}.json"
    rm -f "$j"
    (cd "$tmp" && CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$here/target}" cargo "+$nightly" rustdoc -p "$1" --lib --all-features -- -Z unstable-options --output-format json --document-hidden-items > /dev/null 2>&1 || true)
    [ -f "$j" ] || { echo "canary: rustdoc JSON of $1 failed to build" >&2; return 1; }
    jq -r -f canary/exposed.jq "$j"
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
plant_leak "a doc(hidden) pub use of expose" factor '#[doc(hidden)]
pub use expose::Expose;'
plant_leak "a doc(hidden) pub mod re-exporting expose" factor '#[doc(hidden)]
pub mod planted_mod {
    pub use expose::Expose;
}'
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
# a cargo config, a file under .cargo-home, a CI or mise wrapper variable or a doc cfg is refused: each in a scratch git repository, so the tracked list is the real one's kind
g="$tmp/gitplant"
mkdir -p "$g/.cargo" "$g/rust/.cargo" "$g/.cargo-home/registry/src/x/.cargo"
git -C "$g" init -q
printf '[build]\nrustc-wrapper = "x"\n' | tee "$g/.cargo/config.toml" "$g/.cargo-home/registry/src/x/.cargo/config.toml" > "$g/.cargo-home/registry/src/x/.cargo/config"
printf '[build]\nrustflags = []\n' > "$g/.cargo/config"
printf 'x = 1\n' > "$g/rust/.cargo/mutants.toml"
[ -z "$(tracked "$g" | cargo_cfg)" ] || { echo "canary: untracked cargo configs (bundled in a vendored crate or not added) were reported"; exit 1; }
git -C "$g" add -f rust/.cargo/mutants.toml
[ -z "$(tracked "$g" | cargo_cfg)" ] || { echo "canary: cargo-mutants' own config was reported as a cargo config"; exit 1; }
git -C "$g" add -f .cargo/config.toml
[ "$(tracked "$g" | cargo_cfg)" = ".cargo/config.toml" ] || { echo "canary: a tracked .cargo/config.toml went unreported"; exit 1; }
git -C "$g" add -f .cargo/config
[ "$(tracked "$g" | cargo_cfg | sort | xargs)" = ".cargo/config .cargo/config.toml" ] || { echo "canary: a tracked .cargo/config went unreported"; exit 1; }
[ -z "$(tracked "$g" | home_files)" ] || { echo "canary: untracked files under .cargo-home were reported"; exit 1; }
git -C "$g" add -f .cargo-home/registry/src/x/.cargo/config.toml
[ -n "$(tracked "$g" | home_files)" ] || { echo "canary: a tracked file under .cargo-home went unreported"; exit 1; }
[ "$(tracked "$g" | cargo_cfg | sort | xargs)" = ".cargo-home/registry/src/x/.cargo/config.toml .cargo/config .cargo/config.toml" ] || { echo "canary: a tracked vendored config went unreported"; exit 1; }
{ home_ok "$root/.cargo-home" "$root" && home_ok "/elsewhere/h" "$root" && home_ok "$root/../h" "$root"; } || { echo "canary: an acceptable CARGO_HOME was refused"; exit 1; }
{ ! home_ok "$root/rust" "$root" && ! home_ok "$root" "$root" && ! home_ok "$root/rust/.cargo-home" "$root"; } || { echo "canary: an in-tree CARGO_HOME went unreported"; exit 1; }
rm -rf "$g"
plant_env() { # what, the line it plants
    printf '%s\n' "$2" > "$tmp/planted_ci.yml"
    [ -n "$(env_flags "$tmp/planted_ci.yml")" ] || { echo "canary: $1 went unreported"; exit 1; }
    rm "$tmp/planted_ci.yml"
}
plant_env "a RUSTC_WORKSPACE_WRAPPER variable" '  RUSTC_WORKSPACE_WRAPPER: x'
plant_env "a bare RUSTC variable" '  RUSTC: x'
plant_env "a bare RUSTC assignment in a script" 'RUSTC=x cargo build'
plant_env "a --config build.rustc-wrapper" 'cargo build --config build.rustc-wrapper=\"x\"'
plant_env "a --config build.rustc" 'cargo build --config=build.rustc=x'
plant_env "a --config build.rustflags" "cargo build --config 'build.rustflags=[\"-Lx\"]'"
plant_env "a lowercase rustc-wrapper written by a script" 'printf "rustc-wrapper = x" >> cfg'
plant_env "a lowercase rustflags written by a script" 'echo rustflags >> cfg'
plant_env "a mise _.file" '_.file = ".env"'
plant_env "a mise _.source" '_.source = "env.sh"'
printf '# RUSTC_WRAPPER=x and RUSTC, RUSTFLAGS and rustflags in a comment\n' > "$tmp/planted_ci.yml"
[ -z "$(env_flags "$tmp/planted_ci.yml")" ] || { echo "canary: a comment line was reported as a variable"; exit 1; }
printf 'variables:\n  CARGO_HOME: /x\n' > "$tmp/planted_ci.yml"
[ -n "$(home_vars "$tmp/planted_ci.yml")" ] || { echo "canary: a CARGO_HOME other than CI's went unreported"; exit 1; }
printf '  CARGO_HOME: "$CI_PROJECT_DIR/.cargo-home"\n  # CARGO_HOME: /y\n' > "$tmp/planted_ci.yml"
[ -z "$(home_vars "$tmp/planted_ci.yml")" ] || { echo "canary: CI's own CARGO_HOME or a comment was reported"; exit 1; }
rm "$tmp/planted_ci.yml"
[ "$(printf 'rust/mise.toml\nrust/mise.local.toml\n.mise.toml\n.config/mise.toml\nmise.toml\nmise.ci.toml\nrust/base/src/lib.rs\n' | mise_files | xargs)" = "rust/mise.toml rust/mise.local.toml .mise.toml .config/mise.toml mise.toml mise.ci.toml" ] || { echo "canary: a mise file name went unlisted"; exit 1; }
plant_doc() { # what, the item
    printf '%s\n' "$2" > "$tmp/planted_doc.rs"
    [ "$(doc_cfg "$tmp/planted_doc.rs")" = "$tmp/planted_doc.rs" ] || { echo "canary: $1 went unreported"; exit 1; }
    rm "$tmp/planted_doc.rs"
}
plant_doc "cfg(not(doc)) over a pub use" '#[cfg(not(doc))]
pub use expose::Expose;'
plant_doc "cfg_attr(doc, ...)" '#[cfg_attr(doc, allow(unused))]
pub fn f() {}'
plant_doc "cfg_attr setting doc(hidden)" '#[cfg_attr(all(), doc(hidden))]
pub use expose::Expose;'
plant_doc "cfg(doc) split over lines" '#[cfg(all(
    unix,
    doc
))]
pub fn f() {}'
printf '#[cfg_attr(all(), doc = "x")]\n#[cfg(feature = "doc")]\npub fn f() {}\n' > "$tmp/planted_doc.rs"
[ -z "$(doc_cfg "$tmp/planted_doc.rs")" ] || { echo "canary: a doc = attribute or a doc feature was reported as a doc cfg"; exit 1; }
rm "$tmp/planted_doc.rs"
echo "canary: expose is a dependency of [$(echo $declared)] only; undeclared plants in [$(echo $undeclared)] are caught (edges in $probe, unsafe, E0599, E0432, re-export and dyn and subtrait leaks, tracked cargo configs and files under .cargo-home, CARGO_HOME, CI and mise flag variables, doc cfgs, doc(hidden) leaks, wipe)"
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
