#!/usr/bin/env bash
# `own-plants.sh [OWN.SH]`: judge planted branches of a scratch repo with own.sh (default: the one beside this script; an argument names another,
# for demonstrating that a plant catches an older one) and require each plant's exact verdict, so an oracle item's admission and refusals are proved by running them.
# Real queue.json plus one lookalike item, scratch history.
set -euo pipefail
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR
here=$(cd "$(dirname "$0")" && pwd -P)
own=$(realpath "${1:-$here/own.sh}")
queue=$here/queue.json
for id in p0-oracle-jose jose-lane; do
    jq -e --arg id "$id" 'any(.items[]; .id == $id)' "$queue" > /dev/null || { echo "own-plants: queue.json has no item $id"; exit 1; }
done
jlane=$(jq -r '.items[] | select(.id == "jose-lane") | .globs[0]' "$queue")
[[ $jlane == */'*' ]] || { echo "own-plants: jose-lane's first glob $jlane does not end in /*"; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export GIT_AUTHOR_NAME=plant GIT_AUTHOR_EMAIL=plant@invalid GIT_COMMITTER_NAME=plant GIT_COMMITTER_EMAIL=plant@invalid GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
cd "$tmp"
git init -q -b main .
mkdir primitives
cp "$own" primitives/own.sh
# p0-oraclex is the id a loosened `p0-oracle*` prefix test would admit
jq '.items += [{id: "p0-oraclex", milestone: "M0", rows: [], globs: ["rust/vectors/*"], deps: [], state: "running", model: "opus", title: "plant"}]' "$queue" > primitives/queue.json
git add -A
git commit -qm base
bad=0
n=0
plant() { # item, path, expected rc, a regex the output must match, then file (default), symlink or gitlink
    local item=$1 path=$2 want=$3 re=$4 kind=${5:-file} out rc
    n=$((n + 1))
    git checkout -q -b "plant$n" main
    mkdir -p "$(dirname "$path")"
    case "$kind" in
        file) echo planted > "$path" && git add -A ;;
        symlink) ln -s ../../../primitives/own.sh "$path" && git add -A ;;
        gitlink) git update-index --add --cacheinfo "160000,$(git rev-parse HEAD),$path" ;;
    esac
    git commit -qm "plant $n"
    out=$(OWN_MAIN=main bash primitives/own.sh "$item" 2>&1) && rc=0 || rc=$?
    git checkout -q -f main
    git clean -qfd
    if [ "$rc" != "$want" ] || ! grep -Eq "$re" <<< "$out"; then
        echo "own-plants: $item over $path ($kind) gave rc $rc [$out], wanted rc $want matching /$re/"
        bad=1
    fi
}
# plant S4b: an item p0-oracle-* writes rust/vectors/* and nothing else
plant p0-oracle-jose rust/vectors/x/planted.json 0 'all 1 paths changed since [0-9a-f]+ are its own'
plant p0-oracle-jose rust/vectors/x/expected-fail.txt 1 'expected-fail\.txt is oracle'
plant p0-oracle-jose rust/vectors/x/Expected-Fail.txt 1 'Expected-Fail\.txt is oracle'
plant p0-oracle-jose rust/vectors/expected-fail/planted.json 1 'planted\.json is oracle'
plant p0-oracle-jose rust/vectors/exam/planted.json 1 'planted\.json is oracle'
plant p0-oracle-jose rust/vectors/x/EXAM/planted.json 1 'planted\.json is oracle'
plant p0-oracle-jose rust/vectors/.gitattributes 1 '\.gitattributes is oracle'
plant p0-oracle-jose rust/vectors/x/.GitAttributes 1 '\.GitAttributes is oracle'
plant p0-oracle-jose rust/vectors/x/link.json 1 'link\.json is a symlink' symlink
plant p0-oracle-jose rust/vectors/x/sub 1 'sub is a gitlink' gitlink
plant p0-oracle-jose rust/jose/src/planted.rs 1 'planted\.rs is outside its globs'
plant p0-oracle-jose rust/Cargo.toml 1 'Cargo\.toml is outside its globs'
plant p0-oracle-jose rust/Cargo.lock 1 'Cargo\.lock is outside its globs'
plant p0-oracle-jose rust/jose/public-api.txt 1 'public-api\.txt is outside its globs'
plant p0-oracle-jose primitives/rows.json 1 'rows\.json is oracle'
plant p0-oracle-jose primitives/queue.json 1 'queue\.json is outside its globs'
plant p0-oracle-jose .gitlab-ci.yml 1 '\.gitlab-ci\.yml is outside its globs'
plant p0-oracle-nosuch rust/vectors/x/planted.json 1 'no item p0-oracle-nosuch'
plant p0-oraclex rust/vectors/x/planted.json 1 'planted\.json is oracle'
# every other item finds rust/vectors/* oracle, and keeps the Cargo.lock and public-api.txt exception
plant jose-lane rust/vectors/x/planted.json 1 'planted\.json is oracle'
plant jose-lane rust/vectors/x/expected-fail.txt 1 'expected-fail\.txt is oracle'
plant jose-lane rust/Vectors/x/planted.json 1 'planted\.json is oracle'
plant jose-lane rust/Cargo.lock 0 'all 1 paths changed since [0-9a-f]+ are its own'
plant jose-lane rust/jose/public-api.txt 0 'all 1 paths changed since [0-9a-f]+ are its own'
plant jose-lane "${jlane%\*}planted.rs" 0 'all 1 paths changed since [0-9a-f]+ are its own'
[ "$bad" = 0 ] || exit 1
echo "own-plants: $n plants judged as wanted"
