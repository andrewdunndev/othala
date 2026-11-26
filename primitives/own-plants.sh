#!/usr/bin/env bash
# `own-plants.sh`: judge planted branches of a scratch repo with own.sh (OWN_SH overrides this directory's) and require each plant's exact verdict,
# so an oracle item's admission and refusals are proved by running them, not by reading own.sh. Real queue.json, scratch history.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd -P)
own=${OWN_SH:-$here/own.sh}
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
cp "$queue" primitives/queue.json
git add -A
git commit -qm base
bad=0
n=0
plant() { # item, path, expected rc, then a regex the output must match
    local item=$1 path=$2 want=$3 re=$4 out rc
    n=$((n + 1))
    git checkout -q -b "plant$n" main
    mkdir -p "$(dirname "$path")"
    echo planted > "$path"
    git add -A
    git commit -qm "plant $n"
    out=$(OWN_MAIN=main bash primitives/own.sh "$item" 2>&1) && rc=0 || rc=$?
    git checkout -q main
    if [ "$rc" != "$want" ] || ! grep -Eq "$re" <<< "$out"; then
        echo "own-plants: $item over $path gave rc $rc [$out], wanted rc $want matching /$re/"
        bad=1
    fi
}
plant p0-oracle-jose rust/vectors/x/planted.json 0 'all 1 paths changed since [0-9a-f]+ are its own'
plant p0-oracle-jose rust/vectors/x/expected-fail.txt 1 'expected-fail\.txt is oracle'
plant p0-oracle-jose rust/vectors/expected-fail/planted.json 1 'planted\.json is oracle'
plant p0-oracle-jose rust/vectors/exam/planted.json 1 'planted\.json is oracle'
plant p0-oracle-jose rust/jose/src/planted.rs 1 'planted\.rs is outside its globs'
plant p0-oracle-jose rust/Cargo.toml 1 'Cargo\.toml is outside its globs'
plant p0-oracle-jose primitives/rows.json 1 'rows\.json is oracle'
plant p0-oracle-jose primitives/queue.json 1 'queue\.json is outside its globs'
plant p0-oracle-jose .gitlab-ci.yml 1 '\.gitlab-ci\.yml is outside its globs'
plant p0-oracle-nosuch rust/vectors/x/planted.json 1 'no item p0-oracle-nosuch'
plant jose-lane rust/vectors/x/planted.json 1 'planted\.json is oracle'
plant jose-lane rust/vectors/x/expected-fail.txt 1 'expected-fail\.txt is oracle'
plant jose-lane "${jlane%\*}planted.rs" 0 'all 1 paths changed since [0-9a-f]+ are its own'
[ "$bad" = 0 ] || exit 1
echo "own-plants: $n plants judged as wanted"
