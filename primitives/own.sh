#!/usr/bin/env bash
# `own.sh ITEM`: fail when this branch's diff from main names a path outside ITEM's globs (rust/Cargo.lock excepted) or
# an oracle path (OWN_MAIN overrides origin/main). Globs and oracle patterns are bash patterns over repo-root paths, where * also crosses /.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
item=${1:?own: name an item}
q=primitives/queue.json
jq -e --arg id "$item" 'any(.items[]; .id == $id)' "$q" > /dev/null || { echo "own: no item $item in $q"; exit 1; }
mapfile -t globs < <(jq -r --arg id "$item" '.items[] | select(.id == $id) | .globs[]' "$q")
mapfile -t oracle < <(jq -r '.oracle[]' "$q")
base=$(git merge-base "${OWN_MAIN:-origin/main}" HEAD)
mapfile -t paths < <(git diff --name-only "$base")
bad=0
for p in "${paths[@]}"; do
    [ "$p" = rust/Cargo.lock ] && continue
    for o in "${oracle[@]}"; do [[ $p == $o ]] && { echo "own $item: $p is oracle"; bad=1; continue 2; }; done
    for g in "${globs[@]}"; do [[ $p == $g ]] && continue 2; done
    echo "own $item: $p is outside its globs"
    bad=1
done
[ "$bad" = 0 ] || exit 1
echo "own $item: all ${#paths[@]} paths changed since ${base:0:8} are its own"
