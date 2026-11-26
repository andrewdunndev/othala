#!/usr/bin/env bash
# `own.sh ITEM`: fail when this branch's diff from main names a path outside ITEM's globs (rust/Cargo.lock and each rust/*/public-api.txt excepted: both are regenerated at integration and checked by their gates) or
# an oracle path (OWN_MAIN overrides origin/main). Globs and oracle patterns are bash patterns over repo-root paths, where * also crosses /.
# The queue is read from the merge base, never the branch, so a branch cannot widen its own globs; CI runs the base's own.sh.
# It judges commits only, merge base against HEAD, so an LFS-filtered checkout cannot read as a change; uncommitted edits are ignored.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
item=${1:?own: name an item}
base=$(git merge-base "${OWN_MAIN:-origin/main}" HEAD)
q=primitives/queue.json
# a base with no queue is the one that introduces it, so there is nothing yet to protect
if git cat-file -e "$base:$q" 2> /dev/null; then queue=$(git show "$base:$q"); else queue=$(cat "$q"); fi
jq -e --arg id "$item" 'any(.items[]; .id == $id)' <<< "$queue" > /dev/null || { echo "own: no item $item in $q at ${base:0:8}"; exit 1; }
mapfile -t globs < <(jq -r --arg id "$item" '.items[] | select(.id == $id) | .globs[]' <<< "$queue")
mapfile -t oracle < <(jq -r '.oracle[]' <<< "$queue")
if [ "$item" = p0-spine ]; then
    # p0-spine owns primitives/*, rows.json included; every other item treats rows.json as oracle
    mapfile -t oracle < <(printf '%s\n' "${oracle[@]}" | grep -vxF primitives/rows.json || true)
else
    # the ownership gate and the queue are the spine's: no other item may rewrite what checks it
    oracle+=(primitives/queue.json 'primitives/*.sh' .gitlab-ci.yml)
fi
mapfile -d '' -t paths < <(git diff --name-only --no-renames -z "$base" HEAD)
bad=0
for p in "${paths[@]}"; do
    case "$p" in rust/Cargo.lock | rust/*/public-api.txt) continue ;; esac
    for o in "${oracle[@]}"; do [[ $p == $o ]] && { echo "own $item: $p is oracle"; bad=1; continue 2; }; done
    for g in "${globs[@]}"; do [[ $p == $g ]] && continue 2; done
    echo "own $item: $p is outside its globs"
    bad=1
done
[ "$bad" = 0 ] || exit 1
echo "own $item: all ${#paths[@]} paths changed since ${base:0:8} are its own"
