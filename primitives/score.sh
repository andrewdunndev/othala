#!/usr/bin/env bash
# `score.sh`: run each rows.json command from rust/ in file order and print its id, milestone and PASS or FAIL, then
# per-milestone totals. Green is exit 0 with no `running 0 tests` line, so a missing crate, test or filter is red.
# Each row's output goes to <target>/score/<id>.log; nothing timed or unordered reaches stdout.
set -euo pipefail
cd "$(dirname "$0")/../rust"
rows=../primitives/rows.json
logs=${CARGO_TARGET_DIR:-target}/score
mkdir -p "$logs"
out=$(for i in $(seq 0 $(($(jq length "$rows") - 1))); do
    IFS=$'\t' read -r id milestone < <(jq -r --argjson i "$i" '.[$i] | "\(.id)\t\(.milestone)"' "$rows")
    if bash -c "$(jq -r --argjson i "$i" '.[$i].cmd' "$rows")" > "$logs/$id.log" 2>&1 < /dev/null && ! grep -q '^running 0 tests' "$logs/$id.log"; then
        echo "$id $milestone PASS"
    else
        echo "$id $milestone FAIL"
    fi
done)
echo "$out"
awk '{ n[$2]++; p[$2] += $3 == "PASS" } END { for (m in n) print m, p[m] "/" n[m] }' <<< "$out" | LC_ALL=C sort
awk '{ n++; p += $3 == "PASS" } END { print "total", p "/" n }' <<< "$out"
