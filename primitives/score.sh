#!/usr/bin/env bash
# `score.sh`: run each rows.json command from rust/ in file order and print its id, milestone and PASS or FAIL, then
# per-milestone totals. Green is exit 0 (pipes included) and, for a cargo test row, a `test result: ok. N passed` line with
# N >= 1 and no line with an ignored test, so a missing crate, filter or an all-#[ignore] row is red.
# Each row's output goes to <target>/score/<id>.log; nothing timed or unordered reaches stdout.
set -euo pipefail
cd "$(dirname "$0")/../rust"
rows=../primitives/rows.json
logs=${CARGO_TARGET_DIR:-target}/score
mkdir -p "$logs"
green() { # a cargo test row needs a passed count of 1 or more on some result line and no ignored tests; any other row, exit 0
    [[ $2 == *'cargo test'* ]] || return 0
    grep -qE '^test result: ok\. [1-9][0-9]* passed' "$1" && ! grep -qE '^test result: .*; [1-9][0-9]* ignored' "$1"
}
out=$(for i in $(seq 0 $(($(jq length "$rows") - 1))); do
    IFS=$'\t' read -r id milestone < <(jq -r --argjson i "$i" '.[$i] | "\(.id)\t\(.milestone)"' "$rows")
    cmd=$(jq -r --argjson i "$i" '.[$i].cmd' "$rows")
    if bash -o pipefail -c "$cmd" > "$logs/$id.log" 2>&1 < /dev/null && green "$logs/$id.log" "$cmd"; then
        echo "$id $milestone PASS"
    else
        echo "$id $milestone FAIL"
    fi
done)
echo "$out"
awk '{ n[$2]++; p[$2] += $3 == "PASS" } END { for (m in n) print m, p[m] "/" n[m] }' <<< "$out" | LC_ALL=C sort
awk '{ n++; p += $3 == "PASS" } END { print "total", p "/" n }' <<< "$out"
