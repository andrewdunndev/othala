#!/usr/bin/env bash
# `check.sh`: queue.json and rows.json hold their schema, ids are unique, each item's rows and deps exist, and deps are acyclic.
set -euo pipefail
cd "$(dirname "$0")"
errors=$(jq -nr --slurpfile q queue.json --slurpfile r rows.json '
    def str: type == "string" and length > 0 and (test("\n") | not);
    def strs: type == "array" and all(.[]; str);
    def milestone: str and test("^M[0-7]$");
    $r[0] as $rows | $q[0] as $q | ($rows | map(.id)) as $rids | ($q.items | map(.id)) as $ids
    | def settle($done): [$q.items[] | select((.id | IN($done[])) | not) | select(all(.deps[]; IN($done[]))) | .id] as $n
        | if $n == [] then $done else settle($done + $n) end;
    ( $rows | select(length == 0) | "rows.json: no rows" ),
    ( $rows[] | select(keys != ["cmd", "id", "milestone", "title"] or ([.id, .title, .cmd] | strs | not) or (.milestone | milestone | not))
        | "row \(.id // tojson): wants exactly id, milestone (M0 to M7), title and cmd, each one line" ),
    ( $q | select(keys != ["items", "oracle"] or (.oracle | strs | not)) | "queue.json: wants exactly oracle (patterns) and items" ),
    ( $q.items[] | select(keys != ["deps", "globs", "id", "milestone", "model", "rows", "state", "title"]
        or ([.id, .title] | strs | not) or (.id | test("^[a-z0-9][a-z0-9-]*$") | not) or (.milestone | milestone | not)
        or ([.rows, .globs, .deps] | all(.[]; strs) | not)
        or (.state | IN("ready", "running", "review", "landed", "parked", "needs_decision") | not) or (.model | IN("sonnet", "opus") | not))
        | "item \(.id // tojson): wants exactly id ([a-z0-9-]), milestone, rows, globs, deps, state, model and title" ),
    ( $rids, $ids | group_by(.)[] | select(length > 1) | "duplicate id \(.[0])" ),
    ( $q.items[] | .id as $i | ((.rows - $rids)[] | "item \($i): no row \(.)"), ((.deps - $ids)[] | "item \($i): no item \(.)") ),
    ( $ids - settle([]) | select(length > 0) | "deps never settle: \(join(", "))" )')
[ -z "$errors" ] || { echo "$errors"; exit 1; }
echo "queue: $(jq '.items | length' queue.json) items and $(jq length rows.json) rows hold"
