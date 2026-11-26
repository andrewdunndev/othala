#!/usr/bin/env bash
# `crates.sh`: one JSON line per workspace member, in name order: its <dir>/gates.json plus its name. A member without
# gates.json, or whose directory is not its name, fails here so no recipe silently skips it.
# gates.json keys, each optional: published (canary), doc, ui (trybuild twins in tests/ui), api (public-api.txt),
# targets {triple: [cargo feature args]}, mutants {floor, tests: [packages], default the workspace},
# vectors [SOURCES.toml source names], allow [crates its graph adds to deny.toml's bans.allow],
# expose [src modules that read secrets, R-j; a member with a direct dependency on the expose crate, base apart, must name them, and the canary checks both ways].
set -euo pipefail
# the one rule for a mutants floor: a crate with a mutants key names a non-negative integer, spelled as digits only;
# `crates.sh --floor` applies it to one gates.json on stdin (exit 0 when it holds), for the recipes that read other revisions
floor_ok='def floor_ok: if has("mutants") then (.mutants | type == "object") and (.mutants.floor | tojson | test("^[0-9]+$")) else true end;'
if [ "${1:-}" = "--floor" ]; then exec jq -e "$floor_ok floor_ok" > /dev/null; fi
cd "$(dirname "$0")"
cargo metadata --locked --no-deps --format-version 1 | jq -r '.packages[] | "\(.name)\t\(.manifest_path)"' | sort |
    while IFS=$'\t' read -r name manifest; do
        dir=$(basename "$(dirname "$manifest")")
        [ "$dir" = "$name" ] || { echo "crates: member $name lives in $dir/; a member's directory is its name" >&2; exit 1; }
        [ -f "$name/gates.json" ] || { echo "crates: $name has no gates.json" >&2; exit 1; }
        jq -ce --arg name "$name" "$floor_ok"'(keys - ["published", "doc", "ui", "api", "targets", "mutants", "vectors", "allow", "expose"]) as $bad
            | if $bad != [] then error("crates: \($name)/gates.json: unknown \($bad)") else . end
            | if floor_ok then . + {name: $name} else error("crates: \($name)/gates.json: mutants.floor must be a non-negative integer") end' "$name/gates.json"
    done
