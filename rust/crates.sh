#!/usr/bin/env bash
# `crates.sh`: one JSON line per workspace member, in name order: its <dir>/gates.json plus its name. A member without
# gates.json, or whose directory is not its name, fails here so no recipe silently skips it.
# gates.json keys, each optional: published (canary), doc, ui (trybuild twins in tests/ui), api (public-api.txt),
# targets {triple: [cargo feature args]}, mutants {floor, tests: [packages], default the workspace},
# vectors [SOURCES.toml source names], allow [crates its graph adds to deny.toml's bans.allow].
set -euo pipefail
cd "$(dirname "$0")"
cargo metadata --locked --no-deps --format-version 1 | jq -r '.packages[] | "\(.name)\t\(.manifest_path)"' | sort |
    while IFS=$'\t' read -r name manifest; do
        dir=$(basename "$(dirname "$manifest")")
        [ "$dir" = "$name" ] || { echo "crates: member $name lives in $dir/; a member's directory is its name" >&2; exit 1; }
        [ -f "$name/gates.json" ] || { echo "crates: $name has no gates.json" >&2; exit 1; }
        jq -ce --arg name "$name" '(keys - ["published", "doc", "ui", "api", "targets", "mutants", "vectors", "allow"]) as $bad
            | if $bad == [] then . + {name: $name} else error("crates: \($name)/gates.json: unknown \($bad)") end' "$name/gates.json"
    done
