#!/usr/bin/env bash
# bash -n over every tracked shell script. Reads the git index, like check-purity.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

files=()
while IFS= read -r -d '' f; do files+=("$f"); done < <(git ls-files -z -- '*.sh')
if [ "${#files[@]}" -eq 0 ]; then
  echo "ERROR: 0 tracked .sh files, bash -n would check nothing"
  exit 1
fi

rc=0
for f in "${files[@]}"; do
  bash -n "$f" || { echo "FAIL: bash -n $f"; rc=1; }
done
[ "$rc" -eq 0 ] && echo "OK: bash -n clean on ${#files[@]} scripts"
exit "$rc"
