# othala: task recipes. `just setup` once, then `just test`.
# Local tools come from mise.toml (`mise install`); CI's image bakes just and node.

set shell := ["bash", "-euo", "pipefail", "-c"]

# list recipes
default:
    @just --list

# the node major mise.toml pins must be the one running; CI's image is graded here
[private]
node-guard:
    #!/usr/bin/env bash
    want=$(sed -n 's/^node = "\([0-9]*\).*/\1/p' mise.toml)
    have=$(node -p 'process.versions.node.split(".")[0]')
    [ "$want" = "$have" ] || { echo "node $have is running, mise.toml pins $want"; exit 1; }

# first-time install: the three npm trees, lockfile-exact, no install scripts
setup: node-guard
    npm ci --include=dev --ignore-scripts --prefix portal
    npm ci --include=dev --ignore-scripts --prefix e2e
    npm ci --include=dev --ignore-scripts --prefix site

# unit tests (vitest: src and scripts)
test:
    cd portal && npm test

# the CI check-portal sequence: astro check, tsc over e2e and site, vitest, manifest lint, YAML parse
check: node-guard
    cd portal && npm run check
    portal/node_modules/.bin/tsc --noEmit -p e2e
    portal/node_modules/.bin/tsc --noEmit -p site
    cd portal && npm test
    cd portal && npm run lint:manifests
    node scripts/check-yaml.mjs

# production bundle
build:
    cd portal && npm run build

# UI iteration without the full stack
dev:
    cd portal && npm run dev

# the purity gate, then bash -n over every tracked shell script
purity:
    bash scripts/check-purity.sh
    bash scripts/check-shell.sh

# the full stack from this working tree: build both images locally, then run the e2e harness
e2e:
    #!/usr/bin/env bash
    set -euo pipefail
    registry=localhost/othala
    version=local
    podman build -t "$registry:$version" -f portal/Containerfile .
    podman build -t "$registry/e2e-tester:$version" -f e2e/Containerfile e2e
    cd e2e
    AUTH_REGISTRY="$registry" AUTH_VERSION="$version" bash validate.sh

# one-shot custom-format pg_dump of the kratos and hydra databases into <dir>, from a running deploy/example stack
backup dir compose="deploy/example/compose.yml":
    #!/usr/bin/env bash
    set -euo pipefail
    umask 077
    mkdir -p "{{ dir }}"
    for db in kratos hydra; do
      docker compose -f "{{ compose }}" exec -T postgres pg_dump --username postgres --format custom --dbname "$db" > "{{ dir }}/$db.dump.partial"
    done
    for db in kratos hydra; do mv "{{ dir }}/$db.dump.partial" "{{ dir }}/$db.dump"; done

# favicon rasters from portal/public/favicon.svg (the repo-root favicon.svg): ico 16/32/48, touch icon 180 on white, manifest 192/512
icons:
    #!/usr/bin/env bash
    set -euo pipefail
    cd portal/public
    cp ../../favicon.svg favicon.svg
    t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
    for s in 16 32 48; do /opt/homebrew/bin/rsvg-convert -w $s -h $s favicon.svg -o "$t/$s.png"; done
    /opt/homebrew/bin/magick "$t/16.png" "$t/32.png" "$t/48.png" favicon.ico
    /opt/homebrew/bin/rsvg-convert -w 180 -h 180 -b white favicon.svg -o apple-touch-icon.png
    /opt/homebrew/bin/rsvg-convert -w 192 -h 192 favicon.svg -o icon-192.png
    /opt/homebrew/bin/rsvg-convert -w 512 -h 512 favicon.svg -o icon-512.png
