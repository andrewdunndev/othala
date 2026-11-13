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

# one-shot dump of the identity database from a running deploy/example stack into <out>
backup out compose="deploy/example/compose.yml":
    #!/usr/bin/env bash
    set -euo pipefail
    docker compose -f "{{ compose }}" exec -T postgres pg_dump --username postgres --dbname kratos > "{{ out }}.partial"
    mv "{{ out }}.partial" "{{ out }}"
