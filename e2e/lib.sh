# Shared by validate.sh, smoke.sh and upgrade.sh.

# Prefer the rootful podman socket: postgres chowns PGDATA as real root, which fails rootless.
# Set both DOCKER_HOST and CONTAINER_HOST so compose, login and logs share one store.
if [[ -z "${DOCKER_HOST:-}" && -S /run/podman/podman.sock ]]; then
  export DOCKER_HOST="unix:///run/podman/podman.sock"
  export CONTAINER_HOST="unix:///run/podman/podman.sock"
  echo "  rootful podman socket detected → DOCKER_HOST/CONTAINER_HOST=/run/podman/podman.sock"
fi

# podman-compose prepends an ANSI reset to the first line of exec output, which breaks
# JSON parses and string compares; _strip_ansi is a no-op under docker.
_strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }

# node_in <container>: run a JS program from STDIN inside <container>'s node (podman-compose
# mangles argv with spaces/quotes). othala has no wget/curl, so its probes route here.
node_in() {
    local container="$1"
    docker compose exec -T "$container" node 2>/dev/null | _strip_ansi
}

# run_dance <subject> -> the result line (OK claims=... / DENIED... / STEP/EXC). Pipes
# oidc-dance.mjs with the subject and grafana client secret into the dance-runner oneshot;
# grafana is the role-mapping client whose consent block emits grafana_role.
run_dance() {
    local out res
    out=$(sed "s|__SUBJECT__|$1|g; s|__GRAFANA_SECRET__|${GRAFANA_CLIENT_SECRET}|g" ./oidc-dance.mjs \
        | docker compose --profile oneshot run --rm --no-deps -T dance-runner 2>&1 | _strip_ansi)
    res=$(echo "$out" | grep -E '^OK |^DENIED|^STEP|^EXC' | tail -1)
    if [[ -z "$res" ]]; then
        # No result line means the dance crashed; surface the full output.
        echo "  ----- dance produced no OK/DENIED/STEP/EXC line; full output: -----" >&2
        echo "$out" | sed 's/^/    | /' | tail -45 >&2
        echo "  ----- end dance output -----" >&2
    fi
    echo "$res"
}

# Registry login (skipped when the CI vars are absent, for local runs).
registry_login() {
    if [[ -n "${CI_REGISTRY_USER:-}" && -n "${CI_REGISTRY_PASSWORD:-}" ]]; then
        echo "  podman login to $AUTH_REGISTRY..."
        echo "$CI_REGISTRY_PASSWORD" | podman login --username "$CI_REGISTRY_USER" --password-stdin "${AUTH_REGISTRY%%/*}"
    fi
}

# gen_secrets <version>: a deployer's secrets.env, the image's gen-secrets over the content (mints each client secret).
gen_secrets() {
    podman run --rm -v "$PWD/content:/etc/othala:ro,z" "$AUTH_REGISTRY:$1" node dist/server/config.mjs gen-secrets
}

# smoke.sh reads the same values the containers get; read literally, as compose does.
load_env() {
    while IFS= read -r line; do export "$line"; done < <(grep -hE '^[A-Za-z_][A-Za-z0-9_]*=' othala.env secrets.env)
}

# up_and_wait: bring the stack up and wait until the substrate and the edge answer; exits 1 with diagnostics.
up_and_wait() {
    # Wrapped in a timeout: a never-healthy dependency makes `up -d` block until the CI limit.
    echo "  docker compose up (timeout 300s)..."
    if ! timeout 300 docker compose up -d; then
        echo "  ✗ compose up failed or timed out — diagnostics:"
        docker compose ps || true
        docker compose logs --tail=120 || true
        exit 1
    fi

    # Step 4: wait for healthy
    echo "  waiting for healthchecks (max 240s)..."
    DEADLINE=$(($(date +%s) + 240))
    while true; do
        if [[ $(date +%s) -gt $DEADLINE ]]; then
            echo "  ✗ healthcheck timeout"
            docker compose ps
            # Native `podman logs`: the compose logs shim is unreliable and /tmp is not an artifact.
            echo "=== container logs (healthcheck timeout) ==="
            for svc in render postgres kratos-migrate kratos hydra-migrate hydra othala mailpit caddy; do
                echo "--- lab-$svc ---"
                podman logs --tail=60 "lab-$svc" 2>&1 || true
            done
            exit 1
        fi
        # Count "(healthy)" in plain `ps` output: podman-compose's JSON shape differs from docker's,
        # so a JSON parser counts 0 and times out.
        healthy=$(docker compose ps 2>/dev/null | grep -c '(healthy)')
        # Expect 5 long-runners: postgres, kratos, hydra, othala, mailpit.
        if [[ "${healthy:-0}" -ge 5 ]]; then
            echo "  ✓ substrate healthy ($healthy/5 long-runners up)"
            break
        fi
        sleep 5
    done

    # The edge has no healthcheck. Smoke and the browser run enter through it (the portal reaches Kratos and
    # Hydra directly on the internal network), so wait until it answers.
    for _ in $(seq 1 30); do
        (exec 3<>/dev/tcp/127.0.0.1/8443) 2>/dev/null && break
        sleep 2
    done
}
