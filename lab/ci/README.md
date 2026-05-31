# CI lab

QEMU-runner-driven substrate validation. Replaces the static
`lab/compose/` flow (which is now legacy — see `lab/compose/README.md`).

## How it works

GitLab CI dispatches a job tagged `[carmine, qemu]` to the carmine
GitLab Runner. The runner's Custom Executor spawns a per-job ephemeral
Fedora VM (qcow2 linked clone from the `baser` golden, which pre-bakes
podman + podman-docker + skopeo + jq + curl). The job script runs
INSIDE the VM as the `fedora` user.

Inside the VM, `lab/ci/validate.sh`:

1. Generates per-run substrate secrets (`gen-secrets.sh > .env`)
2. Logs in to the GitLab registry using `$CI_REGISTRY_USER` +
   `$CI_REGISTRY_PASSWORD` (auto-injected by GitLab)
3. `docker compose up -d` (podman-docker bridge translates to podman)
4. Waits for healthchecks on postgres + kratos + hydra + consent + portal
5. Runs `smoke.sh` against each substrate endpoint
6. Tears down

VM dies on job end. Total turnaround: ~3-5 minutes including image
pulls.

## What it validates

- Postgres up; kratos + hydra databases exist; uuid-ossp extension
  on hydra.
- Kratos admin + public health.
- Hydra admin health + public openid-configuration with issuer
  byte-match + jwks.json RS256.
- Consent + portal healthz.
- apply-clients runs (auth-util image) and registers every yaml in
  `hydra/clients/` against Hydra admin; specific clients (keep,
  tailscale) verified.
- Identity create via Kratos admin API + metadata_admin.groups
  round-trip.
- Recovery-gate webhook semantics: admin → 403 (HIGH-3),
  non-admin → 200, empty groups → 403 (LOW-5), wrong secret → 403
  (MEDIUM-2).

## What it does NOT validate

- TLS / Caddy / production DNS. Substrate runs HTTP-only inside the
  compose network. Production-shape TLS validation is manual lab
  work (or a future iteration of this lab that wires Caddy with
  `tls internal`).
- Browser-driven OIDC flows. Playwright suite at `lab/tests/` is
  the harness for that; the CI lab focuses on substrate health.
- Apps registry tile dashboard rendering. Portal tests at
  `portal/scripts/*.test.mjs` cover the MD frontmatter shape; the
  full UI rendering is browser-driven.

## Files

| File | Purpose |
|---|---|
| `compose.yml` | docker-compose for the Topology B substrate |
| `kratos.yml` | Kratos config with `${LAB_DOMAIN}` substitution |
| `hydra.yml` | Hydra config (lab-shape: HTTP issuer, expose_internal_errors=true) |
| `identity.schema.json` | Production identity schema, vendored |
| `recovery-gate.jsonnet` | Recovery-gate webhook body, vendored |
| `glauth.cfg` | LDAP bridge config (debug mode) |
| `postgres-init.sh` | DB + extension setup |
| `gen-secrets.sh` | Per-run secret generator |
| `smoke.sh` | Probe matrix (pass/fail counters) |
| `validate.sh` | Top-level orchestrator |

## Local operator invocation

```sh
# Requires: podman, docker-compose-compat or podman-compose, registry login
cd lab/ci
AUTH_VERSION=latest bash validate.sh
```

If a probe fails, container logs land at `/tmp/lab-smoke-failure.log`.

## CI invocation

`.gitlab-ci.yml`'s `lab-validate` job. Tagged `[carmine, qemu]`.
Depends on the four `build-*` jobs so the just-built images are
pulled at `${CI_COMMIT_SHA}`. Gates the package + release stages.

## When to evolve

When the first Ory upgrade lands, this lab validates the substrate
in CI before the bump reaches carmine. The smoke matrix should grow
with each Ory-surface-change we want to catch — e.g., when v27 lands
with a new admin API endpoint shape, add a probe.

For browser-flow validation, layer Playwright on top later. Today
the substrate-up matrix is the high-leverage piece.
