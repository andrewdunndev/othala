# Othala end-to-end harness

`docker compose` stack (Postgres, Kratos, Hydra, the othala app, Mailpit) plus a
smoke matrix and Playwright specs. It is the release gate and a worked adopter
example: the same `compose.yml` and `validate.sh` run in CI and on a workstation.
Topology, ports and the check sequence are in the headers of `compose.yml`,
`validate.sh` and `smoke.sh`. There is no TLS in the smoke path.

## Run the smoke matrix

```sh
# Requires: podman, docker-compose-compat or podman-compose
cd e2e
AUTH_VERSION=latest bash validate.sh
```

## Build the image from current source

`validate.sh` also runs the Playwright specs. A stale image gives false results.

```sh
# from the repo root
podman build -t registry.gitlab.com/dunn.dev/othala:lab -f portal/Containerfile .
```

## CI

The `e2e` job runs on a QEMU runner selected by the project CI/CD variable
`E2E_RUNNER_TAG` (unprotected, unmasked, no default); set it to your runner's
label or the job sits pending forever.
