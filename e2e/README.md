# Othala end-to-end harness

A deployment of [`deploy/example/`](../deploy/example/) and the release gate. `validate.sh` copies in
its `compose.yml`, mints `secrets.env` with the image's `gen-secrets` and layers `compose.e2e.yml`, a
test-only overlay outside the deployment contract, then runs `smoke.sh` and the Playwright specs.

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
