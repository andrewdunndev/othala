# Othala end-to-end harness

A deployment of [`deploy/example/`](../deploy/example/) and the release gate. `validate.sh` copies in
its `compose.yml`, mints `secrets.env` with the image's `gen-secrets` and layers `compose.e2e.yml`, a
test-only overlay outside the deployment contract, then runs `smoke.sh` and the Playwright specs.

## Run the smoke matrix

```sh
# Requires: podman, docker-compose-compat or podman-compose
just e2e   # from the repo root
```

`just e2e` builds the portal and e2e-tester images from this working tree before it runs `validate.sh`, so
the specs and the product under test are the checked-out ones. To validate a published image instead:
`cd e2e && AUTH_VERSION=<tag> bash validate.sh`.

`smoke.sh` section I assumes the compose container store (it runs `podman run --volumes-from lab-render`) and fails loudly if the store differs.

## CI

The `e2e` job runs on a QEMU runner selected by the project CI/CD variable
`E2E_RUNNER_TAG` (unprotected, unmasked, no default); set it to your runner's
label or the job sits pending forever.
