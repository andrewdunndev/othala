# auth-util

One-shot operator container. Carries the toolchain
(curl + jq + yq + bash) needed to register OIDC client manifests with
the auth-hydra admin API on carmine.

## Why this exists

Hydra's admin port (4445) is `auth.network`-internal. The operator
workstation can't reach it directly without exposing the admin port
publicly — explicitly out-of-policy. Instead, we run a small
short-lived container ON the auth network that does the registration
and exits.

This image carries no application logic. It's a runner.

## What it does

The default command is `apply-clients`, which:

1. Walks `$CLIENTS_DIR/*.yaml` (default: `/etc/util/manifests/`).
2. Validates each yaml has the `oidc:` and `consent:` namespace split.
3. POSTs (new) or PUTs (existing) the `oidc:` block to
   `${HYDRA_ADMIN_URL}/admin/clients`. Idempotent.
4. Reads each `<CLIENT_ID>_CLIENT_SECRET` env var and injects it as
   `client_secret` in the POST body (capitalisation matches the
   client_id uppercase).
5. Optionally runs `$CONSENT_RELOAD_HOOK` after success (SIGHUP to
   consent on the same pod / network).

## How iac uses it

The iac repo provides the operator-facing make target:

```
make auth-apply-clients HOST=carmine
```

Under the hood (in `dunn.dev/iac/Makefile`):

```sh
podman run --rm --network=auth \
  -v /var/srv/auth/consent/manifests:/etc/util/manifests:ro \
  -e HYDRA_ADMIN_URL=http://auth-hydra:4445 \
  -e KEEP_CLIENT_SECRET="$(sops -d ... carmine.keep_oidc_client_secret)" \
  -e OBSERVE_CLIENT_SECRET="$(sops -d ... carmine.observe_oidc_client_secret)" \
  registry.gitlab.com/dunn.dev/auth/util:v0.1.4
```

Each new OIDC consumer added later is one new yaml + one new sops
entry + one new `-e <SLUG>_CLIENT_SECRET=...` line.

## Image shape

UBI 9 minimal base. Tools installed via microdnf + pip:

- bash, curl, jq — package install
- python3 + pip → python-yq (kislyuk/yq, not mikefarah/yq) — matches
  the script's `yq -r '.oidc | type'` semantics

`apply-clients.sh` lands at `/usr/local/bin/apply-clients` and is
the default CMD.

## Adding new tools

If you need another one-shot operator script (e.g., a Kratos
identity-import tool, a Hydra OAuth2 client lister), add it under
`util/<tool>.sh`, install it in the Containerfile to
`/usr/local/bin/`, and call it from iac via:

```sh
podman run --rm --network=auth … auth-util:vX <tool>
```

No need for a new image per script — the util image is a toolkit.

## Build + publish

CI builds + signs + SBOMs the image per tag, same shape as
consent / portal / ldap-bridge. See `.gitlab-ci.yml` "util" section.

## Local lab use

The lab compose stack and iac don't share network names. Bind the
util container to the lab compose stack's auto-created network and
mount the source-controlled manifests:

```sh
cd dunn.dev/auth/lab/compose
podman compose up -d
HYDRA_ADMIN_URL=http://localhost:4445 \
  KEEP_CLIENT_SECRET=lab-secret-value \
  podman run --rm \
    --network=compose_default \
    -v $(pwd)/../../hydra/clients:/etc/util/manifests:ro \
    -e HYDRA_ADMIN_URL \
    -e KEEP_CLIENT_SECRET \
    dunn.dev/auth-util:lab
```
