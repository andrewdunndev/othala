# Lab compose (LEGACY)

This directory contains the Phase 3 lab compose stack that validated the
substrate end-to-end on a single VM. It is preserved for historical
evidence (Phase 3 GREEN runs documented in `../docs/`) but is **not the
primary lab path going forward**.

## Why legacy

Production now runs Topology B (single FQDN at `auth.dunn.dev`). This
compose stack is still on Topology A (auth-lab + home-lab + keep-lab
subdomains). It works for substrate-up smoke validation but the
production-shape OIDC redirect flow it exercises is the old shape.

## Replacement

A QEMU-CI lab is the next work stream. Shape:

- A GitLab CI job runs on the carmine GitLab Runner.
- The job spins up a QEMU VM in the lab VLAN, installs podman, and
  brings up the auth substrate via the same quadlet files iac uses
  on carmine.
- A smoke suite hits openid-configuration, exercises the OIDC flow,
  asserts the WebFinger byte-match (against a temporary apex stub),
  and tears the VM down.

This delivers what static compose can't:

- Production-shape (quadlets, not compose) validation
- Reproducible-via-CI every Renovate / push / MR
- Cheap re-validation on Ory upgrades (the substrate up-and-smoke
  cycle is ~3-5 minutes on carmine's spare capacity)

See `../qemu-ci-lab.md` for the implementation plan.

## Until then

This compose stack stays available for manual smoke testing:

```sh
cd lab/compose
cp .env.example .env
# fill in secrets per lab/scripts/gen-secrets.sh
podman compose up -d
```

But: don't extend it. New flow validations go in the QEMU-CI lab.

## What's here

| File | Purpose |
|---|---|
| `compose.yml` | Phase 3 full substrate (Kratos + Hydra + Postgres + consent + portal + Vaultwarden + Caddy) |
| `compose-ldap.yml` | Phase 2 narrow substrate (Kratos + glauth-kratos + Caddy) for LDAP-only validation |
| `Caddyfile` | auth-lab + home-lab + keep-lab routing (Topology A shape) |
| `Caddyfile.ldap` | Phase 2 Caddyfile (Kratos + reference UI only) |
| `kratos.lab.yml` | Lab Kratos config (passwords-only, registration enabled, smaller TTLs) |
| `hydra.lab.yml` | Lab Hydra config (reference consent app fallback) |
| `glauth.cfg` | LDAP bridge lab config (debug=true) |
| `postgres-init.sh` | Same init script production uses (vendored copy lives in `dunn.dev/iac/services/auth/postgres/`) |
| `identity.schema.json` | Lab identity schema (mirrors production with shorter passwords) |
