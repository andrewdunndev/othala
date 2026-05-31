# QEMU-CI lab — design + implementation plan

Status: not yet implemented. Tracked as the replacement for the static
`lab/compose/` stack which is now legacy.

## Why

Static `lab/compose/` worked for Phase 3 substrate validation but:

1. It runs Topology A (auth-lab / home-lab / keep-lab subdomains).
   Production is Topology B (auth.dunn.dev only). Lab-to-prod drift
   is real and lab evidence stops mapping cleanly to production shape.
2. It's not exercisable from CI — every validation is an operator
   running `podman compose up` on a workstation. Renovate MRs don't
   trigger end-to-end validation.
3. It uses compose, not quadlets. Production uses quadlets. The
   compose-to-quadlet translation isn't lossless (network defaults,
   userns, secrets shape).

A CI-driven lab fixes all three. The right shape:

- **GitLab CI job** that runs on the carmine GitLab Runner (already
  provisioned in iac for the dunn.dev runner pool).
- **QEMU VM** spawned inside carmine's `lab` libvirt network (172.22.10.0/24).
- **Real podman + quadlets** on the VM — the same .container files iac
  ships to carmine on real deploy.
- **Smoke suite** validates the substrate up-and-running.
- **Teardown** drops the VM after each run.

Total turnaround target: 5 minutes per CI invocation.

## Topology

```
                           GitLab.com (push / MR / Renovate / tag)
                                  │
                                  ▼ webhook
                           carmine GitLab Runner
                              (lab-validate job)
                                  │
                                  │ virsh
                                  ▼
                           QEMU VM in 172.22.10.0/24 (carmine lab network)
                              - Fedora bootc (basef minimal image)
                              - podman + quadlets installed
                              - auth substrate brought up via iac copies
                                 of services/auth/.config/containers/systemd/
                              - smoke suite hits:
                                * auth.lab/.well-known/openid-configuration
                                * auth.lab/.well-known/jwks.json (issuer byte-match)
                                * auth-hydra:4445/admin/clients (via auth-util)
                                * auth-kratos:4434/admin/identities (via portal SSR mock)
                                * dunn.dev apex WebFinger stub
                              - VM torn down on completion (success or fail)
```

## Why on carmine, not on shared runners

The shared GitLab runner pool can't do nested virt or persistent
podman state without per-job overhead we can't justify. carmine has
spare capacity, a real KVM hypervisor, and the lab VLAN already
provisioned (per iac's earlier work on the gitlab-runner VM pool).
This is the highest-leverage use of carmine's idle cycles.

## Components

### `lab/ci/setup.sh`

- Pull the basef-minimal image from the registry.
- Use `cloud-localds` or `virt-builder` to inject:
  - SSH keys (transient; new pair per run)
  - cloud-init that installs podman + sets up auth user
  - The auth quadlets (rsynced from `dunn.dev/iac/services/auth/`)
  - The auth project's hydra/clients/*.yaml (mounted volume)
  - Generated random secrets for kratos, hydra, etc.
- Boot the VM. Wait for SSH.
- Apply: `podman secret create` for each Hydra/Kratos secret, then
  `systemctl --user start auth-*.service`.
- Wait for healthchecks (timeout 120s).

### `lab/ci/test.sh`

End-to-end smoke matrix. Each assertion is a single curl + match:

```
auth-lab.<ip>/.well-known/openid-configuration -> issuer matches expected
auth-lab.<ip>/.well-known/jwks.json -> jwks.alg = RS256
auth-lab.<ip>/oauth2/auth -> 302 with login_challenge
auth-lab.<ip>/login?login_challenge=... -> redirects to portal /auth/login
auth-lab.<ip>/auth/login -> Kratos session API works
auth-portal:8080/healthz -> 200
auth-consent:4477/healthz -> 200
auth-hydra:4445/admin/clients -> 200 with apply-clients-registered set
```

Plus the apex WebFinger stub: a temporary Worker dev fixture (cf wrangler
dev) serving the JRD; the smoke matrix asserts byte-match between the
Worker fixture's response and Hydra's `urls.self.issuer`.

### `lab/ci/teardown.sh`

`virsh destroy && virsh undefine` for the VM. The QEMU snapshot
volume is on a dedicated zpool dataset so cleanup is cheap.

### `.gitlab-ci.yml` — `lab-validate` job

Runs on push, MR, tag, AND a nightly schedule:

```yaml
lab-validate:
  stage: verify
  image: registry.access.redhat.com/ubi9-minimal:9.8
  tags: [carmine-host]   # custom runner tag exposing libvirt access
  variables:
    LAB_VM_NAME: auth-lab-${CI_PIPELINE_ID}
  before_script:
    - microdnf install -y libvirt-client virt-install openssh-clients curl jq
  script:
    - ./lab/ci/setup.sh
    - ./lab/ci/test.sh
  after_script:
    - ./lab/ci/teardown.sh
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == "main"'
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
    - if: '$CI_COMMIT_TAG'
```

## Carrying the iac quadlets into the lab

Two options:

1. **Git submodule** — `lab/ci/iac/` is a submodule pointed at
   `dunn.dev/iac`. The lab uses whatever revision is pinned.
   Pro: explicit dependency. Con: submodule UX.

2. **CI download** — `lab/ci/setup.sh` does
   `git clone --depth=1 ... dunn.dev/iac /tmp/iac` against the
   shared GitLab token. Pro: no submodule. Con: indirection.

Option 2 starts simpler. Migrate to a submodule if iac-version drift
causes problems.

## QEMU VM image

Use the carmine `basef-minimal` image (Fedora bootc, no extra packages).
cloud-init installs podman + curl + jq at first boot. Total VM boot to
ready-for-deploy: ~30 seconds.

If basef-minimal isn't built yet, fallback is Fedora 40 cloud image with
`dnf install -y podman` in cloud-init. Adds ~30 more seconds.

## Secrets in CI

Two cohorts:

1. **Substrate secrets** — kratos_cookie, hydra_system, postgres_password.
   Generated per-run via `openssl rand`. Never persisted. The VM dies;
   the secrets die with it.

2. **Apex WebFinger fixture** — runs via `wrangler dev` on the runner.
   No real CF credentials needed; fixture is local-only.

3. **Client secrets for apply-clients** — also generated per-run. The
   lab doesn't validate consumer apps (no Vaultwarden, no Grafana);
   it validates the substrate. So per-run randomness is fine.

The QEMU VM has no access to production sops. Lab is fully isolated.

## Timeline + sizing

- Image bring-up: 30-45s
- Substrate bring-up (quadlets up + healthchecks): 60-90s
- Smoke matrix: 10s
- Teardown: 5s

Total: ~3 minutes per run. Concurrent runs serialised on the runner
(per-pipeline VM names prevent name collision but libvirt resource
contention argues for one-at-a-time).

## What this enables

- **Ory upgrade re-validation in CI**. Renovate proposes a kratos /
  hydra image bump → MR → lab-validate fires → green or red. The
  bump can land without operator manual lab work.
- **Topology change re-validation**. If we ever add a new auth flow
  (e.g., add device_code grant), the smoke matrix gains an assertion
  and the matrix re-runs on every change touching kratos/hydra.
- **Confidence between dunn.dev/auth and dunn.dev/iac**. iac quadlet
  edits get tested against the application code in the same flow.

## What this doesn't replace

- Production deploy. iac's `make auth-deploy` is still where carmine
  gets updated.
- Per-app integration testing. The lab validates substrate health;
  it doesn't validate Vaultwarden's OIDC flow specifically.
- Backup / restore drills. Postgres backup work lives elsewhere.

## Open questions

- Do we run the test suite on every MR, or only on tag? MR-level is
  safer (catches Renovate bumps); tag-only is cheaper (we'd save
  carmine cycles).
  - Recommend: MR + main + tag + nightly schedule.
- Does the lab smoke matrix include the Astro portal tile dashboard
  rendering? That requires a browser; Playwright is the natural
  driver. Out-of-scope for first land; nice-to-have eventually.

## When to build this

After the v0.1.4 substrate cutover on carmine is stable for ~2 weeks.
Until then, the static `lab/compose/` stack covers manual smoke.
