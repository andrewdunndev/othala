<!-- TODO(site-rewrite): Strip the internal 'Renamed + converged' history framing (lab/ci -> e2e) and present the harness as its current shape. `e2e/*` are repo paths, not site pages — link to the repo or describe. Re-check the 'implemented in v0.2.0' status line against current state before publish. This comment is stripped at render time and does not appear on the published page. -->

# QEMU-CI lab — design + implementation

Status: **implemented in v0.2.0** (this commit set). Replaces the
static compose stack which is now legacy.

Files: `e2e/{compose.yml,kratos.yml,hydra.yml,identity.schema.json,
recovery-gate.jsonnet,glauth.cfg,postgres-init.sh,gen-secrets.sh,
smoke.sh,validate.sh,README.md}` + the `e2e` job in `.gitlab-ci.yml`
tagged `[carmine, qemu]`.

> **Renamed + converged.** The directory was `lab/ci/` and the job was
> `lab-validate`; both are now `e2e` (the project's canonical OSS-facing
> end-to-end harness — see `e2e/README.md`). The topology converged:
> the `consent` and `util` containers are gone (folded into the single
> `othala` app image at the registry root); the LDAP bridge has been
> extracted to `gitlab.com/dunn.dev/kratos-ldap` (no e2e spec exercises
> LDAP, so no bridge image is pulled here). The substrate is postgres +
> kratos + hydra + othala. The smoke probes the converged app's
> `/oauth2/*` public challenge handlers and its loopback `/admin/*`
> endpoints.

See `e2e/README.md` for invocation notes, environment variables, and
the smoke assertion list. The harness gates future tags; the v0.2.0
first deploy proves the substrate manually.

Pipeline shape:

```
verify   →   build     →   e2e        →   package   →   release
                            (gate)         (sbom)
```

`e2e` `needs: [build-othala, build-e2e-tester]` — pulls the just-built
image set at `${CI_COMMIT_TAG}` (tag pipelines) or
`${CI_COMMIT_SHORT_SHA}` (push to main + MR). On red, blocks the SBOM +
release stages. On green, the substrate is proven to come up + smoke
clean before the SBOM/release jobs touch the registry.

## Why QEMU on carmine, not shared runners

Static compose worked for Phase 3 substrate validation but:

1. It ran Topology A (auth-lab / home-lab / keep-lab subdomains).
   Production is Topology B (dag.dunn.dev only). Lab-to-prod drift
   was real and evidence stopped mapping cleanly to production shape.
2. It was not exercisable from CI — every validation was an operator
   running `podman compose up` on a workstation. Renovate MRs did not
   trigger end-to-end validation.
3. It used compose, not quadlets. Production uses quadlets. The
   compose-to-quadlet translation is not lossless (network defaults,
   userns, secrets shape).

The shared GitLab runner pool cannot do nested virt or persistent
podman state without per-job overhead. carmine has spare capacity, a
real KVM hypervisor, and a lab VLAN already provisioned (per the
deploy plane's earlier work on the gitlab-runner VM pool). The QEMU-CI harness spawns
a QEMU VM inside carmine's `lab` libvirt network, runs real podman +
quadlets on it, smokes the substrate, and tears the VM down. Total
turnaround target: 5 minutes per CI invocation.

### Update 2026-05-31

Built earlier than the original 2-week recommendation. The carmine
runner infrastructure was already in place (the deploy repo's `services/runner/`)
and the lab is light enough to land alongside the substrate v0.2.0
changes. See `e2e/README.md` for invocation notes. The harness does not
gate the carmine deploy of v0.2.0 — it gates future v0.2.X tags.
