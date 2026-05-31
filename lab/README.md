# lab

Substrate validation for the Ory-based auth stack (Topology B). Two
paths live here, with the CI path as the primary going forward.

## Layout

| Path | Status | Purpose |
|---|---|---|
| `ci/` | active | QEMU-CI lab. GitLab CI dispatches a job to the carmine runner, spins an ephemeral Fedora VM, brings up the full substrate (Postgres + Kratos + Hydra + consent + portal), runs the smoke matrix, tears down. ~3-5 min turnaround. See `ci/README.md`. |
| `compose/` | legacy | Static docker-compose stack from the Phase 3 substrate-up validation. Kept until the CI lab fully proves; deletion next session. See `compose/README.md`. |

The pre-Ory substrate evaluations, feasibility studies, phase
evidence, and the older GCP-VM bench scripts/Playwright suite have
been deleted — git history retains the lineage if anyone needs to
reconstruct the decision trail.

## Where things go now

- Substrate health probes → `ci/smoke.sh` (extend with each Ory
  surface change worth catching in CI).
- Production-shape rendering (TLS, Caddy, OIDC redirect flow) →
  manual lab work or a future CI iteration that wires Caddy with
  `tls internal`.
- Browser-driven OIDC / portal UI validation → planned Playwright
  layer on top of the CI lab; not in scope today.
