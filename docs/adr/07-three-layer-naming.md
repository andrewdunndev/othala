# 07 — Three-layer naming: Othala / dag.dunn.dev / kratos+hydra

## Status

Accepted (2026-08-15). The naming settled at v0.2.0 and has not moved since.
`ARCHITECTURE.md` carries the authoritative name list; `CHANGELOG.md` records
the v0.2.0 "Convergence release" rename.

## Context

The auth stack has three layers that use different names, and the project's own
history produced several renames that left stale references scattered through
docs and tooling. Conflating the layers retired three FQDNs and staled an
architecture section inside one release cycle — that is the concrete damage this
record exists to prevent, not a hypothetical.

**The OSS project name: Othala.** The project started as `auth` (the repo was
`dunn.dev/auth`). At v0.2.0 it was renamed to **Othala** (the Elder Futhark
rune ᛟ, meaning "inheritance" / "home"). The GitLab project is now
`gitlab.com/dunn.dev/othala`. The older names (`auth`, `dag-auth`) are retired.
The rationale: "Ory for your home" as an OSS identity — the name signals what
the project is for (a home SSO substrate) without implying a managed-service
product competing with Ory Network.

**The running instance: dag.dunn.dev.** The deployed instance uses
`dag.dunn.dev` as its public FQDN, replacing the earlier `auth.dunn.dev`. The
service group in the deploy repo is `dag` (`services/dag/`, `dag-*` quadlets,
`dag_*` sops keys, `dag-internal.network`). The rune motif on the login page
transitions ᛞ (Dagaz, "day" / "dawn") → ᛟ (Othala, "home"), expressing "the door
to home."

**The functional component names: kratos + hydra.** The Ory service names
(Kratos, Hydra, Postgres) are used for what they are: Ory's service identifiers.
They appear in config-file content (database DSNs, self-referential URLs inside
`kratos.yml` / `hydra.yml`) and in log lines without any rename. They are
functional identifiers, not project branding — and **not network identities**.

**Earlier naming confusion.** An earlier architecture used `home.dunn.dev` as
the user-facing host and `auth.dunn.dev` as the IdP; both were retired at the
v0.2.0 rename.

## Decision

Three distinct naming layers, each used consistently, never conflated:

1. **Othala** — the OSS project name. Used in: the GitLab project, the README,
   the published image name (`othala`), the application name in logs and
   metrics, env vars prefixed `OTHALA_*`, and any public communication about the
   project.

2. **dag.dunn.dev** — this deployment. Used in: the deployed FQDN, the service
   group (`dag`), the sops key prefix (`dag_*`), the quadlet prefix (`dag-*`),
   and the `dag-internal` network.

3. **kratos / hydra / postgres** — the Ory functional component names. Used
   as-is in config-file content (the postgres DSN role/db names in `kratos.yml`
   and `hydra.yml`) and in log analysis. Sibling containers do **not** resolve
   each other by these bare names: each quadlet sets an instance-scoped
   `ContainerName` (`dag-kratos`, `dag-hydra`, …), no `NetworkAlias` is defined
   anywhere in the deployed units, and that `ContainerName` is what peers use on
   the internal network. Not renamed to `dag-kratos-svc` or `othala-kratos` for
   branding, but not bare `kratos`/`hydra` at the network layer either.

**The layers exist so a change lands in the right file.** That is the whole
payoff, and it is a maintenance property, not a presentation one: which layer a
name belongs to decides which document owns it and which repo the edit goes in.
A project-layer fact belongs in this repo's README or `ARCHITECTURE.md`; an
instance-layer fact belongs in the deploy plane; a component-layer fact belongs
in the Ory config content. Without the distinction, documentation slides between
"Othala does X", "dag does X" and "Kratos does X", and every one of those
sentences ends up in the wrong file, where it rots unnoticed.

## Consequences

- Stale references (`auth.dunn.dev`, `home.dunn.dev`, `dag-auth`, the `auth_*`
  sops key prefix) are marked HISTORICAL or REVERSED in the documents that carry
  them. They are retained as rationale, not as active guidance.
- The purity gate (`scripts/check-purity.sh`) is what makes the project layer
  mechanically checkable: it fails when instance strings appear in the surfaces
  it scopes. Those scopes are narrow and deliberate — `hydra/hydra.yml` and
  `kratos/kratos.yml` for the instance domain, `portal/scripts/` and
  `e2e/manifests/` likewise, `docs/runbooks/` for instance hostnames and login
  names. **`docs/adr/` is deliberately outside every one of those matchers**, so
  these records may name the instance, the deploy repo, its paths and its
  commits — that is the corpus contract in `docs/adr/README.md`, and the gate is
  what keeps the two postures from colliding.
- The three-layer distinction is what makes the purity gate coherent in the
  first place: `dag.dunn.dev` is an instance string, `othala` is not, and
  without the layers there is no principled line between them. The deploy plane
  records the same dependency from its side —
  `iac docs/adr/supply-chain/0002-detection-as-code-ci-gates.md` cites this
  record three times, including in its CI-gates table where othala's
  `check-purity.sh` is justified *by this ADR*. This record therefore has an
  external consumer and cannot be folded into `ARCHITECTURE.md` without
  dangling a cross-repo link.
- Worked examples that show inter-service addressing must reference the
  `ContainerName`-scoped identity (`dag-kratos:4433`), never a bare Ory name
  (`kratos:4433`): with no `NetworkAlias` defined, a bare-name example does not
  resolve on the wire and would send a reader debugging a DNS failure that is
  actually a documentation error.
  `UNENFORCED — convention only`: no gate checks example hostnames.

## Alternatives considered

- **Rename everything to `othala-*`.** Clean from an OSS perspective, but Kratos
  and Hydra are Ory's projects and use Ory's names in their own config and APIs.
  Renaming them inside the Othala context creates a mental-model mismatch the
  moment anyone reads Ory's own documentation. Functional names stay functional.
- **Use only the instance name (`dag`) as the primary identifier.** This is how
  the deploy repo operates internally, and it is wrong here: the project ships an
  image, an env prefix and a public repo that outlive any one instance, and
  collapsing the two layers is precisely what left `auth.dunn.dev` embedded in
  project-layer documents after the instance moved.
- **No formal distinction; let context determine the meaning.** The original
  docs did this, which is why the decision history carries REVERSED annotations
  for three different FQDNs and why an architecture section went stale within a
  single release cycle. Formal layers are the fix for that failure, and the
  failure is the argument.
