# 07 — Three-layer naming: Othala / dag.dunn.dev / kratos+hydra

## Status

Accepted. The naming settled at v0.2.0. Reference: `docs/decision.md` (superseded
notice), `ARCHITECTURE.md` (current), `CHANGELOG.md` (v0.2.0 "Convergence release").

## Context

The auth stack has three layers that use different names, and the history of the
project produced several name changes that left stale references in docs and
tooling. The layers need to be clearly distinguished so adopters and maintainers
do not conflate them.

**The OSS project name: Othala.** The project started as `auth` (the repo was
`dunn.dev/auth`). At v0.2.0 it was renamed to **Othala** (the Elder Futhark
rune ᛟ, meaning "inheritance" / "home"). The GitLab project is now
`gitlab.com/dunn.dev/othala`. The older names (`auth`, `dag-auth`) are retired.
The rationale: "Ory for your home" as an OSS identity -- the name Othala signals
the project's purpose (home SSO substrate) without being a product claim that
implies managed-service competition with Ory Network.

**The running instance: dag.dunn.dev.** The operator's deployed instance uses
`dag.dunn.dev` as its public FQDN. This replaced `auth.dunn.dev`. The service
group in the deploy repo is `dag` (`services/dag/`, `dag-*` quadlets, `dag_*`
sops keys, `dag-internal.network`). The rune motif on the login page transitions
ᛞ (Dagaz, "day" / "dawn") → ᛟ (Othala, "home"), expressing "the door to home."
The instance name `dag` is instance-specific; adopters use whatever grouping
name fits their deploy repo.

**The functional component names: kratos + hydra.** The Ory service names
(Kratos, Hydra, Postgres) are used for what they are: Ory's service identifiers.
They appear in config-file content (database DSNs, self-referential URLs inside
`kratos.yml` / `hydra.yml`) and log lines without any rename. These names are
functional identifiers, not project branding, and not network identities: the
containers themselves are addressed by their quadlet `ContainerName`
(`dag-kratos`, `dag-hydra`, ...), not by bare Ory names.

**Why the three-layer distinction matters.** Without it, documentation slides
between "Othala does X" (the OSS project's behavior), "dag does X" (the
instance-specific config), and "Kratos does X" (the underlying Ory service).
Conflating these produces doc that is either too specific to the operator's
instance (not useful to adopters) or too vague to debug. The ARCHITECTURE.md
"Doc source-of-truth hierarchy" encodes this: each doc has exactly one job, and
the layer it describes determines which doc owns it.

**Earlier naming confusion.** The original decision doc (`docs/decision.md`)
described an architecture using `home.dunn.dev` as the user-facing host and
`auth.dunn.dev` as the IDP. Both were retired. The REVERSED annotations in that
doc are historical markers, not active guidance. The authoritative names are in
ARCHITECTURE.md, not the original decision doc.

## Decision

Three distinct naming layers, each used consistently:

1. **Othala** -- the OSS project name. Used in: the GitLab project, the README,
   the published image name (`othala`), the application name in logs and metrics,
   env vars prefixed `OTHALA_*`, and any public communication about the project.

2. **dag.dunn.dev** -- the operator's running instance. Used in: the deployed
   FQDN, the service group (`dag`), the sops key prefix (`dag_*`), the quadlet
   prefix (`dag-*`). Adopters substitute their own instance name; nothing in the
   Othala source bakes in `dag.dunn.dev` except the worked examples (which are
   clearly annotated as instance-specific, with adopter-substitution notes).

3. **kratos / hydra / postgres** -- the Ory functional component names. Used as-is
   in config-file content (e.g. the postgres DSN role/db names in `kratos.yml`,
   `hydra.yml`) and in log analysis. Sibling containers do not resolve each
   other by these bare names: each quadlet sets a `ContainerName` scoped to the
   instance (`dag-kratos`, `dag-hydra`), and that is the name peers use to reach
   it on the internal network. Not renamed to `dag-kratos-svc` or
   `othala-kratos` for branding purposes, but not bare `kratos`/`hydra` at the
   network layer either.

## Consequences

- ARCHITECTURE.md must carry adopter-substitution callouts on every
  instance-specific value (`dag.dunn.dev`, `OTHALA_WEBAUTHN_RP_ID`, etc.) so
  readers know which values are the operator's choices and which are locked
  behaviors.
- Stale references (`auth.dunn.dev`, `home.dunn.dev`, `dag-auth`, the `auth_*`
  sops key prefix) are explicitly marked HISTORICAL or REVERSED in the documents
  that carry them. They are retained as rationale, not as active guidance.
- The purity gate (`scripts/check-purity.sh`) catches instance-specific strings
  in OSS-facing documents. The three-layer naming is what makes the purity gate
  coherent: `dag.dunn.dev` is an instance string; `othala` is not.
- Adopters who read the ARCHITECTURE.md load-bearing decisions section will
  encounter `dag.dunn.dev` in worked examples. Each occurrence has an
  adopter note explaining that it is an instance value, not a framework
  constraint. Without the three-layer naming convention, those notes would have
  no coherent frame.
- Worked examples that show inter-service addressing should reference the
  `ContainerName`-scoped identity (`dag-kratos:4433`), not a bare Ory name
  (`kratos:4433`): no `NetworkAlias` is defined in the deployed quadlets, so a
  bare-name example would not resolve on the wire.

## Alternatives considered

- **Rename everything to `othala-*`.** Clean from an OSS perspective, but
  Kratos and Hydra are Ory's projects and use Ory's names in their own config
  and APIs. Renaming them in the Othala context creates a mental-model mismatch
  when adopters read Ory's documentation. Functional names stay functional.
- **Use only the instance name (`dag`) as the primary identifier.** This is how
  the deploy repo operates internally. It is wrong for the OSS project: an
  adopter who sets up Othala does not deploy `dag`; they deploy `Othala` and give
  their instance whatever name fits their naming conventions. The OSS project
  name must be distinct from the instance name.
- **No formal distinction; let the context determine the meaning.** The original
  docs did this, which is why the decision doc has REVERSED annotations for three
  different FQDNs and the architecture section became stale within one release
  cycle. Formal naming layers are the fix for that pattern.
