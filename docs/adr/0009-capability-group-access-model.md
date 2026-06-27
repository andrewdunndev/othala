# 0009 — capability-group access model

## Status

Accepted (2026-06-27).

Graduates the design in [`../access-model.md`](../access-model.md)
("primitives, not policy") into the canonical access *model*, and folds in the
groups-claim findings from
[`../oidc-standards-audit-2026-06-20.md`](../oidc-standards-audit-2026-06-20.md)
(H1 set-union, H2 scope-gating). Sits alongside
[0008 — admin authority model](0008-admin-authority-model.md): that ADR governs
who administers **Othala**; this one governs how access to **apps** is expressed.
The concrete roster (which services exist, who is in which group) is **instance**
data, not part of this model — see [Links](#links).

## Context

Othala issues authorization off Kratos identity groups
(`metadata_admin.groups`, admin-API-writable only). The early convention used
**cohort** groups — `family` / `friends` / `kids` / `admin` — naming *who a
person is*. Cohorts bundle identity with reach: adding a service, or changing one
person's access to one service, forces re-cutting cohorts or special-casing. They
also conflate "may use app X" with "may administer app X", and put a single flat
`admin` next to user-visible display groups.

Two further forces shaped the model:

- **Public surfaces exist.** Some apps integrated via forward-auth have
  legitimately public paths (landing pages, share links, RSS, health). An
  all-or-nothing forward-auth gate breaks them.
- **The OIDC `groups` claim was wrong twice.** A role's `claim_emit.groups`
  *overwrote* the real membership array (last-write-wins merge), silently
  dropping a membership; and claims were emitted without honoring requested
  scope. Both are documented in the
  [OIDC standards audit](../oidc-standards-audit-2026-06-20.md) (H1, H2).

## Decision

**Authorization is expressed as capability groups keyed to service capabilities,
not cohorts:**

- **`access-<svc>`** — member tier: holding it makes you a member of `<svc>` and
  may enter/use it.
- **`admin-<svc>`** — per-service admin: grants the elevated **app-admin role
  inside `<svc>`** (a role claim the app consumes). It is *not* Othala portal
  admin — that stays the `metadata_admin.admin` marker of
  [0008](0008-admin-authority-model.md).
- **`root`** — estate-wide capability: confers access to every service. Also not
  portal admin.

This **replaces** the `family` / `friends` / `kids` / `admin` cohort groups.

- **Type is binding-derived, not name-derived.** A group is "access" because some
  manifest's `access:` binds it, "role" because a `group_role_map` references it
  ([`../access-model.md`](../access-model.md) §10). The `access-` / `admin-`
  prefixes are a **recommended convention**, not policy enforced in code — Othala
  imposes no naming scheme; adopters name their own services.
- **Forward-auth is path-selective** where an app has public surfaces: gate
  `/admin/*` (require `admin-<svc>`) and the auth/login paths (require
  `access-<svc>`); leave declared public paths open. Default for an app with no
  public surface is gate-everything.
- **The `groups` claim emits the full membership set (set-union), scope-gated.**
  The ID-token `groups` claim is the union of all held groups (RP decides
  precedence, SCIM-style), emitted **only when the `groups` scope is granted** to
  the client. No membership is shadowed; clients without the scope get no claim.

## Diagram

Capability-group tiers mapped onto the service roster (service names are
illustrative; the real roster is instance data):

```{mermaid}
flowchart LR
  root(["root<br/>estate-wide &mdash; all services"])

  subgraph roster["service roster (instance-named, e.g. photos / docs / media)"]
    direction TB
    subgraph photos["photos"]
      pm["access-photos &rarr; member"]
      pa["admin-photos &rarr; app-admin role"]
    end
    subgraph docs["docs"]
      dm["access-docs &rarr; member"]
      da["admin-docs &rarr; app-admin role"]
    end
    subgraph media["media"]
      mm["access-media &rarr; member"]
    end
  end

  root --> photos
  root --> docs
  root --> media

  note["OIDC groups claim = set-union of ALL held groups, scope-gated.<br/>Group TYPE (access / admin / identity) is derived from manifest<br/>bindings, never from the name prefix."]
  roster -.-> note
```

Path-selective forward-auth (inset) — for an app with legitimate public surfaces.
The gate runs in the per-service TLS terminator at the edge (see the estate
networking ADR in [Links](#links)):

```{mermaid}
flowchart LR
  user([user request]) --> edge["per-service edge / TLS terminator<br/>(forward-auth gate)"]

  edge -->|"/ , /share/* , /pages/* &mdash; public, open"| app["app"]
  edge -->|"/login, /auth/* &rarr; require access-&lt;svc&gt;"| gate{forward-auth<br/>check}
  edge -->|"/admin/* &rarr; require admin-&lt;svc&gt;"| gate
  gate -->|allow| app
  gate -->|"deny &mdash; fail-closed"| denied([401 / 403])
```

## Consequences

- **Authorization composes.** Grant exactly the services a person needs; elevate
  per-service independently; `root` for the operator. Adding a service is a new
  `access-<svc>` / `admin-<svc>` pair, not a cohort re-cut.
- **The portal-admin boundary stays clean.** `admin-<svc>` and `root` are *app*
  authority and live in the user-visible group namespace; the security-critical
  Othala-admin bit stays the admin-API-only `metadata_admin.admin` marker
  ([0008](0008-admin-authority-model.md)). This is exactly the conflation 0008
  rejected group-based portal admin to avoid.
- **Public-by-design apps keep working.** Path-selective forward-auth means a
  share link or landing page is reachable while `/admin` stays gated. Obligation:
  each forward-auth app must *declare* its public paths; an undeclared path
  defaults to gated (fail-closed).
- **The `groups` claim is now trustworthy and minimal.** RPs that test
  `admin-<svc> in groups` get the true, complete set; clients that never
  requested `groups` never see it.
- **Adopters keep their own names.** Because type is binding-derived, the
  `access-`/`admin-` convention is a recommendation, not a constraint — an
  adopter may name groups `memories` / `photo-admins` and bind them the same way.
- **Footgun:** flat groups have no referential integrity or hierarchy; a typo in
  an `access:` binding fails closed (locks out, never opens). A manifest lint
  ([`../access-model.md`](../access-model.md) §11) is the guardrail.

## Alternatives considered

- **Keep cohort groups (`family` / `friends` / `kids` / `admin`).** Rejected:
  bundles identity with reach and conflates use with administration; every new
  service or per-person change re-cuts cohorts.
- **One global `admin` group for all app admin.** Rejected: collapses
  per-service admin into estate-wide power and re-introduces the display-group /
  authority-bit conflation. `admin-<svc>` scopes elevation to one service; `root`
  is the deliberate, single estate-wide grant.
- **Code-enforce the `access-`/`admin-` prefix.** Rejected in
  [`../access-model.md`](../access-model.md) (R1): the prefix was a hidden runtime
  type-tag; deriving type from bindings frees naming for adopters while keeping
  the mechanism.

## Links

- Related OSS ADRs:
  [0001 — auth substrate: Ory Kratos + Hydra](0001-auth-substrate-ory.md)
  (groups live in Kratos `metadata_admin.groups`) ·
  [0005 — passkey-first auth](0005-passkey-first-auth.md)
  (AAL2 step-up on the `/admin` paths this model gates) ·
  [0007 — three-layer naming](0007-three-layer-naming.md)
  (Othala / instance / functional-name layering this model respects) ·
  [0008 — admin authority model](0008-admin-authority-model.md)
  (portal admin vs the app-admin / `root` boundary)
- Design + evidence: [`../access-model.md`](../access-model.md)
  (primitives-not-policy, binding-derived group registry, lint) ·
  [`../oidc-standards-audit-2026-06-20.md`](../oidc-standards-audit-2026-06-20.md)
  (H1 set-union, H2 scope-gating) ·
  [`../per-app-oidc.md`](../per-app-oidc.md) (OIDC + forward-auth integration
  runbook) · [`../STATUS.md`](../STATUS.md) (live access-gate status)
- Estate / instance (the concrete roster lives here, not in this model):
  [iac estate ADR set](../../../iac/docs/adr/README.md) ·
  [iac 0005 — host-and-estate networking topology](../../../iac/docs/adr/0005-host-and-estate-networking-topology.md)
  (the per-service edge where the path-selective forward-auth gate physically runs)
