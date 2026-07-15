# 09 — Capability-group access model

## Status

Accepted (2026-06-27). Partially migrated as deployed — see Consequences
("Migration is incomplete"): the capability model is the default for new
services, but the legacy cohort groups (`family` / `friends` / `kids`) still
back the older service catalogs as a compatibility layer.

Folds in the groups-claim findings from the OIDC standards audit of 2026-06-20
(set-union merge, scope-gating). Sits alongside [08](08-admin-authority-model.md):
that ADR governs who administers **Othala** (the portal-admin bit); this one
governs how access to **apps** is expressed. The concrete roster — which services
exist, who is in which group — is **instance** data and lives only in the private
deploy repo, never in this ADR.

## Context

Othala issues app authorization off Kratos identity groups
(`metadata_admin.groups`, admin-API-writable only). The early convention used
**cohort** groups — `family` / `friends` / `kids` / `admin` — naming *who a person
is*. Cohorts bundle identity with reach: adding a service, or changing one
person's access to one service, forces re-cutting cohorts or special-casing. They
also conflate "may use app X" with "may administer app X", and put a single flat
`admin` next to user-visible display groups.

Two further forces shaped the model:

- **Public surfaces exist.** Some apps behind forward-auth have legitimately
  public paths (landing pages, share links, health). An all-or-nothing gate
  breaks them.
- **The OIDC `groups` claim was wrong twice.** A role's `claim_emit.groups`
  *overwrote* the real membership array (last-write-wins merge), silently
  dropping a membership; and claims were emitted without honoring requested
  scope. Both are fixed in the merge/emit path below.

## Decision

**Authorization is expressed as capability groups keyed to service capabilities,
not cohorts:**

- **`access-<svc>`** — member tier: holding it makes you a member of `<svc>` and
  may enter/use it.
- **`admin-<svc>`** — per-service admin: grants the elevated **app-admin role
  inside `<svc>`** (a role claim the app consumes). It is *not* Othala portal
  admin — that stays the `OTHALA_ADMIN_IDS` allowlist of
  [08](08-admin-authority-model.md).
- **`root`** — estate-wide capability: confers the admin role in every service
  (one catalog binds it to the member role instead — reach is per-manifest, not
  hard-coded). Also not portal admin.

This is the **target** model and the default for every new service. It does not
retroactively delete the cohort groups — those persist as a compatibility layer
(see Consequences).

- **Type is binding-derived, not name-derived.** A group is "access" because some
  manifest's `access:` binds it, "role" because a `group_role_map` references it,
  "identity" because it is listed in `OTHALA_IDENTITY_GROUPS`. A group can carry
  several kinds at once. The `access-` / `admin-` prefixes are a **recommended
  convention**, not policy enforced in code — the runtime type comes from the
  binding (`group-registry.ts`), never the name. Adopters name their own services.
- **Forward-auth is path-selective** where an app has public surfaces: gate
  `/admin/*` (require `admin-<svc>`) and the auth/login paths (require
  `access-<svc>`); leave declared public paths open. Default for an app with no
  public surface is gate-everything, fail-closed.
- **The `groups` claim emits the full membership set (set-union), scope-gated.**
  A role's `claim_emit` arrays are *unioned* into the user's real membership array
  (`deepMergeClaims` in `claims.ts`), never overwriting it; the claim is emitted
  **only when the `groups` scope is granted** to the client. No membership is
  shadowed; clients without the scope get no claim.

## Consequences

- **Authorization composes.** Grant exactly the services a person needs; elevate
  per-service independently; `root` for the operator. Adding a service is a new
  `access-<svc>` / `admin-<svc>` pair, not a cohort re-cut. The gather media stack
  (`access-gather`, `access-gather-torrent`, `access-gather-usenet`) and the
  `observe`, `tune`, `infer` services are already capability-only, with no cohort
  keys.
- **Migration is incomplete — cohorts are still live.** The deployed catalog
  still carries `family` / `friends` / `kids` as `group_role_map` keys (mapping to
  the member role; `friends` maps to `external` in one) in eight service catalogs:
  `cinema`, `forge`, `larder`, `keep`, `memory`, `prompt`, `listen`, `tailscale`.
  Separately, `bitwarden` binds the raw cohort `family` directly as its
  `access_group` (an un-migrated cohort access binding, not a capability group);
  and `keep` and `memory` emit `groups: ["family"]` in their role `claim_emit`.
  These persist deliberately so existing memberships keep working — a person in
  `family` still resolves the member role everywhere — while new services adopt
  the capability groups. Retiring the cohorts means re-cutting each roster onto
  `access-<svc>` and removing the cohort keys; until then both schemes co-exist
  and a user may be reached by either.
- **The portal-admin boundary stays clean.** `admin-<svc>` and `root` are *app*
  authority and live in the user-visible group namespace; the security-critical
  Othala-admin bit stays the `OTHALA_ADMIN_IDS` UUID allowlist
  ([08](08-admin-authority-model.md)), not a group. `metadata_admin.groups` is
  display/derivation input only.
- **Public-by-design apps keep working.** Path-selective forward-auth means a
  share link or landing page is reachable while `/admin` stays gated. Obligation:
  each forward-auth app must *declare* its public paths; an undeclared path
  defaults to gated (fail-closed).
- **The `groups` claim is now trustworthy and minimal.** RPs that test
  `admin-<svc> in groups` get the true, complete set; clients that never
  requested `groups` never see it.
- **Adopters keep their own names.** Because type is binding-derived, the
  `access-`/`admin-` convention is a recommendation, not a constraint — an adopter
  may name groups `memories` / `photo-admins` and bind them the same way.
- **Footgun:** flat groups have no referential integrity or hierarchy; a typo in
  an `access:` binding fails closed (locks out, never opens). The manifest lint
  (cross-checking references against the group registry's known-group set) is the
  guardrail.

## Alternatives considered

- **Keep cohort groups (`family` / `friends` / `kids` / `admin`).** Rejected as
  the target: bundles identity with reach and conflates use with administration;
  every new service or per-person change re-cuts cohorts. They survive only as a
  compatibility layer during migration, not as the model.
- **One global `admin` group for all app admin.** Rejected: collapses per-service
  admin into estate-wide power and re-introduces the display-group / authority-bit
  conflation. `admin-<svc>` scopes elevation to one service; `root` is the
  deliberate, single estate-wide grant (and even its reach is per-manifest, not
  hard-coded).
- **Code-enforce the `access-`/`admin-` prefix.** Rejected: the prefix was a
  hidden runtime type-tag. Deriving type from bindings frees naming for adopters
  while keeping the mechanism; the registry, not the string, is the discriminator.

---

Related: this model runs the path-selective forward-auth gate in each
service's Caddy TLS terminator (the instance fronts every service with its own
Caddy behind an SNI edge). The per-service access roster lives in the
instance's catalog, not in this ADR — the OSS record stays abstract.
