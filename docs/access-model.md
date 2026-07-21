# Othala Access Model — Primitives, Not Policy

Status: Accepted (2026-06-19); implemented and shipped in v0.3.0. Replaced
othala's hardcoded `access-<slug>` access-group convention with adopter-declared
primitives: a manifest binds adopter-named groups via `presentation.access`, and
a group's type (identity / access / role) is derived from its bindings by
`group-registry.ts`, not from an `access-` name prefix. This document is the
load-bearing reference for the access-binding layer (the code cites it by
section); see also ADR 09 (capability-group model) for how the capability
groups themselves are defined.

## 1. Problem

othala currently bakes a naming **policy** into the access **mechanism**:

- `portal/src/lib/app-slug.ts` validates that a manifest's `access_group`
  equals `access-<filename-slug>`. The `access-` prefix is mandatory and the
  group name is forced to match the filename.
- `portal/src/lib/gate.ts` hardcodes `ACCESS_GROUP_PREFIX = 'access-'` and
  derives the gating group as `access-<clientId>`.
- A default-group fallback (`OTHALA_DEFAULT_GROUP`, default `everyone`) grants
  tile visibility to manifests that omit `access_group`.

The result: an adopter who deploys othala inherits othala's group-naming
opinions. That is the wrong layer. Whether a group is called `access-immich`,
`memories`, `photos-team`, or `family` is the **adopter's** decision, not the
framework's. Forcing a convention is over-opinionated and has no analogue in
comparable systems (Section 3).

## 2. Goal

othala provides the **mechanism** (group membership → access + role, with a
fail-closed gate spanning the three integration classes). The **adopter**
provides the **policy** (group names, which groups bind to which apps, what
counts as elevated). No naming convention is imposed by othala's code.

The maintainer's own deployment (`dag.dunn.dev`) then expresses *its* policy as
data, not as framework code (Section 6).

## 3. Prior art

No established self-hosted access system hardcodes a group-naming convention.
They expose a mechanism; the operator names groups and declares bindings.

- **Authelia** — `access_control` rules reference operator-defined groups
  (`subject: 'group:whatever'`); no naming scheme is imposed.
- **Authentik** — you explicitly *bind* a group to an application, plus
  property mappings for role/claim emission; group names are the operator's.
- **Keycloak** — roles/groups with explicit group→role and client-role mappers.
- **oauth2-proxy** — `--allowed-group` is a list of IdP group names you choose.

The universal pattern: **mechanism in the system, group names + bindings in the
adopter's config.** othala's `access-<slug>` enforcement is the outlier.

othala already has the *role* half of this right: `group_role_map` is an
arbitrary-group → role map (the operator names the keys). Only the *access*
binding and the default-fallback are over-opinionated.

## 4. The primitives (what othala provides)

1. **Identity groups** — arbitrary strings on the Kratos identity
   (`metadata_admin.groups`). othala assigns no meaning to the strings.
2. **Access binding** — each app manifest declares the group(s) whose members
   may access the app (a list of arbitrary names). Tile visibility AND the entry
   gate both key off "is the identity a member of any group this manifest binds
   for access?"
3. **Role binding** — `group_role_map` (already present): arbitrary group →
   role/claim, for apps that consume a role (OIDC `groups`/role claims).
4. **One gate, three transports** — OIDC (Hydra consent + claims), LDAP
   (kratos-ldap bridge, currently parked; see Section 13), forward-auth (the
   `/api/forward-auth?group=` edge endpoint). All three answer the *same*
   question against the *same* primitive: membership in a manifest-declared
   access group, identity `state == active`, fail-closed.
5. **No implicit access** — absence of a binding means no access. There is no
   framework default that silently grants visibility.

## 5. Manifest schema (the binding is declared data)

```yaml
presentation:
  name: Immich
  url: https://memories.example.org
  auth_kind: oidc            # oidc | ldap | forward_auth | external
  access:                    # NEW: adopter-named groups that grant access.
    - memories               # arbitrary; no prefix required or forbidden.
  # access_group: access-immich   # OLD single-field form still accepted (it
  #                                # is just one group name; the access-<slug>
  #                                # *validation* is removed).
oidc: { ... }                # transport-specific (Hydra client) as today
consent:
  group_role_map:            # arbitrary group → role; unchanged primitive
    memories: viewer
    admin-memories: admin    # 'admin-' here is the ADOPTER's convention, data.
```

- `access` (list) supersedes the single `access_group`. The old field is read
  as a one-element list for backward compatibility.
- No prefix is required or rejected. No filename match is enforced. othala
  validates only that names are non-empty and within a safe charset
  (`^[a-z0-9][a-z0-9-]*$`).

## 6. Policy layer (adopter's, including dag's)

othala ships no naming convention. dag expresses its policy as manifest +
config data:

- **dag naming**: a bare group name grants use (`memories` → immich); an
  `admin-`-prefixed group grants elevation (`admin-memories` → immich admin),
  realised purely as `group_role_map` entries. The `admin-` prefix is dag data,
  not othala code.
- **dag policy: explicit access only.** Every gate (including forward-auth)
  requires a specific declared group. dag does not use the session-only
  forward-auth pattern.
- **othala keeps options for adopters**: the session-only forward-auth snippet
  remains shipped (any-authenticated-user gating is a legitimate adopter
  choice); the default-group fallback becomes an explicit opt-in
  (`OTHALA_DEFAULT_GROUP` unset → no fallback, the dag/strict default).

Portal-admin authority stays separate (the `metadata_admin.admin` marker,
ADR 08), unchanged. App-level `admin-*` groups are about app roles, not
portal admin.

## 7. Migration from `access-<slug>`

1. `app-slug.ts`: delete the `access_group == access-<slug>` enforcement; keep
   only the charset check. (Removes the prefix requirement.)
2. `gate.ts`: drop `ACCESS_GROUP_PREFIX`; the gating group(s) come from the
   manifest's `access` list, not a derived `access-<clientId>`.
3. `manifests.ts`/`tiles.ts`: parse `access` (list); fall back to `[access_group]`
   when only the old field is present; remove the implicit default-group
   fallback (make it opt-in via `OTHALA_DEFAULT_GROUP`).
4. `/api/forward-auth`: relax the `^access-[a-z0-9-]+$` param check to the
   charset check; the group is whatever the adopter declared.
5. Existing dag manifests keep working: `access-<slug>` is still a valid group
   *name*; it is simply no longer *required*. (No data migration forced; the
   maintainer can rename to bare/`admin-` at leisure.)
6. Tests/e2e: the access-group fixtures lose the prefix assertion; add coverage
   for multi-group `access` lists and the no-fallback default.

## 8. Open decisions (for the review to pressure-test)

- **Multi-role apps** (Grafana viewer/editor/admin): handled by multiple
  `group_role_map` entries (`grafana-editors: editor`, etc.). Is two-level
  (`x` / `admin-x`) too thin a default, and if so is that othala's problem or
  the adopter's?
- **Footgun surface**: with no enforced convention, an adopter can typo a group
  name and silently lock everyone out (fail-closed) or, worse, bind an app to a
  group nobody audits. Do we need a lint that cross-checks manifest `access`
  groups against the known identity-group set (`OTHALA_IDENTITY_GROUPS`)?
- **`access` as list vs single**: does multi-group OR-semantics complicate the
  consent claim / role resolution (which group's role wins when a user is in
  two bound groups)? Today `group_role_map` precedence is stored-order; does
  that still hold?
- **Removing the default fallback**: any path that relied on `everyone` (e.g.,
  a landing tile) breaks. Is opt-in enough, or does removal strand adopters?

## 9. Adversarial review verdict (2026-06-19, 4 independent reviewers)

Intent **validated**: "primitives not policy" is prior-art-aligned and the right
layering. But the review surfaced three substantive revisions the original draft
missed. The §7 migration as written was incomplete and would have shipped a
broken role model.

### R1 — The `access-` prefix is a runtime TYPE DISCRIMINATOR, not just naming (BLOCKER)

All four reviewers converged here independently. The prefix is overloaded: it is
both the naming convention we want to drop AND a runtime type-tag the code uses
to tell "access group" from "identity group". `startsWith('access-')` /
`ACCESS_GROUP_PREFIX` drives:
- `access.ts:86` `normalizeGroupOrder` — partitions identity vs access groups;
  this ordering is what makes `claims.ts:145` role-precedence deterministic.
  Drop the prefix and stored-order role resolution becomes ambiguous (a user in
  `family` + `admin-family` could silently get the wrong role).
- `admin/users/[id].astro:235-236` + `groups.astro` — split membership into
  "identity groups" vs "access groups" columns by the prefix. A group named
  `memories` would be mis-filed and its access invisible.
- `access.ts:117` `computeEffectiveAccess` reads singular `m.accessGroup`, and
  `manifests.ts:284` hardcodes `accessGroup = access-<clientId>`, ignoring any
  new `access:` list — so the admin "Effective Access" view lies.
- `tiles.ts:205` reads `presentation.access_group` while the OIDC gate derives
  `access-<clientId>` — two data sources that can diverge (tile shows, gate
  denies, or vice versa).
- `api/forward-auth.ts:48` `GROUP_RE = ^access-...$` and
  `validate-clients.test.mjs:333` assert the prefix.

**Revision:** a group's *type* (access-bearing / role-bearing / identity) is
DERIVED from manifest **bindings**, not from its name. A group is "access" if
some manifest's `access:` lists it; "role" if some `group_role_map` references
it; "identity" if it's in `OTHALA_IDENTITY_GROUPS`. Replace every
`startsWith('access-')` with a binding-derived lookup, give `AppTile`/
`ClientManifest` an `accessGroups: string[]` field sourced from `access:` (with
`[access_group]` fallback), and route tile + OIDC + forward-auth + admin-UI off
that single field. This is a bigger refactor than "swap the prefix."

### R2 — Keep access-binding and role-mapping as SEPARATE manifest fields (resolves the orthogonality loss)

"Membership = access" must NOT collapse *access* and *role* into one binding.
Today access (which group gates entry) and role (`group_role_map`) are separate
concerns; the review showed a real scenario the naive collapse loses: "everyone
in `family` may ENTER app B, but only `family-editors` get the editor ROLE."
Resolution: the flat group namespace is shared, but **meaning comes from which
manifest field references the group** — `access: [family]` (who enters) and
`group_role_map: {family-editors: editor, family: viewer}` (what role) stay
distinct fields. A plain `family` member enters with the default/no role; a
`family-editors` member gets editor. Orthogonality preserved, naming freed.

### R3 — "No policy" needs guardrails (feedback loops), or it's a footgun farm

Pure primitives with no validation means a typo (`access: [memmories]`) silently
locks everyone out (fail-closed, no error) and a brand-new user sees a blank
dashboard with no explanation. Add:
- **Lint** (CLI + CI, not optional): cross-check every group referenced by a
  manifest (`access:` + `group_role_map`) against the known group set; warn on
  unknowns. This is the canonical-registry the flat-string model otherwise lacks.
- **First-run UX**: empty-state copy + a create-form/edit warning when an
  identity has zero access groups ("no implicit access" must not mean "no
  explanation").
- **Document the deliberate gaps** rather than hide them: OR-only group
  semantics (no AND / no DENY / no precedence beyond stored-order role — Authelia
  and Keycloak have all three; acceptable at family-scale but state it),
  `skip_access_check` as an explicit per-app bypass, and flat groups (no
  hierarchy/inheritance, no referential integrity on rename).

### Prior-art framing fix (§3)

Split the citation: Authelia/oauth2-proxy are **authentication-gateway** ("can
you reach the door"); Keycloak/Authentik authz is **role/claim** ("what you may
do inside"). The doc spans both with one primitive — legitimate, but say which
comparison is which so the claim isn't doing double duty.

### dag impact

The deployed observe wiring is **not** broken: `access-observe` is a valid flat
group name and passes the current regex, so observe keeps working as-is; renaming
to `observe` is optional post-refactor cleanup. The forward-auth regex relax is
still required before any non-prefixed adopter group works.

### Net

Proceed with the model, with R1-R3 folded in. The refactor is larger than the
draft implied (the prefix's type-tag duty is the load-bearing surprise), and it
must land atomically across gate/access/manifests/tiles/forward-auth/admin-UI +
the lint, or it half-breaks the role model. Sequence it as its own unit before
wiring more apps.

---

# Part II — Implementation spec (enhancement round 2, 2026-06-19)

This part makes Part I implementable. It is the spec the refactor follows.

## 10. The group registry (resolves R1)

The prefix's type-tag duty is replaced by a single **derived registry** computed
from the already-cached manifest set + `OTHALA_IDENTITY_GROUPS`. It is the one
source of truth for: the gate, role-precedence ordering, the admin-UI split, the
lint, and admin discoverability. New file `portal/src/lib/group-registry.ts`:

```ts
export interface GroupEntry {
  name: string;
  kinds: Set<'identity' | 'access' | 'role'>;
  accessFor: string[]; // clientIds whose manifest access: lists this group
  roleFor: string[];   // clientIds whose group_role_map references it
}
export type GroupRegistry = Map<string, GroupEntry>;
export function buildGroupRegistry(manifests, envIdentityGroups): GroupRegistry
```

Builder: seed `identity` kind from `OTHALA_IDENTITY_GROUPS`; for each manifest add
`access` kind for every `accessGroups[]` entry (+ `accessFor`) and `role` kind for
every `group_role_map` key (+ `roleFor`). O(M×G), memoized on the manifest cache
key. A group's *type comes from its bindings, never its name.*

**`ClientManifest`/`AppTile` change**: replace singular `accessGroup: string`
with `accessGroups: string[]`, populated by `parseAccessGroups()` (see §11).
Remove `ACCESS_GROUP_PREFIX` / `requiredGroupFor` from `gate.ts`.

**Per-consumer changes** (the atomic set):
- `gate.ts enforceAccessGate` + `access.ts computeEffectiveAccess`:
  `manifest.accessGroups.some(g => userGroups.includes(g))` (OR semantics).
- `tiles.ts` visibility + OIDC gate read the SAME `accessGroups` field (kills the
  dual-source divergence the review found).
- `api/forward-auth.ts`: relax `GROUP_RE` `^access-[a-z0-9-]+$` →
  `^[a-z0-9][a-z0-9-]*$` (still the SSRF guard, just charset not prefix).
- `admin/users/[id].astro` + `groups.astro`: split columns by
  `registry.get(g)?.kinds.has('identity')` / `.has('access')`, not `startsWith`.

**Deterministic role ordering (replaces the prefix partition in
`normalizeGroupOrder`):** identity groups in `IDENTITY_GROUP_ORDER` order first,
then all remaining groups alphabetically. Determinism proof: both partitions sort
within themselves (fixed env order; alphabetical), so stored order is a pure
function of inputs. Worked case: identity in `[family-editors, family, admin]`,
`IDENTITY_GROUP_ORDER=[admin, family]` → stored `[admin, family, family-editors]`;
`claims.ts` stored-order walk gives `family`'s role before `family-editors`
(coarser-group-wins, same intent as today, no prefix needed). To prefer the
finer role, don't also assign the coarse group — identical semantics to current.

## 11. Manifest schema, parse precedence, and the lint

`parseAccessGroups`: (1) `presentation.access` non-empty list → use it; (2) else
`presentation.access_group` non-empty → `[access_group]` (compat shim, no prefix
validation); (3) else `[]` (NO `everyone` fallback — absence = no access).
`OTHALA_DEFAULT_GROUP` becomes opt-in: unset → `config.ts` returns `''`, no
fallback appended (the strict/dag default). `skip_access_check:true` still
bypasses the membership check (state-active never bypassed); document it.

**Lint** (`lintManifests(set, knownGroups) -> {source,severity,message}[]`),
surfaced three ways: a CI `lint-manifests` job (`just lint`), an `othala lint`
CLI, and a non-blocking yellow callout in `/admin/oauth2`. Severity matrix:
- BLOCK (reload-blocking, joins existing `validateClients` hard-fails):
  `accessGroups` empty AND not `skipAccessCheck` (definitionally unreachable);
  duplicate group within a manifest; `group_role_map` key with no declared role.
- WARN (never blocks — adopters may already run nonstandard names): a group named
  in `access:`/`group_role_map` not in the known set (typo → silent lockout);
  `access_group` present alongside `access:` (shim ignored); charset miss.

## 12. Empty-state / first-run + discoverability

- Dashboard empty state: "No apps yet — every app needs an explicit
  `presentation.access:` group binding; there's no default that grants access."
- User create/edit: a `.notice-warn` when an active identity has zero access
  groups ("This user has no app access — assign a group named in some app's
  `access:` list, or they see a blank dashboard"). Replaces the old `access-*`
  hint.
- `/admin/groups`: replace the prefix-derived "Access groups" section with a
  **Group → Apps** table from the registry (group | members | apps it grants
  access to | apps it maps a role in). Answers "which group lets this user reach
  app X" without manual manifest cross-referencing. Note that
  `OTHALA_IDENTITY_GROUPS` groups need a restart; manifest-referenced groups
  appear without one.

## 13. LDAP class + cross-class consistency

> **Note (2026-06-26):** The kratos-ldap bridge is a **parked** separate project
> (`gitlab.com/dunn.dev/kratos-ldap`). It is not currently deployed. Cinema
> (Jellyfin) moved to OIDC + Jellyfin-local password for native clients
> (see `docs/per-app-oidc.md`). The LDAP transport class is a parked capability;
> the analysis below is retained for adopters who deploy the bridge.

kratos-ldap already exposes `metadata_admin.groups` as `memberOf` over SEARCH
(`handler.go:331`) and filters inactive identities (KL-3, `client.go`). BIND is a
pure Kratos credential check (active-state covered transitively). **The gap
(real):** the bridge does NOT read othala manifests and does NOT group-filter
SEARCH — it returns the full active roster, so the access-group decision is
delegated to the *app's* LDAP group filter (e.g. Jellyfin requiring
`cn=jellyfin,ou=groups,...`). A misconfigured app filter = bypass.

**Cross-class consistency rule:** all three classes enforce `state==active` AND
membership in the manifest-declared access group. OIDC + forward-auth enforce
both internally; LDAP enforces active (Kratos) but delegates the group check to
app config. **Hardening (recommended):** add a `permitted_groups` option to
kratos-ldap that filters SEARCH projection at the bridge so only members of the
declared group are returned — closes the delegated-enforcement gap. Manifest:
```yaml
presentation: { auth_kind: ldap, access: [jellyfin] }
group_role_map: { jellyfin: viewer, jellyfin-admin: admin }
ldap: { group_dn: "cn=jellyfin,ou=groups,<baseDN>" }  # derived from access[0]
```
The manifest is source of truth; the app's LDAP filter is a derived artifact a
lint step cross-checks. (kratos-ldap `permitted_groups` is a follow-up to its
current tag.)

## 14. Audit logging (dogfoods observe)

Every gate decision emits one structured stdout line (the container log shipper
already routes stdout → ClickStack/HyperDX), so access events land in the same
observability surface — the "see login events flowing in" goal extends to access
decisions. Helper `portal/src/lib/gate-log.ts`:
`{ts, event:"access_decision", identity_id, app, transport:"oidc|forward_auth",
decision:"allow|deny", reason, groups:[...]}`. Emitted at both call sites
(consent handler, `/api/forward-auth`) BEFORE the response, including denies and
null-identity (`identity_id:null, decision:deny`). No new dependency.

## 15. Group lifecycle (family-scale, tooled not enforced)

Kratos has no group referential integrity; that's accepted. Guard with tooling:
- Create: add to `OTHALA_IDENTITY_GROUPS` (restart) + assign via admin UI; lint
  warns on unknown manifest references.
- Rename/Delete: `portal/scripts/group-rename.mjs <old> <new> [--apply|--delete]`
  — dry-run by default, patches every identity's `metadata_admin.groups` via the
  Kratos admin API and rewrites manifest YAMLs; CI lint then catches any orphan.
- Fail-closed means a botched rename makes an app go dark, never open.

## 16. Testing: the fail-closed property is the load-bearing test

`portal/scripts/gate-property.test.mjs` asserts: for ALL (identity, manifest),
deny unless `state==active` AND `groups ∩ accessGroups ≠ ∅` (or
`skipAccessCheck` with active). Matrix: null id; inactive-in-group; active-not-in-
group; active-in-unbound-group; active-in-bound-group→allow; skipAccessCheck;
multi-group OR (`access:[a,b]`, user has only `b`→allow); `groups:[]`→deny. Update
`forward-auth.test.mjs` (bare `observe` now PASSES the relaxed regex — the old
"no-prefix→403" case inverts), delete `validate-clients.test.mjs:333`'s
`accessGroup==access-<clientId>` assertion (→ `accessGroups.length>0`), and
re-base `access.test.mjs` `normalizeGroupOrder` on registry partition. Count is
irrelevant; what matters is dropping `startsWith('access-')` flips the matrix.

## 17. Safe phased rollout (live dag must not lock out)

Key fact: `access-observe` is a valid flat name post-refactor, so the running
dag keeps working; no data migration is forced.
- **Phase 1 — dual-read**: `manifests.ts`/`tiles.ts` parse `access:` list, fall
  back to `[access_group]`. Old manifests unchanged. Restart. (additive, low risk)
- **Phase 2 — drop the discriminator** (load-bearing): registry-based
  `normalizeGroupOrder` + `computeEffectiveAccess` + admin-UI split. Gate: the
  §16 property test green in CI. Restart in a low-traffic window.
- **Phase 3 — relax the forward-auth regex**: enables non-prefixed groups;
  `access-observe` still passes → zero dag behavior change. Restart.
- **Phase 4 (optional)**: `group-rename.mjs access-observe observe --apply` +
  Caddyfile update. Cosmetic.
Each phase is a single-file-ish revert + restart. Pre-Phase-2 verification:
`audit-access-bindings.mjs --dry-run` prints every manifest's resolved
`accessGroups` cross-checked against `OTHALA_IDENTITY_GROUPS`; operator confirms
before cutover.

## 18. Net (round 2)

The model is implementation-ready. The registry (§10) is the linchpin that
retires the prefix's hidden type-tag duty while feeding the lint (§11) and admin
discoverability (§12). The phased rollout (§17) makes it safe on the live dag.
Two cross-repo follow-ups: kratos-ldap `permitted_groups` (§13) and the lint as a
pipeline component. Implementation sequence = Phases 1→4, then resume app wiring
(mealie/immich/jellyfin/stacks) on the finished model.
