# Othala Access Model — what decides entry, and what decides role

Status: **Accepted**, and this is what runs. The binding-derived model shipped
in v0.3.0; the explicit-both-groups rule in §6 landed in the 2026-08
convergence pass. ADR 09 records the decision; this document describes the
mechanism, and the code cites it by section number. Section numbers are
therefore stable: sections get rewritten in place, never renumbered.

Every rule below names the file that enforces it. Where something is described
that nothing enforces, it says so in those words. A rule you cannot check is a
rule that gets believed.

## The model in four sentences

1. **Entry** to an app comes from holding a group the app's manifest lists
   under `presentation.access:`. Always, for everyone, admins included.
2. **Role** inside an app comes from `consent.group_role_map:`. A role mapping
   never admits anybody.
3. An admin therefore holds **both** groups, explicitly: `<svc>-access` to get
   in, `<svc>-admin` for the elevated role. Nothing is derived from anything
   else.
4. No binding means no access. Absence is a denial, never a grant.

The thing being bought is intelligibility. "Can this person get into X?" has a
one-lookup answer: are they in a group X binds for access? There is no second
rule to remember, no implication to trace, and no case where the answer depends
on what else the identity happens to hold.

## 1. What this replaced

The first implementation baked a naming **policy** into the access
**mechanism**:

- `app-slug.ts` validated that a manifest's `access_group` equalled
  `access-<filename-slug>`. The prefix was mandatory and the group name was
  forced to match the filename.
- `gate.ts` hardcoded `ACCESS_GROUP_PREFIX = 'access-'` and derived the gating
  group as `access-<clientId>`.
- A default-group fallback (`OTHALA_DEFAULT_GROUP`, default `everyone`) granted
  tile visibility to any manifest that omitted `access_group`.

Two things were wrong with that. The prefix was doing double duty as both a
naming convention and a runtime type discriminator (§9 R1), which is the part
that actually hurt. And a framework-imposed group name is the wrong layer: what
a group is called is a deployment's decision, not the code's.

## 2. Goal

The code provides the **mechanism**: group membership resolves to entry and to
role, through a fail-closed gate, the same way across every integration
transport. The manifest set provides the **policy**: which groups exist, which
apps they open, and which of them mean "elevated". No naming convention is
imposed by code, and none is inferred from a name at runtime.

This instance's own policy is then data, not code (§6).

## 3. Prior art

No established self-hosted access system hardcodes a group-naming convention.
They expose a mechanism; the operator names groups and declares bindings.

- **Authelia** — `access_control` rules reference operator-defined groups
  (`subject: 'group:whatever'`); no naming scheme is imposed.
- **oauth2-proxy** — `--allowed-group` is a list of IdP group names you choose.
- **Authentik** — you explicitly *bind* a group to an application, plus
  property mappings for role/claim emission; group names are the operator's.
- **Keycloak** — roles/groups with explicit group→role and client-role mappers.

Two different questions are in that list, and the split matters. Authelia and
oauth2-proxy are **authentication gateways**: can you reach the door. Keycloak
and Authentik authz is **role/claim**: what you may do once inside. Othala
answers both from one primitive, which is legitimate at this scale but is the
reason §4 keeps access-binding and role-mapping as separate manifest fields.

The role half was always right here: `group_role_map` has always been an
arbitrary-group→role map. It was the access binding and the default fallback
that were over-opinionated.

## 4. The primitives

1. **Identity groups** — arbitrary strings on the Kratos identity at
   `metadata_admin.groups`, writable only through the Kratos admin API. The
   code assigns no meaning to the strings themselves.
2. **Access binding** — each app manifest declares the group(s) whose members
   may enter, as a list. Tile visibility and the entry gate read the same
   field, which is what stopped them disagreeing (§9 R1). One fallback survives
   on the tile path only; §11 says exactly where.
3. **Role binding** — `consent.group_role_map`, an arbitrary group→role map,
   for apps that consume a role over OIDC claims.
4. **One gate, three transports** — OIDC (Hydra consent plus claims), LDAP (the
   kratos-ldap bridge, unmaintained and not deployed; see §13), and forward-auth
   (the `/api/forward-auth?group=` edge endpoint). All three answer the same
   question: identity `state == active` AND membership in the required group,
   fail-closed. They differ in where the required group is **declared**. OIDC
   reads it from the manifest's `accessGroups`. Forward-auth is told by the
   caller: the edge site's Caddyfile passes `?group=<svc>-access`, and
   `enforceGroupGate` checks that one group. The parameter is charset-guarded,
   not prefix-checked, so the Caddyfile is the binding site for that transport
   and has to be kept in step with the manifest by hand.
5. **No implicit access** — absence of a binding means no access. There is no
   default that silently grants entry. Enforced at `gate.ts` (an empty
   `accessGroups` returns `allowed: false` with a reason, before any group
   comparison runs) and at load time by `validateClients` in `manifests.ts`,
   which BLOCKs a manifest whose access binding is empty and which does not set
   `skip_access_check`.

## 5. Manifest schema

```yaml
presentation:
  name: Keep
  url: https://keep.example.org
  auth_kind: oidc            # oidc | oidc+ldap | forward_auth | ldap | external
                             # (the two ldap values are parked, §13)
  access:                    # the groups that grant ENTRY. Membership in ANY
    - keep-access            # one of them is enough (OR-semantics).
consent:
  roles:                     # declared roles, HIGHEST PRIVILEGE FIRST (§10).
    admin:                   # Declaration order here IS the rank order.
      claim_emit: { … }
    user:
      claim_emit: { … }
  group_role_map:            # group → role. This grants a ROLE, never entry.
    keep-admin: admin
    keep-access: user
oidc: { … }                  # Hydra client, unchanged
```

Rules the code actually applies:

- `presentation.access` is a list. The singular `presentation.access_group` is
  read as a one-element list for compatibility (§11), with no prefix
  validation.
- Group names are validated for charset only: `^[a-z0-9][a-z0-9-]*$`
  (`access-groups.ts`). No prefix is required and none is rejected. No filename
  match is enforced.
- Every role named in `group_role_map` must be declared in `roles`.
  `validateClients` (`manifests.ts`) BLOCKs the reload if not, and
  `lintManifests` (`manifest-lint.ts`) reports it.
- `skip_access_check: true` bypasses the membership check and **not** the
  active-state check. It is an explicit per-app opt-out, visible in the
  manifest.

## 6. The naming policy this instance runs

Group names carry no meaning to the code. They carry a lot of meaning to the
person reading a user's group list at 11pm, which is what this convention is
for.

**Two groups per service, and only two:**

- `<svc>-access` grants entry. `keep-access` gets you into Keep.
- `<svc>-admin` grants the elevated role inside that service.

**Both are held explicitly. Admin does not imply access.** An identity that
holds only `<svc>-admin` is **not admitted**. That is a misconfigured identity,
not a supported shortcut. An admin who uses a service holds
`["keep-access", "keep-admin"]`.

This is the deliberate reversal of the earlier rule, in which a manifest listed
both groups in its access binding so that holding `<svc>-admin` alone let you
in. That derivation is abolished. The manifest access list names
`<svc>-access` and nothing else, which is what makes the list itself the whole
answer to "who can get in".

What it costs: every admin identity carries two group entries per service
instead of one, and provisioning has to remember both.

What it buys, and why the trade was taken: the access list of a manifest is a
complete and literal answer. Reading `access: [keep-access]` tells you the
membership test in full, with no inference and no exception for privileged
identities. The failure mode is also the safe one: forget `<svc>-access` on an
admin and they are denied loudly at the door, rather than admitted through a
rule nobody remembered was there.

This is also why forward-auth needed no code change. An edge Caddyfile passing
`?group=<svc>-access` now admits everybody who should be admitted, admins
included, because admins hold that group. A site may additionally gate a
sub-path on `<svc>-admin` (an `/admin/*` prefix, say), and that is the right
use of the admin group: a second, narrower check on top of entry, never the
thing that grants entry.

Two adjacent facts, so they are not re-derived from the naming:

- **`-access` and `-admin` are UNENFORCED, convention only.** A group's type
  comes from its bindings, never its name (§10). Nothing in the loader rejects
  a group called `memories`, and `manifest-lint.ts` only WARNs on names outside
  the known set. If you rename a group, nothing breaks by name; things break by
  binding.
- **Portal-admin authority is a separate thing entirely.** It is the
  `metadata_admin.admin` marker (ADR 08), writable only through the Kratos
  admin API. It governs `/admin/*` in this portal. It is not a group, it is not
  in `metadata_admin.groups`, and it admits nobody to any downstream app.
  `<svc>-admin` is an app role; `metadata_admin.admin` is portal authority.
  They are unrelated. A bare `admin` string can still turn up in a group
  selector, because `config.ts` prepends it to `OTHALA_IDENTITY_GROUPS`. It is
  a name in a list. It confers nothing, here or anywhere.

Most gates here are explicit: an edge site names a specific group, and
`/api/forward-auth` checks it. **Two are not.** As deployed, the `memory`
(Immich) and `tune` (Navidrome) edges point `forward_auth` at Kratos
`/sessions/whoami` directly — no `group` parameter, and not through this portal
at all. That is the session-only ("any authenticated user") pattern, and it IS
in use. An earlier version of this paragraph said it was not; that was false,
and the correction is the point of this note.

What session-only means at those two sites, stated in both directions because it
lands wrong at both ends:

- Every enrolled identity with a valid session reaches those apps in **full**.
  No `memory-access` / `tune-access` membership is consulted, so nothing in this
  model separates one household member from another's library there — the apps'
  own internal permissions are the entire boundary.
- Nobody **without** a session reaches them at all, including a stranger holding
  a share link the app itself generated, because the gate fires before the app
  ever sees the path.

**This is an open design question owned by the operator, and this document does
not prescribe the fix.** Both services have public-share surfaces, and what those
surfaces are allowed to do is a decision about those services rather than a
defect in this access model. Recorded here so the state is not rediscovered as a
finding a fourth time.

*UNENFORCED — nothing here checks this*: which `forward_auth` URI an edge picks
is the deploy plane's choice, expressed in that service's own Caddyfile. othala
neither imposes nor validates it, and no lint, test, or gate in this repo will
report a session-only edge.

One fallback does still exist, on the tile path only, and §11 says exactly where.

## 7. What the migration removed

Shipped in v0.3.0. Recorded because the removals explain shapes still visible
in the code:

1. `app-slug.ts`, which held the `access_group == access-<slug>` enforcement,
   is gone entirely. The surviving charset check lives in `access-groups.ts`.
2. `gate.ts`: `ACCESS_GROUP_PREFIX` and `requiredGroupFor` are gone. The gating
   groups come from the manifest, never from the clientId.
3. `manifests.ts`: parse `access:` as a list, fall back to `[access_group]`,
   and no implicit `everyone` fallback on the entry path (§11 has the part of
   that fallback which survived, in tiles).
4. `/api/forward-auth`: the `^access-[a-z0-9-]+$` parameter check relaxed to
   the charset check. It is still an injection guard, just not a prefix rule.
5. No data migration was forced: `access-<slug>` remained a valid group *name*,
   it simply stopped being *required*. The rename to `<svc>-access` happened
   afterwards, at leisure.

## 8. The questions the review left open, and how they were answered

- **Multi-role apps** (viewer/editor/admin): multiple `group_role_map` entries.
  Two levels is this instance's convention, not a limit in the code.
- **Footgun surface.** A typo'd group name locks people out silently, because
  the gate is fail-closed and a name nobody binds simply matches nobody.
  Answered by the lint (§11), which cross-checks every group a manifest
  references against the known set and WARNs on unknowns.
- **`access` as a list.** Multi-group OR-semantics does complicate role
  resolution, because an identity can now match two groups that both map to a
  role. Answered in §10: the resolver takes the highest-ranked role, not the
  first stored one, so the outcome is a function of the group *set* and stored
  order cannot change it.
- **Removing the default fallback.** Removed from the entry gate, and only
  from the entry gate. It is still live on the tile path and
  `OTHALA_DEFAULT_GROUP` still defaults to `everyone`. §11 has the detail; this
  is the one question the implementation answered differently from the plan.

## 9. Adversarial review verdict (2026-06-19, 4 independent reviewers)

Intent validated: "primitives not policy" is prior-art-aligned and the right
layering. The review surfaced three revisions the original draft missed; the
migration as first written would have shipped a broken role model.

### R1 — The `access-` prefix was a runtime TYPE DISCRIMINATOR, not just naming (BLOCKER)

All four reviewers converged here independently. The prefix was overloaded: it
was both the naming convention being dropped AND a runtime type-tag the code
used to tell an access group from an identity group. `startsWith('access-')`
drove `normalizeGroupOrder` (which made role precedence deterministic), the
admin-UI identity/access column split, `computeEffectiveAccess`, tile
visibility, and the forward-auth parameter regex. Dropping the prefix without
replacing that duty would have made role resolution ambiguous and mis-filed any
group that did not carry the prefix.

**Revision, implemented:** a group's type is DERIVED from manifest bindings,
never from its name. A group is "access" if some manifest's `access:` lists it,
"role" if some `group_role_map` references it, "identity" if it is in
`OTHALA_IDENTITY_GROUPS`. Every `startsWith('access-')` was replaced by a
registry lookup (§10), and `ClientManifest` / `AppTile` gained
`accessGroups: string[]` as the single field the tile, the OIDC gate, the
forward-auth endpoint, and the admin UI all read.

### R2 — Access binding and role mapping stay SEPARATE manifest fields

"Membership means access" must not collapse access and role into one binding.
The review produced a case the naive collapse loses: everyone in a group may
ENTER an app while only a second group gets the editor ROLE. Resolution: the
group namespace is flat and shared, but meaning comes from **which manifest
field references the group**. `access:` says who enters; `group_role_map` says
what they are once in. This is what makes §6's two-group rule expressible at
all: `keep-access` appears in both fields (entry, plus the baseline role),
`keep-admin` appears only in `group_role_map`.

### R3 — "No policy" needs feedback loops, or it is a footgun farm

Pure primitives with no validation means a typo silently locks everyone out and
a new user sees a blank dashboard with no explanation. The answers are the lint
(§11), the discoverability surfaces (§12), and documenting the deliberate gaps
rather than hiding them: OR-only group semantics (no AND, no DENY), flat groups
(no hierarchy, no inheritance, no referential integrity on rename), and
`skip_access_check` as an explicit per-app bypass.

## 10. The group registry and role resolution

**The registry** (`portal/src/lib/group-registry.ts`) replaces the prefix's
type-tag duty. It is derived from the cached manifest set plus
`OTHALA_IDENTITY_GROUPS`:

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

It is the one source of truth for the admin-UI identity/access split, the
lint's known-group set, and the Group→Apps view (§12). A group can carry
several kinds at once. Its type comes from its bindings, never its name.

**Entry** is `gate.ts enforceAccessGate` and `access.ts computeEffectiveAccess`,
both reading `manifest.accessGroups` with OR-semantics after the active-state
check. `tiles.ts` visibility reads the same field, which is what killed the old
tile-shows / gate-denies divergence for every manifest that declares a binding
(§11 covers the one case that still diverges: a manifest that declares none).

**Role** is `lookupRole` in `portal/src/lib/claims.ts`:

1. An explicit per-app override at `metadata_admin.roles[clientId]` wins, if it
   names a role the manifest declares. An override naming an undeclared role
   falls through rather than emitting nothing.
2. Otherwise every stored group is mapped through `group_role_map`, and of the
   roles that are declared in `manifest.roles`, **the highest-ranked one wins**.
   Rank is the role's index in `consent.roles`, index 0 being highest.
3. Otherwise no role.

Step 2 taking the highest rather than the first match is load-bearing under §6,
not a refinement. Admins now routinely hold two groups that both map to a role,
and `normalizeGroupOrder` sorts non-identity groups alphabetically, which places
`keep-access` before `keep-admin`: a first-match walk would hand every admin the
`user` role. `metadata_admin.groups` also makes no ordering promise for any
identity touched outside the admin form. Because the winner is the minimum index
over the matched set, the result is a pure function of the group set and stored
order cannot change it. `normalizeGroupOrder` is now cosmetic: stable display,
stable diffs. It is not what makes role resolution deterministic.

One convention in that chain is **enforced by nobody**: RANK is declaration
order in `consent.roles`, and no check asserts that roles are declared in
descending privilege. Every manifest in the deployed catalog and the e2e
fixtures does declare them that way (`admin, user`; `admin, editor, viewer`),
and the resolver reads that order rather than hardcoding the name "admin",
because name-based inference is exactly what R1 retired. A manifest that lists
roles in ascending privilege gets a downgrade, which is the fail-safe direction,
but it is silent. If that ever needs to stop being a convention, the place to
enforce it is `manifest-lint.ts`.

## 11. Parse precedence, load failure, and the lint

**`parseAccessGroups`** (`portal/src/lib/access-groups.ts`), in order:

1. `presentation.access` non-empty list, use it;
2. else `presentation.access_group` non-empty, use `[access_group]`;
3. else `[]`, which is no access, not a fallback.

**The default-group fallback is gone from the entry gate and still present on
the tile path.** Be precise about which, because the two disagree:

- `gate.ts` and `computeEffectiveAccess` never see a default. An empty
  `accessGroups` is a denial (§4.5). Nothing appends a fallback group there.
- `tiles.ts` still applies one. `parseTile` sets the singular `accessGroup` to
  `OTHALA_DEFAULT_GROUP` when a manifest declares no `access_group:`, and
  `tileAccessGroups` falls back to that singular value when the `access:` list
  is empty. So a presentation-only tile that binds nothing is visible to
  members of the default group rather than to nobody.
- `OTHALA_DEFAULT_GROUP` is **not** opt-in: `config.ts` defaults it to
  `everyone`. The original plan was to make an unset variable mean "no
  fallback". That was not implemented.

The gap only reaches a manifest that declares no binding at all. An OIDC
manifest like that is BLOCKed at load, so what is left is presentation-only
tiles (forward-auth or external links), where entry is enforced at the edge by
the group named in that site's Caddyfile rather than by the tile. The tile can
therefore be visible to someone the edge will still refuse. That is documented
here rather than quietly tolerated, because a tile that shows and an app that
refuses is a support call.

**A bad manifest set must fail loudly at lint time and must not take the portal
down at runtime.** Those are two different code paths on purpose
(`portal/src/lib/manifest-store.ts`):

- STRICT: the registrar and the lint CLI call `manifests.ts` directly and throw
  on an invalid set. A half-valid catalog must never reach Hydra, and a lint
  that does not exit non-zero is not a gate.
- SERVING: every request path goes through `manifest-store.ts`, which never
  throws. It serves the last known good set, logs to stderr under
  `[portal:manifests]`, retries on every call so recovery needs no restart, and
  surfaces staleness in a banner on the admin surfaces. With no last known good
  set (a cold start onto a broken catalog) it serves the empty set, which is
  fail-closed everywhere it lands.

That split exists because one semantic error, an undeclared role or an empty
access binding, is set-wide and fatal: without it, a single bad file 500s every
OIDC login in the estate plus the admin UI you would use to diagnose it. A YAML
syntax error is already per-file isolated in `manifests.ts loadOne`.

**The lint** (`lintManifests` in `portal/src/lib/manifest-lint.ts`), severity
matrix:

- BLOCK, joining `validateClients`' hard-fails: an empty access binding with no
  `skip_access_check` (definitionally unreachable), a duplicate group inside one
  manifest's access list, a `group_role_map` key mapping to an undeclared role.
- WARN, never blocking: a group named in `access:` or `group_role_map` that is
  not in the known set (the typo case), `access_group` present alongside
  `access:` (the shim is ignored), charset miss.

The CLI is `npm run lint:manifests` (`portal/src/server/manifest-lint-cli.ts`),
which exits 1 on any BLOCK finding and 2 on a usage or read error.

## 12. Discoverability

- `/admin/groups` renders a registry-driven **Group → Apps** table: each group
  with the apps it grants ENTRY to (`accessFor`) and the apps it maps a ROLE in
  (`roleFor`). This answers "which group lets this person reach app X" without
  cross-referencing manifests by hand, and it is the surface to check after any
  group rename. Groups from `OTHALA_IDENTITY_GROUPS` need a restart to appear;
  manifest-referenced groups do not.
- `/admin/users/[id]` splits a user's membership into identity and access
  columns using `registry.get(g)?.kinds`, not a name prefix, so a group called
  `memories` files correctly.

**Not built:** the dashboard empty-state copy and the "this user has zero access
groups" warning on the user create/edit form, both proposed in the original R3
answer, do not exist. A new identity with no access groups gets a blank
dashboard and no explanation. The lint's known-group WARN is the only feedback
loop actually wired.

## 13. The LDAP transport class

> The kratos-ldap bridge is a separate repo, `gitlab.com/dunn.dev/kratos-ldap`.
> It is shelved (2026-06-26), not deployed, and **unmaintained**. It is kept
> public as a reference to read and copy, not as a supported transport. Cinema
> (Jellyfin) moved to OIDC plus a Jellyfin-local password for native clients.
> The analysis below is retained because it documents a real asymmetry, not
> because the bridge is coming back.

The bridge exposes `metadata_admin.groups` as `memberOf` over SEARCH and filters
inactive identities. BIND is a pure Kratos credential check, so active-state is
covered transitively. The gap: the bridge does not read manifests and does not
group-filter SEARCH, so it returns the full active roster and delegates the
access decision to the app's own LDAP group filter. A misconfigured app filter
is a bypass.

So the cross-class consistency rule holds for two of the three transports and
not the third. OIDC enforces active-state and the manifest-declared group
membership itself; forward-auth enforces active-state and the group the edge
names (§4.4); LDAP enforces active-state and delegates the group check
entirely. Closing that would mean a `permitted_groups` option in the bridge,
filtering the SEARCH projection at the bridge itself. Nobody is going to write
it while the bridge is parked, which is one of the reasons it is parked.

## 14. Audit logging — NOT BUILT

The design called for one structured stdout line per gate decision
(`{ts, event:"access_decision", identity_id, app, transport, decision, reason,
groups}`) emitted at both call sites before the response, including denies, so
access decisions land in the same observability surface as everything else.

There is no `gate-log.ts` and no `access_decision` event anywhere in
`portal/src`. Gate denials are not logged as events today. This paragraph is
here so nobody greps for the helper, fails to find it, and assumes they broke
something.

## 15. Group lifecycle

Kratos has no group referential integrity, and that is accepted. The intended
guard rails were tooling, of which one exists:

- **Create**: add to `OTHALA_IDENTITY_GROUPS` (restart) or reference it from a
  manifest (no restart), then assign in the admin UI. The lint WARNs on a
  manifest reference to an unknown group.
- **Rename / delete**: the proposed `portal/scripts/group-rename.mjs`, which
  would patch every identity's `metadata_admin.groups` through the admin API and
  rewrite the manifest YAMLs, **does not exist**. A rename today is manual on
  both sides, and the only thing that catches a missed half is the lint WARN
  plus `/admin/groups` showing a group bound to no apps or an app with no
  members.
- Fail-closed means a botched rename makes an app go dark, never open. That is
  the whole safety margin here, and it is worth saying out loud that it is the
  only one.

## 16. Testing: the fail-closed property is the load-bearing test

`portal/scripts/gate-property.test.mjs` asserts, for all (identity, manifest):
deny unless `state == active` AND `groups ∩ accessGroups ≠ ∅`, or
`skipAccessCheck` with an active identity. The matrix covers a null identity,
inactive-but-in-group, active-not-in-group, active-in-an-unbound-group,
active-in-a-bound-group (the one allow), `skipAccessCheck`, multi-group OR
(`access: [a, b]`, identity holds only `b`, allow), and `groups: []`.

The count of cases is not the point. The point is that removing the group check
flips the matrix rather than one assertion.

§6's two properties are pinned end-to-end in
`e2e/playwright/tests/t-access-model.spec.ts`, against a real Kratos identity
and a real consent flow:

- **T4** seeds an identity holding only `grafana-admin` and asserts it is
  DENIED. That test fails the moment anyone reintroduces admin-implies-access;
  T8 does the same at the forward-auth edge.
- **T2 and T3** seed the same two-group set in opposite stored orders and
  assert both resolve to the admin role. A T2/T3 disagreement means role
  resolution has gone back to depending on array order.

## 17. How it rolled out

Kept because it explains the compatibility shapes still in the parser. The live
instance was never locked out, because `access-observe` remained a valid flat
group name throughout and no data migration was forced.

1. **Dual-read**: parse `access:` as a list, fall back to `[access_group]`. Old
   manifests unchanged. Additive.
2. **Drop the discriminator**: registry-based group typing,
   `computeEffectiveAccess`, and the admin-UI split, gated on the §16 property
   test being green.
3. **Relax the forward-auth regex**: charset instead of prefix, which enabled
   non-prefixed groups with zero behaviour change for existing ones.
4. **Rename** to `<svc>-access` / `<svc>-admin`, cosmetic, done by hand.

The 2026-08 convergence pass then removed `<svc>-admin` from every manifest's
access list, which is the change §6 describes.

## 18. What to remember

If you retain four things:

- The access list on a manifest is the complete answer to "who gets in".
- A `group_role_map` entry decides a role and admits nobody.
- `metadata_admin.admin` is portal authority and is not a group.
- When this document and the code disagree, the code is right, and fixing this
  document is part of the change that made it wrong.
