# 08 — Admin authority model: bootstrap floor + `metadata_admin`-managed admins

## Status

Accepted (2026-06-25); deployed on dag.dunn.dev. Two honest gaps are recorded
in Consequences and must not be silently closed: (1) the deployed Kratos
identity schema does **not** enumerate the `admin` marker this ADR's day-to-day
tier relies on — it lists only `groups` and `roles` — so the marker works only
because Kratos treats `metadata_admin` as opaque; (2) the bootstrap/break-glass
floor is currently the `root` identity filling the role **by role**, not the
dedicated `breakglass` identity that iac's break-glass ADRs specify.

See also [03](03-proxy-originated-mtls.md) (the admin-API hop is now a direct
internal call, not an mTLS proxy — the write-boundary consequence below depends
on that reversal), [05](05-passkey-first-auth.md) (passkey-first + AAL2 step-up
that gate `/admin`), [06](06-two-pki.md) (the step-ca PKI a proxy would have
used — now unused on this path), and [09](09-capability-group-access-model.md)
(the group model that carries the `root` group referenced here). Retires the env
allowlist design and the `id`-pinning dance from the pre-ADR decision notes.

## Context

Othala is a self-hosted family identity provider built on Ory Kratos and Hydra.
Kratos is identity-only by design: it has no built-in admin, superuser, or role
concept. Its admin API is protected by network position (possession of network
access is the authorization); application-level authorization is explicitly the
application's responsibility, or Ory Keto's. Kratos exposes `metadata_admin`: a
per-identity JSON blob writable only through the admin API, never through
self-service flows or OIDC claims (which map to traits only). Kratos does not
enforce anything off `metadata_admin`; the application decides what it means.
Notably, Kratos validates the identity schema against `traits` only —
`metadata_admin` is stored as **opaque free-form JSON** and is not schema-checked
at write time. That fact is load-bearing for a gap recorded below.

Four questions had to be answered as a unit:

1. How does the portal determine whether a session holder is an admin?
2. How is the first admin bootstrapped when no admin yet exists to grant the
   privilege?
3. How are admins added and removed day-to-day?
4. How does an operator recover admin access when the stack is degraded?

**What forced a re-examination.** An earlier design pinned Kratos identity UUIDs
into an env allowlist (`OTHALA_ADMIN_IDS`). We verified empirically that Kratos
v26.2.0 rejects caller-supplied identity ids on create: the API returns HTTP 400
`"unknown field id"`. Kratos mints the id; the caller cannot choose it. This
makes an id-based allowlist impractical to populate: create-identity, read back
the minted id, write it into config, restart the portal. Changing the admin set
requires a redeploy. That is not how a mature IdP manages administrators.

The re-examination also considered how comparable open-source IdPs solve the same
problem. Authentik uses group-based superuser assignment plus an env-seeded
`akadmin` bootstrap identity. Keycloak uses realm roles plus a deliberately
temporary env bootstrap-admin revoked after first use. The consensus across
opinionated IdPs: an env-seeded bootstrap floor for the chicken-and-egg, and a
live role or group mechanism for day-to-day administration. None use a static
list as the ongoing mechanism.

## Decision

A two-tier model.

**Tier 1 — Day-to-day admins: `metadata_admin.admin` marker.** The portal
determines admin status by reading a dedicated boolean marker from
`metadata_admin.admin` via a fresh Kratos admin-API `getIdentity` call
(`portal/src/lib/admin-auth.ts` `isAdminMarker`: `meta.admin === true`, strict
boolean, fail-closed). The field is admin-API-only-writable, so it cannot be set
by the identity through self-service flows and cannot be populated via OIDC claim
mapping (claims land in traits). The portal validates the marker's shape on every
write (`portal/src/lib/metadata-admin.ts`: `admin` must be a strict boolean).
Admins are granted and revoked live through the admin UI by an existing admin
(`patchAdminMarker`, `portal/src/lib/admin-api.ts`). The admin set can be any
size; an operator may run with exactly one.

**Tier 2 — Bootstrap and break-glass floor.** The Ory-native network admin plane
(shell access to the host, SOPS-encrypted secrets, the internally-reachable
Kratos admin API) is always available and always authoritative. During initial
setup the operator seeds a `root` identity (password in sops as
`dag_root_password`; TOTP intended) that stamps the first `metadata_admin.admin`
marker, solving the chicken-and-egg, and is the recovery path when the managed
tier is degraded. Because the floor always exists, the managed tier can carry
hard guards that would otherwise be dangerous: the portal refuses to demote the
last admin, and admins cannot silently demote themselves. The floor is the escape
hatch if those guards must be overridden. (As-deployed the floor is `root`
by role — see Consequences; the dedicated `breakglass` identity is future.)

**AAL2 on `/admin`.** Every request to the admin surface requires an AAL2
session. Enforcement is server-side in the portal SSR guard
(`portal/src/lib/admin.ts` `requireAdminSession`: `authenticator_assurance_level`
must equal `'aal2'`, else a step-up redirect to
`?aal=aal2&refresh=true`), not inferred from a `200`. AAL2 is satisfied by TOTP
or passkey — both work offline, removing any email dependency from the admin
authentication path and satisfying disconnected administration.

## Consequences

**The authority center of gravity is the Kratos admin-API write boundary, and
the portal reaches that API by a direct internal hop — not an mTLS proxy.** The
portal→Kratos-admin call is plain HTTP to `http://10.89.11.10:4434` over the
shared `dag-internal` network; the Ory-native model treats network isolation as
the authorization. The admin listener is bound to the `dag-internal` IP and never
host-published, so `:4434` is unreachable from outside that network. An earlier
design fronted the admin API with a step-ca-backed per-CN mTLS proxy on a
dedicated `dag-admin` network; that layer was **removed** (iac reverted it
2026-07-01) because no multi-site requirement justified it — see
[03](03-proxy-originated-mtls.md). The isolation is verified statically by iac's
dag contract gate (`deploy/checks/check_dag_contract.py`, check `N3`:
`:4434` never host-published, admin bind pinned to `10.89.11.10`,
`dag-admin.network` asserted absent, portal carries the direct
`KRATOS_ADMIN_URL`). The LDAP bridge is shelved; no other write-capable consumer
exists.

**`metadata_admin` must never appear in the public session.** Kratos v26.2.0's
`/sessions/whoami` response excludes `metadata_admin` (only `metadata_public`
surfaces there), so the portal always fetches the identity fresh from the admin
API to read the marker — never from the `whoami` identity object. Serving
`metadata_admin` publicly would make the marker self-service readable, letting an
unprivileged session probe its own admin status.

**AAL2 must be enforced server-side on every admin request.** The global session
`whoami` AAL can be `aal1` — the session/`whoami` flow is deliberately pinned
`required_aal: aal1` in `kratos.yml`, and a first-factor-only login returns `200`
without AAL2 — so a `200` does not imply `aal2`. `requireAdminSession` enforces
AAL2 with a fresh step-up redirect and fails closed on any non-`aal2` value.

**HONEST GAP — the deployed identity schema does not sanction the `admin`
marker.** The deployed `kratos/identity.schema.json` `metadata_admin` object
enumerates **only** `groups` and `roles`, with `additionalProperties: false`; it
does **not** list an `admin` boolean. The portal code (Tier 1 above) nonetheless
reads and writes `metadata_admin.admin`, and its own validator
(`metadata-admin.ts`) allows the `admin` key. These work only because Kratos does
not validate `metadata_admin` against the identity schema — the block is
documentation, enforced at the portal write paths, not by Kratos. So the marker
functions today, but the schema-as-deployed and the code-as-deployed disagree on
the sanctioned field set: a contributor reading only the schema would not learn
that `admin` is the live authority bit, and any future move to schema-validate
`metadata_admin` (or to treat the schema as the field-set source of truth) would
break admin authority. This is recorded, not resolved — do not alter the live
schema to close it without a deploy plan.

**Recovery-gate workaround (Kratos v26.2.0 empirical gap, 2026-06-25).** The
recovery-gate webhook (`kratos/hooks/recovery-gate.jsonnet`) is a Kratos
after-hook with `can_interrupt: true` that refuses recovery for admin identities.
Kratos omits `metadata_admin` from `ctx.identity` in the after-hook body-template
context, so the jsonnet `is_admin` field always evaluates to `false` regardless
of the real marker. The gate (`portal/src/server/listen.mjs` `fetchAdminMarker`)
ignores that field and calls the Kratos admin API directly
(`GET KRATOS_ADMIN_URL/admin/identities/:id`) to read the authoritative
`metadata_admin.admin` value — so this gate rides the same marker, and the same
schema gap above applies to it. The jsonnet `identity_id` field is load-bearing;
the gate fails closed (403) when it is absent. Both the end-to-end block and the
AAL2 mitigation are covered by the browser e2e suite (`j-recovery-flow.spec.ts`).

**HONEST GAP — break-glass is `root`-by-role, not a dedicated identity.** iac's
break-glass ADRs (`docs/adr/identity/0002-break-glass-local-admin-convention.md`
and `docs/adr/identity/0003-break-glass-seed-and-rebuild-verification.md`) call
for a dedicated `breakglass` Kratos identity, seeded idempotently at deploy from a
`dag_breakglass_password` sops key. That identity is **not yet deployed**:
`dag_breakglass_password` is absent from sops (only `dag_root_password` exists),
so today the SSO-independent admin path is the `root` identity filling the
break-glass role by role. iac's dag `DRIFT.md` carries this exact divergence with
a close-condition (seed a dedicated `breakglass` identity per identity/0003).
Recorded here as the deployed state; not resolved.

**Retired:** the `OTHALA_ADMIN_IDS` env allowlist (gone from portal code — only
historical comments remain — and asserted absent from the dag quadlets by iac's
`preflight.sh`), the create-read-back-configure-restart id dance, and the bespoke
Kratos hook that blocked email-code login for admins. The admin AAL2 gate is now
enforced by the portal SSR step-up plus the canonical Kratos flow config
(`required_aal: highest_available` on the settings flow), not by custom hook code.

**Adding an admin is a live UI action, not a config edit plus restart.**
Onboarding and offboarding an admin is a few clicks and takes effect immediately
with no service interruption.

**Adopters** who want a different day-to-day mechanism (a different marker name,
or a Keto policy) can substitute it. The interface is the `metadata_admin` JSON
blob and the admin-API write boundary; the portal's admin-check helper reads
both. The floor (host/shell access to the Kratos admin API) is inherent to the
Ory architecture and depends on no Othala convention.

## Alternatives considered

- **Static env list of admin identity UUIDs.** Authority lives outside Kratos,
  which is conceptually clean. But Kratos mints the id on create and rejects
  caller-supplied ids; the only way to populate the list is the
  create-read-back-configure-restart dance, and changing the admin set requires a
  redeploy and a service interruption. Rejected on operational grounds.

- **Static env list of admin usernames.** The username is knowable before
  enrollment, so no dance. But authority would ride a trait that is, in
  principle, user-editable through the self-service settings flow. Hardening it
  requires making usernames immutable, i.e. disabling profile self-service
  globally — but users need to update their own email (a trait on the same
  schema) without admin intervention. Too blunt.

- **Static env list of verified admin emails.** Escalation would require
  controlling the target inbox — an acceptable trust assumption — but the static
  list problem persists, email is a self-editable trait, and email recovery on
  the admin path creates an email dependency that conflicts with disconnected
  administration. An admin locked to a mailbox cannot recover when email is down.

- **Group-based admin (`metadata_admin.groups` contains `"admin"`).** Rejected at
  design time because it conflates user-visible display groups (shown in the UI,
  passed in OIDC claims) with a security-critical authority bit: a user who can
  see their own group membership might infer or probe their admin status. The
  dedicated `metadata_admin.admin` marker is an authority bit, not a display
  concept, and the self-demote footgun is less ambiguous in a boolean-flag model
  than in a group model. Worth flagging honestly against the deployed reality:
  the `root` **group** already carries admin *into downstream apps* via each
  catalog manifest's `group_role_map` (`root: admin` — Jellyfin, GitLab, LiteLLM,
  etc.; see [09](09-capability-group-access-model.md)), so group-carried admin is
  in fact deployed — but only for downstream services, distinct from the portal's
  own `/admin` surface, which stays on the boolean marker.

- **Ory Keto for authorization.** The correct long-term answer for multi-tenant,
  policy-heavy authorization graphs. At family scale with a fixed, small admin
  set, Keto adds an operational dependency for a use case `metadata_admin` handles
  directly. If Othala grows to multi-tenant or multi-operator use, migrating the
  admin check from a `metadata_admin` flag to a Keto relation tuple is a
  single-function change; the interface does not change.
