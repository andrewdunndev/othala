# 08 — Admin authority model: bootstrap floor + `metadata_admin`-managed admins

## Status

Accepted (2026-08-15); decided 2026-06-25 and deployed on dag.dunn.dev.

Two tiers. Day-to-day portal admin is the strict-boolean
`metadata_admin.admin` marker, admin-API-only-writable and AAL2-gated
server-side. The always-available floor is the Ory-native admin plane — host
shell, sops, the network-isolated Kratos admin API — carrying the `root`
identity and, since 2026-08-13 (`iac` commit `9fb0d83`), a dedicated
`breakglass` Kratos identity seeded create-only and idempotently from the
`dag_breakglass_password` sops key.

**One honest gap remains, deliberately recorded rather than fixed:** the deployed
Kratos identity schema does not enumerate the `admin` marker this ADR's
day-to-day tier relies on — it lists only `groups` and `roles` — so the marker
works only because Kratos treats `metadata_admin` as opaque. It is recorded in
full under Consequences, with its re-litigation trigger; closing it is a
coordinated deploy, not an edit. The second gap this record used to
carry (break-glass filled by `root` **by role**, with no dedicated identity) is
**closed** — see the floor description in Decision.

See also [03](03-proxy-originated-mtls.md) (the admin-API hop is a direct
internal call, not an mTLS proxy — the write-boundary consequence below depends
on that reversal), [05](05-passkey-first-auth.md) (passkey-first + AAL2 step-up
that gate `/admin`), [06](06-two-pki.md) (the step-ca PKI a proxy would have
used — unused on this path),
[09](09-capability-group-access-model.md) (the per-service group model; **there
is no estate-wide `root` group and no estate-wide admin group**), and
[14](14-enrollment-out-of-band.md) (enrollment and the lost-device path, which
the recovery gate below deliberately closes to admin identities). Retires the
env allowlist design and the `id`-pinning dance from the pre-ADR decision notes.

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
write (`portal/src/lib/metadata-admin.ts`: `admin` must be a strict boolean —
that validator is the enforcer, because the Kratos schema is not, see the gap
below). Admins are granted and revoked live through the admin UI by an existing
admin (`patchAdminMarker`, `portal/src/lib/admin-api.ts`). The admin set can be
any size; an operator may run with exactly one.

**Tier 2 — Bootstrap and break-glass floor.** The Ory-native network admin plane
(shell access to the host, sops-encrypted secrets, the internally-reachable
Kratos admin API) is always available and always authoritative. Two identities
sit on it:

- **`root`** — seeded by the operator during initial setup, by hand, against the
  admin API: traits plus a bcrypt password hash taken from the
  `dag_root_password` sops key (the plaintext never enters the repo or a command
  log) and `metadata_admin: { admin: true }`. That first marker solves the
  chicken-and-egg. The procedure is a deliberate manual runbook, not automation
  — `iac DEPLOY.md § dag admin identity bootstrap`.
- **`breakglass`** — a dedicated identity seeded at deploy from the
  `dag_breakglass_password` sops key
  (`iac deploy/hosts/lodestone/services/dag/hooks.py` `_seed_breakglass_identity`,
  wired from `post_deploy`). It carries a password credential **only**: no
  `metadata_admin.admin`, no group membership. It is an SSO-independent
  admin-API entry point — reached by `podman exec dag-kratos` against the admin
  listener — and is neither a portal admin nor an app login. The seed is
  **create-only and idempotent**: it probes
  `GET /admin/identities?credentials_identifier=breakglass` and returns without
  touching anything unless the result is empty, so a reconverge can never reset
  a human's password. dag is the SSO plane, so its break-glass cannot route
  through SSO; this identity is what makes that concrete.

Because the floor always exists, the managed tier can carry hard guards that
would otherwise be dangerous: the portal refuses to demote the last admin and
blocks self-revoke (`portal/src/pages/admin/users/[id].astro`). The floor is the
escape hatch if those guards must be overridden.

**AAL2 on `/admin`.** Every request to the admin surface requires an AAL2
session. Enforcement is server-side in the portal SSR guard
(`portal/src/lib/admin.ts` `requireAdminSession`: `authenticator_assurance_level`
must equal `'aal2'`, else a step-up redirect to `?aal=aal2&refresh=true`), not
inferred from a `200`. AAL2 is satisfied by TOTP or passkey — both work offline,
removing any email dependency from the admin authentication path and satisfying
disconnected administration.

## Consequences

**The authority center of gravity is the Kratos admin-API write boundary, and
the portal reaches that API by a direct internal hop — not an mTLS proxy.** The
portal→Kratos-admin call is plain HTTP over the shared `dag-internal` network;
the Ory-native model treats network isolation as the authorization. The admin
listener is bound to the dag-internal address and `:4434` is never
host-published, so it is unreachable from outside that network. **This record
carries no address literal**: the authority for the bind address, for `:4434`
never being host-published, and for `dag-admin.network` staying absent is the
deploy-plane contract gate `iac deploy/checks/check_dag_contract.py`, check
`N3`, which fails the deploy if any of the three regresses. A previous revision
pinned the address here twice and it rotted when the deploy plane renumbered its
networks. An earlier design fronted the admin API with a step-ca-backed per-CN
mTLS proxy on a dedicated `dag-admin` network; that layer was **removed**
(2026-07-01) because no multi-site requirement justified it — see
[03](03-proxy-originated-mtls.md). No LDAP bridge exists
([01](01-auth-substrate-ory.md)); no other write-capable consumer exists.

**`metadata_admin` must never appear in the public session.** Kratos v26.2.0's
`/sessions/whoami` response excludes `metadata_admin` (only `metadata_public`
surfaces there), so the portal always fetches the identity fresh from the admin
API to read the marker — never from the `whoami` identity object. The enforcer is
`portal/src/lib/admin-auth.ts`, whose contract is that callers supply an
admin-API-fetched identity. Serving `metadata_admin` publicly would make the
marker self-service readable, letting an unprivileged session probe its own
admin status.

**AAL2 must be enforced server-side on every admin request, by
`requireAdminSession` (`portal/src/lib/admin.ts`).** The global session `whoami`
AAL can be `aal1` — the session/`whoami` flow is deliberately pinned
`required_aal: aal1` in `kratos.yml`, and a first-factor-only login returns `200`
without AAL2 — so a `200` does not imply `aal2`. `requireAdminSession` enforces
AAL2 with a fresh step-up redirect and fails closed on any non-`aal2` value.
**The `aal1` pin is not this record's to change:** it has a consumer of its own,
the forward-auth gate, and [15](15-forward-auth-gate-aal1.md) owns the reason —
changing it to `highest_available` locks every MFA-enrolled identity out of every
forward-auth-fronted app at once. Trace that consumer before
touching the setting.

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
schema to close it without a deploy plan. **Re-litigation trigger:** any Kratos
release that begins validating `metadata_admin`. Closing it is a coordinated
change, not a one-line edit: `kratos/identity.schema.json` is one of the
byte-vendored files ([13](13-vendored-config-contract.md)), so the schema edit
and the portal land together and
are re-vendored into the deploy plane in the same pass — the deploy plane's
`iac deploy/checks/check_vendored_drift.sh` fails on any byte deviation, which is
what makes that coordination mandatory rather than advisory.

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
the gate fails closed (403) when it is absent. The end-to-end block and its AAL2
mitigation are exercised by `e2e/playwright/tests/j-recovery-flow.spec.ts`. The
jsonnet is byte-vendored ([13](13-vendored-config-contract.md)): a correction
lands in this repo first and is
then re-vendored, never edited in the deploy plane.

**Retired:** the `OTHALA_ADMIN_IDS` env allowlist (absent from portal source, and
asserted absent from the deployed dag quadlets by
`iac deploy/hosts/lodestone/services/dag/preflight.sh`), the
create-read-back-configure-restart id dance, and the bespoke Kratos hook that
blocked email-code login for admins. The admin AAL2 gate is now enforced by the
portal SSR step-up plus the canonical Kratos flow config
(`required_aal: highest_available` on the settings flow), not by custom hook code.

**Adding an admin is a live UI action, not a config edit plus restart.**
Onboarding and offboarding an admin is a few clicks and takes effect immediately
with no service interruption.

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

- **Group-based admin (`metadata_admin.groups` contains an admin group).**
  Rejected for the portal's own `/admin` surface because it conflates
  user-visible display groups (shown in the UI, passed in OIDC claims) with a
  security-critical authority bit: a user who can see their own group membership
  might infer or probe their admin status. The dedicated `metadata_admin.admin`
  marker is an authority bit, not a display concept, and the self-demote footgun
  is less ambiguous in a boolean-flag model than in a group model. Group-carried
  admin *is* deployed, but only **downstream and per service**: each catalog
  manifest's `group_role_map` maps that service's `<svc>-admin` group to the
  admin role inside that app. It never grants entry — entry comes from holding
  `<svc>-access`, which an app admin holds too
  ([09](09-capability-group-access-model.md)). There is no estate-wide `root`
  group and no estate-wide admin group; the operator holds `<svc>-admin`
  explicitly, per service, and portal `/admin` stays on the boolean marker
  regardless.

- **Ory Keto for authorization.** The correct answer for policy-heavy
  authorization graphs. At this scale, with a fixed and small admin set, Keto
  adds a service to run, back up and upgrade for a decision `metadata_admin`
  answers directly. If the admin check ever needs to become a relation tuple, it
  is a single-function change behind `isAdminMarker`.
