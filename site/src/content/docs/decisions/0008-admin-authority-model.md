# 0008 — Admin authority model: bootstrap floor + `metadata_admin`-managed admins

## Status

Accepted (2026-06-25). Implementation in progress. See also
[0003](0003-proxy-originated-mtls.md) (mTLS proxy model that the admin-API
write-boundary consequence depends on), [0005](0005-passkey-first-auth.md)
(passkey-first + AAL2 step-up that gate `/admin`),
[0006](0006-two-pki.md) (two-PKI that backs the per-client-cert authorization
described in Consequences). Retires the env allowlist design and the
`id`-pinning dance documented in the pre-ADR decision notes.

## Context

Othala is a self-hosted family identity provider built on Ory Kratos and Hydra.
Kratos is identity-only by design: it has no built-in admin, superuser, or role
concept. Its admin API is protected by network position (possession of network
access is the authorization); application-level authorization is explicitly the
application's responsibility, or Ory Keto's. Kratos does expose `metadata_admin`:
a per-identity JSON blob writable only through the admin API, never through
self-service flows or OIDC claims (which map to traits only). Kratos does not
enforce anything off `metadata_admin`; the application decides what it means.

Four questions had to be answered as a unit:

1. How does the portal determine whether a session holder is an admin?
2. How is the first admin bootstrapped when no admin yet exists to grant the
   privilege?
3. How are admins added and removed day-to-day?
4. How does an operator recover admin access when the stack is degraded?

**What forced a re-examination.** An earlier design pinned Kratos identity UUIDs
into an env allowlist. We verified empirically that Kratos v26.2.0
rejects caller-supplied identity ids on create: the API returns HTTP 400
`"unknown field id"`. Kratos mints the id; the caller cannot choose it. This
makes an id-based allowlist impractical to populate: the workflow is
create-identity, read back the minted id, write it into config, restart the
portal. Changing the admin set requires a redeploy. That is not how a mature IdP
manages administrators.

The re-examination also considered how comparable open-source IdPs solve the same
problem. Authentik uses group-based superuser assignment plus an env-seeded
`akadmin` bootstrap identity. Keycloak uses realm roles plus a deliberately
temporary env bootstrap-admin that is revoked after first use. The consensus
across opinionated IdPs is: an env-seeded bootstrap floor for chicken-and-egg,
and a live role or group mechanism for day-to-day administration. None use a
static list as the ongoing mechanism.

## Decision

We use a two-tier model.

**Tier 1 — Day-to-day admins: `metadata_admin` marker.** The portal determines
admin status by reading a dedicated marker from `metadata_admin.admin` via the
Kratos admin API. The field is admin-API-only-writable, so it cannot be set by
the identity through self-service flows, and it cannot be populated via OIDC
claim mapping (claims land in traits). The portal validates the marker's shape on
every write. Admins are granted and revoked live through the admin UI by an
existing admin. The admin set can be any size; an operator may run with exactly
one.

**Tier 2 — Bootstrap and break-glass floor.** The Ory-native network admin plane
(shell access, SOPS-encrypted secrets, the mTLS-fronted Kratos admin API) is
always available and always authoritative. Optionally, an operator seeds a `root`
identity (password plus TOTP, SOPS-backed credentials) during initial setup. The
floor stamps the first `metadata_admin` marker, solving the chicken-and-egg
problem, and is the recovery path when the managed tier is degraded. Because the
floor always exists, the managed tier can carry hard guards that would otherwise
be dangerous: the portal refuses to demote the last admin, and admins cannot
silently demote themselves. The floor is the escape hatch if those guards need to
be overridden.

**AAL2 on `/admin`.** Every request to the admin surface requires an AAL2 session
(TOTP or passkey as a second factor). Both work offline, removing any email
dependency on the admin authentication path and satisfying disconnected
administration.

## Consequences

**The authority center of gravity moves onto the Kratos admin-API write
boundary. The load-bearing control is network isolation, not per-cert mTLS.**
Per decision N2 (2026-06-27), the portal→Kratos admin hop is plain HTTP on
the shared `dag-internal` network — the Ory-native model treats isolation as
the authorization. `:4434` is only reachable from the `dag-admin` bridge (a
two-container network shared exclusively by `dag-kratos-admin-proxy` and
`dag-kratos`), so no other container — including the portal — can reach Kratos
admin directly. The proxy then forwards to the portal on `dag-internal`. The
LDAP bridge is shelved; no other write-capable consumer exists. Per decision N3,
`:4434` must be provably bridge-only (verified by converge + a negative reachability
test), because that lockdown is now the single barrier. An earlier implementation
used per-CN+per-method mTLS (SP-1) at the proxy; that mechanism is superseded by
the N2/N3 isolation model — removing a dependency on a step-ca client cert that
is not yet operational at rebuild.

**`metadata_admin` must never appear in the public session.** Kratos's
`/sessions/whoami` response must not expose `metadata_admin`; only `metadata_public`
surfaces there. This is verified empirically against each Kratos version we
deploy. Serving `metadata_admin` publicly would make the marker self-service
readable, enabling an unprivileged session to confirm or probe its own admin
status in ways the admin UI did not grant.

**AAL2 must be enforced server-side on every admin request, not inferred from the
session.** The global session `whoami` AAL can be `aal1` (the LDAP bridge uses
`aal1`), so a `200` from `whoami` does not imply `aal2`. The portal enforces AAL2
with a fresh step-up redirect (`?aal=aal2&refresh=true`) and fail-closed
freshness checks on every admin handler.

**Retired:** the env admin allowlist, the create-read-back-configure-restart id
dance, and the bespoke Kratos hook that blocked email-code login for admins. The
hook is replaced by the canonical `required_aal: aal2` configuration, which is
the intended Kratos mechanism and does not require custom hook code.

**Recovery-gate workaround (Kratos v26.2.0 empirical gap, 2026-06-25):** The
recovery-gate webhook (`kratos/hooks/recovery-gate.jsonnet`) is configured as a
Kratos after-hook with `can_interrupt: true`. Empirical testing against a live
v26.2.0 stack confirmed that Kratos omits `metadata_admin` from `ctx.identity`
in the after-hook body-template context. The jsonnet `is_admin` field therefore
always evaluates to `false` regardless of the real marker value. The gate
(`portal/src/server/listen.mjs: handleRecoveryGate`) bypasses the jsonnet field
by calling the Kratos admin API directly (`GET KRATOS_ADMIN_URL/admin/identities/:id`)
to read the authoritative `metadata_admin.admin` value. This workaround is
encapsulated in `fetchAdminMarker()` and is transparent to operators. The jsonnet
`identity_id` field is the load-bearing field; the gate fails closed (403) when it
is absent. Both the full end-to-end blocking (no session issued on admin recovery)
and the AAL2 mitigation (admin sessions from recovery cannot reach `/admin` without
step-up) are verified in the browser e2e suite (`j-recovery-flow.spec.ts`).

**Adding an admin is now a live UI action, not a config edit plus restart.** The
operational overhead of onboarding and offboarding admins is reduced to a few
clicks, and changes take effect immediately without a service interruption.

**Adopters** who want a different bootstrap mechanism (e.g. a different naming
convention for the marker, or a separate Keto policy file) can substitute it. The
interface is the `metadata_admin` JSON blob and the admin API write boundary; the
portal's admin-check helper reads both. The floor (shell access to the Kratos
admin API) is inherent to the Ory architecture and does not depend on any Othala
convention.

## Alternatives considered

- **Static env list of admin identity UUIDs.** Authority lives outside Kratos,
  which is conceptually clean. However, Kratos mints the id on create and rejects
  caller-supplied ids; the only way to populate the list is the create-read-back-
  configure-restart dance. Changing the admin set requires a redeploy and a service
  interruption. Not how any mature IdP manages administrators; rejected on
  operational grounds.

- **Static env list of admin usernames.** The username is knowable before
  enrollment (the operator assigns it), so there is no dance. However, authority
  would ride a trait that is, in principle, user-editable through the self-service
  settings flow. Hardening this requires making usernames immutable, which means
  disabling Kratos's profile self-service globally. We want users to be able to
  update their own email (a trait on the same schema) without admin intervention;
  disabling profile self-service to protect one trait is too blunt.

- **Static env list of verified admin emails.** An operator escalating to admin
  would need to control the target inbox, which is an acceptable trust assumption.
  The static list problem persists (redeploy to change the admin set), and email is
  a trait the identity can self-edit. More critically, email recovery on the admin
  path creates an email dependency that conflicts with disconnected administration;
  an admin locked to a mailbox is an admin who cannot recover when email is down.

- **Group-based admin (`metadata_admin.groups` contains `"admin"`).** Rejected at
  design time because it conflates user-visible display groups (which may need to
  be shown in the UI or passed in OIDC claims) with a security-critical authority
  bit. A user who can see their own group membership in a UI might infer or probe
  their admin status in unintended ways. The dedicated `metadata_admin.admin`
  marker is not a display concept; it is an authority bit, and it lives in the
  admin-API-only namespace for exactly that reason. The self-demote footgun is
  also more ambiguous in a group-based model (is removing yourself from the group
  the same as revoking your admin?) than in a boolean-flag model.

- **Ory Keto for authorization.** Keto is the correct long-term answer for
  multi-tenant, policy-heavy authorization graphs. At family scale with a fixed,
  small admin set, Keto adds an operational dependency (another service to deploy,
  configure, and keep available) for a use case that `metadata_admin` handles
  directly with no additional infrastructure. If Othala grows to multi-tenant or
  multi-operator use, migrating the admin check from a `metadata_admin` flag to a
  Keto relation tuple is a single-function change; the interface does not change.
