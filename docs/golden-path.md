# Golden path

The integration choices that keep this stack durable across Ory upgrades.

## Why this doc exists

Ory's release cadence is approximately annual minor releases with
infrequent breaking changes. Looking at the v1.3 → v25.4 → v26.2
arc (Sep 2024 to Mar 2026, ~18 months), exactly one breaking-change
set landed (v25.4: removed `x-total-count` header from `/admin/sessions`,
changed OIDC account-linking error response code, gated
`show_verification_ui` emission, and moved OIDC registration error
fields between node groups). **None of those touched our integration.**
That isn't luck — it's the result of deliberate choices, each of which
is listed here as a load-bearing commitment.

Read this doc when you're tempted to widen the integration surface
("should we turn on OIDC self-service registration?"). The choices
below are the upgrade-burden tradeoffs we already paid for; reverting
them costs the next future-Andrew time and money on every Ory bump.

## The choices

### 1. No OIDC self-service registration

`kratos.yml: selfservice.flows.registration.enabled: false`. Onboarding
is admin-driven (one-time enrollment URLs sent via Signal / iMessage).

This cuts us out of the most-frequently-changed area in Kratos. The
v25.4 release alone moved OIDC registration error fields to a different
node group; the v26.x cycle continues to iterate on the registration
flow. We don't ride that treadmill.

**To break this**: turn on OIDC self-service registration. Cost: track
Kratos's registration-flow node-group changes on every bump.

### 2. Admin pagination uses cap-and-render, not total-count

`portal/src/lib/admin-api.ts` calls `/admin/identities?per_page=250`
and renders whatever comes back. No reliance on the `x-total-count`
header.

v25.4 removed `x-total-count` from `/admin/sessions`. We never read
it, so we didn't bite. Future Ory changes to pagination semantics
(cursor-based, total-counts on/off per endpoint) won't break us as
long as we keep capping at a fixed per_page.

**To break this**: add pagination UI that displays "Page 3 of 47."
That requires reading total-count, exposing us to its presence-or-not
across Ory versions.

### 3. Portal owns its own verification + recovery UIs

`portal/src/pages/auth/*.astro` renders the verification, recovery,
settings, and login flows. The portal calls Kratos's `/self-service/*`
APIs to drive the flow but renders its own UI; it doesn't render
Kratos-emitted state flags like `show_verification_ui` that change
between versions.

v25.4 changed when `show_verification_ui` is emitted. We don't read
it, so we didn't bite. Similarly, Kratos's `oidc` node group rename
in v25.4 doesn't reach us because we don't render OIDC flow node
groups.

**To break this**: switch to the `kratos-selfservice-ui-node` reference
UI. That UI renders Kratos's emitted node groups directly; we'd
inherit every Kratos UI-shape change.

### 4. Conservative OIDC grant types

Every `hydra/clients/*.yaml` uses `authorization_code` + `refresh_token`
or `client_credentials`. No `urn:ietf:params:oauth:grant-type:device_code`,
no implicit, no novel grant patterns.

v25.4 added Device Authorization Grant (RFC 8628) to Hydra additively.
No consumer in our manifest set requests device_code, so we don't even
touch the new surface. Future Ory grant-type additions are similarly
opt-in.

**To break this**: add a consumer that uses device_code (e.g., a
TV-app integration that displays a code-to-pair). Cost: device-flow
UI screens to add to portal + new Hydra config + new threat-model
considerations.

### 5. No mTLS in-cluster, but pod-network as trust domain

Plain HTTP across the auth pod (consent → hydra:4445, portal →
kratos:4434, kratos → consent:4477). The pod boundary is the trust
domain; defense-in-depth between in-pod services is partial-and-deliberate.

Ory's roadmap could add mTLS or SPIFFE primitives; we ignore them
because the family-scale single-tenant homelab doesn't justify the
operator burden. If Ory ever makes mTLS a default-on assumption (it
won't; the maintainers care about ergonomics), we'd have to revisit.

**To break this**: bring mTLS or service-mesh discipline. Costs operator
time forever.

### 6. Conservative subject identifier

`hydra.yml: oidc.subject_identifiers.supported_types: ["public"]`. Same
`sub` per user across every client. No pairwise.

Pairwise is supported by Hydra; we don't use it because no consumer
needs cross-client correlation prevention at family scale. Pairwise
adds operator burden (per-client salt config + key rotation
implications) for a privacy property the family doesn't value.

**To break this**: turn on pairwise for an external SaaS that demands
it. Operationally fine but a one-way change for that client.

### 7. Single security domain

The auth pod is one security domain. Documented in
`ARCHITECTURE.md` "Trust boundary." Network isolation
is the gate, not service-level auth. The webhook from Kratos to consent
is unauthenticated-at-the-network-layer but secret-gated via
`X-Webhook-Auth` (the recovery-gate posture). Cross-pod traffic is
podman-network-isolated.

Ory will continue to ship per-service auth primitives (Hydra admin
bearer tokens, Kratos session validators, etc.); we use them where
useful (Hydra admin via consent's CONSENT_ADMIN_BEARER) but don't
treat them as required boundaries.

**To break this**: bring multi-tenancy into the auth pod, which would
need real service-to-service auth. Out of scope for family.

### 8. Recovery-gate is the only "we extend Kratos" code path

The recovery-gate webhook (`consent/recovery_gate.go`) is the single
piece of code where we intercept a Kratos flow. We use it because
admin email-recovery is the worst-case footgun (compromised Fastmail
→ admin takeover). Everything else uses Kratos's defaults.

Web_hook is a stable Kratos primitive (documented, configurable,
auth-supported via api_key). The risk surface is bounded.

**To break this**: add more webhooks. Each one is a new contract
with Kratos's webhook config schema; each one is a future-upgrade-burden
item. Add carefully.

### 9. `secrets.system` non-rotatable, doubly backed up

Hydra's at-rest encryption key. Stored in sops (`carmine.hydra_system_secret`)
AND independently backed up via the standing estate backup posture
(rclone → Backblaze B2 + zfs send to onsite tank). Rotation is
break-glass-only (full DB rebuild).

The non-rotatable property is Ory's, not ours. We accept it and
document.

### 10. Substrate secret collapse (homelab simplification)

v0.1.3 had 19 sops keys for the auth substrate. v0.1.4 collapses to 6:
`auth_db_password`, `auth_session_secret` (used for both Kratos and
Hydra cookie current+previous slots), `auth_cipher_secret`,
`hydra_system_secret`, `auth_pairwise_salt`, `auth_internal_bearer`.

The two-slot cookie rotation pattern (CURRENT + PREVIOUS) is reduced
to single-value reuse in production. **This trades a small amount of
rotation ergonomics for substantial operator clarity.** The two-slot
pattern is still available in lab and documented in
`docs/runbooks/cookie-rotation.md` for production-grade environments
that need rolling rotation; we accept the brief disruption window in
exchange for simpler sops state.

**To break this**: re-introduce the two-slot model. Operator burden:
the sops file grows; rotation runbook becomes more careful.

### 11. The portal is the only metadata_admin writer

Every write to a Kratos identity's `metadata_admin.groups` goes through
`portal/src/lib/metadata-admin.ts: validateMetadataAdmin`. Kratos's
schema treats `metadata_admin` as opaque (`additionalProperties` not
enforced). Network isolation prevents direct kratos:4434 writes from
outside the auth pod; in-pod writes are limited to the portal.

If a second writer is ever added (CLI tool, migration script), the
validator gets factored out into a Go package shared with consent so
both languages enforce the same shape. Documented in
`docs/security-review-2026-05-04.md` MEDIUM-3.

**To break this**: add a second writer without factoring the validator.
Cost: typo'd groups silently land in storage; users lose role access
without obvious cause.

## When to revisit

This doc is a contract with future-you. Revisit when:

- An Ory release breaks one of these choices and we have to adapt.
- A scale-up genuinely needs one of these doors opened (e.g., a
  second admin operator needs CLI access to write metadata_admin;
  factor the validator).
- The QEMU-CI lab (forthcoming) makes upgrade re-validation cheap
  enough that one of these closed doors is worth opening on a per-bump
  basis.

Each opening is a permanent operator-burden increase. Default closed.
