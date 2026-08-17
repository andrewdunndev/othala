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
them costs time and money on every Ory bump.

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

`portal/src/lib/admin-api.ts`'s `listIdentities` calls the Ory SDK with
`{ perPage: 250 }` and renders whatever comes back. No reliance on the
`x-total-count` header — the string appears nowhere in the portal.

v25.4 removed `x-total-count` from `/admin/sessions`. We never read
it, so we didn't bite. Future Ory changes to pagination semantics
(cursor-based, total-counts on/off per endpoint) won't break us as
long as we keep capping at a fixed per_page.

The cost of the cap is stated in the code, not hidden: the Kratos identities
endpoint paginates via a `Link` header and this call does **not** follow it, so
the listing truncates past the cap. That is deliberate at family scale and is
the thing to revisit first if the identity count ever grows.

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

Every client manifest's `oidc:` block uses `authorization_code` +
`refresh_token` or `client_credentials`. No
`urn:ietf:params:oauth:grant-type:device_code`,
no implicit, no novel grant patterns.

v25.4 added Device Authorization Grant (RFC 8628) to Hydra additively.
No consumer in our manifest set requests device_code, so we don't even
touch the new surface. Future Ory grant-type additions are similarly
opt-in.

**To break this**: add a consumer that uses device_code (e.g., a
TV-app integration that displays a code-to-pair). Cost: device-flow
UI screens to add to portal + new Hydra config + new threat-model
considerations.

### 5. No in-pod mTLS, but pod-network as trust domain

Plain HTTP across the auth pod: the portal reaches Kratos and Hydra,
including their admin APIs, without TLS. The pod boundary is the trust
domain; defense-in-depth between in-pod services is partial-and-deliberate.
Othala hard-codes no peer address: every host in `kratos/kratos.yml` and
`hydra/hydra.yml` is a `${VAR}` token, "so the same file lands in both
topologies" — the compose harness and a production deployment supply different
names for the same slot, and the naming layers are ADR 07's. The standalone
consent service is retired; consent is folded into the app, so there is no
longer a kratos -> consent hop.

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
is the gate, not service-level auth. The one exception is the
recovery-gate webhook (Kratos to the app's `:4431/admin/recovery-gate`),
which is secret-gated: Kratos webhooks support only `api_key` and
`basic_auth`, so `kratos.yml` uses `type: api_key` with header name
`Authorization` and value `Bearer ${RECOVERY_GATE_SECRET}`, and
`handleRecoveryGate` constant-time compares that bearer before reading
the body, failing closed on a missing or wrong secret.

Ory will continue to ship per-service auth primitives (Hydra admin
bearer tokens, Kratos session validators, etc.); we use them where
useful but don't treat them as required boundaries.

**To break this**: bring multi-tenancy into the auth pod, which would
need real service-to-service auth. Out of scope for family.

### 8. Recovery-gate is the only "we extend Kratos" code path

The recovery-gate webhook (handled in `portal/src/server/listen.mjs` via
`portal/src/lib/access.ts`) is the single piece of code where we
intercept a Kratos flow. We use it because
admin email-recovery is the worst-case footgun (compromised Fastmail
→ admin takeover). Everything else uses Kratos's defaults.

Web_hook is a stable Kratos primitive (documented, configurable,
auth-supported via api_key). The risk surface is bounded.

**To break this**: add more webhooks. Each one is a new contract
with Kratos's webhook config schema; each one is a future-upgrade-burden
item. Add carefully.

### 9. `secrets.system` non-rotatable, doubly backed up

Hydra's at-rest encryption key. `hydra/hydra.yml` states the contract in-file:
"secrets.system is non-rotatable for the life of the Hydra DB. Generate once,
store in sops as `<host>.hydra_system_secret`. Never change without rebuilding
the database." The deployment is responsible for backing it up independently of
the running host; rotation is break-glass-only (full DB rebuild), and the
procedure is `docs/runbooks/secrets-rotation.md`.

The non-rotatable property is Ory's, not ours. We accept it and
document.

### 10. Substrate secrets are collapsed to a small core set

The substrate holds a handful of core secrets: a DB password, a session
secret (Kratos and Hydra cookies), a cipher secret (Kratos at-rest
encryption), the non-rotatable `secrets.system` key (Hydra at-rest
encryption), and a pairwise salt. Earlier revisions of the stack carried
several times that number, including a bearer token for the standalone
consent service, which was retired with the service. Exact key names and
the current count live in the deployment's own secret store;
`CHANGELOG.md` is the only place release state is asserted, so no
count is restated here.

Each rotation slot is collapsed to a single value — one key per slot, no
`_PREVIOUS` at rest.
**This trades a small amount of rotation ergonomics for substantial operator
clarity.** It is also the only shape the substrate accepts at rest: Kratos and
Hydra enforce `uniqueItems` on their secrets arrays, so a single active secret
is a single-element array and two identical slots is a config error. Rolling
rotation is still available, as a prepend-a-distinct-entry procedure rather
than a standing second slot; it is documented in
`docs/runbooks/cookie-rotation.md`.

**To break this**: re-introduce the two-slot model. Operator burden:
the sops file grows; rotation runbook becomes more careful.

### 11. The portal is the only metadata_admin writer

Every write to a Kratos identity's `metadata_admin.groups` goes through
`portal/src/lib/metadata-admin.ts: validateMetadataAdmin`. Kratos's
schema treats `metadata_admin` as opaque (`additionalProperties` not
enforced). Network isolation prevents direct kratos:4434 writes from
outside the auth pod; in-pod writes are limited to the portal.

If a second writer is ever added (CLI tool, migration script), the
validator gets factored out into a shared package so both paths enforce
the same shape. Documented in the project's adversarial security review,
MEDIUM-3.

**To break this**: add a second writer without factoring the validator.
Cost: typo'd groups silently land in storage; users lose role access
without obvious cause.

## When to revisit

Revisit when:

- An Ory release breaks one of these choices and we have to adapt.
- A scale-up genuinely needs one of these doors opened (e.g., a
  second admin operator needs CLI access to write metadata_admin;
  factor the validator).
- The QEMU-CI lab makes upgrade re-validation cheap enough that one of
  these closed doors is worth opening on a per-bump basis. It exists and
  runs the `e2e` job; the question is whether its coverage is good enough
  to trust a door open.

Each opening is a permanent operator-burden increase. Default closed.
