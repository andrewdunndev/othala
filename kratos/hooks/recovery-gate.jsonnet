// Recovery-gate webhook body (H1 / D3).
//
// Kratos posts this body to the Othala app's loopback admin endpoint
// (http://127.0.0.1:4431/admin/recovery-gate, authenticated with
// Bearer RECOVERY_GATE_SECRET) after the recovery code is verified,
// BEFORE issuing the privileged settings session.
//
// The gate checks whether the recovering identity's id appears in the
// OTHALA_ADMIN_IDS allowlist (immutable Kratos identity UUIDs). If it
// does, the gate replies 403 to abort recovery — admins must use the
// console break-glass path (docs/runbooks/admin-recovery.md). For all
// other identities it replies 200 to allow recovery to proceed.
//
// NOTE: the `groups` field below is display metadata (from
// metadata_admin), NOT the access-control key. The gate logic in
// portal/src/pages/admin/recovery-gate.ts keys exclusively on
// identity_id vs OTHALA_ADMIN_IDS. Groups are forwarded for
// observability/logging only.
//
// Available context per Kratos's web_hook spec:
//   - ctx.identity      : the resolved identity (traits, metadata_admin)
//   - ctx.flow          : the recovery flow object
//   - ctx.request_url   : the originating request URL
//
// We forward only what the gate needs: identity id, groups, and traits.
function(ctx) {
  identity_id: ctx.identity.id,
  groups: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'groups', []),
  traits: ctx.identity.traits,
}
