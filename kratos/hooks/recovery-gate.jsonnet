// Recovery-gate webhook body (docs/adr/08-admin-authority-model.md).
//
// Kratos posts this body to the Othala app's loopback admin endpoint
// (http://<CONSENT_HOST>:4431/admin/recovery-gate, authenticated with
// Bearer RECOVERY_GATE_SECRET) after the recovery code is verified,
// BEFORE issuing the privileged settings session. The gate refuses
// recovery for admin identities — defense-in-depth per ADR 08.
//
// Kratos v26.2.0 serialization gap (recorded in ADR 08): ctx.identity omits
// `metadata_admin` in the after-hook body-template context, so `is_admin`
// below always evaluates to false. The gate does NOT rely on it — it reads
// `identity_id` and queries the Kratos admin API for the authoritative
// marker (portal/src/server/listen.mjs: fetchAdminMarker); is_admin is kept
// for forward compatibility.
//
// The load-bearing field is `identity_id` — without a valid one the gate
// fails closed (403). `groups` is display/observability metadata only,
// never the access-control key.
//
// Available context per Kratos's web_hook spec:
//   - ctx.identity      : the resolved identity (traits; metadata_admin ABSENT
//                         in v26.2.0 after-hook context — see note above)
//   - ctx.flow          : the recovery flow object
//   - ctx.request_url   : the originating request URL
function(ctx) {
  identity_id: ctx.identity.id,
  // NOTE: always false in Kratos v26.2.0 (metadata_admin absent from ctx.identity
  // in after-hook context). Gate ignores this field; uses admin API lookup instead.
  is_admin: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'admin', false),
  groups: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'groups', []),
  traits: ctx.identity.traits,
}
