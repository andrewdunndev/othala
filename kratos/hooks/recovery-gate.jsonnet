// Recovery-gate webhook body (H1 / D3, updated ADR 0008).
//
// Kratos posts this body to the Othala app's loopback admin endpoint
// (http://<CONSENT_HOST>:4431/admin/recovery-gate, authenticated with
// Bearer RECOVERY_GATE_SECRET) after the recovery code is verified,
// BEFORE issuing the privileged settings session.
//
// The gate refuses recovery for admin identities (ADR 0008 — defense-in-depth).
// Admin authority is the `metadata_admin.admin` boolean, set only via the
// Kratos admin API (never writable through self-service flows or OIDC claims).
//
// IMPORTANT — Kratos v26.2.0 serialization gap (confirmed 2026-06-25):
//   ctx.identity in the after-hook body-template context does NOT include
//   `metadata_admin`. std.get() returns the default (false) regardless of the
//   real marker value. The `is_admin` field below therefore always evaluates
//   to false in the current Kratos version.
//
//   The gate (portal/src/server/listen.mjs: fetchAdminMarker) does NOT rely on
//   the `is_admin` field for its decision. Instead it reads `identity_id` from
//   this payload and calls the Kratos admin API directly to get the authoritative
//   metadata_admin.admin value. The `is_admin` field is kept for future
//   compatibility — it will be correct once Kratos fixes the hook serialization.
//
// The load-bearing field is `identity_id`. The gate uses it for the admin API
// lookup (GET KRATOS_ADMIN_URL/admin/identities/:identity_id). Without a valid
// identity_id the gate fails closed (403) regardless of other fields.
//
// The `groups` field is display metadata for observability and logging only.
// It is NOT the access-control key. The gate ignores it for the decision.
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
