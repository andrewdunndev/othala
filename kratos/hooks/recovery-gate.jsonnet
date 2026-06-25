// Recovery-gate webhook body (H1 / D3, updated ADR 0008).
//
// Kratos posts this body to the Othala app's loopback admin endpoint
// (http://127.0.0.1:4431/admin/recovery-gate, authenticated with
// Bearer RECOVERY_GATE_SECRET) after the recovery code is verified,
// BEFORE issuing the privileged settings session.
//
// The gate refuses recovery for admin identities (defense-in-depth).
// Admin authority is determined by the `is_admin` field below, which
// reads `metadata_admin.admin` (a boolean set only via the Kratos admin
// API — never writable via self-service flows or OIDC claim mapping).
// The retired OTHALA_ADMIN_IDS UUID allowlist is no longer consulted.
//
// The gate logic in portal/src/server/listen.mjs (recoveryGateVerdict)
// keys exclusively on `is_admin === true`. If is_admin is absent or not
// a boolean true, the gate treats it as non-admin (fail-safe for the
// common case; std.get ensures a default of false when the key is absent).
//
// NOTE: the `groups` field below is display metadata forwarded for
// observability/logging only. It is NOT the access-control key.
//
// Available context per Kratos's web_hook spec:
//   - ctx.identity      : the resolved identity (traits, metadata_admin)
//   - ctx.flow          : the recovery flow object
//   - ctx.request_url   : the originating request URL
//
// We forward only what the gate needs: identity id, admin marker,
// groups (observability), and traits.
function(ctx) {
  identity_id: ctx.identity.id,
  is_admin: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'admin', false),
  groups: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'groups', []),
  traits: ctx.identity.traits,
}
