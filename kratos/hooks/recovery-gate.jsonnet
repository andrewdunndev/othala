// Recovery-gate webhook body.
//
// Kratos posts this body to the Othala app's loopback admin endpoint
// (http://<CONSENT_HOST>:4431/admin/recovery-gate, authenticated with
// Bearer RECOVERY_GATE_SECRET) after the recovery code is verified,
// BEFORE issuing the privileged settings session. The gate refuses
// recovery for admin identities, so a compromised mailbox is not a path to
// admin authority. The login-by-code gate (/admin/login-code-gate, on
// selfservice.flows.login.after.code) posts this same body.
//
// The gate reads `identity_id` and queries the Kratos admin API for the admin
// marker (portal/src/server/listen.mjs: fetchAdminMarker); without a valid id
// it fails closed (403).
//
// Available context per Kratos's web_hook spec:
//   - ctx.identity      : the resolved identity (traits)
//   - ctx.flow          : the recovery flow object
//   - ctx.request_url   : the originating request URL
//   - ctx.session       : the current session, where the flow has one; the
//                         profile-sessions hook keeps it and ends the rest
function(ctx) {
  identity_id: ctx.identity.id,
  traits: ctx.identity.traits,
  session_id: std.get(std.get(ctx, 'session', {}), 'id', ''),
}
