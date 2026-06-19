// Login-gate webhook body (CVP-P3).
//
// Kratos posts this body to the portal's /admin/login-gate endpoint on the
// `after.code` login hook before issuing the session. The gate refuses admin
// identities (returning 403 with a Kratos-webhook error shape); Kratos
// interprets the 403 as a flow interruption and surfaces the error to the user.
// Admins must use a passkey or console — not email-code — which would yield an
// admin AAL1 session from transient mailbox access.
//
// Only the `after.code` hook fires: passkey/password/webauthn login methods
// are unaffected. Admin identities can still complete passkey or password login
// normally.
//
// Available context per Kratos's web_hook spec:
//   - ctx.identity      : the resolved identity (traits, metadata_admin)
//   - ctx.flow          : the login flow object
//   - ctx.request_url   : the originating request URL
//
// We forward only what the gate needs: identity id, groups, and traits.
// This mirrors recovery-gate.jsonnet exactly (same payload shape, same gate
// trust domain — RECOVERY_GATE_SECRET — no new secret required).
function(ctx) {
  identity_id: ctx.identity.id,
  groups: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'groups', []),
  traits: ctx.identity.traits,
}
