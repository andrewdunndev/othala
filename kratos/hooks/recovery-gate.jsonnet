// Recovery-gate webhook body (H1 / D3).
//
// Kratos posts this body to the consent service's /webhooks/recovery-gate
// endpoint after the recovery code is verified, BEFORE issuing the
// privileged settings session. The gate replies 403 to abort recovery for
// admin identities; 200 to allow.
//
// Available context per Kratos's web_hook spec:
//   - ctx.identity      : the resolved identity (traits, metadata_admin)
//   - ctx.flow          : the recovery flow object
//   - ctx.request_url   : the originating request URL
//
// We forward only what the gate needs: identity id, traits, and groups.
function(ctx) {
  identity_id: ctx.identity.id,
  groups: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'groups', []),
  traits: ctx.identity.traits,
}
