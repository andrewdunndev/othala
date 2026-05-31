// Recovery-gate webhook body (lab copy, structurally identical to production).
function(ctx) {
  identity_id: ctx.identity.id,
  groups: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'groups', []),
  traits: ctx.identity.traits,
}
