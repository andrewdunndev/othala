// Recovery-gate webhook body (lab copy, structurally identical to production).
//
// is_admin mirrors kratos/hooks/recovery-gate.jsonnet: derived from
// metadata_admin.admin (the ADR 08 marker; std.get defaults to false
// so the field is always a boolean in the payload).
// groups is display/observability metadata, NOT the authority key.
function(ctx) {
  identity_id: ctx.identity.id,
  is_admin: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'admin', false),
  groups: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'groups', []),
  traits: ctx.identity.traits,
}
