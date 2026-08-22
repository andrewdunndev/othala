// Recovery-gate webhook body (lab copy, structurally identical to production).
//
// is_admin mirrors kratos/hooks/recovery-gate.jsonnet: derived from
// metadata_admin.admin (the admin-authority marker; std.get defaults to false
// so the field is always a boolean in the payload).
// groups is display/observability metadata, NOT the authority key.
//
// Kratos v26.2.0 serialization gap applies here too: ctx.identity omits
// metadata_admin in the after-hook context, so is_admin always evaluates to
// false (see kratos/hooks/recovery-gate.jsonnet for the full note).
function(ctx) {
  identity_id: ctx.identity.id,
  is_admin: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'admin', false),
  groups: std.get(std.get(ctx.identity, 'metadata_admin', {}), 'groups', []),
  traits: ctx.identity.traits,
}
