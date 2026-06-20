// Access-group parsing for unified manifests (access-model — group binding).
//
// The manifest layer reads `presentation.access:` (adopter-named groups,
// arbitrary charset, no `access-` prefix required) into a normalized
// `accessGroups: string[]` field on both the OIDC `ClientManifest` and the
// dashboard `AppTile`. As of Phase 2 (docs/access-model.md §10/§17) this field
// is the LOAD-BEARING access binding: the OIDC gate (gate.ts), effective-access
// view (access.ts), tile visibility (tiles.ts), and the group registry
// (group-registry.ts) all key off it. The `access-` prefix is no longer a
// runtime type discriminator — a group's type comes from its binding, derived
// by group-registry.ts. (The forward-auth GROUP_RE prefix check is the one
// remaining prefix consumer, relaxed in Phase 3.)
//
// Parse precedence (docs/access-model.md §11):
//   1. presentation.access non-empty list → use it.
//   2. else presentation.access_group non-empty → [access_group] (compat shim,
//      NO prefix validation applied here).
//   3. else [] (no fallback of any kind — absence is absence. othala primitive
//      #5: absence of a binding means NO access; there is no framework default
//      that silently grants visibility. manifests.ts carries the `[]` through
//      verbatim, and a bare manifest with `[]` + no skip_access_check is a
//      load-time BLOCK in validateClients).
//
// Validation here is non-throwing: names that miss the safe charset are
// skipped, not rejected. Hard validation is the lint in manifest-lint.ts (§11).

/** Safe group-name charset (docs/access-model.md §5): no prefix required. */
export const ACCESS_GROUP_NAME_RE = /^[a-z0-9][a-z0-9-]*$/;

/** True when `name` is a non-empty string within the safe access-group charset. */
export function isValidAccessGroupName(name: unknown): name is string {
  return typeof name === 'string' && ACCESS_GROUP_NAME_RE.test(name);
}

/**
 * Resolve the normalized access-group list for a `presentation:` block.
 *
 * `p` is the raw parsed `presentation:` mapping. The precedence above is
 * applied; each candidate is charset-validated and silently dropped on a miss
 * (Phase 1 is non-breaking — see the module header). Duplicates are de-duped
 * while preserving declared order.
 */
export function parseAccessGroups(p: Record<string, unknown>): string[] {
  // (1) presentation.access — a non-empty list wins outright.
  const access = p['access'];
  if (Array.isArray(access)) {
    const out: string[] = [];
    for (const raw of access) {
      const name = typeof raw === 'string' ? raw.trim() : '';
      if (isValidAccessGroupName(name) && !out.includes(name)) out.push(name);
    }
    if (out.length > 0) return out;
  }

  // (2) compat shim: singular access_group → one-element list, NO prefix
  //     validation (the access-<slug> rule is intentionally not applied here).
  const single = p['access_group'];
  if (typeof single === 'string') {
    const name = single.trim();
    if (isValidAccessGroupName(name)) return [name];
  }

  // (3) absence → empty list.
  return [];
}
