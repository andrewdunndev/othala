// Access-group parsing: reads `presentation.access` (else the `access_group`
// compat shim, else []) into `accessGroups`, the load-bearing access binding
// used by gate, access, tiles and the group registry. Absence means no access.
// Non-throwing: names missing the canonical form are skipped; hard validation
// is manifest-lint.ts.

/**
 * THE canonical group-name policy. Not an input guard on one parameter: this
 * is the one form a group name may take anywhere in the portal, so that the
 * group comparisons scattered across src/ can compare raw strings and agree by
 * construction instead of by staying in sync. No prefix is required.
 *
 * The boundaries that enforce it:
 *   - portal/src/lib/metadata-admin.ts `validateGroups` — the identity write
 *     path (createIdentity / updateIdentity in portal/src/lib/admin-api.ts).
 *   - `parseAccessGroups` below — manifest load (`presentation.access`,
 *     `presentation.access_group`).
 *   - portal/src/lib/manifest-lint.ts — WARNs on an access-binding name or a
 *     `group_role_map` key that misses it.
 *   - portal/src/pages/api/forward-auth.ts — the operator-set `?group=` param.
 *   - portal/src/lib/gate.ts `nonCanonicalGroups` — the READ boundary we do
 *     NOT own: a group stored straight through the Kratos admin API.
 *
 * kratos/identity.schema.json is NOT an enforcer of it — Kratos validates
 * `traits` only, so that file's `metadata_admin.groups` pattern is
 * documentation. It is nevertheless kept byte-identical to this one: when the
 * two diverged, the schema advertised names (leading digit, dot) that gate.ts
 * then refused on read, which is a lockout with no error message anywhere.
 */
export const GROUP_RE = /^[a-z][a-z0-9-]*$/;

/** True when `name` is a non-empty string matching the canonical policy. */
export function isValidAccessGroupName(name: unknown): name is string {
  return typeof name === 'string' && GROUP_RE.test(name);
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
