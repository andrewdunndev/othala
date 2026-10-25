/**
 * The one form a group name takes anywhere in the portal, so group comparisons are raw string equality.
 * Kratos does not validate metadata_admin, so gate.ts re-checks on read.
 */
export const GROUP_RE = /^[a-z][a-z0-9-]*$/;

export function isValidAccessGroupName(name: unknown): name is string {
  return typeof name === 'string' && GROUP_RE.test(name);
}

/** The `presentation.access` names in declared order, de-duplicated; a name missing GROUP_RE is dropped. */
export function parseAccessGroups(p: Record<string, unknown>): string[] {
  const access = p['access'];
  if (!Array.isArray(access)) return [];
  const out: string[] = [];
  for (const raw of access) {
    const name = typeof raw === 'string' ? raw.trim() : '';
    if (isValidAccessGroupName(name) && !out.includes(name)) out.push(name);
  }
  return out;
}
