// Admin allowlist — the authoritative admin-access gate (DAG CU3 / B2, CVP-P1).
//
// Admin authority is an explicit env allowlist keyed on IMMUTABLE identity IDs,
// NOT group membership and NOT the user-editable email trait. Identity `id` is
// a Kratos-assigned UUID that is never writable via the self-service profile
// flow, so it cannot be escalated by editing a trait.
//
// OTHALA_ADMIN_IDS is a comma-separated list of Kratos identity UUIDs
// (sops-backed in deployment). An identity is an admin iff its `id`, trimmed
// and lowercased, appears in that list. UUIDs are case-insensitive.
//
// This REPLACES the former email-based OTHALA_ADMIN_SUBJECTS allowlist. Every
// former `metadata_admin.groups.includes('admin')` access/recovery/role gate
// and every email-trait-based gate is gone. The `admin` group is DISPLAY-ONLY:
// it still renders in the admin UI's group chips and may drive group_role_map
// role derivation for individual apps, but NO code path may gate portal-admin
// access, recovery refusal, or admin authority on it. Self-demote (an admin
// removing the `admin` group from their own identity) therefore can no longer
// drop admin authority — the ID allowlist is the only source of truth, and it
// lives outside Kratos.
//
// Bootstrap: OTHALA_ADMIN_IDS=<kratos-identity-uuid>
//
// Fail-closed: an unset / empty / whitespace-only list yields NO admins.
// A missing or empty identity id yields a non-admin.

/** Parse OTHALA_ADMIN_IDS into a normalized Set of admin identity UUIDs. */
export function adminIds(): Set<string> {
  const raw = process.env.OTHALA_ADMIN_IDS ?? '';
  const out = new Set<string>();
  for (const part of raw.split(',')) {
    const id = part.trim().toLowerCase();
    if (id) out.add(id);
  }
  return out;
}

/**
 * Authoritative admin check. Returns true iff `id` (trimmed, lowercased)
 * is present in OTHALA_ADMIN_IDS. Fail-closed on empty / missing id.
 */
export function isAdminId(id: string | null | undefined): boolean {
  if (!id) return false;
  const normalized = id.trim().toLowerCase();
  if (!normalized) return false;
  return adminIds().has(normalized);
}
