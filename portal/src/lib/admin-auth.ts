// Admin allowlist — the authoritative admin-access gate (DAG CU3 / B2).
//
// Admin authority is an explicit env allowlist, NOT group membership.
// AUTH_ADMIN_SUBJECTS is a comma-separated list of identity emails
// (sops-backed in deployment). A subject is an admin iff its email,
// case-folded and trimmed, appears in that list.
//
// This REPLACES every former `metadata_admin.groups.includes('admin')`
// access/recovery/role gate. The `admin` group is now DISPLAY-ONLY: it
// still renders in the admin UI's group chips and may drive
// group_role_map role derivation for individual apps, but NO code path
// may gate portal-admin access, recovery refusal, or admin authority on
// it. Self-demote (an admin removing the `admin` group from their own
// identity) therefore can no longer drop admin authority — the allowlist
// is the only source of truth, and it lives outside Kratos.
//
// Bootstrap: AUTH_ADMIN_SUBJECTS=andrew@dunn.dev
//
// Fail-closed: an unset / empty / whitespace-only list yields NO admins.
// A missing email on the identity yields a non-admin.

/** Parse AUTH_ADMIN_SUBJECTS into a normalized Set of admin emails. */
export function adminSubjects(): Set<string> {
  const raw = process.env.AUTH_ADMIN_SUBJECTS ?? '';
  const out = new Set<string>();
  for (const part of raw.split(',')) {
    const email = part.trim().toLowerCase();
    if (email) out.add(email);
  }
  return out;
}

/**
 * Authoritative admin check. Returns true iff `email` (case-folded,
 * trimmed) is present in AUTH_ADMIN_SUBJECTS. Fail-closed on empty /
 * missing email.
 */
export function isAdminSubject(email: string | null | undefined): boolean {
  if (!email) return false;
  const normalized = email.trim().toLowerCase();
  if (!normalized) return false;
  return adminSubjects().has(normalized);
}
