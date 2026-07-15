// Application-level validator for `metadata_admin` writes.
//
// Why this exists (J1):
//
// Kratos identity-schema `additionalProperties: false` only enforces
// against `traits`. The `metadata_admin` block is admin-controlled and
// the schema validator treats it as opaque, so a typo (`grupos` instead
// of `groups`) is silently accepted and stored. The schema declaration
// for metadata_admin is documentation; runtime enforcement has to live
// at the write paths in this portal.
//
// Contract (matches identity.schema.json metadata_admin):
//   { groups?: string[]; roles?: Record<string, string>; admin?: boolean }
// where:
//   - groups: array of lowercase-dash-strings, length 1..64, no
//     duplicates, regex ^[a-z][a-z0-9.\-]*$
//   - roles: object with keys matching ^[a-z][a-z0-9]*$ mapping to role
//     names matching ^[a-z][a-z0-9_\-]*$, length 1..64
//   - admin: strict boolean (true|false); rejects non-boolean (string "true",
//     number 1, null, etc.) — fail-closed for admin authority (ADR 08)
//   - no other top-level keys allowed
//
// Returns the input on success (typed as MetadataAdmin) or an Error
// the caller surfaces as a notice. Hand-rolled, no schema-validator
// dependency: family-scale identity admin runs once a week, the cost
// of a validator dependency is not worth it.

import type { MetadataAdmin } from './admin-api';

const GROUP_NAME_RE = /^[a-z][a-z0-9.\-]*$/;
const CLIENT_ID_RE = /^[a-z][a-z0-9]*$/;
const ROLE_NAME_RE = /^[a-z][a-z0-9_\-]*$/;
const MAX_LEN = 64;

export class MetadataAdminError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MetadataAdminError';
  }
}

const ALLOWED_KEYS = new Set(['groups', 'roles', 'admin']);

export function validateMetadataAdmin(input: unknown): MetadataAdmin {
  if (input === null || input === undefined) return {};
  if (typeof input !== 'object' || Array.isArray(input)) {
    throw new MetadataAdminError('metadata_admin must be an object.');
  }

  // Reject unknown top-level keys: mirrors the schema's
  // additionalProperties: false intent. Catches grupos, role, etc.
  for (const key of Object.keys(input)) {
    if (!ALLOWED_KEYS.has(key)) {
      throw new MetadataAdminError(
        `metadata_admin: unknown field "${key}". Allowed: groups, roles, admin.`,
      );
    }
  }

  const out: MetadataAdmin = {};
  const obj = input as Record<string, unknown>;

  if ('groups' in obj && obj.groups !== undefined) {
    out.groups = validateGroups(obj.groups);
  }

  if ('roles' in obj && obj.roles !== undefined) {
    out.roles = validateRoles(obj.roles);
  }

  if ('admin' in obj && obj.admin !== undefined) {
    if (typeof obj.admin !== 'boolean') {
      throw new MetadataAdminError(
        `metadata_admin.admin must be a strict boolean (true or false); got ${typeof obj.admin}.`,
      );
    }
    out.admin = obj.admin;
  }

  return out;
}

function validateGroups(value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new MetadataAdminError('metadata_admin.groups must be an array of strings.');
  }
  const seen = new Set<string>();
  const out: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const item = value[i];
    if (typeof item !== 'string') {
      throw new MetadataAdminError(
        `metadata_admin.groups[${i}] must be a string; got ${typeof item}.`,
      );
    }
    if (item.length === 0 || item.length > MAX_LEN) {
      throw new MetadataAdminError(
        `metadata_admin.groups[${i}] length must be 1..${MAX_LEN}.`,
      );
    }
    if (!GROUP_NAME_RE.test(item)) {
      throw new MetadataAdminError(
        `metadata_admin.groups[${i}] "${item}" must match ${GROUP_NAME_RE}.`,
      );
    }
    if (seen.has(item)) {
      throw new MetadataAdminError(`metadata_admin.groups: duplicate entry "${item}".`);
    }
    seen.add(item);
    out.push(item);
  }
  return out;
}

function validateRoles(value: unknown): Record<string, string> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new MetadataAdminError(
      'metadata_admin.roles must be an object keyed by client_id.',
    );
  }
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (!CLIENT_ID_RE.test(k)) {
      throw new MetadataAdminError(
        `metadata_admin.roles: client_id "${k}" must match ${CLIENT_ID_RE}.`,
      );
    }
    if (typeof v !== 'string') {
      throw new MetadataAdminError(
        `metadata_admin.roles["${k}"]: role name must be a string.`,
      );
    }
    if (v.length === 0 || v.length > MAX_LEN) {
      throw new MetadataAdminError(
        `metadata_admin.roles["${k}"]: role name length must be 1..${MAX_LEN}.`,
      );
    }
    if (!ROLE_NAME_RE.test(v)) {
      throw new MetadataAdminError(
        `metadata_admin.roles["${k}"]: role name "${v}" must match ${ROLE_NAME_RE}.`,
      );
    }
    out[k] = v;
  }
  return out;
}
