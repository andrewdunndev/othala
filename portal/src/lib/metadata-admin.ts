// Validator for `metadata_admin` writes. Kratos does not validate that block
// (its schema only covers traits), so a typo would be stored silently.
// Contract: { groups?: string[]; roles?: Record<string,string>; admin?: boolean; prerequisites?: string[] }
// with canonical group names (GROUP_RE), a strict boolean admin, and no other
// keys. Hand-rolled, no validator dependency; returns the input or an Error.

import type { MetadataAdmin } from './admin-api';
import { GROUP_RE } from './access-groups';

const CLIENT_ID_RE = /^[a-z][a-z0-9]*$/;
const ROLE_NAME_RE = /^[a-z][a-z0-9_\-]*$/;
const MAX_LEN = 64;

export class MetadataAdminError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MetadataAdminError';
  }
}

const ALLOWED_KEYS = new Set(['groups', 'roles', 'admin', 'prerequisites']);
const PREREQUISITE_RE = /^[a-z][a-z0-9-]{0,39}$/;

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
        `metadata_admin: unknown field "${key}". Allowed: groups, roles, admin, prerequisites.`,
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

  if ('prerequisites' in obj && obj.prerequisites !== undefined) {
    out.prerequisites = validatePrerequisites(obj.prerequisites);
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

function validatePrerequisites(value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new MetadataAdminError('metadata_admin.prerequisites must be an array of strings.');
  }
  const out: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const item = value[i];
    if (typeof item !== 'string' || !PREREQUISITE_RE.test(item)) {
      throw new MetadataAdminError(
        `metadata_admin.prerequisites[${i}] must be a lowercase slug matching ${PREREQUISITE_RE}.`,
      );
    }
    if (out.includes(item)) {
      throw new MetadataAdminError(`metadata_admin.prerequisites: duplicate entry "${item}".`);
    }
    out.push(item);
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
    if (!GROUP_RE.test(item)) {
      throw new MetadataAdminError(
        `metadata_admin.groups[${i}] "${item}" must match ${GROUP_RE}.`,
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
