// Validator for `metadata_admin` writes. Kratos's schema covers traits only, so a typo here would be stored silently.

import type { MetadataAdmin } from './admin-api';
import { GROUP_RE } from './access-groups';
import { CREDENTIAL_ID_RE, cleanPasskeyName } from './passkey-names';
import { CLIENT_ID_RE } from './manifests';
import { avatarProblem, type Avatar } from './avatar';

const ROLE_NAME_RE = /^[a-z][a-z0-9_\-]*$/;
const MAX_LEN = 64;

export class MetadataAdminError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MetadataAdminError';
  }
}

const ALLOWED_KEYS = new Set(['groups', 'roles', 'admin', 'prerequisites', 'passkeyNames', 'avatar', 'grants_revoked']);
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
        `metadata_admin: unknown field "${key}". Allowed: groups, roles, admin, prerequisites, passkeyNames, avatar, grants_revoked.`,
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

  if ('passkeyNames' in obj && obj.passkeyNames !== undefined) {
    out.passkeyNames = validatePasskeyNames(obj.passkeyNames);
  }

  if ('avatar' in obj && obj.avatar !== undefined) {
    const problem = avatarProblem(obj.avatar);
    if (problem) throw new MetadataAdminError(`metadata_admin.avatar: ${problem}`);
    out.avatar = obj.avatar as Avatar;
  }

  if ('grants_revoked' in obj && obj.grants_revoked !== undefined) {
    const m = obj.grants_revoked as Record<string, unknown> | null;
    if (!m || typeof m !== 'object' || typeof m.fp !== 'string' || !/^[0-9a-f]{64}$/.test(m.fp) || typeof m.at !== 'string') {
      throw new MetadataAdminError('metadata_admin.grants_revoked must be { fp: 64 hex characters, at: ISO time }.');
    }
    out.grants_revoked = { fp: m.fp, at: m.at };
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

function validatePasskeyNames(value: unknown): Record<string, string> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new MetadataAdminError('metadata_admin.passkeyNames must be an object keyed by credential id.');
  }
  const out: Record<string, string> = {};
  for (const [id, name] of Object.entries(value as Record<string, unknown>)) {
    const clean = cleanPasskeyName(name);
    if (!CREDENTIAL_ID_RE.test(id) || clean === null) {
      throw new MetadataAdminError(`metadata_admin.passkeyNames["${id}"]: needs a hex credential id and a short name.`);
    }
    out[id] = clean;
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
