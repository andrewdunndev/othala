// App manifest loader. loadClientManifests() returns every manifest, presentation-only tiles included;
// oidcClientManifests() narrows to the OIDC clients.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { parseAccessGroups } from './access-groups';
import { IDENTITY_GROUPS, MANIFEST_DIR } from './constants';

export interface ClientRole {
  name: string;
  description: string;
  /** null when the key is absent, which the validator flags. */
  claimEmit: Record<string, unknown> | null;
}

export interface ClientManifest {
  clientId: string;
  /** A `presentation:` tile with no `oidc:` client: it has access groups but registers no OIDC client. */
  presentationOnly: boolean;
  clientName: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  scopes: string[];
  /** Raw `oidc.scope` string as Hydra expects it. */
  scope: string;
  audience: string[];
  grantTypes: string[];
  responseTypes: string[];
  tokenEndpointAuthMethod: string;
  skipConsent: boolean;
  backchannelLogoutUri: string;
  /** Includes the sid claim in the logout token. */
  backchannelLogoutSessionRequired: boolean;
  /** Groups whose members may enter this app (any one suffices), from `presentation.access`; no implicit fallback. */
  accessGroups: string[];
  roles: ClientRole[];
  /** Identity group to the role its members get by default. */
  groupRoleMap: Record<string, string>;
  /** `null` when absent, which means true. */
  emitGroupsClaim: boolean | null;
  /** Disables the access gate for this app. */
  skipAccessCheck: boolean;
  sourcePath: string;
  /** Prerequisite names defined under requirements/. */
  requires?: string[];
}

/** Only an explicit `emit_groups_claim: false` suppresses. */
export function shouldEmitGroups(m: ClientManifest): boolean {
  return m.emitGroupsClaim ?? true;
}

let manifestDirOverride: string | undefined;

/** Point the loaders at another directory, or back at MANIFEST_DIR with `undefined`. Tests only: production never calls it. */
export function setManifestDir(dir: string | undefined): void {
  manifestDirOverride = dir;
}

/** The manifest directory every loader reads. Production is fixed at MANIFEST_DIR; under `astro dev` the MANIFEST_DIR env var points the dev server at a scratch catalog. */
export function manifestDir(): string {
  const devDir = import.meta.env?.DEV ? process.env.MANIFEST_DIR : undefined;
  return manifestDirOverride ?? devDir ?? MANIFEST_DIR;
}

interface CacheEntry {
  manifests: ClientManifest[];
  mtimeMs: number;
  loadedAtMs: number;
}

let cache: CacheEntry | null = null;
export const CACHE_TTL_MS = 30 * 1000;

/** Drop the manifest cache so the next load re-reads disk (SIGHUP path in registrar.ts). */
export function invalidateManifestCache(): void {
  cache = null;
}

function splitScope(scope: unknown): string[] {
  if (!scope) return [];
  if (Array.isArray(scope)) return scope.map(String);
  return String(scope).split(/\s+/).filter(Boolean);
}

function rawScope(scope: unknown): string {
  if (!scope) return '';
  if (Array.isArray(scope)) return scope.map(String).join(' ');
  return String(scope).trim();
}

function readClaimEmit(v: unknown): Record<string, unknown> | null {
  if (v && typeof v === 'object' && !Array.isArray(v) && 'claim_emit' in v) {
    const ce = (v as { claim_emit?: unknown }).claim_emit;
    if (ce && typeof ce === 'object' && !Array.isArray(ce)) {
      return ce as Record<string, unknown>;
    }
    return null;
  }
  return null;
}

function normaliseRoles(raw: unknown): ClientRole[] {
  if (!raw) return [];
  if (Array.isArray(raw)) {
    return raw
      .filter((r): r is { name: unknown; description?: unknown } => typeof r === 'object' && r !== null && 'name' in r)
      .map((r) => ({
        name: String(r.name),
        description: String(r.description ?? ''),
        claimEmit: readClaimEmit(r),
      }));
  }
  if (typeof raw === 'object') {
    return Object.entries(raw as Record<string, unknown>).map(([name, v]) => ({
      name,
      description: String((v && typeof v === 'object' && 'description' in v ? (v as { description?: unknown }).description : '') ?? ''),
      claimEmit: readClaimEmit(v),
    }));
  }
  return [];
}

function readEmitGroups(c: Record<string, unknown>): boolean | null {
  if (!('emit_groups_claim' in c)) return null;
  const v = c.emit_groups_claim;
  if (typeof v === 'boolean') return v;
  return null;
}

function normaliseGroupRoleMap(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

/** A read or parse error is warned and skipped so one bad file does not fail the whole load. */
function loadOne(file: string, dir: string): ClientManifest | null {
  try {
    const text = readFileSync(join(dir, file), 'utf8');
    return parseManifest(text, file);
  } catch (err) {
    console.warn(`manifests: skipping ${file}: ${err}`);
    return null;
  }
}

/** `presentation.requires` as raw strings, unnormalized, so the lint can flag a malformed or unknown name. */
function readRequires(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/** Parse one manifest YAML body; exported so tests skip the filesystem. */
export function parseManifest(yamlText: string, filename: string): ClientManifest {
  const yaml = parseYaml(yamlText) ?? {};

  const file = filename;
  const oidc = (yaml as { oidc?: unknown }).oidc;
  const consent = (yaml as { consent?: unknown }).consent;

  const presentation = (yaml as { presentation?: unknown }).presentation;
  const p = (presentation && typeof presentation === 'object' && !Array.isArray(presentation)
    ? presentation
    : {}) as Record<string, unknown>;
  const hasPresentation = presentation != null && typeof presentation === 'object' && !Array.isArray(presentation);

  const accessGroups = parseAccessGroups(p);

  if (!oidc || typeof oidc !== 'object') {
    if (!hasPresentation) {
      throw new Error(`${file}: missing or non-object oidc: block`);
    }
    const clientId = String(p.client_id ?? file.replace(/\.ya?ml$/, ''));
    const c = (consent && typeof consent === 'object' ? consent : {}) as Record<string, unknown>;
    return {
      clientId,
      presentationOnly: true,
      clientName: String(p.name ?? clientId),
      redirectUris: [],
      postLogoutRedirectUris: [],
      scopes: [],
      scope: '',
      audience: [],
      grantTypes: [],
      responseTypes: [],
      tokenEndpointAuthMethod: '',
      skipConsent: false,
      backchannelLogoutUri: '',
      backchannelLogoutSessionRequired: false,
      accessGroups,
      roles: [],
      groupRoleMap: {},
      emitGroupsClaim: null,
      skipAccessCheck: Boolean(c.skip_access_check ?? false),
      sourcePath: file,
      requires: readRequires(p.requires),
    };
  }

  const o = oidc as Record<string, unknown>;
  const clientId = String(o.client_id ?? file.replace(/\.ya?ml$/, ''));
  const c = (consent && typeof consent === 'object' ? consent : {}) as Record<string, unknown>;

  return {
    clientId,
    presentationOnly: false,
    clientName: String(o.client_name ?? clientId),
    redirectUris: Array.isArray(o.redirect_uris) ? o.redirect_uris.map(String) : [],
    postLogoutRedirectUris: Array.isArray(o.post_logout_redirect_uris)
      ? o.post_logout_redirect_uris.map(String)
      : [],
    scopes: splitScope(o.scope),
    scope: rawScope(o.scope),
    audience: Array.isArray(o.audience) ? o.audience.map(String) : [],
    grantTypes: Array.isArray(o.grant_types) ? o.grant_types.map(String) : [],
    responseTypes: Array.isArray(o.response_types) ? o.response_types.map(String) : [],
    tokenEndpointAuthMethod: o.token_endpoint_auth_method ? String(o.token_endpoint_auth_method) : '',
    skipConsent: Boolean(o.skip_consent ?? false),
    backchannelLogoutUri: o.backchannel_logout_uri ? String(o.backchannel_logout_uri) : '',
    backchannelLogoutSessionRequired: Boolean(o.backchannel_logout_session_required ?? false),
    accessGroups,
    roles: normaliseRoles(c.roles),
    groupRoleMap: normaliseGroupRoleMap(c.group_role_map),
    emitGroupsClaim: readEmitGroups(c),
    skipAccessCheck: Boolean(c.skip_access_check ?? false),
    sourcePath: file,
    requires: readRequires(p.requires),
  };
}

/** The sorted app manifest filenames in `dir`, groups.yaml excluded; an absent directory has none. */
export function manifestFiles(dir: string): string[] {
  try {
    return readdirSync(dir)
      .filter((f) => (f.endsWith('.yaml') || f.endsWith('.yml')) && f !== 'groups.yaml')
      .sort();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
}

function loadFromDisk(): ClientManifest[] {
  const dir = manifestDir();
  return manifestFiles(dir)
    .map((f) => loadOne(f, dir))
    .filter((m): m is ClientManifest => m !== null);
}

function freshestMtime(): number {
  const dir = manifestDir();
  try {
    let max = 0;
    for (const f of manifestFiles(dir)) {
      const m = statSync(join(dir, f)).mtimeMs;
      if (m > max) max = m;
    }
    return max;
  } catch {
    return 0;
  }
}

/** Drops, with a logged reason, every manifest that fails validation or shares a client_id (case-insensitive) with another, so one bad file never takes the rest down. */
function quarantine(manifests: ClientManifest[]): ClientManifest[] {
  const files = new Map<string, string[]>();
  for (const m of manifests) {
    const key = m.clientId.toLowerCase();
    files.set(key, [...(files.get(key) ?? []), m.sourcePath]);
  }
  return manifests.filter((m) => {
    const key = m.clientId.toLowerCase();
    const sharing = files.get(key) ?? [];
    const reason =
      sharing.length > 1
        ? `duplicate client_id ${JSON.stringify(key)} in ${sharing.join(', ')}`
        : validateClients([m]).join('; ');
    if (reason) console.warn(`manifests: dropping ${m.sourcePath}: ${reason}`);
    return !reason;
  });
}

/** Every valid app manifest, sorted by filename; cached 30 s or until an mtime changes. Invalid files are quarantined, not fatal. */
export function loadClientManifests(): ClientManifest[] {
  const now = Date.now();
  const mtime = freshestMtime();
  if (
    cache &&
    cache.mtimeMs === mtime &&
    now - cache.loadedAtMs < CACHE_TTL_MS
  ) {
    return cache.manifests;
  }

  const manifests = quarantine(loadFromDisk());
  cache = { manifests, mtimeMs: mtime, loadedAtMs: now };
  return manifests;
}

/** The registrable OIDC subset: manifests declaring `oidc:`. registerAllClients() needs a secret per manifest,
 * so callers pushing to Hydra must narrow through this first. */
export function oidcClientManifests(
  set: ClientManifest[] = loadClientManifests(),
): ClientManifest[] {
  return set.filter((m) => !m.presentationOnly);
}

/**
 * True when every requested audience matches a redirect_uri by exact parsed origin (scheme://host[:port]).
 * Fail-closed: unknown client, empty redirect set, non-URL audience or any mismatch returns false.
 * An empty audience list returns true (nothing to constrain).
 */
export function audienceMatchesRedirect(
  manifest: ClientManifest | undefined,
  audience: string[] | undefined,
): boolean {
  if (!manifest) return false;

  const auds = audience ?? [];
  if (auds.length === 0) return true;

  const allowedOrigins = new Set<string>();
  for (const redirect of manifest.redirectUris) {
    const origin = originOf(redirect);
    if (origin) allowedOrigins.add(origin);
  }
  if (allowedOrigins.size === 0) return false;

  for (const aud of auds) {
    const audOrigin = originOf(aud);
    if (audOrigin === null || !allowedOrigins.has(audOrigin)) {
      return false;
    }
  }
  return true;
}

function originOf(raw: string): string | null {
  try {
    return new URL(raw).origin;
  } catch {
    return null;
  }
}

/** The one client_id form: manifests, metadata_admin.roles keys and the registrar's `<CLIENT_ID>_CLIENT_SECRET` all key on it. */
export const CLIENT_ID_RE = /^[a-z][a-z0-9]*$/;

/** Lint pass shared by the reload guard and `--validate-manifests`; one string per finding, empty when clean. */
export function validateClients(set: ClientManifest[]): string[] {
  const errs: string[] = [];
  for (const cm of set) {
    const src = cm.sourcePath || cm.clientId;

    if (cm.clientId === '') {
      errs.push(`${src}: oidc.client_id is empty`);
    }

    // A presentation-only tile has no client, and its slug may be hyphenated.
    if (!cm.presentationOnly && cm.clientId !== '' && !CLIENT_ID_RE.test(cm.clientId)) {
      errs.push(`${src}: oidc.client_id ${JSON.stringify(cm.clientId)} must match ${CLIENT_ID_RE}.`);
    }

    if (cm.accessGroups.length === 0 && !cm.skipAccessCheck) {
      errs.push(
        `${src}: presentation.access is empty and consent.skip_access_check is not set: ` +
          `no group can satisfy the gate, so this app is unreachable (no implicit access — ` +
          `declare presentation.access: or set consent.skip_access_check)`,
      );
    }

    const seenGroups = new Set<string>();
    for (const g of cm.accessGroups) {
      if (seenGroups.has(g)) {
        errs.push(`${src}: presentation.access lists ${JSON.stringify(g)} more than once`);
      }
      seenGroups.add(g);
    }

    if (!cm.presentationOnly) {
      if (cm.audience.length === 0) {
        errs.push(
          `${src}: oidc.audience is empty (every client needs an audience for id_token aud verification)`,
        );
      } else if (cm.redirectUris.length > 0) {
        if (!audienceMatchesRedirect(cm, cm.audience)) {
          errs.push(
            `${src}: no oidc.audience origin matches any redirect_uris origin (apps verify id_token.aud against their own URL)`,
          );
        }
      }
    }

    for (const g of [...new Set([...cm.accessGroups, ...Object.keys(cm.groupRoleMap)])]) {
      if (IDENTITY_GROUPS.includes(g)) {
        errs.push(
          `${src}: ${JSON.stringify(g)} is an identity group and cannot appear in presentation.access or ` +
            `consent.group_role_map (omitting access leaves the app unreachable; set consent.skip_access_check to open it to everyone)`,
        );
      }
    }

    for (const [groupName, roleName] of Object.entries(cm.groupRoleMap)) {
      if (!cm.roles.some((r) => r.name === roleName)) {
        errs.push(
          `${src}: consent.group_role_map[${JSON.stringify(groupName)}] points at role ${JSON.stringify(roleName)} which is not declared in consent.roles`,
        );
      }
    }

    for (const role of cm.roles) {
      if (role.claimEmit === null) {
        errs.push(
          `${src}: consent.roles[${JSON.stringify(role.name)}] has no claim_emit`,
        );
      }
    }

    if (cm.emitGroupsClaim === false) {
      for (const role of cm.roles) {
        if (role.claimEmit === null) continue;
        if (Object.prototype.hasOwnProperty.call(role.claimEmit, 'groups')) {
          errs.push(
            `${src}: consent.emit_groups_claim:false but consent.roles[${JSON.stringify(role.name)}].claim_emit.groups is set; the role's groups will still be emitted`,
          );
        }
      }
    }
  }
  return errs;
}

/** Throws one error joining all findings; called before any client is pushed to Hydra. */
export function assertManifestsValid(set: ClientManifest[]): void {
  const errs = validateClients(set);
  if (errs.length > 0) {
    throw new Error(
      `manifest validation failed (${errs.length} finding(s)):\n  - ${errs.join('\n  - ')}`,
    );
  }
}

