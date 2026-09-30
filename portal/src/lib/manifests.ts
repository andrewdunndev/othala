// OIDC client manifest loader. Reads <slug>.yaml from MANIFEST_DIR at request time (30 s cache, dropped on SIGHUP).
// loadClientManifests() returns EVERY app manifest, presentation-only tiles included; the OIDC subset
// comes from oidcClientManifests() and getClientManifest().

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { parseAccessGroups } from './access-groups';

export interface ClientRole {
  name: string;
  description: string;
  /** `claim_emit` map; null when the key is absent, which the validator flags (Go `Role.ClaimEmit == nil`). */
  claimEmit: Record<string, unknown> | null;
}

export interface ClientManifest {
  clientId: string;
  /**
   * True for a `presentation:` block with no `oidc:` client (a forward_auth / external tile). It still names an
   * access group but registers no OIDC client, so the audience, redirect and env-var-stem rules skip it and
   * getClientManifest() refuses to resolve it. The loader does not filter it out.
   */
  presentationOnly: boolean;
  clientName: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  /** Scope tokens, split for presentation/lookup. */
  scopes: string[];
  /** Raw `oidc.scope` string as Hydra's OAuth2Client.scope expects it; `scopes` is the parsed form. */
  scope: string;
  audience: string[];
  grantTypes: string[];
  /** `oidc.response_types`; empty for client_credentials clients. */
  responseTypes: string[];
  /** `oidc.token_endpoint_auth_method`; empty string when the yaml omits it. */
  tokenEndpointAuthMethod: string;
  skipConsent: boolean;
  /** OIDC Back-Channel Logout 1.0 endpoint; empty when the yaml omits it. */
  backchannelLogoutUri: string;
  /** `oidc.backchannel_logout_session_required`; includes the sid claim. */
  backchannelLogoutSessionRequired: boolean;
  /**
   * The access binding: groups whose members may enter this app (OR). From `presentation.access:` with an
   * `[access_group]` compat shim. Absence yields `[]` with no implicit fallback (primitive #5); a bare manifest
   * without `skip_access_check` is a load-time BLOCK (validateClients).
   */
  accessGroups: string[];
  /** Declared role enum for the app; may be empty if the yaml has no `roles:` block. */
  roles: ClientRole[];
  /** identity-group → role-name map; what role a member of <group> gets by default. */
  groupRoleMap: Record<string, string>;
  /** `consent.emit_groups_claim`; `null` = absent (default true), so the M10 lint can see an explicit false. */
  emitGroupsClaim: boolean | null;
  /** `consent.skip_access_check`; disables the access-<client_id> gate. */
  skipAccessCheck: boolean;
  /** Source filename the manifest was parsed from (Go `SourcePath`). */
  sourcePath: string;
}

/** Mirrors Go `ShouldEmitGroups`: only an explicit `emit_groups_claim: false` suppresses. */
export function shouldEmitGroups(m: ClientManifest): boolean {
  return m.emitGroupsClaim ?? true;
}

function manifestDir(): string {
  return process.env.MANIFEST_DIR ?? '/etc/portal/manifests';
}

interface CacheEntry {
  manifests: ClientManifest[];
  mtimeMs: number;
  loadedAtMs: number;
}

let cache: CacheEntry | null = null;
const CACHE_TTL_MS = 30 * 1000;

/** Drop the manifest cache so the next load re-reads disk (SIGHUP path in registrar.ts). */
export function invalidateManifestCache(): void {
  cache = null;
}

function splitScope(scope: unknown): string[] {
  if (!scope) return [];
  if (Array.isArray(scope)) return scope.map(String);
  return String(scope).split(/\s+/).filter(Boolean);
}

/** Raw scope string: an array is space-joined, a string is trimmed. */
function rawScope(scope: unknown): string {
  if (!scope) return '';
  if (Array.isArray(scope)) return scope.map(String).join(' ');
  return String(scope).trim();
}

/** Read a role's `claim_emit`: the map when present (even `{}`), `null` when the key is absent. */
function readClaimEmit(v: unknown): Record<string, unknown> | null {
  if (v && typeof v === 'object' && !Array.isArray(v) && 'claim_emit' in v) {
    const ce = (v as { claim_emit?: unknown }).claim_emit;
    if (ce && typeof ce === 'object' && !Array.isArray(ce)) {
      return ce as Record<string, unknown>;
    }
    // Present but not a mapping (e.g. claim_emit: null) → treat as nil.
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

/** Read `consent.emit_groups_claim`: `null` = absent, else the explicit boolean. */
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

/**
 * Load one manifest file. Every well-formed manifest is returned, presentation-only ones included
 * (empty OIDC fields, presentationOnly:true); a flat-shape manifest or one with neither block throws.
 * The loader must not drop presentation-only tiles: the registry and admin UI need their access groups,
 * and a save would otherwise drop groups it cannot see. The registrar's constraint (no client, no secret)
 * lives in oidcClientManifests() and getClientManifest().
 * Any read/parse error is warned and returned as null so one bad file does not fail the whole load.
 */
function loadOne(file: string, dir: string): ClientManifest | null {
  try {
    const text = readFileSync(join(dir, file), 'utf8');
    return parseManifest(text, file);
  } catch (err) {
    console.warn(`manifests: skipping ${file}: ${err}`);
    return null;
  }
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

  // Reject the pre-namespace flat shape so a stale manifest does not load silently.
  const flatLikely =
    'client_id' in yaml ||
    'client_name' in yaml ||
    'grant_types' in yaml ||
    'roles' in yaml ||
    'group_role_map' in yaml;
  if (!oidc && flatLikely) {
    throw new Error(`${file}: pre-namespace flat shape detected. Migrate to oidc:/consent: blocks.`);
  }

  // No implicit `access-<clientId>` fallback (primitive #5): an empty binding is a load-time BLOCK in validateClients.
  const accessGroups = parseAccessGroups(p);

  // Presentation-only manifest: a `presentation:` block with no `oidc:`; OIDC-specific rules skip it.
  if (!oidc || typeof oidc !== 'object') {
    if (!hasPresentation) {
      throw new Error(`${file}: missing or non-object oidc: block`);
    }
    const clientId = String(p.client_id ?? file.replace(/\.ya?ml$/, ''));
    // A tile may set skip_access_check to suppress the empty-binding BLOCK (e.g. external tiles open to all logged-in users).
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
  };
}

function loadFromDisk(): ClientManifest[] {
  const dir = manifestDir();
  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f) => (f.endsWith('.yaml') || f.endsWith('.yml')) && f !== 'groups.yaml')
      .sort();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      // Manifest dir not provisioned yet: return empty list so the
      // admin UI renders "no clients yet" rather than 500-ing.
      return [];
    }
    throw err;
  }
  return files
    .map((f) => loadOne(f, dir))
    .filter((m): m is ClientManifest => m !== null);
}

function freshestMtime(): number {
  const dir = manifestDir();
  try {
    const files = readdirSync(dir).filter(
      (f) => (f.endsWith('.yaml') || f.endsWith('.yml')) && f !== 'groups.yaml',
    );
    let max = 0;
    for (const f of files) {
      const m = statSync(join(dir, f)).mtimeMs;
      if (m > max) max = m;
    }
    return max;
  } catch {
    return 0;
  }
}

/** Every app manifest in MANIFEST_DIR, sorted by filename; cached 30 s, invalidated on mtime change.
 * Validates the candidate set before swapping the cache and throws on failure, keeping the prior cache
 * (Go Reload M2). Duplicate client_ids (case-insensitive) throw before the swap. */
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

  const priorCache = cache;

  const manifests = loadFromDisk();

  const seen = new Map<string, string>(); // lowercase clientId -> sourcePath
  for (const m of manifests) {
    const key = m.clientId.toLowerCase();
    const existing = seen.get(key);
    if (existing !== undefined) {
      cache = priorCache;
      throw new Error(
        `duplicate client_id ${JSON.stringify(key)} in ${existing} and ${m.sourcePath}`,
      );
    }
    seen.set(key, m.sourcePath);
  }

  // Pre-swap validation guard (Go M2): validate before swapping the cache.
  const errs = validateClients(manifests);
  if (errs.length > 0) {
    cache = priorCache;
    throw new Error(
      `manifest validation failed (${errs.length} finding(s)):\n  - ${errs.join('\n  - ')}`,
    );
  }

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

/** OIDC client manifest for a client_id, case-insensitive. Presentation-only tiles never resolve, so an
 * OAuth2 request cannot bind a client_id to a tile that was never registered. */
export function getClientManifest(clientId: string): ClientManifest | undefined {
  const key = clientId.toLowerCase();
  return loadClientManifests().find(
    (m) => !m.presentationOnly && m.clientId.toLowerCase() === key,
  );
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
  // No usable redirect origins -> fail closed (Go silently allowed here).
  if (allowedOrigins.size === 0) return false;

  for (const aud of auds) {
    const audOrigin = originOf(aud);
    if (audOrigin === null || !allowedOrigins.has(audOrigin)) {
      return false;
    }
  }
  return true;
}

/** Parse a URL string to its exact origin (scheme://host[:port]), or null. */
function originOf(raw: string): string | null {
  try {
    return new URL(raw).origin;
  } catch {
    return null;
  }
}

/** A client_id must be a valid env-var stem: the registrar derives `<CLIENT_ID_UPPER>_CLIENT_SECRET` from it. */
export const CLIENT_ID_ENV_STEM_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Lint pass shared by the Reload pre-swap guard and `--validate-manifests`; one string per finding, empty = clean.
 * Rules: client_id non-empty and a valid env-var stem; audience non-empty; an audience matches a redirect
 * origin; group_role_map values name declared roles; every role has a claim_emit; and M10 (emit_groups_claim:false
 * with a role claim_emit setting `groups`).
 */
export function validateClients(set: ClientManifest[]): string[] {
  const errs: string[] = [];
  for (const cm of set) {
    const src = cm.sourcePath || cm.clientId;

    if (cm.clientId === '') {
      errs.push(`${src}: oidc.client_id is empty`);
    }

    // OIDC-only: a presentation-only tile derives no secret, and firing this would hard-fail the whole load for
    // a valid hyphenated slug. The error names the expected env var.
    if (!cm.presentationOnly && cm.clientId !== '' && !CLIENT_ID_ENV_STEM_RE.test(cm.clientId)) {
      const wouldBe = `${cm.clientId.toUpperCase()}_CLIENT_SECRET`;
      errs.push(
        `${src}: oidc.client_id ${JSON.stringify(cm.clientId)} contains characters that are ` +
          `invalid in a POSIX env var name (rule: ^[A-Za-z_][A-Za-z0-9_]*$). ` +
          `The registrar derives the secret env var as ${JSON.stringify(wouldBe)}, ` +
          `which is not a valid shell variable and will never resolve. ` +
          `Rename the client_id to use only letters, digits, and underscores.`,
      );
    }

    // BLOCK: an empty binding without skip_access_check is unreachable (primitive #5: no binding means no access).
    if (cm.accessGroups.length === 0 && !cm.skipAccessCheck) {
      errs.push(
        `${src}: presentation.access is empty and consent.skip_access_check is not set: ` +
          `no group can satisfy the gate, so this app is unreachable (no implicit access — ` +
          `declare presentation.access: or set consent.skip_access_check)`,
      );
    }

    // BLOCK (manifest-lint §11): a group listed twice in one manifest's binding.
    const seenGroups = new Set<string>();
    for (const g of cm.accessGroups) {
      if (seenGroups.has(g)) {
        errs.push(`${src}: presentation.access lists ${JSON.stringify(g)} more than once`);
      }
      seenGroups.add(g);
    }

    // OIDC-only rules: a presentation-only tile registers no client; the access-binding BLOCK above still applies.
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

    // M10: the role's groups ship in the token despite the suppressed auto claim; an error so the pre-swap guard rejects it.
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

/** Distinct access groups across the whole catalog, forward_auth and external tiles included, so the admin form
 * renders a checkbox for each. An auth_kind filter upstream would make a save drop the groups it hides. */
export function knownAccessGroups(): string[] {
  const set = new Set<string>();
  for (const m of loadClientManifests()) {
    for (const g of m.accessGroups) set.add(g);
  }
  return Array.from(set).sort();
}
