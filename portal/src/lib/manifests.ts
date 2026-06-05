// OIDC client manifest loader for SSR pages.
//
// v0.2.0: manifests are now read at REQUEST time from a mounted
// directory (default `/etc/portal/manifests/`). The build-time JSON
// bundle is gone; the Workers-era reasoning that motivated it
// (Workers can't read the filesystem at runtime) no longer applies
// since the portal runs as Astro Node SSR on the SSO host.
//
// Why runtime read:
//
// - Adding a new OIDC client is now: edit the unified `<slug>.yaml`
//   manifest, sync it into the runtime manifest directory on the SSO
//   host (e.g. via `make auth-sync-manifests`), restart the consent
//   service and the portal. No image rebuild required.
// - Source-of-truth is the unified per-app manifest set; the portal and
//   consent service read the same files from the same directory
//   (MANIFEST_DIR), and the operator's sync target keeps the on-host
//   copy current.
// - A 30-second in-process cache prevents per-request YAML parsing
//   from being a hot path. Cache is invalidated on SIGHUP (future).
//
// Source-of-truth chain:
//
//   unified manifests <slug>.yaml                    (canonical, this repo)
//     -> sync via operator sync target (e.g. make auth-sync-manifests)
//     -> runtime manifest dir on SSO host (MANIFEST_DIR)
//        -> consent container reads via volume mount
//        -> portal container reads via volume mount
//
// A single `<slug>.yaml` serves both loaders: this OIDC client loader
// reads the `oidc:`/`consent:` blocks, while tiles.ts reads the
// `presentation:` block (with an optional sibling `<slug>.md` for the
// per-app detail-page education content). Both read at request time from
// MANIFEST_DIR — there is no build-time content collection, so adding or
// removing an app is a manifest-dir change with no portal image rebuild.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { identityGroups } from './config';

export interface ClientRole {
  name: string;
  description: string;
  /**
   * Free-form claim_emit map injected into the id_token when the role
   * resolves for a user (CU2). Mirrors Go `Role.ClaimEmit`. `null` when
   * the yaml declares the role but omits a `claim_emit:` key — the
   * validator treats that as a lint error (Go: `role.ClaimEmit == nil`),
   * so it is preserved faithfully here rather than coerced to `{}`.
   */
  claimEmit: Record<string, unknown> | null;
}

export interface ClientManifest {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  /** Scope tokens, split for presentation/lookup. */
  scopes: string[];
  /**
   * Raw `oidc.scope` string exactly as written in the yaml (space- or
   * array-joined). This is what Hydra's OAuth2Client.scope expects (a
   * single space-separated string) and what apply-clients.sh forwarded
   * verbatim. `scopes` is the parsed form for the UI; `scope` is the
   * on-the-wire form for registration.
   */
  scope: string;
  audience: string[];
  grantTypes: string[];
  /** `oidc.response_types`; empty for client_credentials clients (vLLM). */
  responseTypes: string[];
  /** `oidc.token_endpoint_auth_method`; empty string when the yaml omits it. */
  tokenEndpointAuthMethod: string;
  skipConsent: boolean;
  /**
   * OIDC Back-Channel Logout 1.0 endpoint, when the app supports it.
   * Empty string when the yaml leaves the field absent (Tailscale, vLLM,
   * BookLore, current Jellyfin SSO plugin). The admin "Force re-login"
   * action posts a signed logout token to this URI per supported app.
   */
  backchannelLogoutUri: string;
  /**
   * `oidc.backchannel_logout_session_required`; flips the "include sid
   * claim" toggle. Defaults false (Go `OIDCConfig.BackchannelLogoutSessionRequired`).
   */
  backchannelLogoutSessionRequired: boolean;
  /** Conventional `access-<clientId>` group that grants entry to this app. */
  accessGroup: string;
  /** Declared role enum for the app; may be empty if the yaml has no `roles:` block. */
  roles: ClientRole[];
  /** identity-group → role-name map; what role a member of <group> gets by default. */
  groupRoleMap: Record<string, string>;
  /**
   * `consent.emit_groups_claim`. Pointer-to-bool in Go (default true; an
   * explicit `false` suppresses the auto groups claim). Represented here
   * as `boolean | null` where `null` means "absent → default true", so
   * the M10 contradiction lint can distinguish an explicit false.
   */
  emitGroupsClaim: boolean | null;
  /** `consent.skip_access_check`; disables the access-<client_id> gate. */
  skipAccessCheck: boolean;
  /** Source filename the manifest was parsed from (Go `SourcePath`). */
  sourcePath: string;
}

/**
 * ShouldEmitGroups — mirrors Go `(*ClientManifest).ShouldEmitGroups`.
 * Default true; only an explicit `emit_groups_claim: false` suppresses.
 */
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

function splitScope(scope: unknown): string[] {
  if (!scope) return [];
  if (Array.isArray(scope)) return scope.map(String);
  return String(scope).split(/\s+/).filter(Boolean);
}

/**
 * Raw on-the-wire scope string, as Hydra's OAuth2Client.scope expects it:
 * a single space-separated list. apply-clients.sh forwarded `oidc.scope`
 * verbatim, so an array form is joined with spaces and a string form is
 * passed through (trimmed).
 */
function rawScope(scope: unknown): string {
  if (!scope) return '';
  if (Array.isArray(scope)) return scope.map(String).join(' ');
  return String(scope).trim();
}

/**
 * Read a role's `claim_emit` block. Returns the map when present (even
 * when empty, e.g. `claim_emit: {}` for identity-only clients), and
 * `null` when the key is absent — faithfully mirroring Go's
 * `Role.ClaimEmit == nil` so the validator can flag a declared role that
 * forgot its claim_emit.
 */
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

/**
 * Read `consent.emit_groups_claim` preserving the absent/false/true
 * distinction Go's `*bool` carries: `null` = absent (default true), and
 * an explicit boolean otherwise.
 */
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
 * Load one manifest file as a ClientManifest, or null when it is a
 * presentation-only unified manifest (a tile for a forward_auth / ldap /
 * external app that has NO OIDC client). Those carry a `presentation:`
 * block and no `oidc:` block, and must be skipped by the OIDC client
 * loader rather than throwing. A stale flat manifest (client fields at the
 * top level, no `oidc:`) still throws via parseManifest's flat-shape guard.
 *
 * Any read/parse/validate error (ENOENT from a TOCTOU race during manifest
 * sync, YAML syntax error, parseManifest throw) is caught, warned, and
 * returned as null so a single bad file does not take down the whole load.
 * The caller's .filter() already strips nulls. Mirrors the per-file
 * isolation pattern used in tiles.ts loadFromDisk.
 */
function loadOne(file: string, dir: string): ClientManifest | null {
  try {
    const text = readFileSync(join(dir, file), 'utf8');
    const doc = (parseYaml(text) ?? {}) as { oidc?: unknown; presentation?: unknown };
    const hasOidc = doc.oidc != null && typeof doc.oidc === 'object';
    const hasPresentation = doc.presentation != null && typeof doc.presentation === 'object';
    if (!hasOidc && hasPresentation) return null;
    return parseManifest(text, file);
  } catch (err) {
    console.warn(`manifests: skipping ${file}: ${err}`);
    return null;
  }
}

/**
 * Parse one manifest YAML body into a ClientManifest. Exported so the
 * test suite can drive parser behaviour without round-tripping through
 * the filesystem. The on-disk loader uses this via `loadOne`.
 */
export function parseManifest(yamlText: string, filename: string): ClientManifest {
  const yaml = parseYaml(yamlText) ?? {};

  const file = filename;
  const oidc = (yaml as { oidc?: unknown }).oidc;
  const consent = (yaml as { consent?: unknown }).consent;

  // Namespace split (D6 / C3): reject pre-namespace flat shape so a
  // stale manifest doesn't silently load. Same guard as apply-clients.sh
  // and the consent service's manifest loader.
  const flatLikely =
    'client_id' in yaml ||
    'client_name' in yaml ||
    'grant_types' in yaml ||
    'roles' in yaml ||
    'group_role_map' in yaml;
  if (!oidc && flatLikely) {
    throw new Error(`${file}: pre-namespace flat shape detected. Migrate to oidc:/consent: blocks.`);
  }
  if (!oidc || typeof oidc !== 'object') {
    throw new Error(`${file}: missing or non-object oidc: block`);
  }

  const o = oidc as Record<string, unknown>;
  const clientId = String(o.client_id ?? file.replace(/\.ya?ml$/, ''));
  const c = (consent && typeof consent === 'object' ? consent : {}) as Record<string, unknown>;

  return {
    clientId,
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
    accessGroup: `access-${clientId}`,
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

/** Return all known clients sorted by clientId. Cached 30s + invalidates on mtime change.
 *
 * B (pre-swap validation): runs validateClients on the candidate set BEFORE
 * writing to cache. If validation fails, preserves the prior good cache and
 * throws. Matches Go Reload() behavior: "A reload that introduces (e.g.) an
 * undeclared role in group_role_map is rejected with prior state intact."
 *
 * Duplicate client_id detection: if two files declare the same client_id
 * (case-insensitive), throws before swapping. Matches Go:
 * 'duplicate client_id %q in %s and %s'.
 */
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

  // Capture prior cache before loading — restore on validation failure.
  const priorCache = cache;

  const manifests = loadFromDisk();

  // Duplicate client_id detection (case-insensitive, matching Go Reload).
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

/**
 * Return the manifest for a client_id. Case-insensitive lookup to match
 * Go Manifest.Client(clientID) which calls strings.ToLower(clientID).
 */
export function getClientManifest(clientId: string): ClientManifest | undefined {
  const key = clientId.toLowerCase();
  return loadClientManifests().find((m) => m.clientId.toLowerCase() === key);
}

/**
 * audienceMatchesRedirect — TIGHTENED port of consent/manifest.go (CU1 item 5).
 *
 * The Go version compared host-only (url.Host) and, separately, fell back to a
 * bare-string compare when the audience had no parseable host — which let a
 * scheme-mismatched or path-decorated audience slip through, and it returned
 * `true` for the no-usable-redirect-host case (a silent allow). This version:
 *
 *   - matches by parsed ORIGIN (scheme://host[:port]) EXACTLY, so
 *     https://app.example.com.evil.com and http://app.example.com both fail
 *     against an https://app.example.com redirect;
 *   - is FAIL-CLOSED: an unknown client, an empty/absent redirect set, a
 *     non-URL audience, or any audience without an exact-origin redirect match
 *     all return false. There is no silent `return true` path.
 *
 * An empty/absent audience list returns true (nothing to constrain), matching
 * the Go semantics where there is nothing to verify.
 */
export function audienceMatchesRedirect(
  manifest: ClientManifest | undefined,
  audience: string[] | undefined,
): boolean {
  // Unknown client: no silent allow.
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

  // Every requested audience must match an allowed origin exactly.
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

/**
 * validateClients — full TS port of consent/manifest.go `validateClients`
 * (the lint pass shared by Reload's M2 pre-swap guard and the operator
 * `--validate-manifests` path). Returns one human-readable string per
 * finding; an empty array means the set is clean.
 *
 * Rules, 1:1 with the Go source:
 *   1. oidc.client_id non-empty.
 *   2. oidc.audience non-empty (H4: id_token aud verification needs it).
 *   3. When both audience and redirect_uris are present, at least one
 *      audience must match a redirect_uri ORIGIN exactly. Reuses the
 *      CU1-hardened (exact-origin, fail-closed) audienceMatchesRedirect.
 *   4. Every value in consent.group_role_map must name a declared role.
 *   5. Every declared role must have a non-null claim_emit.
 *   6. M10 contradiction: emit_groups_claim:false paired with a role whose
 *      claim_emit sets a `groups` key — the role's groups land in the token
 *      despite the suppression. Promoted to an error (same as Go).
 */
export function validateClients(set: ClientManifest[]): string[] {
  const errs: string[] = [];
  for (const cm of set) {
    const src = cm.sourcePath || cm.clientId;

    if (cm.clientId === '') {
      errs.push(`${src}: oidc.client_id is empty`);
    }

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

    // M10: emit_groups_claim:false + a role claim_emit that sets `groups`
    // is a silent contradiction — the role's groups ship in the token even
    // though the operator suppressed the auto claim. Error, not warning,
    // so the pre-swap guard rejects a contradictory draft.
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

/**
 * assertManifestsValid — throws on the first finding (joining all findings
 * into the message). The in-app successor to the consent service's
 * `--validate-manifests` exit-non-zero behaviour; called by the registrar
 * before any client is pushed to Hydra, so a bad manifest set never
 * half-registers.
 */
export function assertManifestsValid(set: ClientManifest[]): void {
  const errs = validateClients(set);
  if (errs.length > 0) {
    throw new Error(
      `manifest validation failed (${errs.length} finding(s)):\n  - ${errs.join('\n  - ')}`,
    );
  }
}

/** Distinct identity groups referenced by any client's group_role_map.
 *
 * Seeded from OTHALA_IDENTITY_GROUPS (env-driven, always includes 'admin')
 * so the admin UI shows every configured group even if no manifest references
 * it yet. Additional groups discovered in manifest group_role_map keys are
 * appended. Result is sorted for stable display order.
 */
export function knownIdentityGroups(): string[] {
  const set = new Set<string>(identityGroups);
  for (const m of loadClientManifests()) {
    for (const g of Object.keys(m.groupRoleMap)) set.add(g);
  }
  return Array.from(set).sort();
}

/** Distinct access groups across all clients. */
export function knownAccessGroups(): string[] {
  return loadClientManifests().map((m) => m.accessGroup).sort();
}
