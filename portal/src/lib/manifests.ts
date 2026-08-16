// OIDC client manifest loader for SSR pages.
//
// Manifests are read at REQUEST time from a mounted directory
// (default `/etc/portal/manifests/`); the portal runs as Astro Node
// SSR on the SSO host.
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
//   from being a hot path. Cache is invalidated on SIGHUP via
//   invalidateManifestCache() (wired in src/server/registrar.ts).
//
// Source-of-truth chain:
//
//   unified manifests <slug>.yaml                    (canonical, this repo)
//     -> sync via operator sync target (e.g. make auth-sync-manifests)
//     -> runtime manifest dir on SSO host (MANIFEST_DIR)
//        -> consent container reads via volume mount
//        -> portal container reads via volume mount
//
// A single `<slug>.yaml` serves both loaders: this loader reads the
// `oidc:`/`consent:` blocks, while tiles.ts reads the `presentation:`
// block (with an optional sibling `<slug>.md` for the per-app
// detail-page education content). Both read at request time from
// MANIFEST_DIR — there is no build-time content collection, so adding or
// removing an app is a manifest-dir change with no portal image rebuild.
//
// SCOPE: loadClientManifests() returns EVERY app manifest in MANIFEST_DIR,
// of every auth_kind — including presentation-only ones (forward_auth /
// ldap / external tiles that register no OIDC client). It is the app
// catalog, not the OIDC client list. Consumers that genuinely need the
// OIDC subset (the Hydra registrar; the OAuth2/consent lookup) narrow it
// with oidcClientManifests() / getClientManifest(). See the note on
// loadOne for why the loader used to drop presentation-only manifests and
// why that filter moved to the consumers.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { identityGroups } from './config';
import { parseAccessGroups } from './access-groups';

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
  /**
   * True when this manifest carries a `presentation:` block but NO `oidc:`
   * client (a forward_auth / ldap / external tile, e.g. observe.yaml). Such a
   * manifest still names an access group — an assignable, gate-bearing binding
   * that the registry, the admin UI and computeEffectiveAccess must all see —
   * but it registers no OIDC client, so the OIDC-specific rules do not apply
   * to it.
   *
   * This flag is the discriminator every OIDC-specific consumer filters on:
   *
   *   - validateClients skips the audience / redirect-match / env-var-stem
   *     rules for it (they only constrain a real Hydra client);
   *   - oidcClientManifests() narrows the catalog to the registrable subset
   *     for the Hydra registrar;
   *   - getClientManifest() refuses to resolve one, so an OAuth2 request can
   *     never bind a client_id to a tile that was never registered.
   *
   * It is NOT filtered by the loader. loadClientManifests() returns
   * presentation-only manifests alongside OIDC ones (see loadOne).
   */
  presentationOnly: boolean;
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
  /**
   * The LOAD-BEARING access binding (access-model Phase 2). Adopter-named groups
   * (arbitrary charset, no `access-` prefix required) whose members may enter
   * this app — OR-semantics. Sourced from `presentation.access:` (list) with a
   * `[access_group]` compat shim. Absence of a binding yields `[]` — there is NO
   * implicit `access-<clientId>` fallback (othala primitive #5: no implicit
   * access; absence of a binding means no access). A bare manifest with `[]`
   * and no `skip_access_check` is a load-time BLOCK (validateClients). The gate
   * (gate.ts), effective-access view (access.ts), tile visibility
   * (tiles.ts/index.astro), and the group registry (group-registry.ts) all read
   * THIS field. See docs/access-model.md §10/§11/§16.
   */
  accessGroups: string[];
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

/** Drop the in-process manifest cache so the next load re-reads from disk.
 *  Called by the SIGHUP reload path (src/server/registrar.ts reloadOnSighup). */
export function invalidateManifestCache(): void {
  cache = null;
}

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
 * Load one manifest file as a ClientManifest. Every well-formed manifest is
 * returned, of every auth_kind — a presentation-only manifest (a forward_auth /
 * ldap / external tile with a `presentation:` block and no `oidc:` block) parses
 * to a ClientManifest with empty OIDC fields and presentationOnly:true. A stale
 * flat manifest (client fields at the top level, no `oidc:`) still throws via
 * parseManifest's flat-shape guard; a manifest with neither block also throws.
 *
 * WHY THIS USED TO DROP PRESENTATION-ONLY MANIFESTS (B4). Until this change
 * loadOne returned null for `presentation:`-without-`oidc:`, so the entire
 * downstream layer — knownAccessGroups(), buildGroupRegistry() (which reads
 * loadClientManifests()), and therefore every admin group surface — could not
 * see a single forward_auth or external app's access group. The exclusion had a
 * real reason: registerAllClients() drives Hydra registration off this same
 * loader and derives `<CLIENT_ID_UPPER>_CLIENT_SECRET` per manifest, so a tile
 * that has no client and no secret must never reach it. But that is a REGISTRAR
 * constraint, not a loader one, and enforcing it here made the admin UI quietly
 * destructive: groups it could not see had no checkbox, so any identity save
 * dropped them (admin/users/[id].astro rewrites metadata_admin.groups wholesale
 * from the rendered boxes).
 *
 * The constraint therefore moved to the consumers that actually hold it:
 * oidcClientManifests() for the registrar, getClientManifest() for the
 * OAuth2/consent lookup. The loader now returns the whole catalog, which is what
 * the registry, the access model and the admin UI need.
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

  const presentation = (yaml as { presentation?: unknown }).presentation;
  const p = (presentation && typeof presentation === 'object' && !Array.isArray(presentation)
    ? presentation
    : {}) as Record<string, unknown>;
  const hasPresentation = presentation != null && typeof presentation === 'object' && !Array.isArray(presentation);

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

  // access-model Phase 2: `accessGroups` is the LOAD-BEARING access binding (the
  // gate, computeEffectiveAccess, tiles, and the registry all key off it — see
  // docs/access-model.md §10/§16). It is sourced from `presentation.access:` (a
  // list) with a `[access_group]` compat shim (parseAccessGroups, §11). Absence
  // of a binding yields `[]` — there is NO implicit `access-<clientId>` fallback
  // (othala primitive #5: no framework default silently grants visibility). A
  // bare manifest (`[]`, no skip_access_check) is a load-time BLOCK rejected by
  // validateClients, so it is loudly surfaced, never silently dark.
  const accessGroups = parseAccessGroups(p);

  // Presentation-only manifest (forward_auth / ldap / external tile, e.g.
  // observe.yaml): a `presentation:` block with NO `oidc:` client. It registers
  // no OIDC client but still names an assignable access group, so it parses as a
  // valid ClientManifest with empty OIDC fields and presentationOnly:true. The
  // OIDC-specific validateClients rules (audience, redirect/audience match) are
  // skipped for it. A manifest with neither oidc: nor presentation: is malformed
  // and still throws.
  if (!oidc || typeof oidc !== 'object') {
    if (!hasPresentation) {
      throw new Error(`${file}: missing or non-object oidc: block`);
    }
    const clientId = String(p.client_id ?? file.replace(/\.ya?ml$/, ''));
    // Presentation-only manifests may still declare consent.skip_access_check
    // to suppress the empty-access-binding BLOCK when the tile intentionally
    // carries no access group (e.g. auth_kind: external tiles visible to all
    // logged-in users — the authentication gate is "logged in to the portal",
    // not group membership within the portal).
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

/** Return EVERY app manifest in MANIFEST_DIR, sorted by filename. Cached 30s +
 * invalidates on mtime change.
 *
 * The set spans all auth_kinds: OIDC clients AND presentation-only manifests
 * (forward_auth / ldap / external tiles). It is the app catalog. Callers that
 * need only the registrable OIDC subset call oidcClientManifests() on the
 * result; callers that need the group bindings (group-registry.ts,
 * knownAccessGroups, computeEffectiveAccess, the admin group surfaces) want the
 * whole thing — see loadOne for why the loader no longer filters.
 *
 * B (pre-swap validation): runs validateClients on the candidate set BEFORE
 * writing to cache. If validation fails, preserves the prior good cache and
 * throws. Matches Go Reload() behavior: "A reload that introduces (e.g.) an
 * undeclared role in group_role_map is rejected with prior state intact."
 *
 * Duplicate client_id detection: if two files declare the same client_id
 * (case-insensitive), throws before swapping. Matches Go:
 * 'duplicate client_id %q in %s and %s'. This now spans OIDC and
 * presentation-only manifests alike, which is what we want: a tile whose slug
 * collides with a registered client would make getClientManifest ambiguous.
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
 * The registrable OIDC subset of a manifest set — every manifest that declares
 * an `oidc:` client. Defaults to the full loaded catalog.
 *
 * This is the filter that used to live in loadOne (see the note there). It
 * belongs HERE because the constraint is the registrar's, not the loader's:
 * registerAllClients() resolves `<CLIENT_ID_UPPER>_CLIENT_SECRET` for every
 * manifest it is handed, and a presentation-only tile has no client and no
 * secret, so handing it one throws. Any caller that pushes manifests at Hydra
 * — portal/src/lib/register-clients.ts registerAllClients, and the
 * src/server/register-clients-cli.ts one-shot behind it — must narrow through
 * this function first.
 */
export function oidcClientManifests(
  set: ClientManifest[] = loadClientManifests(),
): ClientManifest[] {
  return set.filter((m) => !m.presentationOnly);
}

/**
 * Return the OIDC client manifest for a client_id. Case-insensitive lookup to
 * match Go Manifest.Client(clientID) which calls strings.ToLower(clientID).
 *
 * Presentation-only manifests are NOT resolvable here. They register no Hydra
 * client, so no OAuth2 authorization or consent request can legitimately name
 * one; returning a tile from an OIDC lookup would hand oauth2-handlers a
 * pseudo-client with no redirect_uris and no audience. The lookup stays
 * OIDC-only so that path is unreachable by construction rather than by
 * fail-closed accident.
 */
export function getClientManifest(clientId: string): ClientManifest | undefined {
  const key = clientId.toLowerCase();
  return loadClientManifests().find(
    (m) => !m.presentationOnly && m.clientId.toLowerCase() === key,
  );
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
 * Regex a client_id must satisfy so it can be used as an env-var stem.
 *
 * The registrar derives `<CLIENT_ID_UPPER>_CLIENT_SECRET` from the client_id.
 * POSIX env var names must match `[A-Za-z_][A-Za-z0-9_]*`; a hyphenated id
 * (e.g. "open-webui") becomes "OPEN-WEBUI_CLIENT_SECRET" which is an INVALID
 * env var name and silently fails to resolve. This regex enforces the valid
 * stem at load time so the linter rejects the bad manifest before it can crash
 * the registrar.
 *
 * Root cause: S08 staleness ledger (2026-06-23); Tasks 1 + 2, overnight brief.
 */
export const CLIENT_ID_ENV_STEM_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * validateClients — full TS port of consent/manifest.go `validateClients`
 * (the lint pass shared by Reload's M2 pre-swap guard and the operator
 * `--validate-manifests` path). Returns one human-readable string per
 * finding; an empty array means the set is clean.
 *
 * Rules, 1:1 with the Go source, extended with TS-only env-var-stem guard:
 *   1. oidc.client_id non-empty.
 *   1a. oidc.client_id must be a valid env-var stem (^[A-Za-z_][A-Za-z0-9_]*$)
 *       so the registrar can derive <CLIENT_ID_UPPER>_CLIENT_SECRET without
 *       producing an invalid shell variable name. A hyphen, dot, or leading
 *       digit in client_id silently breaks secret resolution.
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

    // Rule 1a: an OIDC client_id must be a valid env-var stem.
    //
    // The registrar derives the secret env var as `<CLIENT_ID_UPPER>_CLIENT_SECRET`
    // (e.g. "openwebui" → "OPENWEBUI_CLIENT_SECRET"). A client_id that contains
    // hyphens, dots, or starts with a digit produces an INVALID env var name
    // (POSIX: [A-Za-z_][A-Za-z0-9_]*). The env lookup silently returns undefined,
    // which either hard-errors (allowMissing=false, the production default) or
    // registers the client without a secret (allowMissing=true, dry-run only).
    //
    // OIDC-ONLY, deliberately. A presentation-only manifest derives no secret and
    // never reaches secretEnvVar (oidcClientManifests narrows the registrar's
    // input), so the rule has nothing to protect there — while firing it would
    // hard-fail the whole load for a perfectly valid tile whose slug carries a
    // hyphen (e.g. a `gather-usenet.yaml` forward_auth tile, matching the
    // gather-usenet-access group naming already in the catalog). That failure
    // would take EVERY group down with it, which is exactly the blindness this
    // enforcer exists to prevent. The naming constraint is real only where a
    // shell variable is really derived.
    //
    // The expected env var is reported in the error so the operator knows exactly
    // what to look for in the sops file / quadlet Secret= lines.
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

    // BLOCK (manifest-lint §11, wired into the load-time hard-fail path):
    // an empty access binding with no skip_access_check is definitionally
    // unreachable — no group can satisfy the gate. othala primitive #5: absence
    // of a binding means NO access, so a bare manifest must be LOUDLY rejected at
    // load (joining these hard-fails), not silently dark. Applies to OIDC and
    // presentation-only manifests alike.
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

    // OIDC-only rules: a presentation-only manifest (forward_auth / ldap tile,
    // no oidc: client — e.g. observe.yaml) registers no OAuth2 client, so the
    // audience / redirect-match rules do not apply to it. The access-binding
    // BLOCK above still governs it (a presentation-only tile must still name a
    // group or it is unreachable).
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

/** Distinct identity groups referenced by any manifest's group_role_map.
 *
 * Seeded from OTHALA_IDENTITY_GROUPS (env-driven, always includes 'admin')
 * so the admin UI shows every configured group even if no manifest references
 * it yet. Additional groups discovered in manifest group_role_map keys are
 * appended. Result is sorted for stable display order.
 *
 * Reads the whole catalog. Presentation-only manifests currently parse with an
 * empty groupRoleMap (they declare no roles), so today they contribute nothing
 * here — but they are in scope, so a future forward_auth manifest that does map
 * a role is picked up without another loader change.
 */
export function knownIdentityGroups(): string[] {
  const set = new Set<string>(identityGroups);
  for (const m of loadClientManifests()) {
    for (const g of Object.keys(m.groupRoleMap)) set.add(g);
  }
  return Array.from(set).sort();
}

/** Distinct access groups across the whole app catalog (the access-model
 * Phase 2 binding). Derived from each manifest's `accessGroups` list — the same
 * field the gate keys off — so the admin surfaces and the gate agree on the
 * access-bearing group set.
 *
 * INVARIANT (B4): every group bound by any manifest, of any auth_kind, appears
 * here. The forward_auth and external tiles are included, so the groups Caddy
 * actually gates on (observe-access, gather-access, gather-usenet-access,
 * gather-torrent-access, tune-access, bitwarden-access) are grantable in the
 * admin UI. When these were invisible, the identity-edit form rendered no
 * checkbox for them and every save silently dropped them from
 * metadata_admin.groups. Do not reintroduce an auth_kind filter upstream of
 * this function. */
export function knownAccessGroups(): string[] {
  const set = new Set<string>();
  for (const m of loadClientManifests()) {
    for (const g of m.accessGroups) set.add(g);
  }
  return Array.from(set).sort();
}
