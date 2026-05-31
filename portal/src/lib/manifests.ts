// OIDC client manifest loader for SSR pages.
//
// v0.1.4: manifests are now read at REQUEST time from a mounted
// directory (default `/etc/portal/manifests/`). The build-time JSON
// bundle is gone; the Workers-era reasoning that motivated it
// (Workers can't read the filesystem at runtime) no longer applies
// since the portal runs as Astro Node SSR on carmine.
//
// Why runtime read:
//
// - Adding a new OIDC client is now: edit `hydra/clients/<slug>.yaml`
//   in this repo, rsync to `/var/srv/auth/consent/manifests/` on
//   carmine via `make auth-sync-manifests`, restart the consent
//   service and the portal. No image rebuild required.
// - Source-of-truth stays in `dunn.dev/auth/hydra/clients/`. The
//   portal and consent service read the same files from the same
//   directory; iac's sync target keeps the on-carmine copy current.
// - A 30-second in-process cache prevents per-request YAML parsing
//   from being a hot path. Cache is invalidated on SIGHUP (future).
//
// Source-of-truth chain:
//
//   dunn.dev/auth/hydra/clients/*.yaml             (canonical, this repo)
//     -> rsync via dunn.dev/iac make auth-sync-manifests
//     -> /var/srv/auth/{consent,portal}/manifests/ (runtime on carmine)
//        -> consent container reads via volume mount
//        -> portal container reads via volume mount
//
// Tile-dashboard metadata (name, icon, description, education content)
// lives separately in portal/src/content/apps/<slug>.mdx — that DOES
// rebuild the portal image on change, intentionally (rich MDX content
// surface is worth the rebuild cost; OIDC manifest edits are not).

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';

export interface ClientRole {
  name: string;
  description: string;
}

export interface ClientManifest {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  scopes: string[];
  audience: string[];
  grantTypes: string[];
  skipConsent: boolean;
  /**
   * OIDC Back-Channel Logout 1.0 endpoint, when the app supports it.
   * Empty string when the yaml leaves the field absent (Tailscale, vLLM,
   * BookLore, current Jellyfin SSO plugin). The admin "Force re-login"
   * action posts a signed logout token to this URI per supported app.
   */
  backchannelLogoutUri: string;
  /** Conventional `access-<clientId>` group that grants entry to this app. */
  accessGroup: string;
  /** Declared role enum for the app; may be empty if the yaml has no `roles:` block. */
  roles: ClientRole[];
  /** identity-group → role-name map; what role a member of <group> gets by default. */
  groupRoleMap: Record<string, string>;
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

function normaliseRoles(raw: unknown): ClientRole[] {
  if (!raw) return [];
  if (Array.isArray(raw)) {
    return raw
      .filter((r): r is { name: unknown; description?: unknown } => typeof r === 'object' && r !== null && 'name' in r)
      .map((r) => ({ name: String(r.name), description: String(r.description ?? '') }));
  }
  if (typeof raw === 'object') {
    return Object.entries(raw as Record<string, unknown>).map(([name, v]) => ({
      name,
      description: String((v && typeof v === 'object' && 'description' in v ? (v as { description?: unknown }).description : '') ?? ''),
    }));
  }
  return [];
}

function normaliseGroupRoleMap(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function loadOne(file: string, dir: string): ClientManifest {
  const path = join(dir, file);
  const yaml = parseYaml(readFileSync(path, 'utf8')) ?? {};

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
    audience: Array.isArray(o.audience) ? o.audience.map(String) : [],
    grantTypes: Array.isArray(o.grant_types) ? o.grant_types.map(String) : [],
    skipConsent: Boolean(o.skip_consent ?? false),
    backchannelLogoutUri: o.backchannel_logout_uri ? String(o.backchannel_logout_uri) : '',
    accessGroup: `access-${clientId}`,
    roles: normaliseRoles(c.roles),
    groupRoleMap: normaliseGroupRoleMap(c.group_role_map),
  };
}

function loadFromDisk(): ClientManifest[] {
  const dir = manifestDir();
  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
      .sort();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      // Manifest dir not provisioned yet: return empty list so the
      // admin UI renders "no clients yet" rather than 500-ing.
      return [];
    }
    throw err;
  }
  return files.map((f) => loadOne(f, dir));
}

function freshestMtime(): number {
  const dir = manifestDir();
  try {
    const files = readdirSync(dir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
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

/** Return all known clients sorted by clientId. Cached 30s + invalidates on mtime change. */
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
  const manifests = loadFromDisk();
  cache = { manifests, mtimeMs: mtime, loadedAtMs: now };
  return manifests;
}

export function getClientManifest(clientId: string): ClientManifest | undefined {
  return loadClientManifests().find((m) => m.clientId === clientId);
}

/** Distinct identity groups referenced by any client's group_role_map. */
export function knownIdentityGroups(): string[] {
  const set = new Set<string>(['admin', 'family', 'friends', 'kids']);
  for (const m of loadClientManifests()) {
    for (const g of Object.keys(m.groupRoleMap)) set.add(g);
  }
  return Array.from(set).sort();
}

/** Distinct access groups across all clients. */
export function knownAccessGroups(): string[] {
  return loadClientManifests().map((m) => m.accessGroup).sort();
}
