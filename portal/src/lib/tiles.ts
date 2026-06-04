// Runtime app-tile loader for the portal dashboard.
//
// v0.2.0: tiles are read at REQUEST time from the unified manifest
// directory (MANIFEST_DIR, default `/etc/portal/manifests`) — the same
// directory the OIDC client loader (manifests.ts) reads. Each
// `<slug>.yaml` carries a `presentation:` block (tile metadata); an
// optional sibling `<slug>.md` is the education content rendered on the
// `/apps/<slug>` detail page.
//
// This replaces the build-time Astro Content Collection
// (portal/src/content/apps/), so adding/removing an app is a
// manifest-dir change with NO image rebuild — matching how OIDC clients
// already work. A unified manifest serves both loaders: manifests.ts
// reads its `oidc:`/`consent:` blocks (ignoring `presentation:`), this
// loader reads `presentation:` (ignoring `oidc:`).
//
// Productionized from the /preview prototype loader (preview-loader.ts).

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { marked } from 'marked';
import { accessGroupMismatch } from './app-slug';

export type AuthKind = 'oidc' | 'oidc+ldap' | 'forward_auth' | 'ldap' | 'external';

export interface AppTile {
  slug: string;
  name: string;
  description: string;
  url: string;
  /** 1-3 char monogram fallback when no icon resolves. */
  icon: string;
  /** simple-icons slug for the product SVG (preferred). */
  iconSlug?: string;
  /** simple-icons fallback slug for products not in simple-icons. */
  iconFallback?: string;
  authKind: AuthKind;
  /** Conventional `access-<slug>` group that gates this tile. */
  accessGroup: string;
  order: number;
  /** Hidden from the dashboard, but the detail page still resolves. */
  disabled: boolean;
  /** Hostname from presentation.url (e.g. "observe.othala.test"). */
  fqdn: string;
  /** Rendered HTML from the sibling `<slug>.md`, or undefined if absent. */
  educationHtml?: string;
}

function manifestDir(): string {
  return process.env.MANIFEST_DIR ?? '/etc/portal/manifests';
}

interface CacheEntry {
  tiles: AppTile[];
  mtimeMs: number;
  loadedAtMs: number;
}

let cache: CacheEntry | null = null;
const CACHE_TTL_MS = 30 * 1000;

/** Freshest mtime across yaml + md so a sidecar edit also busts the cache. */
function freshestMtime(dir: string): number {
  try {
    const files = readdirSync(dir).filter(
      (f) => f.endsWith('.yaml') || f.endsWith('.yml') || f.endsWith('.md'),
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

/**
 * Parse one unified manifest's `presentation:` block into an AppTile.
 * Returns null when the file carries no `presentation:` block (an
 * OIDC-only manifest, or a non-manifest file). Throws on an explicit
 * access_group ≠ access-<slug> mismatch (mirrors the Content Collection
 * superRefine cross-cut); the caller catches + skips so one bad tile
 * doesn't 500 the whole dashboard.
 */
function parseTile(slug: string, doc: Record<string, unknown>, dir: string): AppTile | null {
  const pBlock = doc['presentation'];
  if (!pBlock || typeof pBlock !== 'object' || Array.isArray(pBlock)) return null;
  const p = pBlock as Record<string, unknown>;

  const accessGroup = p['access_group'] ? String(p['access_group']) : `access-${slug}`;
  const mismatch = accessGroupMismatch(slug, accessGroup);
  if (mismatch) throw new Error(`${slug}.yaml: ${mismatch}`);

  const url = String(p['url'] ?? '');
  let fqdn: string;
  try {
    fqdn = new URL(url).host;
  } catch {
    fqdn = url;
  }

  let educationHtml: string | undefined;
  const mdPath = join(dir, `${slug}.md`);
  if (existsSync(mdPath)) {
    educationHtml = marked.parse(readFileSync(mdPath, 'utf8'), { async: false }) as string;
  }

  const tile: AppTile = {
    slug,
    name: String(p['name'] ?? slug),
    description: String(p['description'] ?? ''),
    url,
    icon: String(p['icon'] ?? '??'),
    authKind: String(p['auth_kind'] ?? 'external') as AuthKind,
    accessGroup,
    order: typeof p['order'] === 'number' ? p['order'] : 999,
    disabled: p['disabled'] === true,
    fqdn,
    educationHtml,
  };

  const iconSlug = p['icon_slug'];
  if (typeof iconSlug === 'string' && iconSlug.trim()) tile.iconSlug = iconSlug.trim();
  const iconFallback = p['icon_fallback'];
  if (typeof iconFallback === 'string' && iconFallback.trim()) tile.iconFallback = iconFallback.trim();

  return tile;
}

function loadFromDisk(): AppTile[] {
  const dir = manifestDir();
  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
      .sort();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }

  const tiles: AppTile[] = [];
  for (const f of files) {
    const slug = f.replace(/\.ya?ml$/, '');
    let doc: unknown;
    try {
      doc = parseYaml(readFileSync(join(dir, f), 'utf8'));
    } catch (err) {
      console.warn(`tiles: skipping ${f}: ${err}`);
      continue;
    }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) continue;
    try {
      const tile = parseTile(slug, doc as Record<string, unknown>, dir);
      if (tile) tiles.push(tile);
    } catch (err) {
      console.warn(`tiles: skipping ${f}: ${err}`);
    }
  }
  return tiles.sort((a, b) => a.order - b.order || a.name.localeCompare(b.name));
}

/** All cached tiles (including disabled), sorted by order then name. 30s cache + mtime-invalidated. */
function allTiles(): AppTile[] {
  const now = Date.now();
  const mtime = freshestMtime(manifestDir());
  if (cache && cache.mtimeMs === mtime && now - cache.loadedAtMs < CACHE_TTL_MS) {
    return cache.tiles;
  }
  const tiles = loadFromDisk();
  cache = { tiles, mtimeMs: mtime, loadedAtMs: now };
  return tiles;
}

/** Tiles for the dashboard: enabled only, sorted by order then name. */
export function loadTiles(): AppTile[] {
  return allTiles().filter((t) => !t.disabled);
}

/**
 * Resolve one tile by slug for the /apps/<slug> detail page. Includes
 * disabled tiles (hidden from the dashboard, but the detail page still
 * resolves) to preserve the prior Content Collection behaviour.
 */
export function getTile(slug: string): AppTile | undefined {
  return allTiles().find((t) => t.slug === slug);
}
