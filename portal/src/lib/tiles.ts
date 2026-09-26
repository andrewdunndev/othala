// Runtime app-tile loader for the portal dashboard.
//
// v0.2.0: tiles are read at REQUEST time from the unified manifest
// directory (MANIFEST_DIR, default `/etc/portal/manifests`) — the same
// directory the OIDC client loader (portal/src/lib/manifests.ts) reads. Each
// `<slug>.yaml` carries a `presentation:` block (tile metadata); an
// optional sibling `<slug>.md` is the education content rendered on the
// `/apps/<slug>` detail page.
//
// This replaces the build-time Astro Content Collection
// (portal/src/content/apps/), so adding/removing an app is a
// manifest-dir change with NO image rebuild — matching how OIDC clients
// already work. A unified manifest serves both loaders:
// portal/src/lib/manifests.ts reads its `oidc:`/`consent:` blocks (ignoring
// `presentation:`), this loader reads `presentation:` (ignoring `oidc:`).
//
// groups.yaml (optional, in MANIFEST_DIR): maps group name → { title,
// description, order }. Loaded by loadGroups(); excluded from the tile
// manifest iteration so it never triggers a "skipping" warning.

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { marked } from 'marked';
import DOMPurify from 'isomorphic-dompurify';
import { parseAccessGroups } from './access-groups';

// Locate the vendored icons directory.
// Branch on import.meta.env.DEV so a stale dist/ from a previous production
// build does not shadow public/icons/ when running `astro dev`.
//
// In dev  (astro dev):        public/icons/ under the project root.
// In prod (node adapter):     dist/client/icons/ (Astro copies public/ there);
//                             fall back to public/icons/ when dist is absent.
const _cwd = process.cwd();
const _iconsDir = (() => {
  // import.meta.env is Astro/Vite-specific; guard it so the module loads
  // cleanly in plain Node (tests, register-clients one-shot, etc.).
  const isDev = typeof import.meta.env !== 'undefined' && import.meta.env.DEV;
  if (isDev) {
    // Always use the source tree in dev; never let a stale dist/ shadow it.
    return join(_cwd, 'public', 'icons');
  }
  // prod: dist/client/icons (Astro output); fall back to public/ if missing.
  const prod = join(_cwd, 'dist', 'client', 'icons');
  if (existsSync(prod)) return prod;
  return join(_cwd, 'public', 'icons');
})();

/** Return the web path for a vendored simple-icons SVG, or undefined if absent. */
function resolveIconHref(iconSlug: string | undefined): string | undefined {
  if (!iconSlug) return undefined;
  const candidate = join(_iconsDir, `${iconSlug}.svg`);
  return existsSync(candidate) ? `/icons/${iconSlug}.svg` : undefined;
}

export type AuthKind = 'oidc' | 'oidc+ldap' | 'forward_auth' | 'ldap' | 'external';

/** Metadata for a named tile group, sourced from groups.yaml. */
export interface GroupMeta {
  title: string;
  description: string;
  order: number;
}

/**
 * Load the optional groups.yaml from MANIFEST_DIR.
 * Returns a Map of group name → GroupMeta.
 * If the file is absent the Map is empty (no noise).
 * Parse errors warn once and return empty (consistent with per-tile isolation).
 */
export function loadGroups(): Map<string, GroupMeta> {
  const path = join(manifestDir(), 'groups.yaml');
  if (!existsSync(path)) return new Map();
  let raw: unknown;
  try {
    raw = parseYaml(readFileSync(path, 'utf8'));
  } catch (err) {
    console.warn(`tiles: groups.yaml parse error — ${err}`);
    return new Map();
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return new Map();
  const out = new Map<string, GroupMeta>();
  for (const [name, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
    const entry = v as Record<string, unknown>;
    out.set(name, {
      title: typeof entry['title'] === 'string' ? entry['title'] : name,
      description: typeof entry['description'] === 'string' ? entry['description'] : '',
      order: typeof entry['order'] === 'number' ? entry['order'] : 999,
    });
  }
  return out;
}

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
  /**
   * Web path to the vendored SVG glyph (e.g. `/icons/grafana.svg`).
   * Resolved at load time via existsSync against public/icons/. Set only
   * when the file is present — renders a CSS-mask glyph; absent = monogram.
   */
  iconHref?: string;
  authKind: AuthKind;
  /**
   * Fallback group, used only when `accessGroups` is empty (see
   * tileAccessGroups). Sourced from the manifest's
   * `presentation.access_group`; falls back to the configured default group
   * (OTHALA_DEFAULT_GROUP) when the field is absent.
   */
  accessGroup: string;
  /**
   * Normalized access-group binding, parsed by parseAccessGroups
   * (portal/src/lib/access-groups.ts) from `presentation.access:` (a list)
   * with a `[access_group]` compat fallback; `[]` when neither is present —
   * no `everyone` fallback applied here. tileAccessGroups prefers this over
   * the singular `accessGroup`, and userCanSeeTile gates on the result.
   */
  accessGroups: string[];
  /**
   * Optional grouping label for the dashboard (e.g. "Usenet", "Torrent").
   * Tiles sharing a group are rendered together under a sub-label.
   * Absent for tiles that belong to no named group.
   */
  group?: string;
  order: number;
  /** Hidden from the dashboard, but the detail page still resolves. */
  disabled: boolean;
  /** Hostname from presentation.url (e.g. "grafana.othala.test"). */
  fqdn: string;
  /** Rendered HTML from the sibling `<slug>.md`, or undefined if absent. */
  educationHtml?: string;
}

function manifestDir(): string {
  return process.env.MANIFEST_DIR ?? '/etc/portal/manifests';
}

/**
 * The fallback access group for tiles whose manifest omits `access_group`.
 * Read at call time (not module load) so runtime env overrides take effect
 * immediately without a module reload — consistent with manifestDir().
 * Mirrors portal/src/lib/config.ts `defaultGroup` (same env var, same
 * 'everyone' fallback, lowercased like every group in
 * OTHALA_IDENTITY_GROUPS).
 */
function tileDefaultGroup(): string {
  return process.env.OTHALA_DEFAULT_GROUP?.trim().toLowerCase() || 'everyone';
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
      (f) =>
        ((f.endsWith('.yaml') || f.endsWith('.yml')) && f !== 'groups.yaml') ||
        f.endsWith('.md'),
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
 * Render an operator-supplied `<slug>.md` to sanitized HTML for `set:html`
 * injection on the /apps/<slug> detail page. Exported so the test corpus
 * (tiles.test.ts) exercises this exact path rather than a copy of it.
 * SVG + common child tags are allowed so inline cat-explainer diagrams
 * survive (USE_PROFILES: { svg: true }); that same width is what a hostile
 * manifest gets to work with.
 */
export function sanitizeEducationMarkdown(raw: string): string {
  const html = marked.parse(raw, { async: false }) as string;
  return DOMPurify.sanitize(html, { USE_PROFILES: { html: true, svg: true } });
}

/**
 * Parse one unified manifest's `presentation:` block into an AppTile.
 * Returns null when the file carries no `presentation:` block (an
 * OIDC-only manifest, or a non-manifest file). Any access_group value is
 * accepted as declared; when the field is absent the tile gates on the
 * default group (OTHALA_DEFAULT_GROUP — see tileDefaultGroup(), which
 * mirrors portal/src/lib/config.ts `defaultGroup`) rather than on a phantom
 * per-slug group.
 *
 * Every tile in Othala gates on group membership — there is no ungated
 * or bypass path. Omitting `access_group` from a manifest is the
 * operator's signal that "any member of the default group can see this
 * tile"; it does NOT make the tile visible to every authenticated user.
 * Explicit `access_group` always wins over the default.
 */
function parseTile(slug: string, doc: Record<string, unknown>, dir: string): AppTile | null {
  const pBlock = doc['presentation'];
  if (!pBlock || typeof pBlock !== 'object' || Array.isArray(pBlock)) return null;
  const p = pBlock as Record<string, unknown>;

  // Accept any non-empty access_group as declared; fall back to the
  // configured default group (OTHALA_DEFAULT_GROUP) when the field is
  // absent. The default group is an identity group that operators assign
  // explicitly — it is not auto-assigned to new users. Tiles using this
  // fallback are visible only to users the admin has placed in the
  // default group.
  const accessGroup = p['access_group'] ? String(p['access_group']) : tileDefaultGroup();

  // Parse `presentation.access:` (with the `[access_group]` compat fallback)
  // into the normalized binding. tileAccessGroups prefers it over the singular
  // accessGroup above; `[]` here means the fallback applies.
  const accessGroups = parseAccessGroups(p);

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
    educationHtml = sanitizeEducationMarkdown(readFileSync(mdPath, 'utf8'));
  }

  const tile: AppTile = {
    slug,
    name: String(p['name'] ?? slug),
    description: String(p['description'] ?? ''),
    url,
    icon: String(p['icon'] ?? '??'),
    authKind: String(p['auth_kind'] ?? 'external') as AuthKind,
    accessGroup,
    accessGroups,
    order: typeof p['order'] === 'number' ? p['order'] : 999,
    disabled: p['disabled'] === true,
    fqdn,
    educationHtml,
  };

  const groupVal = p['group'];
  if (typeof groupVal === 'string' && groupVal.trim()) tile.group = groupVal.trim();

  const iconSlug = p['icon_slug'];
  if (typeof iconSlug === 'string' && iconSlug.trim()) tile.iconSlug = iconSlug.trim();
  const iconFallback = p['icon_fallback'];
  if (typeof iconFallback === 'string' && iconFallback.trim()) tile.iconFallback = iconFallback.trim();

  // Resolve icon href deterministically at load time — no 404s at render.
  tile.iconHref = resolveIconHref(tile.iconSlug) ?? resolveIconHref(tile.iconFallback);

  return tile;
}

function loadFromDisk(): AppTile[] {
  const dir = manifestDir();
  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f) => (f.endsWith('.yaml') || f.endsWith('.yml')) && f !== 'groups.yaml')
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

/**
 * Sanitize a tile/app URL for use in an anchor href.
 *
 * Only http: and https: absolute URLs and root-relative paths (starting with '/')
 * are allowed. Any other scheme (javascript:, data:, vbscript:, blob:, …) returns
 * '#' so a poisoned operator manifest cannot produce a click-to-execute link.
 *
 * @param url   The raw URL string from the manifest.
 * @param base  Optional base URL for resolving relative paths (defaults to
 *              'https://localhost' — only the protocol of the resolved URL is
 *              inspected, not the host, so any dummy base works).
 */
export function safeHref(url: string, base = 'https://localhost'): string {
  if (!url) return '#';
  // Root-relative paths are always safe (no scheme to exploit).
  if (url.startsWith('/')) return url;
  try {
    const resolved = new URL(url, base);
    if (resolved.protocol === 'http:' || resolved.protocol === 'https:') {
      return url;
    }
  } catch {
    // Unparseable URL — fall through to '#'.
  }
  return '#';
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

/**
 * The access-bearing group(s) that gate this tile's visibility. Returns the
 * manifest's `accessGroups` binding — the SAME field the OIDC entry gate keys
 * off, so a tile can never be visible to someone the gate would deny. Falls
 * back to the singular
 * `accessGroup` (which carries the OTHALA_DEFAULT_GROUP fallback) only for
 * presentation-only tiles that declare no `access:`/`access_group:` binding, so
 * the default-group/statuspage pattern keeps working.
 */
export function tileAccessGroups(tile: AppTile): string[] {
  return tile.accessGroups.length > 0 ? tile.accessGroups : [tile.accessGroup];
}

/**
 * Whether a user holding `userGroups` may see `tile` on the dashboard.
 * OR-semantics over the tile's access binding (tileAccessGroups): visible
 * iff the user holds at least one of the bound groups (or the default
 * group, per tileAccessGroups' fallback, when the manifest binds none).
 *
 * This does NOT mirror portal/src/lib/gate.ts's `consent.skip_access_check`
 * bypass (enforceAccessGate) — parseTile (above) only ever reads a manifest's
 * `presentation:` block, never `consent:`, so a skip_access_check manifest
 * gates dashboard visibility on its access binding exactly like any other
 * tile, even though the OIDC gate itself would admit any active identity
 * to that app.
 */
export function userCanSeeTile(tile: AppTile, userGroups: string[]): boolean {
  return tileAccessGroups(tile).some((g) => userGroups.includes(g));
}
