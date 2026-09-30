// Runtime app-tile loader. Reads each `<slug>.yaml` `presentation:` block from MANIFEST_DIR at request time (manifests.ts
// reads `oidc:`/`consent:` from the same files); an optional `<slug>.md` is the /apps/<slug> detail content.
// groups.yaml (optional) maps group name to { title, description, order } via loadGroups() and is skipped as a tile.

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { marked } from 'marked';
import DOMPurify from 'isomorphic-dompurify';
import { parseAccessGroups } from './access-groups';

// Vendored icons directory: public/icons/ in dev (a stale dist/ must not shadow it), dist/client/icons/ in prod.
const _cwd = process.cwd();
const _iconsDir = (() => {
  // import.meta.env is Vite-specific; guard it so the module loads in plain Node.
  const isDev = typeof import.meta.env !== 'undefined' && import.meta.env.DEV;
  if (isDev) {
    // Source tree in dev.
    return join(_cwd, 'public', 'icons');
  }
  // prod: fall back to public/ if dist is missing.
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

export type AuthKind = 'oidc' | 'forward_auth' | 'external';

/** Metadata for a named tile group, sourced from groups.yaml. */
export interface GroupMeta {
  title: string;
  description: string;
  order: number;
}

/** Load the optional groups.yaml as name -> GroupMeta; absent is empty, a parse error warns once and returns empty. */
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
  /** Web path to the vendored SVG glyph (e.g. `/icons/grafana.svg`), set only when the file exists; absent = monogram. */
  iconHref?: string;
  authKind: AuthKind;
  /** Fallback group, used only when `accessGroups` is empty (see tileAccessGroups): `presentation.access_group`, else the default group. */
  accessGroup: string;
  /** Access binding from parseAccessGroups over `presentation.access:` (`[access_group]` compat); `[]` when neither is set. tileAccessGroups prefers it. */
  accessGroups: string[];
  /** Optional dashboard grouping label (e.g. "Usenet"); tiles sharing one render together. */
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

/** Fallback group for tiles omitting `access_group`; read at call time and mirrors config.ts `defaultGroup`. */
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
 * Render an operator-supplied `<slug>.md` to sanitized HTML for `set:html`; exported so tiles.test.ts exercises this path.
 * SVG is allowed (USE_PROFILES) so inline diagrams survive. FORBID_TAGS removes `style` (the CSP has no style-src) and
 * form controls (form-action reaches every apex subdomain).
 */
export function sanitizeEducationMarkdown(raw: string): string {
  const html = marked.parse(raw, { async: false }) as string;
  return DOMPurify.sanitize(html, {
    USE_PROFILES: { html: true, svg: true },
    FORBID_TAGS: ['style', 'form', 'input', 'button', 'select', 'textarea'],
  });
}

/**
 * Parse one manifest's `presentation:` block into an AppTile; null when it has none. An absent `access_group` gates
 * on the default group (tileDefaultGroup), never on a per-slug group or every authenticated user.
 */
function parseTile(slug: string, doc: Record<string, unknown>, dir: string): AppTile | null {
  const pBlock = doc['presentation'];
  if (!pBlock || typeof pBlock !== 'object' || Array.isArray(pBlock)) return null;
  const p = pBlock as Record<string, unknown>;

  // Absent access_group falls back to the default group, which admins assign explicitly.
  const accessGroup = p['access_group'] ? String(p['access_group']) : tileDefaultGroup();

  // Normalized `presentation.access:` binding; `[]` means the accessGroup fallback applies.
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

  // Resolve the icon href at load time so render never 404s.
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
 * Sanitize a URL for an anchor href: only http(s) absolute URLs and root-relative paths pass; any other scheme
 * (javascript:, data:, ...) returns '#'. Only the protocol of the resolved URL is checked, so the dummy `base` is fine.
 */
export function safeHref(url: string, base = 'https://localhost'): string {
  if (!url) return '#';
  // Root-relative paths carry no scheme.
  if (url.startsWith('/')) return url;
  try {
    const resolved = new URL(url, base);
    if (resolved.protocol === 'http:' || resolved.protocol === 'https:') {
      return url;
    }
  } catch {
    // Unparseable: fall through to '#'.
  }
  return '#';
}

/** All cached tiles (disabled included), sorted by order then name; 30 s cache, mtime-invalidated. */
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

/** One tile by slug for /apps/<slug>; includes disabled tiles. */
export function getTile(slug: string): AppTile | undefined {
  return allTiles().find((t) => t.slug === slug);
}

/** The group(s) gating a tile's visibility: the manifest's `accessGroups` (the field the OIDC gate uses), else the singular
 * `accessGroup` (default-group fallback) for tiles with no binding. */
export function tileAccessGroups(tile: AppTile): string[] {
  return tile.accessGroups.length > 0 ? tile.accessGroups : [tile.accessGroup];
}

/** Whether the user may see the tile: OR over tileAccessGroups. Unlike enforceAccessGate, `skip_access_check` is not
 * read (parseTile reads only `presentation:`), so such a manifest still gates visibility on its binding. */
export function userCanSeeTile(tile: AppTile, userGroups: string[]): boolean {
  return tileAccessGroups(tile).some((g) => userGroups.includes(g));
}
