// Runtime app-tile loader. Reads each `<slug>.yaml` `presentation:` block from the manifest dir at request time (manifests.ts
// reads `oidc:`/`consent:` from the same files); an optional `<slug>.md` is the /apps/<slug> detail content.
// groups.yaml (optional) maps group name to { title, description, order } via loadGroups() and is skipped as a tile.
// requirements/<name>.md (optional) defines a prerequisite that a manifest names in `presentation.requires`.

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { marked } from 'marked';
import DOMPurify from 'isomorphic-dompurify';
import { parseAccessGroups } from './access-groups';
import { manifestDir } from './manifests';
import { DEFAULT_GROUP } from './constants';

// Vendored icons directory: public/icons/ in dev (a stale dist/ must not shadow it), dist/client/icons/ in prod.
const _cwd = process.cwd();
const _iconsDir = (() => {
  // import.meta.env is Vite-specific; guard it so the module loads in plain Node.
  const isDev = typeof import.meta.env !== 'undefined' && import.meta.env.DEV;
  if (isDev) return join(_cwd, 'public', 'icons');
  const prod = join(_cwd, 'dist', 'client', 'icons');
  if (existsSync(prod)) return prod;
  return join(_cwd, 'public', 'icons');
})();

/** Return the web path for a vendored simple-icons SVG, or undefined if absent. */
export function resolveIconHref(iconSlug: string | undefined): string | undefined {
  if (!iconSlug) return undefined;
  const candidate = join(_iconsDir, `${iconSlug}.svg`);
  return existsSync(candidate) ? `/icons/${iconSlug}.svg` : undefined;
}

/** True when the logo file opens with its own filled square (a rect at the origin, width equal to height). Such
 *  marks fill the whole plate instead of sitting inside it. */
export function iconIsBleed(iconSlug: string | undefined): boolean {
  if (!iconSlug) return false;
  try {
    const head = readFileSync(join(_iconsDir, `${iconSlug}.svg`), 'utf8').slice(0, 600);
    return /<rect(?![^>]*\s[xy]=)[^>]*\swidth="(\d+(?:\.\d+)?)"[^>]*\sheight="\1"[^>]*\sfill="#/i.test(head);
  } catch {
    return false;
  }
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
  /** Set only when the vendored SVG exists; absent renders the monogram. */
  iconHref?: string;
  /** The logo ships its own filled square, so the plate drops its padding and border. */
  iconBleed?: boolean;
  authKind: AuthKind;
  accessGroups: string[];
  /** Dashboard grouping label; tiles sharing one render together. */
  group?: string;
  order: number;
  /** Hidden from the dashboard, but the detail page still resolves. */
  disabled: boolean;
  fqdn: string;
  /** Rendered HTML from the sibling `<slug>.md`, or undefined if absent. */
  educationHtml?: string;
  /** Prerequisite names from `presentation.requires` (lowercase, deduplicated; malformed names dropped). */
  requires: string[];
}

/** A requirement name is a filename stem under requirements/, so it must stay a plain slug. */
export const REQUIREMENT_NAME_RE = /^[a-z][a-z0-9-]{0,39}$/;

/** One shared prerequisite, from `requirements/<name>.md`: front matter `title` and `why`, then the setup guide. */
export interface Requirement {
  name: string;
  title: string;
  /** One line on why an app needs it. */
  why: string;
  /** Sanitized HTML of the setup guide (steps and explainer); empty when the file has no body. */
  html: string;
}

/** The four sections a guide is laid out in, in display order. Any other heading renders after them. */
export const GUIDE_OUTLINE = [
  { id: 'purpose', title: "What it's for", match: /what.*for|about|purpose/i },
  { id: 'first-time', title: 'First time', match: /first|get(ting)? started|set ?up/i },
  { id: 'good-to-know', title: 'Good to know', match: /good to know|tips|notes?|nuances?/i },
  { id: 'help', title: 'Getting help', match: /help|support|stuck/i },
] as const;

export interface GuideSection {
  /** Outline id, or `extra` for a heading outside the outline. */
  id: string;
  title: string;
  html: string;
}

export interface Guide {
  /** Any text before the first heading. */
  lead: string;
  sections: GuideSection[];
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
    try {
      for (const f of readdirSync(join(dir, 'requirements'))) files.push(join('requirements', f));
    } catch {
      // no requirements directory
    }
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
 * Render an operator-supplied `<slug>.md` to sanitized HTML for `set:html`. SVG is allowed so inline diagrams
 * survive. `style` is forbidden because the CSP has no style-src, form controls because form-action reaches every
 * apex subdomain.
 */
export function sanitizeEducationMarkdown(raw: string): string {
  return sanitizeGuideHtml(marked.parse(raw, { async: false }) as string);
}

function sanitizeGuideHtml(html: string): string {
  return DOMPurify.sanitize(html, {
    USE_PROFILES: { html: true, svg: true },
    FORBID_TAGS: ['style', 'form', 'input', 'button', 'select', 'textarea'],
  });
}

/** Plain text of an HTML fragment for matching a heading against the outline: the sanitizer keeps text only. */
function headingText(html: string): string {
  const text = DOMPurify.sanitize(html, { ALLOWED_TAGS: [] });
  return text.replace(/&#39;|&rsquo;|&apos;/g, "'").replace(/&amp;/g, '&').trim();
}

/**
 * Split guide HTML into the fixed outline. Each `<h2>` opens a section, matched to an outline slot by its
 * text; a slot's first heading wins and later or unmatched headings follow as `extra` sections in source order. The
 * section title is the outline's, so the page reads the same for every app. A guide with no `<h2>` is all `lead`.
 * The split is textual, so each piece is sanitised after it, never trusted as the earlier sanitising left it.
 */
export function splitGuide(html: string | undefined): Guide {
  if (!html || !html.trim()) return { lead: '', sections: [] };
  const parts = html.split(/(?=<h2[\s>])/i);
  let lead = '';
  const slots = new Map<string, GuideSection>();
  const extras: GuideSection[] = [];
  for (const part of parts) {
    const m = /^<h2[^>]*>([\s\S]*?)<\/h2>([\s\S]*)$/i.exec(part);
    if (!m) {
      lead += part;
      continue;
    }
    const text = headingText(m[1] ?? '');
    const body = sanitizeGuideHtml((m[2] ?? '').trim());
    const slot = GUIDE_OUTLINE.find((o) => o.match.test(text));
    if (slot && !slots.has(slot.id)) {
      slots.set(slot.id, { id: slot.id, title: slot.title, html: body });
    } else {
      extras.push({ id: 'extra', title: text, html: body });
    }
  }
  const sections = [
    ...GUIDE_OUTLINE.flatMap((o) => (slots.has(o.id) ? [slots.get(o.id) as GuideSection] : [])),
    ...extras,
  ];
  return { lead: sanitizeGuideHtml(lead.trim()), sections };
}

/** Split `---` YAML front matter off a markdown file; a missing or malformed block yields empty data and the whole text. */
function splitFrontMatter(raw: string): { data: Record<string, unknown>; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(raw);
  if (!m) return { data: {}, body: raw };
  try {
    const data = parseYaml(m[1] ?? '');
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      return { data: data as Record<string, unknown>, body: m[2] ?? '' };
    }
  } catch {
    // fall through: malformed front matter is treated as plain markdown
  }
  return { data: {}, body: m[2] ?? '' };
}

/** Parse one `requirements/<name>.md` body; exported so tests skip the filesystem. */
export function parseRequirement(name: string, raw: string): Requirement {
  const { data, body } = splitFrontMatter(raw);
  const title = typeof data['title'] === 'string' && data['title'].trim() ? data['title'].trim() : titleCase(name);
  const why = typeof data['why'] === 'string' ? data['why'].trim() : '';
  return { name, title, why, html: body.trim() ? sanitizeEducationMarkdown(body) : '' };
}

function titleCase(name: string): string {
  return name.charAt(0).toUpperCase() + name.slice(1);
}

/** Load `requirements/*.md` as name -> Requirement; an absent directory is empty, and a bad filename is skipped. */
export function loadRequirements(): Map<string, Requirement> {
  const dir = join(manifestDir(), 'requirements');
  const out = new Map<string, Requirement>();
  let files: string[];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith('.md')).sort();
  } catch {
    return out;
  }
  for (const f of files) {
    const name = f.slice(0, -3);
    if (!REQUIREMENT_NAME_RE.test(name)) continue;
    try {
      out.set(name, parseRequirement(name, readFileSync(join(dir, f), 'utf8')));
    } catch (err) {
      console.warn(`tiles: skipping requirements/${f}: ${err}`);
    }
  }
  return out;
}

/** Normalize `presentation.requires`: a list of slugs, lowercased, deduplicated, anything malformed dropped. */
export function parseRequires(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const v of raw) {
    if (typeof v !== 'string') continue;
    const n = v.trim().toLowerCase();
    if (REQUIREMENT_NAME_RE.test(n) && !out.includes(n)) out.push(n);
  }
  return out;
}

export type TileReadiness = 'none' | 'ready' | 'needs';

/** Prerequisite state for a person: `none` when the app requires nothing, `ready` when the admin marked every
 *  requirement for them, else `needs`. */
export function tileReadiness(tile: AppTile, marked: readonly string[]): TileReadiness {
  if (tile.requires.length === 0) return 'none';
  return tile.requires.every((r) => marked.includes(r)) ? 'ready' : 'needs';
}

/** Parse one manifest's `presentation:` block into an AppTile; null when it has none. */
function parseTile(slug: string, doc: Record<string, unknown>, dir: string): AppTile | null {
  const pBlock = doc['presentation'];
  if (!pBlock || typeof pBlock !== 'object' || Array.isArray(pBlock)) return null;
  const p = pBlock as Record<string, unknown>;

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
    accessGroups,
    order: typeof p['order'] === 'number' ? p['order'] : 999,
    disabled: p['disabled'] === true,
    fqdn,
    educationHtml,
    requires: parseRequires(p['requires']),
  };

  const groupVal = p['group'];
  if (typeof groupVal === 'string' && groupVal.trim()) tile.group = groupVal.trim();

  const iconSlug = p['icon_slug'];
  if (typeof iconSlug === 'string' && iconSlug.trim()) tile.iconSlug = iconSlug.trim();
  const iconFallback = p['icon_fallback'];
  if (typeof iconFallback === 'string' && iconFallback.trim()) tile.iconFallback = iconFallback.trim();

  // Resolve the icon href at load time so render never 404s.
  tile.iconHref = resolveIconHref(tile.iconSlug) ?? resolveIconHref(tile.iconFallback);
  tile.iconBleed = iconIsBleed(tile.iconHref?.split('/').pop()?.replace(/\.svg$/, ''));

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
    let text = '';
    try {
      text = readFileSync(join(dir, f), 'utf8');
      doc = parseYaml(text);
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

export function loadTiles(): AppTile[] {
  return allTiles().filter((t) => !t.disabled);
}

/** Includes disabled tiles. */
export function getTile(slug: string): AppTile | undefined {
  return allTiles().find((t) => t.slug === slug);
}

/** The groups gating a tile's visibility: its access groups, else the default group, never every signed-in user. */
export function tileAccessGroups(tile: AppTile): string[] {
  return tile.accessGroups.length > 0 ? tile.accessGroups : [DEFAULT_GROUP];
}

/** Whether the user may see the tile: OR over tileAccessGroups. Unlike enforceAccessGate, `skip_access_check` is not
 * read (parseTile reads only `presentation:`), so such a manifest still gates visibility on its binding. */
export function userCanSeeTile(tile: AppTile, userGroups: string[]): boolean {
  return tileAccessGroups(tile).some((g) => userGroups.includes(g));
}

/** The tile's requirements resolved against the loaded set, in declared order; a name nothing defines gets a stand-in. */
export function requirementsFor(tile: AppTile, all: Map<string, Requirement>): Requirement[] {
  return tile.requires.map((n) => all.get(n) ?? { name: n, title: titleCase(n), why: '', html: '' });
}
