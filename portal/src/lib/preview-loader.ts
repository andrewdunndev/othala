// THROWAWAY — preview-loader.ts
//
// Loads portal/preview-manifests/*.yaml into a unified-manifest shape for the
// /preview prototype route. NOT used in production; delete when the design is
// baked into the real content pipeline.
//
// Unified manifest shape:
//   presentation: { name, description, url, icon, auth_kind, access_group?,
//                   order, disabled?, icon_slug?, icon_fallback? }
//   oidc?: { ... }   — present only when auth_kind includes "oidc"
//
// A sibling <slug>.md (same directory) is the optional education sidecar.
// It is rendered to HTML by `marked` (inline HTML / SVG passthrough enabled).

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { marked } from 'marked';

// ── Types ──────────────────────────────────────────────────────────────────

export type AuthKind = 'oidc' | 'oidc+ldap' | 'forward_auth' | 'external';

export interface PreviewPresentation {
  name: string;
  description: string;
  url: string;
  /** 1-3 char label shown when no icon resolves (rarely visible now). */
  icon: string;
  /**
   * simple-icons slug for the product SVG.
   * Rendered via CSS mask-image for uniform monochrome ink.
   * Empty string or absent = use icon_fallback or generic placeholder.
   */
  icon_slug?: string;
  /**
   * simple-icons fallback slug for services not in simple-icons.
   * If both icon_slug and icon_fallback are empty, preview renders a
   * text monogram block.
   */
  icon_fallback?: string;
  auth_kind: AuthKind;
  /** Optional short-circuit access group. */
  access_group?: string;
  order: number;
  disabled?: boolean;
}

export interface PreviewManifest {
  slug: string;
  presentation: PreviewPresentation;
  /** Hostname extracted from presentation.url (e.g. "memory.dunn.dev"). */
  fqdn: string;
  /** OIDC client block — present when auth_kind includes "oidc". */
  oidc?: Record<string, unknown>;
  /** Rendered HTML from the sibling <slug>.md, or undefined if absent. */
  educationHtml?: string;
}

// ── Path resolution ────────────────────────────────────────────────────────

// Resolve relative to this file so it works regardless of cwd.
// __dirname is unavailable in ESM; use import.meta.url.
function previewManifestDir(): string {
  // portal/src/lib/preview-loader.ts → portal/preview-manifests/
  const here = new URL(import.meta.url).pathname;
  return resolve(here, '..', '..', '..', 'preview-manifests');
}

// ── Loader ─────────────────────────────────────────────────────────────────

/**
 * Load all preview manifests from portal/preview-manifests/*.yaml.
 * Sorted by presentation.order ascending; ties broken by name.
 * Skips entries with presentation.disabled = true.
 */
export function loadPreviewManifests(): PreviewManifest[] {
  const dir = previewManifestDir();

  let yamlFiles: string[];
  try {
    yamlFiles = readdirSync(dir)
      .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
      .sort();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }

  const results: PreviewManifest[] = [];

  for (const file of yamlFiles) {
    const slug = file.replace(/\.ya?ml$/, '');
    const yamlPath = join(dir, file);

    let raw: unknown;
    try {
      raw = parseYaml(readFileSync(yamlPath, 'utf8'));
    } catch (err) {
      console.warn(`preview-loader: skipping ${file}: ${err}`);
      continue;
    }

    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      console.warn(`preview-loader: skipping ${file}: not an object`);
      continue;
    }

    const doc = raw as Record<string, unknown>;
    const pBlock = doc['presentation'];

    if (!pBlock || typeof pBlock !== 'object' || Array.isArray(pBlock)) {
      console.warn(`preview-loader: skipping ${file}: missing presentation: block`);
      continue;
    }

    const p = pBlock as Record<string, unknown>;
    const presentation: PreviewPresentation = {
      name:         String(p['name'] ?? slug),
      description:  String(p['description'] ?? ''),
      url:          String(p['url'] ?? ''),
      icon:         String(p['icon'] ?? '??'),
      auth_kind:    String(p['auth_kind'] ?? 'external') as AuthKind,
      order:        typeof p['order'] === 'number' ? p['order'] : 999,
      disabled:     Boolean(p['disabled'] ?? false),
    };

    // icon_slug: empty string means no simple-icons slug; treat as absent.
    const rawIconSlug = p['icon_slug'];
    if (rawIconSlug && typeof rawIconSlug === 'string' && rawIconSlug.trim()) {
      presentation.icon_slug = rawIconSlug.trim();
    }

    // icon_fallback: generic simple-icons slug used when icon_slug is absent.
    const rawFallback = p['icon_fallback'];
    if (rawFallback && typeof rawFallback === 'string' && rawFallback.trim()) {
      presentation.icon_fallback = rawFallback.trim();
    }

    if (p['access_group']) {
      presentation.access_group = String(p['access_group']);
    }

    if (presentation.disabled) continue;

    const oidcBlock =
      doc['oidc'] && typeof doc['oidc'] === 'object' && !Array.isArray(doc['oidc'])
        ? (doc['oidc'] as Record<string, unknown>)
        : undefined;

    // Education sidecar: <slug>.md sibling
    let educationHtml: string | undefined;
    const mdPath = join(dir, `${slug}.md`);
    if (existsSync(mdPath)) {
      const mdText = readFileSync(mdPath, 'utf8');
      // marked.parse returns string | Promise<string>; call synchronous form
      // by passing the string. Inline HTML passthrough is on by default.
      const rendered = marked.parse(mdText, { async: false });
      educationHtml = rendered as string;
    }

    // Derive FQDN from presentation.url; fall back to raw url on parse error.
    let fqdn: string;
    try {
      fqdn = new URL(presentation.url).host;
    } catch {
      fqdn = presentation.url;
    }

    results.push({ slug, presentation, fqdn, oidc: oidcBlock, educationHtml });
  }

  return results.sort(
    (a, b) =>
      a.presentation.order - b.presentation.order ||
      a.presentation.name.localeCompare(b.presentation.name),
  );
}
