// The deployment content tree under the content root: its layout, the app manifests, their sidecars and groups.yaml.
// Every finding names the file and the fix. Dot-entries are skipped, so a Kubernetes ConfigMap mount checks clean.

import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { lintManifests } from './manifest-lint';
import { needsClientSecret, parseManifest, secretEnvVar, validateClients, type ClientManifest } from './manifests';
import { loadIcon, REQUIREMENT_NAME_RE } from './tiles';

/** Where a deployment's courier overrides sit under the content root. */
export const COURIER_OVERRIDE_DIR = 'courier';

const MANIFEST_RE = /\.ya?ml$/;
const APP_SHAPES = /\.(ya?ml|md|svg)$|^NOTICE$|^requirements$/;

function entries(dir: string): string[] {
  return readdirSync(dir)
    .filter((f) => !f.startsWith('.'))
    .sort();
}

const isDir = (path: string) => statSync(path, { throwIfNoEntry: false })?.isDirectory() ?? false;

function brokenLinkErrors(dir: string, label: string): string[] {
  return entries(dir).flatMap((f) => {
    const path = join(dir, f);
    const rel = label ? `${label}/${f}` : f;
    if (statSync(path, { throwIfNoEntry: false }) === undefined) return [`${rel}: broken symlink; fix or delete it`];
    return lstatSync(path).isDirectory() ? brokenLinkErrors(path, rel) : [];
  });
}

const within = (root: string, path: string) => path === root || path.startsWith(root + sep);

export interface AppsLint {
  manifests: ClientManifest[];
  errors: string[];
  warnings: string[];
}

/** Parses, validates and lints every manifest in `appsDir`; BLOCK findings and a shared client_id are errors. */
export function lintApps(appsDir: string): AppsLint {
  const manifests: ClientManifest[] = [];
  const errors: string[] = [];
  for (const f of entries(appsDir).filter((f) => MANIFEST_RE.test(f) && f !== 'groups.yaml')) {
    try {
      manifests.push(parseManifest(readFileSync(join(appsDir, f), 'utf8'), f));
    } catch (err) {
      errors.push(`apps/${f}: does not parse: ${String(err).split('\n')[0]}`);
    }
  }
  errors.push(...validateClients(manifests).map((e) => `apps/${e}`));
  const byId = new Map<string, string[]>();
  for (const m of manifests) byId.set(m.clientId.toLowerCase(), [...(byId.get(m.clientId.toLowerCase()) ?? []), m.sourcePath]);
  for (const [id, files] of byId) {
    if (files.length > 1) errors.push(`apps/: client_id ${JSON.stringify(id)} is shared by ${files.join(', ')}; give each its own`);
  }
  const requirements = existsSync(join(appsDir, 'requirements'))
    ? entries(join(appsDir, 'requirements')).filter((f) => f.endsWith('.md')).map((f) => f.slice(0, -3))
    : [];
  const referenced = manifests.flatMap((m) => [...m.accessGroups, ...Object.keys(m.groupRoleMap)]);
  const warnings: string[] = [];
  for (const finding of lintManifests(manifests, referenced, requirements)) {
    (finding.severity === 'block' ? errors : warnings).push(`apps/${finding.source}: ${finding.message}`);
  }
  return { manifests, errors, warnings };
}

function appsLayoutErrors(appsDir: string): string[] {
  const stems = new Set(entries(appsDir).filter((f) => MANIFEST_RE.test(f)).map((f) => f.replace(MANIFEST_RE, '')));
  const errors: string[] = [];
  for (const f of entries(appsDir)) {
    const path = join(appsDir, f);
    const stem = f.replace(/\.(ya?ml|md|svg)$/, '');
    if (f === 'groups.yaml') {
      errors.push('apps/groups.yaml: groups.yaml lives at the content root; move it up one level');
    } else if (MANIFEST_RE.test(f) || f === 'NOTICE') {
      if (isDir(path)) errors.push(`apps/${f}: must be a file`);
    } else if (f === 'requirements') {
      if (!isDir(path)) {
        errors.push('apps/requirements: must be a directory of <name>.md');
        continue;
      }
      for (const r of entries(path)) {
        if (!r.endsWith('.md') || !REQUIREMENT_NAME_RE.test(r.slice(0, -3))) {
          errors.push(`apps/requirements/${r}: a requirement is <name>.md with a name matching ${REQUIREMENT_NAME_RE}`);
        }
      }
    } else if (f.endsWith('.md') || f.endsWith('.svg')) {
      if (!stems.has(stem)) {
        errors.push(`apps/${f}: no apps/${stem}.yaml for this sidecar; rename it to match a manifest or delete it`);
      } else if (f.endsWith('.svg')) {
        const { reason } = loadIcon(appsDir, stem);
        if (reason) errors.push(`apps/${reason}`);
      }
    } else {
      errors.push(`apps/${f}: not part of the apps layout (<stem>.yaml, <stem>.md, <stem>.svg, requirements/, NOTICE); delete it`);
    }
  }
  return errors;
}

function groupsErrors(path: string): string[] {
  let raw: unknown;
  try {
    raw = parseYaml(readFileSync(path, 'utf8'));
  } catch (err) {
    return [`groups.yaml: does not parse: ${String(err).split('\n')[0]}`];
  }
  if (raw === null || raw === undefined) return [];
  if (typeof raw !== 'object' || Array.isArray(raw)) return ['groups.yaml: must be a mapping of group name to { title, description, order }'];
  return Object.entries(raw as Record<string, unknown>)
    .filter(([, v]) => !v || typeof v !== 'object' || Array.isArray(v))
    .map(([name]) => `groups.yaml: ${name} must be a mapping of title, description and order`);
}

function courierErrors(dir: string, defaults: readonly string[]): string[] {
  if (!isDir(dir)) return ['courier: must be a directory of <name>.gotmpl overrides'];
  const root = realpathSync(dirname(dir));
  return entries(dir).flatMap((f) => {
    const path = join(dir, f);
    if (!defaults.includes(f) || isDir(path)) {
      return [`courier/${f}: no shipped template has this name; an override is one of ${defaults.join(', ')}`];
    }
    return existsSync(path) && !within(root, realpathSync(path)) ? [`courier/${f}: a link must stay inside the content directory; copy the file in`] : [];
  });
}

/** The courier-override errors alone: the only content the Ory render reads. */
export function courierContentErrors(contentDir: string, courierDefaults: readonly string[]): string[] {
  const dir = join(contentDir, COURIER_OVERRIDE_DIR);
  if (statSync(dir, { throwIfNoEntry: false }) === undefined) return existsSync(dir) ? ['courier: broken symlink; fix or delete it'] : [];
  return [...(isDir(dir) ? brokenLinkErrors(dir, COURIER_OVERRIDE_DIR) : []), ...courierErrors(dir, courierDefaults)];
}

/** Every layout, manifest, sidecar, groups.yaml and courier-name error under `contentDir`; reads no secrets. */
export function contentErrors(contentDir: string, courierDefaults: readonly string[]): string[] {
  if (!existsSync(contentDir) || !isDir(contentDir)) return [`${contentDir}: content directory not found`];
  const errors: string[] = brokenLinkErrors(contentDir, '');
  for (const f of entries(contentDir)) {
    const path = join(contentDir, f);
    if (f === 'apps') {
      if (!isDir(path)) errors.push('apps: must be a directory');
    } else if (f === 'groups.yaml') {
      errors.push(...groupsErrors(path));
    } else if (f === COURIER_OVERRIDE_DIR) {
      errors.push(...courierErrors(path, courierDefaults));
    } else if (APP_SHAPES.test(f)) {
      errors.push(`${f}: app content lives under apps/; move it to apps/${f}`);
    } else {
      errors.push(`${f}: not part of the content layout (apps/, groups.yaml, courier/); delete it`);
    }
  }
  const appsDir = join(contentDir, 'apps');
  if (!existsSync(appsDir)) return [...errors, 'apps: missing; the manifests live in apps/ under the content root'];
  if (!isDir(appsDir)) return errors;
  return [...errors, ...appsLayoutErrors(appsDir), ...lintApps(appsDir).errors];
}

/** The `<CLIENT_ID>_CLIENT_SECRET` names the parseable confidential OIDC manifests under `contentDir` need, sorted. */
export function clientSecretNames(contentDir: string): string[] {
  const appsDir = join(contentDir, 'apps');
  if (!existsSync(appsDir)) return [];
  return lintApps(appsDir)
    .manifests.filter(needsClientSecret)
    .flatMap((m) => {
      try {
        return [secretEnvVar(m.clientId)];
      } catch {
        return [];
      }
    })
    .sort();
}
