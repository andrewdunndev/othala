// Ory config render: the image's policy templates plus env values and secrets, out to files Ory reads.
// Errors name variables, never values. Env is a parameter here; only the CLI reads process.env.

import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parse } from 'yaml';
import { clientSecretNames, contentErrors, COURIER_OVERRIDE_DIR } from './content';
import { envNameErrors } from './env-names';

export type Env = Record<string, string | undefined>;
export type RenderedFile = { path: string; content: string };

/** Policy files rendered with `${NAME}` substitution, by path under the policy dir. */
const TEMPLATES = ['kratos/kratos.yml', 'hydra/hydra.yml'];
/** Policy files copied as they are. */
const LITERALS = ['kratos/identity.schema.json', 'kratos/hooks/recovery-gate.jsonnet'];
const COURIER_DIR = 'kratos/courier';
/** The only values a courier override may name: identity, never a secret. */
const COURIER_TOKENS = ['OTHALA_APEX', 'OTHALA_INSTANCE_NAME', 'OTHALA_PUBLIC_URL'];

/** Secrets a render requires, set and non-blank, whether or not a template names them. */
export const SECRETS = [
  'POSTGRES_PASSWORD',
  'KRATOS_PG_PASS',
  'HYDRA_PG_PASS',
  'KRATOS_COOKIE_SECRET_CURRENT',
  'KRATOS_CIPHER_SECRET_CURRENT',
  'HYDRA_SYSTEM_SECRET',
  'HYDRA_COOKIE_SECRET_CURRENT',
  'RECOVERY_GATE_SECRET',
  'CSRF_SECRET',
  'OTHALA_SMTP_CONNECTION_URI',
] as const;

/** The secrets gen-secrets mints, with their byte length; the SMTP URI comes from the operator's relay. */
const GENERATED: Record<string, number> = {
  POSTGRES_PASSWORD: 32,
  KRATOS_PG_PASS: 32,
  HYDRA_PG_PASS: 32,
  KRATOS_COOKIE_SECRET_CURRENT: 32,
  // Kratos requires a cipher secret of exactly 32 characters.
  KRATOS_CIPHER_SECRET_CURRENT: 16,
  HYDRA_SYSTEM_SECRET: 32,
  HYDRA_COOKIE_SECRET_CURRENT: 32,
  RECOVERY_GATE_SECRET: 32,
  CSRF_SECRET: 32,
};

const CLIENT_SECRET_BYTES = 32;

const NONEMPTY_BINDS = ['KRATOS_ADMIN_BIND_HOST', 'HYDRA_ADMIN_BIND_HOST'];

export class RenderError extends Error {}

type Mode = 'yaml' | 'html' | 'text';

function modeOf(path: string): Mode {
  if (path.endsWith('.html.gotmpl')) return 'html';
  if (path.endsWith('.gotmpl')) return 'text';
  return 'yaml';
}

const TOKEN = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;
const IF_RE = /^\s*#@if\s+([A-Za-z_][A-Za-z0-9_]*)\s*$/;
const ENDIF_RE = /^\s*#@endif\s*$/;
const LINE_BREAK = /\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]/;

function splitLines(text: string): string[] {
  const lines = text.split(LINE_BREAK);
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

// #@if NAME ... #@endif keeps the block when NAME is non-empty; blocks do not nest.
function resolveConditionals(path: string, text: string, env: Env): string {
  const out: string[] = [];
  let gate: string | null = null;
  let keep = true;
  splitLines(text).forEach((line, i) => {
    const ifMatch = IF_RE.exec(line);
    if (ifMatch) {
      if (gate !== null) throw new RenderError(`${path}: nested #@if at line ${i + 1} (block '${gate}' still open)`);
      gate = ifMatch[1];
      keep = Boolean(env[gate]);
      return;
    }
    if (ENDIF_RE.test(line)) {
      if (gate === null) throw new RenderError(`${path}: #@endif without a matching #@if at line ${i + 1}`);
      gate = null;
      keep = true;
      return;
    }
    if (gate === null || keep) out.push(line);
  });
  if (gate !== null) throw new RenderError(`${path}: unterminated #@if '${gate}'`);
  return out.join('\n') + (text.endsWith('\n') ? '\n' : '');
}

// A YAML comment may name ${NAME} without requiring it; an inline comment starts at space-hash, so fragment URIs survive.
function stripComments(text: string): string {
  return splitLines(text)
    .map((line) => {
      if (line.trimStart().startsWith('#')) return '';
      const pos = line.indexOf(' #');
      return pos === -1 ? line : line.slice(0, pos);
    })
    .join('\n');
}

function tokens(text: string): string[] {
  return [...new Set([...text.matchAll(TOKEN)].map((m) => m[1]))].sort();
}

const escapeYaml = (v: string) => v.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
const escapeHtml = (v: string) =>
  v.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#x27;');
const ESCAPE: Record<Mode, (v: string) => string> = { yaml: escapeYaml, html: escapeHtml, text: (v) => v };

type Parsed = { resolved: string; needed: string[]; mode: Mode };

function parseTemplate(path: string, src: string, env: Env): Parsed {
  const mode = modeOf(path);
  const resolved = resolveConditionals(path, src, env);
  return { resolved, needed: tokens(mode === 'yaml' ? stripComments(resolved) : resolved), mode };
}

// Unset is missing; empty is a value, except for the Ory admin binds.
function valueErrors(path: string, names: string[], mode: Mode, env: Env): string[] {
  const missing = names.filter((n) => env[n] === undefined);
  if (missing.length > 0) return [`${path}: missing render variable(s): ${missing.join(', ')}`];
  const errors: string[] = [];
  for (const name of NONEMPTY_BINDS) {
    if (names.includes(name) && env[name]!.trim() === '') errors.push(`${path}: ${name} must not be empty`);
  }
  for (const name of names) {
    const val = env[name]!;
    // A line break would restructure a YAML scalar.
    if ([...val].some((c) => c.charCodeAt(0) < 0x20)) errors.push(`${path}: ${name} contains a control character`);
    // Kratos parses mail templates as Go templates: a delimiter would inject an action.
    if (mode !== 'yaml' && (val.includes('{{') || val.includes('}}'))) errors.push(`${path}: ${name} contains a template delimiter`);
  }
  return errors;
}

/** Renders one template: `#@if` blocks resolved, then each needed `${NAME}` escaped for the file's kind. */
export function renderTemplate(path: string, src: string, env: Env): string {
  const { resolved, needed, mode } = parseTemplate(path, src, env);
  const errors = valueErrors(path, needed, mode, env);
  if (errors.length > 0) throw new RenderError(errors.join('\n'));
  const neededSet = new Set(needed);
  return resolved.replace(TOKEN, (whole, name: string) => (neededSet.has(name) ? ESCAPE[mode](env[name]!) : whole));
}

/** The shipped courier template names; a deployment override must reuse one. */
export function courierDefaults(policyDir: string): string[] {
  return readdirSync(join(policyDir, COURIER_DIR))
    .filter((f) => f.endsWith('.gotmpl'))
    .sort();
}

/** A template to render: `path` is where it lands, `label` names it in errors, `file` is what is read. */
type Source = { path: string; label: string; file: string };

// The shipped courier defaults, each replaced by the deployment's `courier/<name>` when one exists.
function sources(policyDir: string, contentDir: string): Source[] {
  const courier = courierDefaults(policyDir).map((name) => {
    const override = join(contentDir, COURIER_OVERRIDE_DIR, name);
    return existsSync(override) && statSync(override).isFile()
      ? { path: `${COURIER_DIR}/${name}`, label: `${COURIER_OVERRIDE_DIR}/${name}`, file: override }
      : { path: `${COURIER_DIR}/${name}`, label: `${COURIER_DIR}/${name}`, file: join(policyDir, COURIER_DIR, name) };
  });
  return [...TEMPLATES.map((p) => ({ path: p, label: p, file: join(policyDir, p) })), ...courier];
}

/** The offline check: policy files present, no retired or unknown env name, the content tree valid, and every
 *  non-secret value the templates need, valid. No secrets read. */
export function check(policyDir: string, contentDir: string, env: Env): string[] {
  const missingFiles = [...TEMPLATES, ...LITERALS, COURIER_DIR].filter((p) => !existsSync(join(policyDir, p)));
  if (missingFiles.length > 0) return missingFiles.map((p) => `${policyDir}: missing policy file ${p}`);
  const secrets = new Set<string>(SECRETS);
  const errors: string[] = [...envNameErrors(env), ...contentErrors(contentDir, courierDefaults(policyDir))];
  for (const { path, label, file } of sources(policyDir, contentDir)) {
    try {
      const { needed, mode } = parseTemplate(label, readFileSync(file, 'utf8'), env);
      const foreign = label === path ? [] : needed.filter((n) => !COURIER_TOKENS.includes(n));
      if (foreign.length > 0) {
        errors.push(`${label}: an override may name only ${COURIER_TOKENS.join(', ')}; remove ${foreign.join(', ')}`);
        continue;
      }
      errors.push(...valueErrors(label, needed.filter((n) => !secrets.has(n)), mode, env));
    } catch (err) {
      if (!(err instanceof RenderError)) throw err;
      errors.push(err.message);
    }
  }
  return errors;
}

/** check, then every secret present (a client secret per confidential manifest too), every template rendered with
 *  the courier overrides merged over the defaults, no `${` left and the YAML well-formed. Writes nothing. */
export function render(policyDir: string, contentDir: string, env: Env): RenderedFile[] {
  const checkErrors = check(policyDir, contentDir, env);
  if (checkErrors.length > 0) throw new RenderError(checkErrors.join('\n'));
  const unset = [...SECRETS, ...clientSecretNames(contentDir)].filter((n) => (env[n] ?? '').trim() === '');
  if (unset.length > 0) throw new RenderError(`missing secret(s): ${unset.join(', ')}`);

  const files: RenderedFile[] = [];
  const errors: string[] = [];
  for (const { path, label, file } of sources(policyDir, contentDir)) {
    try {
      files.push({ path, content: renderTemplate(label, readFileSync(file, 'utf8'), env) });
    } catch (err) {
      if (!(err instanceof RenderError)) throw err;
      errors.push(err.message);
    }
  }
  for (const path of LITERALS) files.push({ path, content: readFileSync(join(policyDir, path), 'utf8') });
  for (const { path, content } of files) {
    if (content.includes('${')) errors.push(`${path}: \${ left in the rendered output`);
    if (TEMPLATES.includes(path)) {
      try {
        parse(content, { logLevel: 'error' });
      } catch {
        errors.push(`${path}: rendered output is not well-formed YAML`);
      }
    }
  }
  if (errors.length > 0) throw new RenderError(errors.join('\n'));
  return files;
}

/** Writes the rendered set under `outDir`, owner-only, replacing any earlier render of the same trees. */
export function writeRendered(outDir: string, files: RenderedFile[]): void {
  const previous = process.umask(0o077);
  try {
    for (const top of new Set(files.map(({ path }) => path.split('/')[0]))) {
      rmSync(join(outDir, top), { recursive: true, force: true });
    }
    for (const { path, content } of files) {
      const target = join(outDir, path);
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
      writeFileSync(target, content, { mode: 0o600 });
      chmodSync(target, 0o600);
    }
  } finally {
    process.umask(previous);
  }
}

/** Fresh values for every secret othala can mint, a client secret per confidential manifest under `contentDir`
 *  included, as `NAME=value` lines. */
export function generateSecrets(contentDir: string): string {
  const clients = Object.fromEntries(clientSecretNames(contentDir).map((name) => [name, CLIENT_SECRET_BYTES]));
  return Object.entries({ ...GENERATED, ...clients })
    .map(([name, bytes]) => `${name}=${randomBytes(bytes).toString('hex')}\n`)
    .join('');
}
