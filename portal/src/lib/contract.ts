import Ajv2020 from 'ajv/dist/2020.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';

export const IDENTITY = 'kratos/identity.schema.json';
export const JSONNET = 'kratos/hooks/recovery-gate.jsonnet';

/** One parse for rendered and given Ory YAML, so both read merge keys alike. */
export const parseOryYaml = (text: string): unknown => parse(text, { merge: true, logLevel: 'error' });

export type OryFiles = { kratos: string; hydra: string; identitySchema: string; jsonnet: string };

const read = (path: string): string | null => {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
};

/** Key order and whitespace are not policy. */
function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, x]) => [k, canonical(x)]));
  return v;
}

const sameJson = (a: string, b: string): boolean => JSON.stringify(canonical(JSON.parse(a))) === JSON.stringify(canonical(JSON.parse(b)));
const lf = (t: string): string => t.replace(/\r\n/g, '\n').trimEnd();
const sameText = (a: string, b: string): boolean => lf(a) === lf(b);

/** Each violation names a file, a JSON pointer and a rule, never a value: the files hold secrets. */
export function checkOry(policyDir: string, files: OryFiles): string[] {
  const ajv = new Ajv2020({ allErrors: true });
  const violations: string[] = [];
  for (const [name, path] of [['kratos', files.kratos], ['hydra', files.hydra]]) {
    const text = read(path);
    const schema = read(join(policyDir, 'contract', `${name}.schema.json`));
    if (text === null || schema === null) {
      violations.push(`${name}: unreadable ${text === null ? 'config' : 'contract'}`);
      continue;
    }
    let doc: unknown;
    try {
      doc = parseOryYaml(text);
    } catch {
      violations.push(`${name}: not well-formed YAML`);
      continue;
    }
    const validate = ajv.compile(JSON.parse(schema));
    if (!validate(doc)) {
      for (const e of validate.errors ?? []) {
        const missing = e.keyword === 'required' ? `/${e.params.missingProperty}` : '';
        violations.push(`${name}: ${e.instancePath}${missing} violates ${e.keyword}`);
      }
    }
  }
  const policy: [string, string, string, (a: string, b: string) => boolean][] = [
    ['identity schema', files.identitySchema, IDENTITY, sameJson],
    ['recovery-gate jsonnet', files.jsonnet, JSONNET, sameText],
  ];
  for (const [label, given, rel, same] of policy) {
    const mine = read(given);
    const image = read(join(policyDir, rel));
    try {
      if (mine === null || image === null || !same(mine, image)) violations.push(`${label}: differs from the image's ${rel}`);
    } catch {
      violations.push(`${label}: differs from the image's ${rel}`);
    }
  }
  return violations;
}
