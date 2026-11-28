#!/usr/bin/env node
// `just layers`: each crate with a layers.json keeps its modules in the layers that file lists, lowest first, and no module imports
// from a layer above its own, so no import cycle between modules can exist. A module is one src file; the crate root (lib.rs) holds only
// re-exports and constants, which every module may name. `#[cfg(test)]` code, from the first such attribute of a file to its end, is not
// read: a test may import any module. A path is resolved through lib.rs's `pub use` lines to the module that defines the item, so
// `crate::Kid` is an import of jwk::decode. Within one layer imports are free but must not form a cycle (a strongly connected set of
// modules fails). The modules on disk and the modules in the file must be the same set, so a new module is placed on purpose.
// usage: layers.mjs [--root RUST_DIR] [CRATE...]   (default: every crate with a layers.json)
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
let root = resolve(here, '..');
if (args[0] === '--root') {
  root = resolve(args[1]);
  args.splice(0, 2);
}

const read = (p) => readFileSync(p, 'utf8');
// comments blanked; string literals are left alone (a `crate::` in one would be a false edge, and none exists)
const bare = (s) => s.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, '');
const productionPart = (s) => {
  const at = s.search(/^[ \t]*#\[cfg\(test\)\]/m);
  return at < 0 ? s : s.slice(0, at);
};

function sourceModules(src, prefix = []) {
  const found = new Map();
  for (const name of readdirSync(src).sort()) {
    const path = join(src, name);
    if (statSync(path).isDirectory()) {
      for (const [m, p] of sourceModules(path, [...prefix, name])) found.set(m, p);
    } else if (name.endsWith('.rs') && !(prefix.length === 0 && name === 'lib.rs')) {
      const stem = name.slice(0, -3);
      found.set(stem === 'mod' ? prefix.join('::') : [...prefix, stem].join('::'), path);
    }
  }
  return found;
}

// `a::{b, c::d}` as the list of its leaf paths
function leaves(tree) {
  const out = [];
  const walk = (prefix, t) => {
    t = t.trim();
    if (t.startsWith('{')) {
      let depth = 0;
      let cur = '';
      const parts = [];
      for (const ch of t.slice(1, t.lastIndexOf('}'))) {
        if (ch === '{') depth++;
        if (ch === '}') depth--;
        if (ch === ',' && depth === 0) {
          parts.push(cur);
          cur = '';
        } else cur += ch;
      }
      parts.push(cur);
      for (const p of parts) if (p.trim()) walk(prefix, p);
      return;
    }
    const m = /^(\w+)\s*::\s*([\s\S]*)$/.exec(t);
    if (m) walk([...prefix, m[1]], m[2]);
    else out.push([...prefix, t.split(/\s+as\s+/)[0].trim()]);
  };
  walk([], tree);
  return out;
}

// every name lib.rs re-exports, with the module that defines it
function reexports(lib) {
  const names = new Map();
  for (const m of bare(lib).matchAll(/pub use ([\w:]+?)::(\{[^}]*\}|\w+);/g)) {
    const list = m[2].startsWith('{') ? m[2].match(/\w+/g) : [m[2]];
    for (const n of list) names.set(n, m[1]);
  }
  return names;
}

function check(crate) {
  const dir = join(root, crate);
  const table = JSON.parse(read(join(dir, 'layers.json')));
  const layerOf = new Map();
  const errors = [];
  table.layers.forEach((l, i) =>
    l.modules.forEach((m) => {
      if (layerOf.has(m)) errors.push(`${crate}: module ${m} is in two layers`);
      layerOf.set(m, i);
    }),
  );
  const files = sourceModules(join(dir, 'src'));
  for (const m of files.keys()) if (!layerOf.has(m)) errors.push(`${crate}: module ${m} is on disk and in no layer of layers.json`);
  for (const m of layerOf.keys()) if (!files.has(m)) errors.push(`${crate}: layers.json lists ${m}, which is not a module`);
  const defined = reexports(read(join(dir, 'src', 'lib.rs')));
  const resolveTo = (path) => {
    if (defined.has(path[0])) return defined.get(path[0]);
    for (let n = path.length; n > 0; n--) if (files.has(path.slice(0, n).join('::'))) return path.slice(0, n).join('::');
    return null; // a constant of the crate root
  };
  const edges = new Map();
  for (const [mod, file] of files) {
    const text = productionPart(bare(read(file)));
    const deps = new Set();
    const uses = [...text.matchAll(/\buse\s+crate::([^;]*);/g)];
    for (const u of uses) for (const p of leaves(u[1])) deps.add(resolveTo(p));
    const rest = text.replace(/\buse\s+crate::[^;]*;/g, '');
    for (const m of rest.matchAll(/(?<![\w:])crate::((?:\w+::)*\w+)/g)) deps.add(resolveTo(m[1].split('::')));
    deps.delete(null);
    deps.delete(mod);
    edges.set(mod, [...deps].sort());
  }
  for (const [mod, deps] of edges) {
    for (const d of deps) {
      if (layerOf.has(mod) && layerOf.has(d) && layerOf.get(d) > layerOf.get(mod)) {
        errors.push(
          `${crate}: ${mod} (layer ${layerOf.get(mod)} ${table.layers[layerOf.get(mod)].name}) imports ${d} (layer ${layerOf.get(d)} ${table.layers[layerOf.get(d)].name}), above it`,
        );
      }
    }
  }
  // a cycle inside one layer: Tarjan's strongly connected sets
  let counter = 0;
  const index = new Map();
  const low = new Map();
  const stack = [];
  const open = new Set();
  const visit = (v) => {
    index.set(v, counter);
    low.set(v, counter++);
    stack.push(v);
    open.add(v);
    for (const w of edges.get(v) ?? []) {
      if (!index.has(w)) {
        visit(w);
        low.set(v, Math.min(low.get(v), low.get(w)));
      } else if (open.has(w)) low.set(v, Math.min(low.get(v), index.get(w)));
    }
    if (low.get(v) === index.get(v)) {
      const set = [];
      let w;
      do {
        w = stack.pop();
        open.delete(w);
        set.push(w);
      } while (w !== v);
      if (set.length > 1) errors.push(`${crate}: import cycle among ${set.sort().join(', ')}`);
    }
  };
  for (const v of edges.keys()) if (!index.has(v)) visit(v);
  const total = [...edges.values()].reduce((n, d) => n + d.length, 0);
  if (files.size < 10 || total < 20) errors.push(`${crate}: read ${files.size} modules and ${total} imports; a parse that matched nothing proves nothing`);
  return { errors, summary: `${crate}: ${files.size} modules in ${table.layers.length} layers, ${total} imports, none upward, no cycle` };
}

const crates = args.length ? args : readdirSync(root).filter((d) => existsSync(join(root, d, 'layers.json')));
if (!crates.length) {
  console.error('layers: no crate has a layers.json');
  process.exit(1);
}
let failed = false;
for (const c of crates) {
  const { errors, summary } = check(c);
  if (errors.length) {
    failed = true;
    for (const e of errors) console.error(`layers: ${e}`);
  } else console.log(`layers: ${summary}`);
}
process.exit(failed ? 1 : 0);
