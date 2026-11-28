#!/usr/bin/env node
// `just layers`: each crate with a layers.json keeps its modules in the layers that file lists, lowest first, and no module imports
// from a layer above its own, so no import cycle between modules can exist. A module is one src file; the crate root (lib.rs) holds only
// re-exports and constants, which every module may name. Within one layer imports are free but must not form a cycle (a strongly
// connected set of modules fails). The modules on disk and the modules in the file must be the same set, so a new module is placed on purpose.
// What is read: code with comments and string and char literals blanked; `#[cfg(test)]` items are blanked (the attribute, then the item or
// block it annotates), since a test may import any module. Imports are `use` trees and inline paths rooted at `crate::`, `super::` (one
// module up per `super`, counted from the file's module, less the inline `mod` blocks enclosing the path) and `self::`, plus names a file
// brought in as a module namespace (`use crate::jwe;` then `jwe::envelope::X`). A path resolves through lib.rs's `pub use` lines (aliases
// kept) to the module that defines the item, else to the longest file module it names; a path that is neither a file module, a lib.rs
// item nor a namespace is an error, never skipped.
// usage: layers.mjs [--root RUST_DIR] [CRATE...]   (default: every crate with a layers.json)
//        layers.mjs --self-test   plants each form of bad import in a copy of jose and requires its exact message
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(p, 'utf8');

// comments, string literals and char literals blanked (newlines kept), so nothing in them is read as code
function blank(s) {
  let out = '';
  let i = 0;
  const pad = (t) => t.replace(/[^\n]/g, ' ');
  while (i < s.length) {
    const rest = s.slice(i, i + 3);
    if (rest.startsWith('//')) {
      const e = s.indexOf('\n', i);
      const end = e < 0 ? s.length : e;
      out += pad(s.slice(i, end));
      i = end;
    } else if (rest.startsWith('/*')) {
      let depth = 0;
      let j = i;
      do {
        if (s.startsWith('/*', j)) { depth++; j += 2; }
        else if (s.startsWith('*/', j)) { depth--; j += 2; }
        else j++;
      } while (depth > 0 && j < s.length);
      out += pad(s.slice(i, j));
      i = j;
    } else if (/^b?r#*"/.test(s.slice(i, i + 12)) && !/[\w]/.test(s[i - 1] ?? ' ')) {
      const m = /^b?r(#*)"/.exec(s.slice(i, i + 12));
      const close = `"${m[1]}`;
      const e = s.indexOf(close, i + m[0].length);
      const end = e < 0 ? s.length : e + close.length;
      out += pad(s.slice(i, end));
      i = end;
    } else if (s[i] === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') j += s[j] === '\\' ? 2 : 1;
      out += pad(s.slice(i, j + 1));
      i = j + 1;
    } else if (s[i] === "'") {
      const m = /^'(\\u\{[0-9a-fA-F_]+\}|\\.|[^'\\\n])'/.exec(s.slice(i, i + 14));
      if (m) { out += pad(m[0]); i += m[0].length; } // a char literal; otherwise a lifetime, kept
      else { out += s[i]; i++; }
    } else { out += s[i]; i++; }
  }
  return out;
}

// the index just past the `}` closing the `{` at `open`
function closing(s, open) {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === '{') depth++;
    else if (s[i] === '}' && --depth === 0) return i + 1;
  }
  return s.length;
}

// `#[cfg(test)]` and the item it annotates (to its `;` or its brace block), blanked
function withoutTests(s) {
  const attr = /#\[cfg\(test\)\]/g;
  let m;
  const spans = [];
  let from = 0;
  while ((m = attr.exec(s))) {
    if (m.index < from) continue;
    let i = m.index + m[0].length;
    let depth = 0;
    let end = s.length;
    for (; i < s.length; i++) {
      const c = s[i];
      if (c === '(' || c === '[') depth++;
      else if (c === ')' || c === ']') depth--;
      else if (depth === 0 && c === ';') { end = i + 1; break; }
      else if (depth === 0 && c === '{') { end = closing(s, i); break; }
    }
    spans.push([m.index, end]);
    from = end;
  }
  let out = s;
  for (const [a, b] of spans) out = out.slice(0, a) + out.slice(a, b).replace(/[^\n]/g, ' ') + out.slice(b);
  return out;
}

// the contents of every brace block blanked: what is declared at the top level of a file
function topLevel(s) {
  let out = '';
  let depth = 0;
  for (const c of s) {
    if (c === '}') depth--;
    out += depth > 0 && c !== '\n' ? ' ' : c;
    if (c === '{') depth++;
  }
  return out;
}

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

// `a::{b, c::d as e, self}` as its leaves: { path, as }
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
        if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch;
      }
      parts.push(cur);
      for (const p of parts) if (p.trim()) walk(prefix, p);
      return;
    }
    const m = /^(\w+)\s*::\s*([\s\S]*)$/.exec(t);
    if (m) { walk([...prefix, m[1]], m[2]); return; }
    const [name, alias] = t.split(/\s+as\s+/).map((x) => x.trim());
    out.push({ path: name === 'self' || name === '*' ? prefix : [...prefix, name], as: alias ?? (name === 'self' ? prefix[prefix.length - 1] : name) });
  };
  walk([], tree);
  return out;
}

function check(crate, root) {
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

  const fileModule = (path) => {
    for (let n = path.length; n > 0; n--) if (files.has(path.slice(0, n).join('::'))) return path.slice(0, n).join('::');
    return null;
  };
  const namespaces = new Set();
  for (const m of files.keys()) {
    const p = m.split('::');
    for (let n = 1; n < p.length; n++) namespaces.add(p.slice(0, n).join('::'));
  }
  // lib.rs: every name it re-exports (alias kept) with the module that defines it, and the items it declares itself
  const lib = withoutTests(blank(read(join(dir, 'src', 'lib.rs'))));
  const defined = new Map();
  for (const u of lib.matchAll(/\bpub(?:\([^)]*\))?\s+use\s+([^;]*);/g)) {
    for (const leaf of leaves(u[1])) {
      const path = leaf.path[0] === 'crate' ? leaf.path.slice(1) : leaf.path;
      const mod = fileModule(path);
      if (mod === null) errors.push(`${crate}: lib.rs re-exports ${path.join('::')}, which is in no module`);
      else defined.set(leaf.as, mod);
    }
  }
  const rootItems = new Set();
  for (const m of topLevel(lib).matchAll(/\b(?:const|static|fn|struct|enum|type|trait|union)\s+(\w+)|\bmacro_rules!\s*(\w+)/g)) rootItems.add(m[1] ?? m[2]);

  // an absolute path (from the crate root) to a module name, or { ns } for a bare namespace, or { root } for a root item
  const resolveAbs = (p) => {
    if (p.length === 0) return { root: true };
    if (defined.has(p[0])) return { mod: defined.get(p[0]) };
    const mod = fileModule(p);
    if (mod !== null) return { mod };
    if (namespaces.has(p.join('::'))) return { ns: p.join('::') };
    if (rootItems.has(p[0])) return { root: true };
    throw new Error(`unresolved path crate::${p.join('::')}`);
  };

  const edges = new Map();
  for (const [mod, file] of files) {
    const me = mod.split('::');
    const text = withoutTests(blank(read(file)));
    const inlineMods = [];
    for (const m of text.matchAll(/\bmod\s+\w+\s*\{/g)) inlineMods.push([m.index, closing(text, m.index + m[0].length - 1)]);
    const depthAt = (pos) => inlineMods.filter(([a, b]) => a <= pos && pos < b).length;
    const deps = new Set();
    const names = new Map(); // names this file brought in as module namespaces
    const add = (path, where, text0) => {
      try {
        const r = resolveAbs(path);
        if (r.mod && r.mod !== mod) deps.add(r.mod);
        return r;
      } catch (e) {
        errors.push(`${crate}: ${mod}: ${e.message.replace(/crate::[\w:]*/, text0)} (${where})`);
        return {};
      }
    };
    // an `anchor::rest` path read at `pos`: anchor is crate, self, super(::super)* or a namespace name this file imported
    const absolute = (anchor, rest, pos) => {
      if (anchor === 'crate') return rest;
      if (names.has(anchor)) return [...names.get(anchor).split('::'), ...rest];
      const supers = anchor === 'self' ? 0 : anchor.split('::').length;
      const d = depthAt(pos);
      if (supers <= d) return null; // a path inside this file's own inline modules
      const up = supers - d;
      if (up > me.length) return undefined; // above the crate root
      return [...me.slice(0, me.length - up), ...rest];
    };
    const anchorOf = (first) => (['crate', 'self'].includes(first) || first === 'super' ? first : names.has(first) ? first : null);
    const stmts = [...text.matchAll(/\buse\s+([^;]*);/g)];
    // pass one: the `use` trees rooted at crate, super or self (they fill `names`); pass two: those rooted at an imported namespace
    for (const pass of [1, 2]) {
      for (const u of stmts) {
        for (const leaf of leaves(u[1])) {
          const p = leaf.path;
          const isNs = names.has(p[0]);
          if ((pass === 1) === isNs) continue;
          if (pass === 1 && !['crate', 'super', 'self'].includes(p[0])) continue;
          let k = 1;
          let anchor = p[0];
          while (anchor.startsWith('super') && p[k] === 'super') { anchor += '::super'; k++; }
          const abs = absolute(anchor, p.slice(k), u.index);
          if (abs === null || abs === undefined) { if (abs === undefined) errors.push(`${crate}: ${mod}: ${p.join('::')} climbs above the crate root`); continue; }
          const r = add(abs, 'use', `crate::${abs.join('::')}`);
          if (r.ns) names.set(leaf.as, r.ns);
        }
      }
    }
    // inline paths: the use statements blanked, then every `anchor::path`
    const rest = text.replace(/\buse\s+[^;]*;/g, (s) => s.replace(/[^\n]/g, ' '));
    const inline = new RegExp(`(?<![\\w:])(crate|self|super(?:::super)*${[...names.keys()].map((n) => `|${n}`).join('')})::((?:\\w+::)*\\w+)`, 'g');
    for (const m of rest.matchAll(inline)) {
      const abs = absolute(m[1], m[2].split('::'), m.index);
      if (abs === null) continue;
      if (abs === undefined) { errors.push(`${crate}: ${mod}: ${m[0]} climbs above the crate root`); continue; }
      add(abs, 'inline', `crate::${abs.join('::')}`);
    }
    edges.set(mod, [...deps].sort());
  }
  const level = (m) => `layer ${layerOf.get(m)} ${table.layers[layerOf.get(m)].name}`;
  for (const [mod, deps] of edges) {
    for (const d of deps) {
      if (layerOf.has(mod) && layerOf.has(d) && layerOf.get(d) > layerOf.get(mod)) {
        errors.push(`${crate}: ${mod} (${level(mod)}) imports ${d} (${level(d)}), above it`);
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
      if (!index.has(w)) { visit(w); low.set(v, Math.min(low.get(v), low.get(w))); }
      else if (open.has(w)) low.set(v, Math.min(low.get(v), index.get(w)));
    }
    if (low.get(v) === index.get(v)) {
      const set = [];
      let w;
      do { w = stack.pop(); open.delete(w); set.push(w); } while (w !== v);
      if (set.length > 1) errors.push(`${crate}: import cycle among ${set.sort().join(', ')}`);
    }
  };
  for (const v of edges.keys()) if (!index.has(v)) visit(v);
  const total = [...edges.values()].reduce((n, d) => n + d.length, 0);
  if (files.size < 10 || total < 20) errors.push(`${crate}: read ${files.size} modules and ${total} imports; a parse that matched nothing proves nothing`);
  return { errors, summary: `${crate}: ${files.size} modules in ${table.layers.length} layers, ${total} imports, none upward, no cycle` };
}

// each seed is one bad input in a copy of jose and the exact error it must draw; the clean copy must draw none
const seeds = [
  ['super:: reaching up a layer', (s) => appendFileSync(join(s, 'jwe/kw.rs'), 'use super::envelope::Jwe;\n'),
    'jose: jwe::kw (layer 3 implementations) imports jwe::envelope (layer 5 formats), above it'],
  ['super::super:: reaching up a layer', (s) => appendFileSync(join(s, 'sig/hmac.rs'), 'use super::super::jwt::Jwt;\n'),
    'jose: sig::hmac (layer 3 implementations) imports jwt (layer 6 tokens), above it'],
  ['inline-mod namespace import', (s) => appendFileSync(join(s, 'alg.rs'), 'use crate::jwe;\nfn zz(_: jwe::envelope::Jwe<\'static>) {}\n'),
    'jose: alg (layer 2 algorithms) imports jwe::envelope (layer 5 formats), above it'],
  ['re-export under an alias', (s) => { appendFileSync(join(s, 'lib.rs'), 'pub use jwt::Jwt as Token;\n'); appendFileSync(join(s, 'alg.rs'), 'use crate::Token;\n'); },
    'jose: alg (layer 2 algorithms) imports jwt (layer 6 tokens), above it'],
  ['production code after an inner cfg(test)', (s) => appendFileSync(join(s, 'error.rs'), '#[cfg(test)]\nmod t { fn f() {} }\nuse crate::jwt::Jwt;\n'),
    'jose: error (layer 0 base) imports jwt (layer 6 tokens), above it'],
  ['inline crate:: path with no use', (s) => appendFileSync(join(s, 'error.rs'), 'fn zz() { let _ = crate::Jwk::kty; }\n'),
    'jose: error (layer 0 base) imports jwk::decode (layer 4 jwk), above it'],
  ['crate:: path after a url string on its line', (s) => appendFileSync(join(s, 'error.rs'), 'fn zz() { let _u = "https://x"; let _ = crate::Jwk::kty; }\n'),
    'jose: error (layer 0 base) imports jwk::decode (layer 4 jwk), above it'],
  ['cycle inside one layer', (s) => appendFileSync(join(s, 'jwk/decode.rs'), 'use crate::jwk::thumbprint::members as m;\n'),
    'jose: import cycle among jwk::decode, jwk::thumbprint'],
  ['module in no layer', (s) => writeFileSync(join(s, 'extra.rs'), '\n'),
    'jose: module extra is on disk and in no layer of layers.json'],
  ['crate:: path that resolves to nothing', (s) => appendFileSync(join(s, 'error.rs'), 'use crate::nonesuch::Thing;\n'),
    'jose: error: unresolved path crate::nonesuch::Thing (use)'],
];

function selfTest() {
  const scratch = mkdtempSync(join(tmpdir(), 'layers-self-'));
  let failed = false;
  try {
    const fresh = (name) => {
      const root = join(scratch, name);
      cpSync(join(here, '..', 'jose', 'src'), join(root, 'jose', 'src'), { recursive: true });
      cpSync(join(here, '..', 'jose', 'layers.json'), join(root, 'jose', 'layers.json'));
      return root;
    };
    const clean = check('jose', fresh('clean')).errors;
    if (clean.length) { failed = true; console.error(`layers self-test: the clean copy fails: ${clean.join('; ')}`); }
    seeds.forEach(([name, plant, want], i) => {
      const root = fresh(`seed${i}`);
      plant(join(root, 'jose', 'src'));
      const got = check('jose', root).errors;
      if (!got.includes(want)) {
        failed = true;
        console.error(`layers self-test: seed "${name}" did not draw "${want}"; got: ${got.join('; ') || 'nothing'}`);
      }
    });
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  if (!failed) console.log(`layers self-test: the clean copy passes and ${seeds.length} planted bad inputs each draw their exact error`);
  return failed;
}

const args = process.argv.slice(2);
if (args[0] === '--self-test') process.exit(selfTest() ? 1 : 0);
let root = resolve(here, '..');
if (args[0] === '--root') {
  root = resolve(args[1]);
  args.splice(0, 2);
}
const crates = args.length ? args : readdirSync(root).filter((d) => existsSync(join(root, d, 'layers.json')));
if (!crates.length) {
  console.error('layers: no crate has a layers.json');
  process.exit(1);
}
let failed = false;
for (const c of crates) {
  const { errors, summary } = check(c, root);
  if (errors.length) {
    failed = true;
    for (const e of errors) console.error(`layers: ${e}`);
  } else console.log(`layers: ${summary}`);
}
process.exit(failed ? 1 : 0);
