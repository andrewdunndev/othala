#!/usr/bin/env node
// `just claims`: every rust/*/CONTRACT.md test ref resolves, and every mutants floor a contract quotes is its crate's gates.json floor.
// usage: claims.mjs [--root RUST_DIR]
//
// A CONTRACT is a strict Markdown subset that this tool owns; what falls outside it fails rather than being guessed at.
// A ref is `prefix:value` outside the legend. The legend is the first `Checks:` line and the bullet or indented lines directly under it,
// up to the first blank line; nothing else is exempt. Every resolver prefix (and its `-pending` form) found in a body must be named in the
// legend, and a legend prefix with no resolver fails the run. A pending ref is `<prefix>-pending:value (reason)`: the reason is inline and has
// three or more words of two or more letters each, the target must not exist yet, and the run counts them. `<crate> unit:...` names the
// crate a ref lives in.
// Fences: an opener is 0-3 spaces then three or more backticks or tildes, except a backtick run followed by text holding a backtick
// (```x``` is not an opener); the closer is 0-3 spaces, the opener's character at least as many times, then only spaces or tabs. Lines
// inside are skipped, but one with an R, T or B id in its first five words fails (a fence never holds a claim), and an unterminated fence fails.
// Outside fences a line whose first non-whitespace character is `<` (an HTML block or comment) fails.
// Rust sources are read with comments and string literals blanked, so a commented-out test or a `proptest!` in a comment counts for nothing.
// unit/lib/it/store resolve in the exact module path given: a file for the longest `src/a/b.rs` prefix (lib.rs for none), then inline `mod`s.
// fuzz:t is a non-empty fuzz/fuzz_targets/t.rs with a committed file (not a dotfile) in fuzz/corpus/t and a test under tests/ whose string literal names fuzz/corpus/t.
// vec/oracle `#id` is an `id` field value in the JSON file, w3c `#s` a `section` field value; an oracle or w3c file also needs a string literal
// under the crate's tests/ that names it, so a vector no test reads proves nothing. oracle reads only the crate's own `<crate>-derived` family.
// row:f is tests/row_f.rs holding a test; mutants:m is src/m.rs (or src/m/mod.rs) holding a fn.
// api:Item and api-absent:Item read the crate's committed public-api.txt (and need a `just api` recipe). Its items are the path each line
// declares, generics dropped (`method Jws::parse fn(..)` declares Jws::parse); impl and attr lines declare none. api:Item resolves when
// Item equals a declared path, so a bare name must be a top-level item. api-absent:A::b resolves when A is declared and A::b is not;
// a bare api-absent:b resolves when no declared path ends in the segment b.
// A quoted floor is a line naming both `mutants` and `floor`: `crate N`, `crate: N`, `floor N`, `floor: N`, `floor = N`, `floor for crate is N`.
// A claim is a line that starts exactly `- <id> ` with an R, T or B id (`- R26b ...`). Any other line with an R, T or B id token (the letter
// not preceded by a letter, digit or `_`, then digits) in its first five whitespace-separated words fails as a claim form, unless it starts
// `- ` and an N, NC, P, O or W-S id (`- P3.7 `, `- W-S7:`); a table row (`|` first) is read only up to its second `|`. A legend line with
// such a token fails too. N, NC and P lines claim nothing, and an O line is proven by the owner it names, outside the crate. Each claim
// carries at least one proof token: a ref or pending ref as above, or a backticked `just <recipe>` naming a justfile recipe. A bare `api`
// is no proof, and naming another claim is no proof.
// Known limits: a claim or a floor split across two lines is not seen; the legend is the first `Checks:` block only; a pending reason is
// checked for shape, not sense.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const read = (p) => readFileSync(p, 'utf8');
const isDir = (p) => existsSync(p) && statSync(p).isDirectory();
const isFile = (p) => existsSync(p) && statSync(p).isFile();
const walk = (d, ext) => (isDir(d) ? readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name), ext) : e.name.endsWith(ext) ? [join(d, e.name)] : [])) : []);
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Rust source with comments (and, unless keepStrings, string and char contents) replaced by spaces, newlines kept
function scrub(src, keepStrings = false) {
    const o = src.split('');
    const n = src.length;
    const blank = (a, b) => {
        for (let k = a; k < b; k++) if (o[k] !== '\n') o[k] = ' ';
    };
    let i = 0;
    while (i < n) {
        const c = src[i];
        const d = src[i + 1];
        const prev = src[i - 1] ?? '';
        if (c === '/' && d === '/') {
            const j = src.indexOf('\n', i);
            const e = j < 0 ? n : j;
            blank(i, e);
            i = e;
        } else if (c === '/' && d === '*') {
            let depth = 1;
            let j = i + 2;
            while (j < n && depth) {
                if (src[j] === '/' && src[j + 1] === '*') (depth++, (j += 2));
                else if (src[j] === '*' && src[j + 1] === '/') (depth--, (j += 2));
                else j++;
            }
            blank(i, j);
            i = j;
        } else if (c === 'r' && /^r#*"/.test(src.slice(i, i + 40)) && (!/\w/.test(prev) || prev === 'b')) {
            const h = /^r(#*)"/.exec(src.slice(i, i + 40))[1].length;
            const end = `"${'#'.repeat(h)}`;
            const from = i + 2 + h;
            const j = src.indexOf(end, from);
            const e = j < 0 ? n : j;
            if (!keepStrings) blank(from, e);
            i = e + end.length;
        } else if (c === '"') {
            let j = i + 1;
            while (j < n && src[j] !== '"') j += src[j] === '\\' ? 2 : 1;
            if (!keepStrings) blank(i + 1, j);
            i = j + 1;
        } else if (c === "'") {
            if (d === '\\') {
                const j = src.indexOf("'", i + 3);
                const e = j < 0 ? n : j;
                if (!keepStrings) blank(i + 1, e);
                i = e + 1;
            } else if (src[i + 2] === "'") {
                if (!keepStrings) blank(i + 1, i + 2);
                i += 3;
            } else i++;
        } else i++;
    }
    return o.join('');
}
const cache = new Map();
const code = (p, keep = false) => {
    const k = `${keep}${p}`;
    if (!cache.has(k)) cache.set(k, scrub(read(p), keep));
    return cache.get(k);
};

const matchBrace = (s, open) => {
    let depth = 0;
    for (let i = open; i < s.length; i++) {
        if (s[i] === '{') depth++;
        else if (s[i] === '}' && --depth === 0) return i;
    }
    return s.length;
};
const ATTR = /#\[\s*(?:\w+::)*test(?:_case)?\b/;
const hasTestIn = (s, a = 0, b = s.length) => ATTR.test(s.slice(a, b)) || /\bproptest!/.test(s.slice(a, b));

// the [start, end) of `mod a { mod b { .. } }` nested in order inside range, or null
function locate(s, mods, range = [0, s.length]) {
    let [a, b] = range;
    for (const m of mods) {
        const re = new RegExp(`\\bmod\\s+${esc(m)}\\s*\\{`, 'g');
        re.lastIndex = a;
        const hit = re.exec(s);
        if (!hit || hit.index >= b) return null;
        a = hit.index + hit[0].length - 1;
        b = matchBrace(s, a);
    }
    return [a, b];
}

// a fn is a test when an attribute directly above it says so, or it sits inside a proptest! block
function isTestAt(s, idx, props) {
    const before = s.slice(0, idx).split('\n');
    if (ATTR.test(before.pop())) return true;
    for (let j = before.length - 1; j >= 0 && before.length - j <= 12; j--) {
        const l = before[j].trim();
        if (ATTR.test(l)) return true;
        if (l !== '' && !/^(#|\)|\]|[A-Za-z_]+\s*=|"|,)/.test(l)) break;
    }
    return props.some(([a, b]) => idx > a && idx < b);
}
function testIn(s, mods, t) {
    const range = locate(s, mods);
    if (!range) return `no mod ${mods.join('::')}`;
    const props = [...s.matchAll(/\bproptest!\s*\{/g)].map((m) => [m.index, matchBrace(s, m.index + m[0].length - 1)]);
    const re = new RegExp(`\\bfn\\s+${esc(t)}\\s*[<(]`, 'g');
    for (const m of s.slice(0, range[1]).matchAll(re)) if (m.index >= range[0] && isTestAt(s, m.index, props)) return 'ok';
    // a `mod t { .. }` that holds tests names all of them
    const inner = locate(s, [t], range);
    if (inner && hasTestIn(s, inner[0], inner[1])) return 'ok';
    return `no test fn ${t}${mods.length ? ` in mod ${mods.join('::')}` : ''}`;
}

const modFile = (dir, mods) => {
    const rel = mods.join('/');
    return [join(dir, 'src', `${rel}.rs`), join(dir, 'src', rel, 'mod.rs')].find(isFile);
};
function unit(c, v) {
    const parts = v.split('::');
    const t = parts.at(-1);
    const mods = parts.slice(0, -1);
    if (!mods.length) {
        const f = modFile(c.dir, [t]);
        return f && hasTestIn(code(f)) ? 'ok' : `no src/${t}.rs with tests`;
    }
    let k = mods.length;
    let file;
    for (; k >= 1 && !(file = modFile(c.dir, mods.slice(0, k))); k--);
    file ??= join(c.dir, 'src/lib.rs');
    if (!isFile(file)) return `no src file for module ${mods.join('::')}`;
    const r = testIn(code(file), mods.slice(k), t);
    return r === 'ok' ? r : `${r} (${file.slice(c.dir.length + 1)})`;
}
function testFile(dir, v, what) {
    const [f, ...rest] = v.split('::');
    const p = join(dir, `${f}.rs`);
    if (!isFile(p)) return `no ${what}/${f}.rs`;
    if (!rest.length) return 'ok';
    const r = testIn(code(p), rest.slice(0, -1), rest.at(-1));
    return r === 'ok' ? r : `${r} (${what}/${f}.rs)`;
}
const anyTest = (files, t) => (files.some((p) => testIn(code(p), [], t) === 'ok') ? 'ok' : `no test fn ${t}`);

// an object anywhere in the JSON with field key equal to id
const hasField = (j, key, id) => (Array.isArray(j) ? j.some((x) => hasField(x, key, id)) : j && typeof j === 'object' ? j[key] === id || Object.values(j).some((x) => hasField(x, key, id)) : false);
function vecIn(p, spec, key) {
    const [, id] = spec.split('#');
    if (id === undefined) return existsSync(p) ? 'ok' : `no ${spec}`;
    if (!isFile(p)) return `no file ${spec.split('#')[0]}`;
    let j;
    try {
        j = JSON.parse(read(p));
    } catch {
        return `${spec.split('#')[0]} is not JSON`;
    }
    return hasField(j, key, id) ? 'ok' : `no ${key} "${id}" in ${spec.split('#')[0]}`;
}
const expand = (v) => {
    const m = /\{([^{}]*)\}/.exec(v);
    return m ? m[1].split(',').flatMap((x) => expand(v.slice(0, m.index) + x + v.slice(m.index + m[0].length))) : [v];
};
const family = (c, v, dirs, key) => {
    const f = v.split('#')[0];
    const d = dirs.find((x) => existsSync(join(c.rust, 'vectors', x, f)));
    if (!d) return `no ${f} under vectors`;
    return readVec(c, `${d}/${v}`, key);
};
// `rel` (a path under vectors/, with an optional `#id`) holds the id and a string literal under the crate's tests/ names its file
function readVec(c, rel, key) {
    const [f] = rel.split('#');
    const r = vecIn(join(c.rust, 'vectors', f), rel, key);
    if (r !== 'ok') return r;
    const named = new RegExp(`"[^"]*\\b${esc(f)}"`);
    return walk(join(c.dir, 'tests'), '.rs').some((p) => named.test(code(p, true))) ? 'ok' : `no test under tests/ reads vectors/${f}`;
}

// the item paths a crate's public-api.txt declares, or the reason it cannot be read
const KINDS = new Set(['constant', 'enum', 'field', 'function', 'method', 'macro', 'module', 'static', 'struct', 'trait', 'trait_item', 'type_alias', 'union', 'variant']);
function apiItems(c) {
    const p = join(c.dir, 'public-api.txt');
    const crate = c.dir.slice(c.rust.length + 1);
    if (!isFile(p)) return `no rust/${crate}/public-api.txt`;
    if (!recipes(c.rust).has('api')) return 'no just recipe api';
    const k = `items ${p}`;
    if (!cache.has(k)) {
        const paths = [];
        for (const l of read(p).split('\n')) {
            const [kind, decl] = l.split(' ');
            if (!KINDS.has(kind) || !decl) continue;
            paths.push(decl.replace(/:$/, '').split('::').map((seg) => seg.replace(/<.*$/, '')).join('::'));
        }
        cache.set(k, paths);
    }
    return cache.get(k);
}
const parentOf = (v) => v.slice(0, v.lastIndexOf('::'));

// each resolver returns 'ok' or the reason the ref is dangling
const resolvers = {
    unit,
    lib: unit,
    it: (c, v) => testFile(join(c.dir, 'tests'), v, 'tests'),
    row: (c, v) => {
        const p = join(c.dir, 'tests', `row_${v}.rs`);
        if (!isFile(p)) return `no tests/row_${v}.rs`;
        return hasTestIn(code(p)) ? 'ok' : `tests/row_${v}.rs holds no test`;
    },
    ui: (c, v) => {
        const need = [`fail/${v}.rs`, `fail/${v}.stderr`, `pass/${v}.rs`].filter((f) => !isFile(join(c.dir, 'tests/ui', f)));
        return need.length ? `no tests/ui/${need.join(', tests/ui/')}` : 'ok';
    },
    prop: (c, v) => anyTest(walk(join(c.dir, 'tests'), '.rs'), v.split('::').at(-1)),
    race: (c, v) => anyTest(walk(join(c.dir, 'tests'), '.rs'), v.split('::').at(-1)),
    vec: (c, v) => {
        const bad = expand(v)
            .map((x) => {
                const [f] = x.split('#');
                if (f.endsWith('/*')) return isDir(join(c.rust, 'vectors', f.slice(0, -2))) && readdirSync(join(c.rust, 'vectors', f.slice(0, -2))).length ? 'ok' : `no vector family ${f}`;
                return vecIn(join(c.rust, 'vectors', f), x, 'id');
            })
            .filter((r) => r !== 'ok');
        return bad[0] ?? 'ok';
    },
    oracle: (c, v) => (existsSync(join(c.rust, 'vectors', v.split('#')[0])) ? readVec(c, v, 'id') : family(c, v, [`${c.dir.slice(c.rust.length + 1)}-derived`], 'id')),
    w3c: (c, v) => family(c, v, c.w3c, 'section'),
    fuzz: (c, v) => {
        const target = join(c.dir, 'fuzz', 'fuzz_targets', `${v}.rs`);
        if (!isFile(target)) return `no fuzz/fuzz_targets/${v}.rs`;
        if (!/\S/.test(code(target))) return `fuzz/fuzz_targets/${v}.rs is empty`;
        const corpus = join(c.dir, 'fuzz', 'corpus', v);
        if (!isDir(corpus) || !readdirSync(corpus).some((f) => !f.startsWith('.') && isFile(join(corpus, f)))) return `no committed corpus file in fuzz/corpus/${v}`;
        const replay = new RegExp(`"[^"]*\\bfuzz/corpus/${esc(v)}"`);
        return walk(join(c.dir, 'tests'), '.rs').some((f) => replay.test(code(f, true))) ? 'ok' : `no test under tests/ replays "fuzz/corpus/${v}"`;
    },
    mutants: (c, v) => {
        const f = modFile(c.dir, v.split('::'));
        if (!f) return `no src/${v.split('::').join('/')}.rs`;
        return /\bfn\s+[A-Za-z_]\w*/.test(code(f)) ? 'ok' : `${f.slice(c.dir.length + 1)} holds no fn`;
    },
    conf: (c, v) => {
        const p = join(c.rust, 'testkit/src/conformance.rs');
        return isFile(p) && new RegExp(`\\bname\\s*=\\s*"${esc(v)}"`).test(code(p, true)) ? 'ok' : `no conformance case "${v}" in testkit/src/conformance.rs`;
    },
    store: (c, v) => testFile(join(c.rust, 'store/tests'), v, 'store/tests'),
    wipe: (c, v) => (anyTest([...walk(join(c.rust, 'wipe/src'), '.rs'), ...walk(join(c.rust, 'wipe/tests'), '.rs')], v.split('::').at(-1)) === 'ok' ? 'ok' : `no test fn ${v} in wipe`),
    api: (c, v) => {
        const items = apiItems(c);
        return typeof items === 'string' ? items : items.includes(v) ? 'ok' : `no ${v.includes('::') ? 'item' : 'top-level item'} ${v} in ${c.dir.slice(c.rust.length + 1)}/public-api.txt`;
    },
    'api-absent': (c, v) => {
        const items = apiItems(c);
        if (typeof items === 'string') return items;
        const snap = `${c.dir.slice(c.rust.length + 1)}/public-api.txt`;
        if (v.includes('::') && !items.includes(parentOf(v))) return `no parent ${parentOf(v)} in ${snap}`;
        const hit = v.includes('::') ? items.includes(v) : items.some((x) => x.split('::').at(-1) === v);
        return hit ? `${snap} declares ${v}` : 'ok';
    },
    gate: (c, v) => (isFile(join(c.rust, 'justfile')) && new RegExp(`^${esc(v)}(\\s[^:=\\n]*)?:(?!=)`, 'm').test(read(join(c.rust, 'justfile'))) ? 'ok' : `no just recipe ${v}`),
};
const PREFIXES = Object.keys(resolvers).sort((a, b) => b.length - a.length);
const CLAIM = /^- ([RTB]\d+[a-z]?) /;
// a non-claim ledger entry, whose own id stands where a claim's would
const LEDGER = /^- (?:NC|N|P|O|W-S)\d+(?:\.\d+)*[a-z]?[ :]/;
// the first R, T or B id token among a line's first five whitespace-separated words; a table row (`|` first) is read up to its second `|`
const ID = /(?<![\p{L}\p{N}])[RTB]\d+[\p{L}\p{N}_]*/u;
const idNear = (l) =>
    (/^\s*\|/.test(l) ? l.replace(/^(\s*\|[^|]*).*$/, '$1') : l)
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 5)
        .map((w) => ID.exec(w)?.[0])
        .find(Boolean);
const JUST = /`just ([a-z_][a-z0-9_-]*)\b/g;
const recipes = (rust) => (isFile(join(rust, 'justfile')) ? new Set([...read(join(rust, 'justfile')).matchAll(/^@?([a-z_][a-z0-9_-]*)(?:\s+[*+$]?[a-z_][a-z0-9_-]*(?:=(?:"[^"\n]*"|'[^'\n]*'|[^\s:]+))?)*\s*:(?!=)/gm)].map((m) => m[1])) : new Set());
const NAME = '(?:[A-Za-z0-9_./*#:-]|\\{[^}\\s]*\\})+';

function check(rust) {
    cache.clear();
    const out = { failures: [], resolved: 0, pending: [], contracts: 0 };
    const crates = readdirSync(rust).filter((d) => isFile(join(rust, d, 'Cargo.toml')));
    const floor = {};
    for (const d of crates) {
        const g = join(rust, d, 'gates.json');
        floor[d] = isFile(g) ? JSON.parse(read(g))?.mutants?.floor : undefined;
    }
    const withFloor = Object.keys(floor).filter((d) => typeof floor[d] === 'number');
    const vdirs = (re) => (isDir(join(rust, 'vectors')) ? readdirSync(join(rust, 'vectors')).filter((d) => re.test(d)) : []);
    const refRe = new RegExp(`(?<![\\w-])(${PREFIXES.flatMap((p) => [`${esc(p)}-pending`, esc(p)]).join('|')}):(?!:)(${NAME})`, 'g');
    for (const d of crates.filter((d) => isFile(join(rust, d, 'CONTRACT.md')))) {
        out.contracts++;
        const file = `rust/${d}/CONTRACT.md`;
        const lines = read(join(rust, d, 'CONTRACT.md')).split('\n');
        const fail = (i, what, why) => out.failures.push(`${file}:${i + 1}: ${what}: ${why}`);
        // the legend: the first Checks line and the bullet or indented lines directly under it
        const start = lines.findIndex((l) => /^Checks:/.test(l));
        const legend = new Set();
        if (start < 0) fail(0, 'legend', 'no `Checks:` line');
        else {
            legend.add(start);
            for (let i = start + 1; i < lines.length && /^(- |\s+\S)/.test(lines[i]); i++) legend.add(i);
        }
        for (const i of legend) if (idNear(lines[i])) fail(i, idNear(lines[i]), 'a claim inside the `Checks:` legend is never checked; end the legend with a blank line first');
        const defined = new Set();
        for (const i of legend) for (const m of lines[i].matchAll(/`([a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)*):(?!:)/g)) defined.add(m[1]);
        for (const p of defined) if (!resolvers[p.replace(/-pending$/, '')]) fail(start, `legend prefix ${p}:`, 'the claims tool has no resolver for it');
        const ctx = { dir: join(rust, d), rust, w3c: vdirs(/^w3c-/) };
        const known = recipes(rust);
        let fence = null;
        const seen = new Set();
        lines.forEach((line, i) => {
            if (fence) {
                const close = /^ {0,3}(`{3,}|~{3,})[ \t]*$/.exec(line);
                if (close && close[1][0] === fence.ch && close[1].length >= fence.len) fence = null;
                else if (idNear(line)) fail(i, idNear(line), 'claim inside a fence: a fence never holds a claim');
                return;
            }
            if (/^\s*</.test(line)) {
                fail(i, 'html', 'html is outside the ledger subset');
                return;
            }
            const open = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
            if (open && !(open[1][0] === '`' && open[2].includes('`'))) {
                fence = { ch: open[1][0], len: open[1].length, at: i };
                return;
            }
            if (legend.has(i)) return;
            const claim = CLAIM.exec(line)?.[1];
            const near = claim || LEDGER.test(line) ? null : idNear(line);
            if (near) fail(i, near, 'claim form: a claim is exactly `- <id> <text>`, and no other line has an R, T or B id in its first five words');
            let proofs = 0;
            for (const m of line.matchAll(JUST)) {
                proofs++;
                if (!known.has(m[1])) fail(i, `just ${m[1]}`, `no just recipe ${m[1]}`);
            }
            for (const m of line.matchAll(refRe)) {
                proofs++;
                const [kind, raw] = [m[1], m[2].replace(/[.:,;]+$/, '')];
                const base = kind.replace(/-pending$/, '');
                if (!defined.has(kind)) {
                    fail(i, `${kind}:${raw}`, 'the prefix is not defined in the legend');
                    continue;
                }
                const q = /([a-z][a-z0-9-]*) $/.exec(line.slice(0, m.index))?.[1];
                const cc = q && crates.includes(q) ? { ...ctx, dir: join(rust, q) } : ctx;
                const res = resolvers[base](cc, raw);
                const key = `${q ?? ''} ${kind}:${raw}`;
                if (kind.endsWith('-pending')) {
                    const after = line.slice(m.index + m[0].length - (m[2].length - raw.length));
                    if (!seen.has(key)) out.pending.push(`${file}:${i + 1}: ${kind}:${raw}`);
                    const why = /^\s*\(([^)]*)\)/.exec(after)?.[1];
                    const words = (why ?? '').split(/\s+/).filter((w) => (w.match(/\p{L}/gu) ?? []).length >= 2);
                    if (words.length < 3) fail(i, `${kind}:${raw}`, 'no inline reason of three or more words of two or more letters each, write `(reason)` after it');
                    else if (res === 'ok') fail(i, `${kind}:${raw}`, `its target exists, retag it ${base}:`);
                } else if (res !== 'ok') fail(i, `${kind}:${raw}`, res);
                else if (!seen.has(key)) out.resolved++;
                seen.add(key);
            }
            if (claim && !proofs) fail(i, claim, 'the claim names no proof: add a ref (`api:<Item>`, `api-absent:<Item>`, ...), `just <recipe>` or `<prefix>-pending:<target> (reason)`');
            // a quoted mutants floor
            if (/mutants/i.test(line) && /floor/i.test(line)) {
                const quoted = [];
                const used = [];
                const names = withFloor.map(esc).join('|');
                if (names) {
                    for (const m of line.matchAll(new RegExp(`(?<![\\w-])(${names})(?:'s)?:?\\s+(\\d+)\\b`, 'g'))) {
                        quoted.push([m[1], +m[2]]);
                        used.push([m.index, m.index + m[0].length]);
                    }
                }
                // a number belongs to the crate its own sentence names, else to the contract's crate
                const sentences = [...line.matchAll(/.+?(?:[.;](?=\s|$)|$)/g)].map((x) => [x.index, x.index + x[0].length, x[0]]);
                const mentionedAt = (idx) => {
                    const seg = sentences.find(([a, b]) => idx >= a && idx < b)?.[2] ?? line;
                    return withFloor.filter((n) => new RegExp(`(?<![\\w-])${esc(n)}\\b`).test(seg));
                };
                for (const m of line.matchAll(/\bfloors?\b(?:\s+for\s+([a-z][a-z0-9-]*))?\s*(?:is|of|at|=|:|reaches|equals)?\s*(\d+)\b/gi)) {
                    if (used.some(([a, b]) => m.index < b && m.index + m[0].length > a)) continue;
                    const mentioned = mentionedAt(m.index);
                    const c = m[1] ?? (mentioned.length === 1 ? mentioned[0] : mentioned.length === 0 ? d : null);
                    if (c === null) fail(i, `floor ${m[2]}`, 'it names several crates, write `crate N`');
                    else quoted.push([c, +m[2]]);
                }
                for (const [c, n] of quoted) {
                    if (typeof floor[c] !== 'number') fail(i, `floor ${c} ${n}`, `${c} has no mutants floor in gates.json`);
                    else if (floor[c] !== n) fail(i, `floor ${c} ${n}`, `rust/${c}/gates.json says ${floor[c]}`);
                }
            }
        });
        if (fence) fail(fence.at, 'fence', `an unterminated ${fence.ch.repeat(fence.len)} fence hides every line after it`);
    }
    return out;
}

function report(rust) {
    const r = check(rust);
    for (const f of r.failures) console.log(f);
    console.log(`claims: ${r.contracts} contracts, ${r.resolved} refs resolved, ${r.pending.length} pending, ${r.failures.length} failures`);
    for (const p of r.pending) console.log(`  pending ${p}`);
    return r.failures.length ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const a = process.argv.slice(2);
    const i = a.indexOf('--root');
    process.exit(report(resolve(i >= 0 ? a[i + 1] : join(dirname(fileURLToPath(import.meta.url)), '..'))));
}
