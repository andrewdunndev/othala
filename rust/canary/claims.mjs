#!/usr/bin/env node
// `just claims`: every rust/*/CONTRACT.md test ref resolves, and every mutants floor a contract quotes is its crate's gates.json floor.
// usage: claims.mjs [--root RUST_DIR] | --selftest
//
// A ref is `prefix:value` outside the legend. The legend is the first `Checks:` line and the bullet or indented lines directly under it,
// up to the first blank line; nothing else is exempt, and fenced code is skipped. Every resolver prefix (and its `-pending` form) found in
// a body must be named in the legend, and a legend prefix with no resolver fails the run. A pending ref is `<prefix>-pending:value (reason)`:
// the reason is inline and non-empty, the target must not exist yet, and the run counts them. `<crate> unit:...` names the crate a ref lives in.
// Rust sources are read with comments and string literals blanked, so a commented-out test or a `proptest!` in a comment counts for nothing.
// unit/lib/it/store resolve in the exact module path given: a file for the longest `src/a/b.rs` prefix (lib.rs for none), then inline `mod`s.
// vec/oracle `#id` is an `id` field value in the JSON file, w3c `#s` a `section` field value.
// A quoted floor is a line naming both `mutants` and `floor`: `crate N`, `crate: N`, `floor N`, `floor: N`, `floor = N`, `floor for crate is N`.
// Known limits: a claim or a floor split across two lines is not seen; the legend is the first `Checks:` block only.
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
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
    const hit = dirs.map((d) => join(c.rust, 'vectors', d, f)).find(existsSync);
    return hit ? vecIn(hit, v, key) : `no ${f} under vectors`;
};

// each resolver returns 'ok' or the reason the ref is dangling
const resolvers = {
    unit,
    lib: unit,
    it: (c, v) => testFile(join(c.dir, 'tests'), v, 'tests'),
    row: (c, v) => (isFile(join(c.dir, 'tests', `row_${v}.rs`)) ? 'ok' : `no tests/row_${v}.rs`),
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
    oracle: (c, v) => (existsSync(join(c.rust, 'vectors', v.split('#')[0])) ? vecIn(join(c.rust, 'vectors', v.split('#')[0]), v, 'id') : family(c, v, c.derived, 'id')),
    w3c: (c, v) => family(c, v, c.w3c, 'section'),
    fuzz: (c, v) => (isFile(join(c.dir, 'fuzz', 'fuzz_targets', `${v}.rs`)) ? 'ok' : `no fuzz/fuzz_targets/${v}.rs`),
    mutants: (c, v) => {
        const rel = v.split('::').join('/');
        return [`${rel}.rs`, `${rel}/mod.rs`].some((f) => isFile(join(c.dir, 'src', f))) ? 'ok' : `no src/${rel}.rs`;
    },
    conf: (c, v) => {
        const p = join(c.rust, 'testkit/src/conformance.rs');
        return isFile(p) && new RegExp(`\\bname\\s*=\\s*"${esc(v)}"`).test(code(p, true)) ? 'ok' : `no conformance case "${v}" in testkit/src/conformance.rs`;
    },
    store: (c, v) => testFile(join(c.rust, 'store/tests'), v, 'store/tests'),
    wipe: (c, v) => (anyTest([...walk(join(c.rust, 'wipe/src'), '.rs'), ...walk(join(c.rust, 'wipe/tests'), '.rs')], v.split('::').at(-1)) === 'ok' ? 'ok' : `no test fn ${v} in wipe`),
    gate: (c, v) => (isFile(join(c.rust, 'justfile')) && new RegExp(`^${esc(v)}(\\s[^:=\\n]*)?:(?!=)`, 'm').test(read(join(c.rust, 'justfile'))) ? 'ok' : `no just recipe ${v}`),
};
const PREFIXES = Object.keys(resolvers);
const NAME = '(?:[A-Za-z0-9_./*#:-]|\\{[^}\\s]*\\})+';

export function check(rust) {
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
        const defined = new Set();
        for (const i of legend) for (const m of lines[i].matchAll(/`([a-z][a-z0-9]*(?:-pending)?):(?!:)/g)) defined.add(m[1]);
        for (const p of defined) if (!resolvers[p.replace(/-pending$/, '')]) fail(start, `legend prefix ${p}:`, 'the claims tool has no resolver for it');
        const ctx = { dir: join(rust, d), rust, derived: vdirs(/-derived$/), w3c: vdirs(/^w3c-/) };
        let fence = false;
        const seen = new Set();
        lines.forEach((line, i) => {
            if (/^```/.test(line)) fence = !fence;
            if (fence || legend.has(i)) return;
            for (const m of line.matchAll(refRe)) {
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
                    if (!/^\s*\([^)]*\S[^)]*\)/.test(after)) fail(i, `${kind}:${raw}`, 'no inline reason, write `(reason)` after it');
                    else if (res === 'ok') fail(i, `${kind}:${raw}`, `its target exists, retag it ${base}:`);
                } else if (res !== 'ok') fail(i, `${kind}:${raw}`, res);
                else if (!seen.has(key)) out.resolved++;
                seen.add(key);
            }
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

// plants: a fixture tree with one good ref per resolver, then one defect at a time; each must fail with its own message
function selftest() {
    const root = mkdtempSync(join(tmpdir(), 'claims-'));
    const put = (p, s) => (mkdirSync(dirname(join(root, p)), { recursive: true }), writeFileSync(join(root, p), s));
    const rs = (name) => `#[test]\nfn ${name}() {}\n`;
    const lib = `fn lib_only() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn lt() {}\n}\n`;
    const m = `#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n    mod inner {\n        #[test]\n        fn deep() {}\n    }\n}\n`;
    // a commented-out test and a proptest! in a comment must count for nothing
    const dead = `// #[test]\nfn commented() {}\n/* proptest! { */\nfn after() {}\nconst S: &str = "#[test]";\nfn in_string() {}\n`;
    const all = 'unit lib it row ui prop race vec oracle w3c fuzz mutants conf store wipe gate'.split(' ');
    const legendOf = (ps) => `Checks: ${ps.map((p) => `\`${p}:x\``).join(', ')}.\n`;
    const build = (body, { floor = 7, legend = legendOf([...all, 'fuzz-pending', 'unit-pending']), extra = {} } = {}) => {
        put('a/Cargo.toml', '[package]\n');
        put('a/gates.json', JSON.stringify({ mutants: { floor } }));
        put('b/Cargo.toml', '[package]\n');
        put('b/gates.json', JSON.stringify({ mutants: { floor: 3 } }));
        put('a/src/lib.rs', lib);
        put('a/src/m.rs', m);
        put('a/tests/it.rs', `${rs('it_t')}mod sub {\n    #[test]\n    fn s() {}\n}\n`);
        put('a/tests/dead.rs', dead);
        put('a/tests/props.rs', `proptest! {\n    fn p(x in 0..1) {}\n}\n${rs('r')}`);
        put('a/tests/row_r.rs', '');
        for (const d of ['fail/x.rs', 'fail/x.stderr', 'pass/x.rs']) put(`a/tests/ui/${d}`, '');
        put('a/fuzz/fuzz_targets/real.rs', '');
        put('vectors/fam/v.json', JSON.stringify({ cases: [{ id: 'c1', note: 'decoy' }] }));
        put('vectors/x-derived/o.json', JSON.stringify({ cases: [{ id: 'o1' }] }));
        put('vectors/w3c-y/w.json', JSON.stringify({ sections: [{ section: '1.2' }] }));
        put('testkit/src/conformance.rs', '// c.name = "commented";\nfn f() { c.name = "case1"; }\n');
        put('store/tests/st.rs', rs('s1'));
        put('wipe/src/lib.rs', rs('w1'));
        put('justfile', 'gt arg:\n    true\n');
        for (const [p, s] of Object.entries(extra)) put(p, s);
        put('a/CONTRACT.md', `# a\n\n${legend}\n## Runtime\n${body}\n`);
    };
    const goodRefs = 'unit:m::t unit:m::inner::deep lib:m::t it:it::it_t it:it::sub::s row:r ui:x prop:p race:r vec:fam/v.json#c1 oracle:o.json#o1 w3c:w.json#1.2 fuzz:real mutants:m conf:case1 store:st::s1 wipe:w1 gate:gt unit:lib::tests'.split(' ');
    const dangling = {
        unit: 'unit:m::gone', lib: 'lib:m::gone', it: 'it:it::gone', row: 'row:nope', ui: 'ui:nope', prop: 'prop:gone', race: 'race:gone',
        vec: 'vec:fam/v.json#nope', oracle: 'oracle:o.json#nope', w3c: 'w3c:w.json#9.9', fuzz: 'fuzz:gone', mutants: 'mutants:gone', conf: 'conf:gone', store: 'store:st::gone', wipe: 'wipe:gone', gate: 'gate:gone',
    };
    const cases = [['good tree', `- R1 ${goodRefs.join(' ')}. The mutants floor of 7 holds. And b's mutants floor is 3.`, {}, null]];
    for (const [k, ref] of Object.entries(dangling)) cases.push([`dangling ${k}`, `- R1 ${ref}`, {}, `${ref}:`]);
    cases.push(
        ['commented-out test is not a test', '- R1 it:dead::commented', {}, 'no test fn commented'],
        ['proptest! in a comment marks nothing', '- R1 prop:after', {}, 'no test fn after'],
        ['#[test] in a string marks nothing', '- R1 it:dead::in_string', {}, 'no test fn in_string'],
        ['conf case in a comment', '- R1 conf:commented', {}, 'no conformance case'],
        ['unit in the wrong module', '- R1 unit:m::wrong::deep', {}, 'no mod wrong'],
        ['unit has no fallback to lib.rs', '- R1 unit:m::lt', {}, 'no test fn lt'],
        ['it middle path is honoured', '- R1 it:it::nomod::s', {}, 'no mod nomod'],
        ['vec #id is an id field, not any string', '- R1 vec:fam/v.json#decoy', {}, 'no id "decoy"'],
        ['w3c #s is a section field', '- R1 w3c:w.json#c1', {}, 'no section "c1"'],
        ['legend ends at the first blank line', '- R1 fuzz:t', { legend: `${legendOf(all)}\n- a bullet after the blank, \`fuzz:t\`\n` }, 'no fuzz/fuzz_targets/t.rs'],
        ['a placeholder in the body is not ignored', '- R1 fuzz:t', {}, 'no fuzz/fuzz_targets/t.rs'],
        ['body prefix not in the legend', '- R1 gate:gt', { legend: legendOf(all.filter((p) => p !== 'gate')) }, 'the prefix is not defined in the legend'],
        ['pending prefix not in the legend', '- R1 unit-pending:q (later)', { legend: legendOf(all) }, 'not defined in the legend'],
        ['pending without a reason', '- R1 fuzz-pending:later', {}, 'no inline reason'],
        ['pending that exists', '- R1 fuzz-pending:real (stale)', {}, 'its target exists'],
        ['unknown legend prefix', '- R1 ok', { legend: legendOf([...all, 'zap']) }, 'no resolver'],
        ['quoted crate floor', '- R1 `just mutants` holds the floor (a 9).', {}, 'rust/a/gates.json says 7'],
        ['quoted crate: floor', '- R1 the mutants floor (a: 9).', {}, 'rust/a/gates.json says 7'],
        ['floor N', '- R1 the mutants floor 9 holds.', {}, 'rust/a/gates.json says 7'],
        ['floor: N', '- R1 the mutants floor: 9 holds.', {}, 'rust/a/gates.json says 7'],
        ['floor = N', '- R1 the mutants floor = 9 holds.', {}, 'rust/a/gates.json says 7'],
        ['floor for crate is N', '- R1 the mutants floor for b is 4.', {}, 'rust/b/gates.json says 3'],
        ["crate's floor is N", "- R1 b's mutants floor is 4.", {}, 'rust/b/gates.json says 3'],
    );
    let bad = 0;
    for (const [name, body, opts, want] of cases) {
        rmSync(root, { recursive: true, force: true });
        mkdirSync(root);
        build(body, opts);
        const r = check(root);
        const got = r.failures.join('\n');
        const ok = want === null ? r.failures.length === 0 && r.pending.length === 0 : r.failures.length >= 1 && got.includes(want);
        if (!ok) bad++;
        console.log(`${ok ? 'ok  ' : 'FAIL'} selftest: ${name}${ok ? '' : `: wanted ${want ?? 'no failure'}, got ${got || 'none'}`}`);
    }
    rmSync(root, { recursive: true, force: true });
    return bad ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const a = process.argv.slice(2);
    if (a[0] === '--selftest') process.exit(selftest());
    const i = a.indexOf('--root');
    process.exit(report(resolve(i >= 0 ? a[i + 1] : join(dirname(fileURLToPath(import.meta.url)), '..'))));
}
