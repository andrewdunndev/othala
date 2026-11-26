#!/usr/bin/env node
// `just claims`: every rust/*/CONTRACT.md test ref resolves, and every mutants floor a contract quotes is its crate's gates.json floor.
// usage: claims.mjs [--root RUST_DIR] | --selftest
//
// A ref is `prefix:value` outside the legend. The legend is the `Checks:` line and the bullets or indented lines under it; the prefixes it
// names in backticks are the ones the contract uses, and a legend prefix this file has no resolver for fails the run. Fenced code is skipped.
// A pending ref is `<prefix>-pending:value (reason)`: the reason is inline and non-empty, the target must not exist yet, and the run counts them.
// A `<crate> word` before a ref names the crate the ref lives in (`testkit unit:vectors`).
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const read = (p) => readFileSync(p, 'utf8');
const isDir = (p) => existsSync(p) && statSync(p).isDirectory();
const isFile = (p) => existsSync(p) && statSync(p).isFile();
const walk = (d, ext) => (isDir(d) ? readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name), ext) : e.name.endsWith(ext) ? [join(d, e.name)] : [])) : []);
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// a fn is a test when an attribute above it says so, or it sits after a proptest! macro
function isTestFn(src, name) {
    const lines = src.split('\n');
    const re = new RegExp(`\\bfn\\s+${esc(name)}\\s*[<(]`);
    for (let i = 0; i < lines.length; i++) {
        if (!re.test(lines[i])) continue;
        for (let j = i - 1; j >= 0 && i - j <= 12; j--) {
            const l = lines[j].trim();
            if (/#\[(\w+::)*test(_case)?\b/.test(l)) return true;
            if (l !== '' && !/^(#|\/\/|\)|\]|[A-Za-z_]+\s*=|"|,)/.test(l)) break;
        }
        if (lines.slice(0, i).some((l) => /\bproptest!/.test(l))) return true;
    }
    return false;
}
// an inline `mod name { .. }` that holds tests names all of them
const isTestMod = (src, name) => {
    const m = new RegExp(`\\bmod\\s+${esc(name)}\\s*\\{`).exec(src);
    return m !== null && hasTest(src.slice(m.index));
};
const hasTest = (src) => /#\[(\w+::)*test\b/.test(src) || /\bproptest!/.test(src);

// src/a/b.rs for `a::b`, then `a/b/mod.rs`; a shorter module path covers an inline `mod`, and the empty one is lib.rs
function moduleFiles(crate, mods) {
    for (let k = mods.length; k >= 0; k--) {
        const rel = mods.slice(0, k).join('/');
        const c = k === 0 ? ['lib.rs'] : [`${rel}.rs`, `${rel}/mod.rs`];
        const hit = c.map((f) => join(crate, 'src', f)).filter(isFile);
        if (hit.length) return hit;
    }
    return [];
}

function vectorFile(rust, spec, dirs) {
    const [f, id] = spec.split('#');
    const cands = dirs.flatMap((d) => [join(rust, 'vectors', d, f)]);
    const hit = cands.find(isFile);
    if (!hit) return isDir(cands[0]) && !id ? 'ok' : `no file ${f} under vectors`;
    return id === undefined || read(hit).includes(`"${id}"`) ? 'ok' : `no case "${id}" in ${f}`;
}

// each resolver returns 'ok' or the reason the ref is dangling
const resolvers = {
    unit: (c, v) => resolveUnit(c, v),
    lib: (c, v) => resolveUnit(c, v),
    it: (c, v) => {
        const [f, ...t] = v.split('::');
        const p = join(c.dir, 'tests', `${f}.rs`);
        if (!isFile(p)) return `no tests/${f}.rs`;
        return !t.length || isTestFn(read(p), t.at(-1)) ? 'ok' : `no test fn ${t.at(-1)} in tests/${f}.rs`;
    },
    row: (c, v) => (isFile(join(c.dir, 'tests', `row_${v}.rs`)) ? 'ok' : `no tests/row_${v}.rs`),
    ui: (c, v) => {
        const need = ['fail/' + v + '.rs', 'fail/' + v + '.stderr', 'pass/' + v + '.rs'].filter((f) => !isFile(join(c.dir, 'tests/ui', f)));
        return need.length ? `no tests/ui/${need.join(', tests/ui/')}` : 'ok';
    },
    prop: (c, v) => resolveInTests(c, v),
    race: (c, v) => resolveInTests(c, v),
    vec: (c, v) => {
        const bad = expand(v).map((x) => resolvers.vec1(c, x)).filter((r) => r !== 'ok');
        return bad.length ? bad[0] : 'ok';
    },
    vec1: (c, v) => {
        const [f, id] = v.split('#');
        if (f.endsWith('/*')) return isDir(join(c.rust, 'vectors', f.slice(0, -2))) && readdirSync(join(c.rust, 'vectors', f.slice(0, -2))).length ? 'ok' : `no vector family ${f}`;
        const p = join(c.rust, 'vectors', f);
        if (!existsSync(p)) return `no vector ${f}`;
        return id === undefined || (isFile(p) && read(p).includes(`"${id}"`)) ? 'ok' : `no case "${id}" in vectors/${f}`;
    },
    oracle: (c, v) => (isFile(join(c.rust, 'vectors', v.split('#')[0])) ? vectorFile(c.rust, v, ['']) : vectorFile(c.rust, v, c.derived)),
    w3c: (c, v) => vectorFile(c.rust, v, c.w3c),
    fuzz: (c, v) => (isFile(join(c.dir, 'fuzz', 'fuzz_targets', `${v}.rs`)) ? 'ok' : `no fuzz/fuzz_targets/${v}.rs`),
    mutants: (c, v) => {
        const rel = v.split('::').join('/');
        return [`${rel}.rs`, `${rel}/mod.rs`].some((f) => isFile(join(c.dir, 'src', f))) ? 'ok' : `no src/${rel}.rs`;
    },
    conf: (c, v) => {
        const p = join(c.rust, 'testkit/src/conformance.rs');
        return isFile(p) && new RegExp(`\\bname\\s*=\\s*"${esc(v)}"`).test(read(p)) ? 'ok' : `no conformance case "${v}" in testkit/src/conformance.rs`;
    },
    store: (c, v) => {
        const [f, ...t] = v.split('::');
        const p = join(c.rust, 'store/tests', `${f}.rs`);
        if (!isFile(p)) return `no store/tests/${f}.rs`;
        return !t.length || isTestFn(read(p), t.at(-1)) ? 'ok' : `no test fn ${t.at(-1)} in store/tests/${f}.rs`;
    },
    wipe: (c, v) => ([...walk(join(c.rust, 'wipe/src'), '.rs'), ...walk(join(c.rust, 'wipe/tests'), '.rs')].some((p) => isTestFn(read(p), v.split('::').at(-1))) ? 'ok' : `no test fn ${v} in wipe`),
    gate: (c, v) => (isFile(join(c.rust, 'justfile')) && new RegExp(`^${esc(v)}(\\s[^:=\\n]*)?:(?!=)`, 'm').test(read(join(c.rust, 'justfile'))) ? 'ok' : `no just recipe ${v}`),
};

function resolveUnit(c, v) {
    const parts = v.split('::');
    if (parts.length === 1) {
        const f = moduleFiles(c.dir, parts);
        return f.length && f.some((p) => hasTest(read(p))) && !f.some((p) => p.endsWith('lib.rs')) ? 'ok' : `no src/${parts[0]}.rs with tests`;
    }
    const files = moduleFiles(c.dir, parts.slice(0, -1));
    const t = parts.at(-1);
    if (!files.length) return `no src file for module ${parts.slice(0, -1).join('::')}`;
    return files.some((p) => isTestFn(read(p), t) || isTestMod(read(p), t)) ? 'ok' : `no test fn ${t} in ${files.map((p) => p.slice(c.dir.length + 1)).join(', ')}`;
}

function resolveInTests(c, v) {
    const t = v.split('::').at(-1);
    return walk(join(c.dir, 'tests'), '.rs').some((p) => isTestFn(read(p), t)) ? 'ok' : `no test fn ${t} under tests/`;
}

// `a{b,c}d` is `abd` and `acd`
const expand = (v) => {
    const m = /\{([^{}]*)\}/.exec(v);
    return m ? m[1].split(',').flatMap((x) => expand(v.slice(0, m.index) + x + v.slice(m.index + m[0].length))) : [v];
};
const NAME = '(?:[A-Za-z0-9_./*#:-]|\\{[^}\\s]*\\})+';

export function check(rust) {
    const out = { failures: [], resolved: 0, pending: [], contracts: 0 };
    const crates = readdirSync(rust).filter((d) => isFile(join(rust, d, 'Cargo.toml')));
    const floor = {};
    for (const d of crates) {
        const g = join(rust, d, 'gates.json');
        if (isFile(g)) floor[d] = JSON.parse(read(g))?.mutants?.floor;
    }
    const vdirs = (re) => (isDir(join(rust, 'vectors')) ? readdirSync(join(rust, 'vectors')).filter((d) => re.test(d)) : []);
    for (const d of crates.filter((d) => isFile(join(rust, d, 'CONTRACT.md')))) {
        out.contracts++;
        const file = `rust/${d}/CONTRACT.md`;
        const lines = read(join(rust, d, 'CONTRACT.md')).split('\n');
        const fail = (i, what, why) => out.failures.push(`${file}:${i + 1}: ${what}: ${why}`);
        // the legend: the Checks line and what follows it while blank, a bullet or indented
        const start = lines.findIndex((l) => /^Checks:/.test(l));
        const legend = new Set();
        if (start < 0) fail(0, 'legend', 'no `Checks:` line');
        else {
            legend.add(start);
            for (let i = start + 1; i < lines.length && /^(\s*$|- |\s)/.test(lines[i]); i++) legend.add(i);
        }
        const prefixes = new Set();
        for (const i of legend) for (const m of lines[i].matchAll(/`([a-z][a-z0-9]*(?:-pending)?):(?!:)/g)) prefixes.add(m[1]);
        for (const p of prefixes) if (!resolvers[p.replace(/-pending$/, '')]) fail(start, `legend prefix ${p}:`, 'the claims tool has no resolver for it');
        const known = [...prefixes].filter((p) => resolvers[p.replace(/-pending$/, '')]).sort((a, b) => b.length - a.length);
        const ctx = { dir: join(rust, d), rust, derived: vdirs(/-derived$/), w3c: vdirs(/^w3c-/) };
        let fence = false;
        const seen = new Set();
        lines.forEach((line, i) => {
            if (/^```/.test(line)) fence = !fence;
            if (fence || legend.has(i)) return;
            if (known.length) {
                const re = new RegExp(`(?<![\\w-])(${known.map(esc).join('|')}):(?!:)(${NAME})`, 'g');
                for (const m of line.matchAll(re)) {
                    const [kind, raw] = [m[1], m[2].replace(/[.:,;]+$/, '')];
                    const q = /([a-z][a-z0-9-]*) $/.exec(line.slice(0, m.index))?.[1];
                    const cc = q && crates.includes(q) ? { ...ctx, dir: join(rust, q) } : ctx;
                    const base = kind.replace(/-pending$/, '');
                    const res = resolvers[base](cc, raw);
                    const key = `${q ?? ''} ${kind}:${raw}`;
                    if (kind.endsWith('-pending')) {
                        const after = line.slice(m.index + m[0].length - (m[2].length - raw.length));
                        if (!/^\s*\([^)]*\S[^)]*\)/.test(after)) fail(i, `${kind}:${raw}`, 'no inline reason, write `(reason)` after it');
                        else if (res === 'ok') fail(i, `${kind}:${raw}`, `its target exists, retag it ${base}:`);
                        else if (!seen.has(key)) out.pending.push(`${file}:${i + 1}: ${kind}:${raw}`);
                    } else if (res !== 'ok') fail(i, `${kind}:${raw}`, res);
                    else if (!seen.has(key)) out.resolved++;
                    seen.add(key);
                }
            }
            // a quoted mutants floor: `crate N` or `floor N` on a line that names both mutants and floor
            if (/mutants/i.test(line) && /floor/i.test(line)) {
                const quoted = [];
                for (const m of line.matchAll(/(?<![\w-])([a-z][a-z0-9-]*) (\d+)\b/g)) if (m[1] in floor) quoted.push([m[1], +m[2]]);
                for (const m of line.matchAll(/\bfloors? (?:of |is |at |=)?(\d+)\b/gi)) quoted.push([d, +m[1]]);
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

// plants: a fixture tree, then one defect at a time; each must fail with its own message and the unplanted tree must pass
function selftest() {
    const root = mkdtempSync(join(tmpdir(), 'claims-'));
    const put = (p, s) => (mkdirSync(dirname(join(root, p)), { recursive: true }), writeFileSync(join(root, p), s));
    const legend = 'Checks: `unit:m::t`, `ui:x`, `fuzz:t`, `fuzz-pending:t`, `mutants:m`.\n\n## Runtime\n';
    const build = (body, floor = 7) => {
        put('a/Cargo.toml', '[package]\n');
        put('a/gates.json', JSON.stringify({ mutants: { floor } }));
        put('a/src/lib.rs', '');
        put('a/src/m.rs', '#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n');
        put('a/tests/ui/fail/x.rs', '');
        put('a/tests/ui/fail/x.stderr', '');
        put('a/tests/ui/pass/x.rs', '');
        put('a/fuzz/fuzz_targets/real.rs', '');
        put('a/CONTRACT.md', `# a\n\n${legend}${body}\n`);
    };
    const cases = [
        ['good tree', '- R1 ok: unit:m::t, ui:x, fuzz:real, mutants:m. A floor of 7 is quoted here for mutants.', 7, null],
        ['dangling unit', '- R1 unit:m::gone', 7, 'no test fn gone in src/m.rs'],
        ['dangling fuzz', '- R1 fuzz:missing', 7, 'no fuzz/fuzz_targets/missing.rs'],
        ['dangling ui', '- R1 ui:nope', 7, 'no tests/ui/fail/nope.rs'],
        ['a legend placeholder is not ignored in the body', '- R1 unit:m::t and fuzz:t', 7, 'no fuzz/fuzz_targets/t.rs'],
        ['pending without a reason', '- R1 fuzz-pending:later', 7, 'no inline reason'],
        ['pending that exists', '- R1 fuzz-pending:real (stale)', 7, 'its target exists'],
        ['wrong quoted floor', '- R1 `just mutants` holds the floor (a 9).', 7, 'rust/a/gates.json says 7'],
        ['wrong floor, bare', '- R1 the mutants floor of 9 holds.', 7, 'rust/a/gates.json says 7'],
        ['unknown legend prefix', '- R1 ok', 7, 'no resolver', 'Checks: `zap:x`, `unit:m::t`.\n\n## Runtime\n'],
    ];
    let bad = 0;
    for (const [name, body, floor, want, lg] of cases) {
        rmSync(root, { recursive: true, force: true });
        mkdirSync(root);
        build(body, floor);
        if (lg) put('a/CONTRACT.md', `# a\n\n${lg}${body}\n`);
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
