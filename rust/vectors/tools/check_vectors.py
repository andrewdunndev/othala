#!/usr/bin/env python3
"""The vector gate: derived files, SOURCES.toml and spec citations all agree with their sources, offline.

usage: python3 -I check_vectors.py [vectors-dir]   (default: the directory above this script)
 (a) every tools/derive_* script re-run into a temp dir reproduces its committed files byte for byte, and no file
     sits in a derived directory that no script writes;
 (b) every SOURCES.toml file entry exists, has the recorded sha256 and, where the file states its own case count
     (numberOfTests, a `cases` list, a step table), that count; each source's `cases` is the sum of its files'; every
     data file is listed;
 (c) tools/check_spec_steps.py passes (cited steps and sections exist, quoted passages are in the cited step).
Exit 1 with one line per problem. Licence of this script: MIT OR Apache-2.0.
"""
import hashlib, json, os, shutil, subprocess, sys, tempfile, tomllib

# how each generator is called: V = vectors dir, OUT = output dir
DERIVERS = {
    "derive_factor.py": ("python", ["V", "OUT"]),
    "derive_jose.py": ("python", ["V", "OUT"]),
    "derive_jose_jwe.mjs": ("node", ["V", "OUT"]),
    "derive_webauthn.py": ("python", ["OUT"]),
    "derive_webauthn_ext.py": ("python", ["OUT"]),
}
NOT_DATA = ("tools/", "SOURCES.toml", "justfile")


def files_under(root):
    for base, _, names in os.walk(root):
        for n in names:
            yield os.path.relpath(os.path.join(base, n), root).replace(os.sep, "/")


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def derive(vectors, problems):
    tools = os.path.join(vectors, "tools")
    found = sorted(n for n in os.listdir(tools) if n.startswith("derive_"))
    for n in found:
        if n not in DERIVERS:
            problems.append(f"tools/{n}: a derive script check_vectors.py does not know; add it to DERIVERS")
    produced = set()
    with tempfile.TemporaryDirectory() as out:
        for n in found:
            if n not in DERIVERS:
                continue
            runner, argv = DERIVERS[n]
            exe = [sys.executable, "-I"] if runner == "python" else [shutil.which("node") or "node"]
            args = [vectors if a == "V" else out for a in argv]
            try:
                r = subprocess.run(exe + [os.path.join(tools, n)] + args, capture_output=True, text=True, timeout=600)
            except FileNotFoundError:
                problems.append(f"tools/{n}: {exe[0]} is not on PATH")
                continue
            if r.returncode != 0:
                problems.append(f"tools/{n}: exited {r.returncode}: {r.stderr.strip().splitlines()[-1:] or ''}")
        for rel in sorted(files_under(out)):
            produced.add(rel)
            committed = os.path.join(vectors, rel)
            if not os.path.isfile(committed):
                problems.append(f"{rel}: derived but not committed")
            elif open(committed, "rb").read() != open(os.path.join(out, rel), "rb").read():
                problems.append(f"{rel}: differs from a fresh derivation")
        for d in sorted({r.split("/")[0] for r in produced}):
            for rel in files_under(os.path.join(vectors, d)):
                if f"{d}/{rel}" not in produced:
                    problems.append(f"{d}/{rel}: committed in a derived directory but no derive script writes it")
    return len(produced)


def own_count(path, raw):
    """The case count a file states itself, or None when its count is a reading of the file, pinned by its sha256."""
    if not path.endswith(".json"):
        return None
    j = json.loads(raw)
    if not isinstance(j, dict):
        return None
    if isinstance(j.get("numberOfTests"), int):
        return j["numberOfTests"]
    if isinstance(j.get("cases"), list):
        return len(j["cases"])
    if isinstance(j.get("steps"), dict):
        return sum(len(v) for v in j["steps"].values())
    return None


def sources(vectors, problems):
    src = tomllib.load(open(os.path.join(vectors, "SOURCES.toml"), "rb"))["source"]
    listed, counted = set(), 0
    for name, s in src.items():
        total = 0
        for f in s.get("files", []):
            p = f["path"]
            listed.add(p)
            total += f["cases"]
            full = os.path.join(vectors, p)
            if not os.path.isfile(full):
                problems.append(f"SOURCES {name}: {p} does not exist")
                continue
            raw = open(full, "rb").read()
            if hashlib.sha256(raw).hexdigest() != f["sha256"]:
                problems.append(f"SOURCES {name}: {p} sha256 is {hashlib.sha256(raw).hexdigest()}, not the recorded {f['sha256']}")
            n = own_count(p, raw)
            if n is not None:
                counted += 1
                if n != f["cases"]:
                    problems.append(f"SOURCES {name}: {p} holds {n} cases, not the recorded {f['cases']}")
        if "cases" in s and s.get("files") and total != s["cases"]:
            problems.append(f"SOURCES {name}: files sum to {total} cases, not the recorded {s['cases']}")
    for rel in sorted(files_under(vectors)):
        if rel not in listed and not rel.startswith(NOT_DATA[0]) and rel not in NOT_DATA[1:]:
            problems.append(f"{rel}: not recorded in SOURCES.toml")
    return len(listed), counted


def main():
    vectors = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    problems = []
    nder = derive(vectors, problems)
    nfiles, ncounted = sources(vectors, problems)
    r = subprocess.run([sys.executable, "-I", os.path.join(vectors, "tools", "check_spec_steps.py"), vectors], capture_output=True, text=True)
    steps = r.stdout.strip().splitlines()
    if r.returncode != 0:
        problems += [f"spec: {l}" for l in (steps[:-1] or [r.stderr.strip()[-300:]])]
    for p in problems[:60]:
        print(p)
    print(f"vectors: {nder} derived files re-derived; {nfiles} SOURCES files hashed, {ncounted} counts read from the file; spec: {steps[-1] if steps else r.stderr.strip()[-100:]}; {len(problems)} problems")
    return 1 if problems else 0


sys.exit(main())
