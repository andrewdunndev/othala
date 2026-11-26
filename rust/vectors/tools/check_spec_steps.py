#!/usr/bin/env python3
"""Fail if a WebAuthn L3 citation in the derived vectors or their generators names a step or section the REC lacks.

usage: python3 -I check_spec_steps.py [--refresh] [vectors-dir]   (default dir: the one above this script)
Offline: reads the vendored table w3c/webauthn-3-steps.json (built by extract_rec_steps.py from the REC that
SOURCES.toml pins by sha256). Checks that each cited "7.1 step N" / "7.2 steps N and M" / "steps N-M" exists, that
each "L3 <section>" exists, that a case citing a step carries a double-quoted passage in its `spec`, and that every
quoted passage appears in one of the cited steps; whether the step means what the case tests is a human review.
--refresh (opt in, needs network) refetches the pinned REC, checks its sha256 and rewrites the table; update the
table's sha256 in SOURCES.toml afterwards.
Licence of this script: MIT OR Apache-2.0.
"""
import glob, hashlib, importlib.util, json, os, re, sys, tomllib, urllib.request

TABLE = os.path.join("w3c", "webauthn-3-steps.json")
STEP = re.compile(r"\b(7\.[12]) steps? (\d+)\b(?:-(\d+)\b|(?: and (\d+)\b(?!\.\d)))?")
STEP_SECTION = re.compile(r"\b7\.[12] steps? \d+(?:-\d+)? and (\d+\.\d+(?:\.\d+)*)\b")
SECTION = re.compile(r"\bL3 (\d+(?:\.\d+)*)((?:(?:, | and |-)\d+\.\d+(?:\.\d+)*\b)*)")
NUMBER = re.compile(r"\d+(?:\.\d+)*")


def norm(s):
    return re.sub(r"\s+", " ", s.replace("’", "'").replace("“", '"').replace("”", '"')).strip()


def step_cites(text):
    for m in STEP.finditer(text):
        sec, a, rng, other = m.group(1), int(m.group(2)), m.group(3), m.group(4)
        yield sec, list(range(a, int(rng) + 1)) if rng else [a] + ([int(other)] if other else [])


def section_cites(text):
    for m in SECTION.finditer(text):
        yield from [m.group(1)] + NUMBER.findall(m.group(2))
    for m in STEP_SECTION.finditer(text):
        yield m.group(1)


def pinned(vectors):
    src = tomllib.load(open(os.path.join(vectors, "SOURCES.toml"), "rb"))["source"]["w3c-webauthn-3"]["revision"]
    return re.search(r"https://\S+/REC-\S+?/", src).group(0), re.search(r"sha256 ([0-9a-f]{64})", src).group(1)


def refresh(vectors):
    url, want = pinned(vectors)
    with urllib.request.urlopen(url, timeout=60) as r:
        raw = r.read()
    got = hashlib.sha256(raw).hexdigest()
    if got != want:
        sys.exit(f"pinned REC sha256 mismatch: want {want} got {got}")
    spec = importlib.util.spec_from_file_location("extract_rec_steps", os.path.join(os.path.dirname(os.path.abspath(__file__)), "extract_rec_steps.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = os.path.join(vectors, TABLE)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(mod.dump(mod.extract(raw, url)))
    print(f"wrote {TABLE} sha256 {hashlib.sha256(open(out, 'rb').read()).hexdigest()}; record it in SOURCES.toml")


def main():
    args = sys.argv[1:]
    do_refresh = "--refresh" in args
    args = [a for a in args if a != "--refresh"]
    vectors = os.path.abspath(args[0] if args else os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    if do_refresh:
        refresh(vectors)
    table = json.load(open(os.path.join(vectors, TABLE), encoding="utf-8"))
    bad = []
    if table["rec_sha256"] != pinned(vectors)[1]:
        bad.append(f"{TABLE}: rec_sha256 is not the REC sha256 SOURCES.toml pins")
    steps = {sec: {int(n): t for n, t in d.items()} for sec, d in table["steps"].items()}
    files = sorted(glob.glob(os.path.join(vectors, "webauthn-rp-derived", "**", "*.json"), recursive=True))
    files += sorted(glob.glob(os.path.join(vectors, "tools", "derive_webauthn*.py")))
    checked = 0
    for f in files:
        text = open(f, encoding="utf-8").read()
        rel = os.path.relpath(f, vectors)
        for sec, nums in step_cites(text):
            for n in nums:
                checked += 1
                if n not in steps[sec]:
                    bad.append(f"{rel}: {sec} step {n} does not exist")
        for s in sorted(set(section_cites(text))):
            checked += 1
            if s not in table["sections"]:
                bad.append(f"{rel}: section {s} does not exist")
        if f.endswith(".json"):
            for case in json.loads(text).get("cases", []):
                spec = case.get("spec", "")
                cited = [(sec, n) for sec, nums in step_cites(spec) for n in nums]
                if not cited:
                    continue
                quotes = re.findall(r'"([^"]+)"', spec)
                if not quotes:
                    bad.append(f"{rel}: case {case['id']}: cites a step but quotes no passage of it")
                for q in quotes:
                    if not any(norm(q) in steps[sec].get(n, "") for sec, n in cited):
                        bad.append(f"{rel}: case {case['id']}: quote {q!r} is in none of the cited steps {cited}")
    for b in bad:
        print(b)
    print(f"{checked} citations in {len(files)} files, {len(bad)} problems")
    return 1 if bad else 0


sys.exit(main())
