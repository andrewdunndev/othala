#!/usr/bin/env python3
"""Fail if a WebAuthn L3 step citation in the derived vectors or their generators names a step that does not exist.

usage: python3 -I check_spec_steps.py [vectors-dir]   (default: the directory above this script)
Fetches the pinned dated REC named by SOURCES.toml (source w3c-webauthn-3) into a temp dir and checks its sha256.
Checks only that each cited "7.1 step N" / "7.2 steps N and M" / "steps N-M" exists in the top-level list of that
section and that any double-quoted text in a case's `spec` appears in the cited step; whether the step means what
the case tests is a human review.
Licence of this script: MIT OR Apache-2.0.
"""
import glob, hashlib, json, os, re, sys, tempfile, tomllib, urllib.request
from html.parser import HTMLParser

SECTIONS = {"7.1": "sctn-registering-a-new-credential", "7.2": "sctn-verifying-assertion"}
VOID = {"br", "img", "hr", "meta", "link", "input", "wbr", "source", "col", "area", "base", "embed", "param", "track"}


class Node:
    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.parent, self.kids = tag, dict(attrs), parent, []

    def text(self):
        return "".join(k if isinstance(k, str) else k.text() for k in self.kids)


class Tree(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = self.cur = Node("root", [], None)

    def handle_starttag(self, tag, attrs):
        if tag in ("li", "p") and self.cur.tag == tag:
            self.cur = self.cur.parent
        node = Node(tag, attrs, self.cur)
        self.cur.kids.append(node)
        if tag not in VOID:
            self.cur = node

    def handle_endtag(self, tag):
        c = self.cur
        while c is not None and c.tag != tag:
            c = c.parent
        if c is not None and c.parent is not None:
            self.cur = c.parent

    def handle_data(self, data):
        self.cur.kids.append(data)


def walk(n):
    yield n
    for k in n.kids:
        if not isinstance(k, str):
            yield from walk(k)


def norm(s):
    return re.sub(r"\s+", " ", s.replace("’", "'").replace("“", '"').replace("”", '"')).strip()


def steps(root, anchor):
    head = next(n for n in walk(root) if n.attrs.get("id") == anchor)
    siblings = head.parent.kids
    out = {}
    for k in siblings[siblings.index(head) + 1:]:
        if isinstance(k, str):
            continue
        if re.fullmatch(r"h[1-6]", k.tag) and k.tag <= head.tag:
            break
        if k.tag == "ol":
            num = int(k.attrs.get("start", "1"))
            for li in k.kids:
                if not isinstance(li, str) and li.tag == "li":
                    num = int(li.attrs.get("value", num))
                    out[num] = norm(li.text())
                    num += 1
            break
    return out


def pinned_html(vectors):
    src = tomllib.load(open(os.path.join(vectors, "SOURCES.toml"), "rb"))["source"]["w3c-webauthn-3"]["revision"]
    url = re.search(r"https://\S+/REC-\S+?/", src).group(0)
    want = re.search(r"sha256 ([0-9a-f]{64})", src).group(1)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "rec.html")
        with urllib.request.urlopen(url, timeout=60) as r, open(path, "wb") as fh:
            fh.write(r.read())
        raw = open(path, "rb").read()
    got = hashlib.sha256(raw).hexdigest()
    if got != want:
        sys.exit(f"pinned REC sha256 mismatch: want {want} got {got}")
    return raw.decode("utf-8")


CITE = re.compile(r"\b(7\.[12]) steps? (\d+)(?:-(\d+)|(?: and (\d+)(?!\.\d)))?")


def cites(text):
    for m in CITE.finditer(text):
        sec, a, rng, other = m.group(1), int(m.group(2)), m.group(3), m.group(4)
        nums = list(range(a, int(rng) + 1)) if rng else [a] + ([int(other)] if other else [])
        yield sec, nums


def main():
    vectors = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), ".."))
    tree = Tree()
    tree.feed(pinned_html(vectors))
    table = {sec: steps(tree.root, a) for sec, a in SECTIONS.items()}
    files = sorted(glob.glob(os.path.join(vectors, "webauthn-rp-derived", "**", "*.json"), recursive=True))
    files += sorted(glob.glob(os.path.join(vectors, "tools", "derive_webauthn*.py")))
    bad, checked = [], 0
    for f in files:
        text = open(f, encoding="utf-8").read()
        rel = os.path.relpath(f, vectors)
        for sec, nums in cites(text):
            for n in nums:
                checked += 1
                if n not in table[sec]:
                    bad.append(f"{rel}: {sec} step {n} does not exist")
        if f.endswith(".json"):
            for case in json.loads(text).get("cases", []):
                spec = case.get("spec", "")
                for sec, nums in cites(spec):
                    for quote in re.findall(r'"([^"]+)"', spec):
                        if not any(norm(quote) in table[sec].get(n, "") for n in nums):
                            bad.append(f"{rel}: case {case['id']}: quote {quote!r} not in {sec} step(s) {nums}")
    for b in bad:
        print(b)
    print(f"{checked} step citations in {len(files)} files, {len(bad)} problems")
    return 1 if bad else 0


sys.exit(main())
