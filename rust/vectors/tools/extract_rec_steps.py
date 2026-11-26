#!/usr/bin/env python3
"""Extract the WebAuthn L3 step table the vector gate checks citations against.

usage: python3 -I extract_rec_steps.py <rec.html> <rec-url> <out.json>
Writes the top-level step texts of 7.1 and 7.2 (nested sub-steps stay inside their step's text) and the
section-number to heading map of every numbered heading, plus the sha256 of the HTML read. Deterministic.
Licence of this script: MIT OR Apache-2.0.
"""
import hashlib, json, re, sys
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


def headings(root):
    out = {}
    for n in walk(root):
        if re.fullmatch(r"h[1-6]", n.tag) and "data-level" in n.attrs:
            content = next((k for k in walk(n) if k.attrs.get("class") == "content"), None)
            if content is not None:
                out[n.attrs["data-level"]] = norm(content.text())
    return out


def extract(raw, url):
    tree = Tree()
    tree.feed(raw.decode("utf-8"))
    table = {sec: steps(tree.root, a) for sec, a in SECTIONS.items()}
    for sec, t in table.items():
        assert t and sorted(t) == list(range(1, len(t) + 1)), f"{sec}: steps are not 1..N"
    return {
        "rec": url,
        "rec_sha256": hashlib.sha256(raw).hexdigest(),
        "steps": {sec: {str(n): t[n] for n in sorted(t)} for sec, t in table.items()},
        "sections": headings(tree.root),
    }


def dump(table):
    return json.dumps(table, indent=1, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    html, url, out = sys.argv[1:4]
    with open(html, "rb") as fh, open(out, "w", encoding="utf-8") as oh:
        oh.write(dump(extract(fh.read(), url)))
