#!/usr/bin/env python3
"""Extract WebAuthn L3 section 16 (test vectors) from the pinned dated spec HTML to JSON.

usage: python3 -I extract_webauthn3.py <spec.html> <out-dir>
spec: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/ (sha256 in ../SOURCES.toml)
Licence of this script: MIT OR Apache-2.0.
"""
import html, json, re, sys
from html.parser import HTMLParser

BLOCK = {"h2", "h3", "h4", "h5", "h6", "p", "pre", "li"}


class P(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.cur, self.tag = [], None, None

    def handle_starttag(self, tag, attrs):
        if tag in BLOCK:
            self.flush()
            self.tag, self.cur = tag, []
        elif tag == "br" and self.cur is not None:
            self.cur.append("\n")

    def flush(self):
        if self.cur is not None and "".join(self.cur).strip():
            self.out.append((self.tag, "".join(self.cur)))
        self.cur = self.tag = None

    def handle_endtag(self, tag):
        if tag == self.tag:
            self.flush()

    def handle_data(self, d):
        if self.cur is not None:
            self.cur.append(d)


def blocks(src):
    a = src.rindex('<h2 class="heading settled" data-level="16"')
    b = src.index('<h2 class="heading settled" data-level="17"', a)
    p = P()
    p.feed(src[a:b])
    return p.out


KV = re.compile(r"^([A-Za-z_][\w.]*)\s*=\s*(.*)$")
TOK = re.compile(r"(h|b64)'([^']*)'")


def split_comment(v):
    # a ';' outside quotes starts a CDDL comment
    q = None
    for i, c in enumerate(v):
        if c in "'\"":
            q = None if q == c else (q or c)
        elif c == ";" and q is None:
            return v[:i].rstrip(), v[i + 1 :].strip()
    return v.rstrip(), None


def parse_pre(text):
    items, lines, i = [], text.strip("\n").split("\n"), 0
    while i < len(lines):
        l = lines[i]
        i += 1
        if not l.strip():
            continue
        m = KV.match(l)
        if l.startswith(";"):
            items.append({"comment": l[1:].strip()})
        elif m and not l.startswith("//"):
            name, val = m.groups()
            val, cm = split_comment(val)
            depth = val.count("{") - val.count("}")
            while depth > 0 and i < len(lines):
                val += "\n" + lines[i]
                depth += lines[i].count("{") - lines[i].count("}")
                i += 1
            it = {"name": name, "value": val}
            hx = [t for k, t in TOK.findall(val) if k == "h"]
            b6 = [t for k, t in TOK.findall(val) if k == "b64"]
            if hx:
                it["hex"] = hx[-1] if len(hx) == 1 else hx
            if b6:
                it["b64"] = b6[-1] if len(b6) == 1 else b6
            if cm:
                it["comment"] = cm
            items.append(it)
        else:
            items.append({"text": l})
    return items


def main(spec, out):
    src = open(spec, encoding="utf-8").read()
    secs, cur, phase = [], None, None
    for tag, txt in blocks(src):
        t = re.sub(r"[ \t]*\n[ \t]*", " ", txt).strip() if tag != "pre" else txt
        if tag in ("h2", "h3", "h4", "h5", "h6"):
            m = re.match(r"(\d+(?:\.\d+)*)\.?\s+(.*)", t)
            cur = {"section": m.group(1), "title": m.group(2), "blocks": []}
            secs.append(cur)
            phase = None
        elif cur is None:
            continue
        elif tag == "p" and t in ("Registration:", "Authentication:"):
            phase = t[:-1].lower()
        elif tag == "pre":
            cur["blocks"].append({"phase": phase, "pre": parse_pre(txt)} if phase else {"pre": parse_pre(txt)})
        else:
            if t:
                cur["blocks"].append({"prose": t} if not phase else {"prose": t, "phase": phase})
    by = {s["section"]: s for s in secs}
    groups = {
        "attestation-root": ["16.1"],
        "none": ["16.2", "16.4", "16.5", "16.6"],
        "packed": ["16.3", "16.7", "16.8", "16.9", "16.10", "16.11", "16.12"],
        "tpm": ["16.13"],
        "android-key": ["16.14"],
        "apple": ["16.15"],
        "fido-u2f": ["16.16"],
        "prf": ["16.17", "16.17.1", "16.17.1.1", "16.17.1.2"],
    }
    intro = [b["prose"] for b in by["16"]["blocks"] if "prose" in b]
    for name, nums in groups.items():
        doc = {
            "source": "W3C WebAuthn Level 3, section 16 Test Vectors (stated non-normative by the spec)",
            "spec": "https://www.w3.org/TR/2026/REC-webauthn-3-20260825/",
            "normative": False,
            "sections": [by[n] for n in nums],
        }
        if name == "attestation-root":
            doc["intro"] = intro
        with open(f"{out}/{name}.json", "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
            f.write("\n")


main(sys.argv[1], sys.argv[2])
