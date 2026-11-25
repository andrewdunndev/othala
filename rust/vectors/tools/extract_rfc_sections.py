#!/usr/bin/env python3
"""Extract named sections of an RFC plain-text file into JSON, paragraph by paragraph.

usage: python3 -I extract_rfc_sections.py <rfcNNNN.txt> <out.json> <section>...
A section is an id such as A.4 or 10 (matched exactly, no subsections unless listed). Page headers
and footers are removed. Each block is one paragraph or preformatted block: text (dedented, line
breaks kept), joined (whitespace removed) and json (parsed value, when it parses).
Licence of this script: MIT OR Apache-2.0.
"""
import json, re, sys

src, out, want = sys.argv[1], sys.argv[2], set(sys.argv[3:])
lines = open(src, encoding="utf-8").read().replace("\r", "").split("\n")
FOOT = re.compile(r"^\S.*\[Page \d+\]\s*$")
HEAD = re.compile(r"^\x0c?RFC \d+ .+\d{4}\s*$")
res, i = [], 0
while i < len(lines):
    if FOOT.match(lines[i]):
        i += 1
        while i < len(lines) and (lines[i].startswith("\x0c") or HEAD.match(lines[i])):
            i += 1
        # keep exactly the blank lines of the text that follows, drop the ones before the footer
        while res and res[-1] == "":
            res.pop()
        while i < len(lines) and lines[i] == "":
            i += 1
        res.append(None)  # page break marker: transparent to paragraphs
        continue
    res.append(lines[i])
    i += 1
SEC = re.compile(r"^(?:Appendix )?(\d+(?:\.\d+)*|[A-Z](?:\.\d+)*)\.\s{1,3}(\S.*)$")
secs, cur, para = [], None, []


def flush():
    global para
    if cur is not None and para:
        ind = min(len(x) - len(x.lstrip()) for x in para)
        text = "\n".join(x[ind:].rstrip() for x in para)
        b = {"text": text, "joined": re.sub(r"\s+", "", text)}
        fixed = re.sub(r'(?<=[^\s,{\[:"])\n\s*(?=[^\s"{}\[\]])', "", text)
        for cand in (text, fixed):
            try:
                b["json"] = json.loads(cand)
                break
            except ValueError:
                pass
        cur["blocks"].append(b)
    para = []


for l in res:
    if l is None:
        continue
    m = SEC.match(l)
    if m and not l.startswith(" "):
        flush()
        cur = {"section": m.group(1), "title": m.group(2), "blocks": []} if m.group(1) in want else None
        if cur:
            secs.append(cur)
        continue
    if l.strip() == "":
        flush()
    elif cur is not None:
        para.append(l)
flush()
json.dump({"sections": secs}, open(out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
open(out, "a").write("\n")
