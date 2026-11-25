#!/usr/bin/env python3
"""Extract the numbered figures of an RFC plain-text file into JSON, grouped by top-level section.

usage: python3 -I extract_rfc_figures.py <rfcNNNN.txt> <out.json> <section-prefix>...
Each figure is the indented block immediately above its 'Figure N: caption' line, with RFC page
headers and footers removed. Fields: figure, caption, section, example (first two section numbers), text (dedented, line breaks kept),
joined (all whitespace removed, for base64url/hex blobs) and json (parsed value, when it parses).
Licence of this script: MIT OR Apache-2.0.
"""
import json, re, sys

src, out, prefixes = sys.argv[1], sys.argv[2], sys.argv[3:]
raw = open(src, encoding="utf-8").read().replace("\r", "")
lines = raw.split("\n")
FOOT = re.compile(r"^\S.*\[Page \d+\]\s*$")
HEAD = re.compile(r"^\x0c?RFC \d+ .+\d{4}\s*$")
PB = "\x00"
res, i = [], 0
while i < len(lines):
    if FOOT.match(lines[i]):
        while res and res[-1] == "":
            res.pop()
        i += 1
        while i < len(lines) and (lines[i].startswith("\x0c") or HEAD.match(lines[i]) or lines[i].strip() == ""):
            i += 1
        res.append(PB)
        continue
    res.append(lines[i])
    i += 1
lines = res
SEC = re.compile(r"^(\d+(?:\.\d+)*)\.\s{1,3}\S")
CAP = re.compile(r"^\s+Figure (\d+): (.*)$")
sec, figs = None, []
for n, l in enumerate(lines):
    m = SEC.match(l)
    if m:
        sec = m.group(1)
    m = CAP.match(l)
    if m:
        k = n - 1
        while k >= 0 and lines[k].strip() == "":
            k -= 1
        end = k
        while k >= 0 and lines[k].strip() != "" and not CAP.match(lines[k]):
            k -= 1
        block = [x for x in lines[k + 1 : end + 1] if x != PB]
        cap = m.group(2)
        j = n + 1
        while j < len(lines) and lines[j].startswith("                 ") and lines[j].strip():
            cap += " " + lines[j].strip()
            j += 1
        ind = min(len(x) - len(x.lstrip()) for x in block)
        text = "\n".join(x[ind:].rstrip() for x in block)
        f = {"figure": int(m.group(1)), "caption": cap, "section": sec, "example": ".".join((sec or "").split(".")[:2]), "text": text, "joined": re.sub(r"\s+", "", text)}
        # JSON in RFCs wraps long strings across lines; rejoin those before parsing
        fixed = re.sub(r'(?<=[^\s,{\[:"])\n\s+(?=[^\s"{}\[\]])', "", text)
        for cand in (text, fixed):
            try:
                f["json"] = json.loads(cand)
                break
            except ValueError:
                pass
        figs.append(f)
keep = [f for f in figs if any(f["section"] == p or f["section"].startswith(p + ".") for p in prefixes)]
json.dump({"figures": keep}, open(out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
open(out, "a").write("\n")
