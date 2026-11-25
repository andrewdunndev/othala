#!/usr/bin/env python3
"""Extract the RFC 4648 section 10 test vectors to JSON.

usage: python3 -I extract_rfc4648.py <rfc4648.txt> <out.json>
Licence of this script: MIT OR Apache-2.0.
"""
import json, re, sys

txt = open(sys.argv[1], encoding="utf-8").read()
sec = txt[txt.index("\n10.  Test Vectors") : txt.index("\n11.  ")]
cases = [
    {"encoding": m.group(1), "input": m.group(2), "output": m.group(3)}
    for m in re.finditer(r'(BASE64|BASE32-HEX|BASE32|BASE16)\("([^"]*)"\)\s*=\s*"([^"]*)"', sec)
]
json.dump({"source": "RFC 4648 section 10", "cases": cases}, open(sys.argv[2], "w"), indent=1)
open(sys.argv[2], "a").write("\n")
