#!/usr/bin/env python3
"""Plant for tools/check_webauthn_ext.mjs: the committed vectors with one bit of the ecdsa-sha1-leaf certificate's SHA-1 signature flipped.

usage: python3 -I plant_sha1_chain.py <out-dir>   (<out-dir>/webauthn-rp-derived/chains.json is rewritten)
The checker must name chains#ecdsa-sha1-leaf, so allowing SHA-1 signatures has not made it accept a bad one.
Licence: MIT OR Apache-2.0.
"""
import json, os, sys

path = os.path.join(sys.argv[1], "webauthn-rp-derived", "chains.json")
doc = json.load(open(path))
case = next(c for c in doc["cases"] if c["id"] == "ecdsa-sha1-leaf")
case["x5c"][0] = case["x5c"][0][:-2] + "%02x" % (int(case["x5c"][0][-2:], 16) ^ 1)
json.dump(doc, open(path, "w"), indent=1)
