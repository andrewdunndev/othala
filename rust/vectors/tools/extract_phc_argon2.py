#!/usr/bin/env python3
"""Extract the Argon2id version 19 `hashtest` cases of the P-H-C reference implementation's src/test.c to JSON.

usage: python3 -I extract_phc_argon2.py <test.c> <out.json>
test.c is src/test.c of github.com/P-H-C/phc-winner-argon2 at the commit SOURCES.toml records; the script refuses any
other file (sha256 below). Each case carries the password and salt text, passes (t), memory in KiB (1 << m in the C),
lanes (p), the raw tag in hex and the encoded string; the script checks that the encoded string says what the other
fields say, so a mis-read of the C cannot reach the JSON.
Licence of this script: MIT OR Apache-2.0. The extracted values are from test.c (CC0 1.0 or Apache-2.0).
"""
import base64, hashlib, json, re, sys

PINNED = "ec518844e823fb6a1bd38f79f2b5d1bbddf23f490c0a343c450aa8e3f5af5988"

raw = open(sys.argv[1], "rb").read()
if hashlib.sha256(raw).hexdigest() != PINNED:
    sys.exit("extract_phc_argon2: test.c is not the pinned file")
txt = raw.decode("utf-8")
start = txt.index('printf("Test Argon2id version number')
body = txt[start : txt.index("/* Common error state tests */", start)]


def literal(chunk):
    return "".join(re.findall(r'"([^"]*)"', chunk))


call = re.compile(
    r"hashtest\(version,\s*(\d+),\s*(\d+),\s*(\d+),\s*\"([^\"]*)\",\s*\"([^\"]*)\",\s*"
    r"((?:\"[^\"]*\"\s*)+),\s*((?:\"[^\"]*\"\s*)+),\s*Argon2_id\);"
)
cases = []
for m in call.finditer(body):
    t, log_m, p, pwd, salt = int(m[1]), int(m[2]), int(m[3]), m[4], m[5]
    hexref, mcf = literal(m[6]), literal(m[7])
    head, tag = mcf.rsplit("$", 1)
    _, alg, ver, params, salt64 = head.split("$")
    unpad = lambda s: base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    assert (alg, ver) == ("argon2id", "v=19")
    assert params == f"m={1 << log_m},t={t},p={p}", params
    assert unpad(salt64) == salt.encode() and unpad(tag).hex() == hexref
    cases.append(
        {
            "id": f"t{t}-m{1 << log_m}-p{p}-{pwd}-{salt}",
            "op": "argon2id_phc",
            "password": pwd,
            "salt": salt,
            "t": t,
            "m": 1 << log_m,
            "p": p,
            "expect": {"tag": hexref, "encoded": mcf},
        }
    )
assert len(cases) == body.count("hashtest("), "a hashtest call was not read"
json.dump(
    {"source": "phc-winner-argon2 src/test.c, Argon2id version 19 hashtest cases", "cases": cases},
    open(sys.argv[2], "w"),
    indent=1,
)
open(sys.argv[2], "a").write("\n")
