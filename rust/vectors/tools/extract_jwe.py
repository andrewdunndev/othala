#!/usr/bin/env python3
"""Extract the JWE examples of RFC 7516 appendix A.1-A.5, RFC 7518 appendices B and C and RFC 7520
section 5 to case JSON (the shape of rfc7515/jws.json).

usage: python3 -I extract_jwe.py <rfc7516.txt> <rfc7518.txt> <rfc7520.txt> <out-dir>
writes <out-dir>/rfc7516/jwe.json, rfc7518/appendix-b.json, rfc7518/appendix-c.json, rfc7520/jwe-cases.json.
Values are copied from the RFC text; byte arrays become hex or base64url. Cases whose id contains
"tampered", "truncated", "nonempty" or "off-curve" are derived by one mechanical edit of an upstream
value. "must-refuse" cases use a non-goal (RSA1_5, PBES2, zip) and expect ok false; those of RFC 7516 name the
error kind the contract gives the algorithm (CONTRACT R65).
RFC 7516 A.4 (general, two recipients) and A.5 (flattened) are cases for the key of one recipient each.
Licence of this script: MIT OR Apache-2.0.
"""
import base64, json, os, re, sys

FOOT = re.compile(r"^\S.*\[Page \d+\]\s*$")
HEAD = re.compile(r"^\x0c?RFC \d+ .+\d{4}\s*$")
B64 = re.compile(r"^[A-Za-z0-9_-]*$")


def unpage(path):
    lines = open(path, encoding="utf-8").read().replace("\r", "").split("\n")
    res, i = [], 0
    while i < len(lines):
        if FOOT.match(lines[i]):
            while res and res[-1] == "":
                res.pop()
            i += 1
            while i < len(lines) and (lines[i].startswith("\x0c") or HEAD.match(lines[i]) or lines[i].strip() == ""):
                i += 1
            res.append(None)
            continue
        res.append(lines[i])
        i += 1
    return res


def dedent(block):
    ind = min(len(x) - len(x.lstrip()) for x in block)
    return "\n".join(x[ind:].rstrip() for x in block)


def as_json(text):
    # RFC JSON wraps long strings across lines; rejoin those before parsing
    fixed = re.sub(r'(?<=[^\s,{\[:"])\n\s*(?=[^\s"{}\[\]])', "", text)
    for cand in (text, fixed):
        try:
            return json.loads(cand)
        except ValueError:
            pass
    return None


def json_at(text, start):
    """The longest run of lines from a line beginning `start` that parses as JSON (a page break can
    merge neighbouring paragraphs into one)."""
    t = text.split("\n")
    for i, l in enumerate(t):
        if l.lstrip().startswith(start):
            for n in range(len(t), i, -1):
                v = as_json("\n".join(t[i:n]))
                if v is not None:
                    return v
    return None


def sections(path):
    """{section id: [paragraph text]}; a page break is transparent to paragraphs."""
    sec = re.compile(r"^(?:Appendix )?(\d+(?:\.\d+)*|[A-Z](?:\.\d+)*)\.\s{1,3}(\S.*)$")
    out, cur, para = {}, None, []

    def flush():
        if cur is not None and para:
            out[cur].append(dedent(para))
        para.clear()

    for l in unpage(path):
        if l is None:
            continue
        m = sec.match(l)
        if m and not l.startswith(" "):
            flush()
            cur = m.group(1)
            out[cur] = []
        elif l.strip() == "":
            flush()
        elif cur is not None:
            para.append(l)
    flush()
    return out


def figures(path):
    """{figure number: text} for every 'Figure N: caption' block, a leading bullet paragraph dropped."""
    lines = [l for l in unpage(path)]
    cap = re.compile(r"^\s+Figure (\d+): ")
    figs = {}
    for n, l in enumerate(lines):
        m = cap.match(l or "")
        if not m:
            continue
        k = n - 1
        while lines[k] is not None and lines[k].strip() == "":
            k -= 1
        end = k
        while k >= 0 and (lines[k] is None or (lines[k].strip() != "" and not cap.match(lines[k]))):
            k -= 1
        block = [x for x in lines[k + 1 : end + 1] if x is not None]
        text = dedent(block)
        if text.startswith("o  "):
            t = text.split("\n")
            text = "\n".join(t[next(i for i, x in enumerate(t) if i and not x.startswith("   ")):])
        figs[int(m.group(1))] = text
    return figs


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def octets(text):
    return bytes(int(x) for x in re.findall(r"\d+", re.search(r"\[[\d,\s]+\]", text).group(0)))


def joined(text):
    return re.sub(r"\s+", "", text)


def flip(seg):
    return ("B" if seg[0] == "A" else "A") + seg[1:]


def compact_cases(cid, base, jwe):
    """The upstream compact JWE, then one derived refusal per edited part."""
    h, k, iv, c, t = jwe.split(".")
    out = [dict(base, id=cid + "-valid", jwe=jwe)]
    bad = {"ok": False}
    edits = [("tampered-tag", [h, k, iv, c, flip(t)]), ("tampered-ciphertext", [h, k, iv, flip(c), t]),
             ("tampered-iv", [h, k, flip(iv), c, t]), ("truncated-tag", [h, k, iv, c, t[:-4]])]
    if k:
        edits.append(("tampered-encrypted-key", [h, flip(k), iv, c, t]))
    else:
        # direct modes require an empty encrypted key (RFC 7516 section 5.2 step 10)
        edits.append(("nonempty-encrypted-key", [h, b64(bytes(16)), iv, c, t]))
    for name, parts in edits:
        out.append(dict(base, id=f"{cid}-{name}", jwe=".".join(parts), expect=bad))
    return out


REFUSED = {"ok": False, "kind": "UnsupportedAlg"}


def rfc7516(path):
    s = sections(path)
    compact = lambda sec: next(joined(p) for p in s[sec] if re.fullmatch(r"[\w-]*(\.[\w-]*){4}", joined(p)))
    jwk = lambda sec: next(v for p in s[sec] if (v := json_at(p, "{")) is not None)
    hdr = lambda sec: next(v for p in s[sec] if (v := json_at(p, '{"alg"')) is not None)
    cases = []
    for sec, cid, refuse in (("A.1", "a1-rsa-oaep-a256gcm", None), ("A.2", "a2-rsa1_5-a128cbc-hs256", "RSA1_5"), ("A.3", "a3-a128kw-a128cbc-hs256", None)):
        h = hdr(sec + ".1")
        base = {"op": "jwe_decrypt", "alg": h["alg"], "enc": h["enc"], "serialization": "compact", "jwk": jwk(sec + ".3")}
        jwe = compact(sec + ".7")
        if refuse:
            cases.append(dict(base, id=cid + "-must-refuse", jwe=jwe, expect=REFUSED, note=f"must-refuse: {refuse} is a non-goal"))
        else:
            base["expect"] = {"ok": True, "plaintext": b64(octets(s[sec][1]))}
            cases += compact_cases(cid, base, jwe)
    # A.4 and A.5 reuse the keys and plaintext of A.2 and A.3; each recipient's case carries that recipient's key
    plaintext = {"ok": True, "plaintext": b64(octets(s["A.3"][1]))}
    whole = lambda sec: next(v for p in s[sec] if (v := json_at(p, "{")) is not None)
    general, flattened = whole("A.4.7"), whole("A.5")
    enc = hdr("A.3.1")["enc"]
    for cid, ser, doc, alg, key, expect, note in (
        ("a4-general-a128kw-valid", "general", general, "A128KW", jwk("A.3.3"), plaintext, "the RSA1_5 recipient is skipped and the A128KW one opens"),
        ("a4-general-rsa1_5-must-refuse", "general", general, "RSA1_5", jwk("A.2.3"), REFUSED, "must-refuse: RSA1_5 is a non-goal; the other recipient is not for this key"),
        ("a5-flattened-a128kw-valid", "flattened", flattened, "A128KW", jwk("A.3.3"), plaintext, None),
    ):
        case = {"id": cid, "op": "jwe_decrypt", "alg": alg, "enc": enc, "serialization": ser, "jwk": key, "jwe": doc, "expect": expect}
        cases.append(dict(case, note=note) if note else case)
    return {"source": "RFC 7516 appendix A.1 to A.5, keys, compact and JSON serializations as given there; tampered cases derived; A.2 and A.4's RSA1_5 recipient are must-refuse", "cases": cases}


def rfc7518_b(path):
    s = sections(path)
    names = {"AES_128_CBC_HMAC_SHA_256": "A128CBC-HS256", "AES_192_CBC_HMAC_SHA_384": "A192CBC-HS384", "AES_256_CBC_HMAC_SHA_512": "A256CBC-HS512"}
    title = {k: v for k, v in (re.match(r"(B\.\d)\.\s+Test Cases for (\S+)", l).groups() for l in open(path, encoding="utf-8") if re.match(r"B\.\d\.\s+Test Cases for ", l))}
    cases = []
    for sec in ("B.1", "B.2", "B.3"):
        v, name = {}, None
        for line in "\n".join(s[sec]).split("\n"):
            m = re.match(r"^(K|MAC_KEY|ENC_KEY|P|IV|A|AL|E|M|T)\s*=\s*((?:[0-9a-f]{2}\s*)+)$", line)
            if m:
                name = m.group(1)
                v[name] = joined(m.group(2))
            elif name and re.fullmatch(r"\s+(?:[0-9a-f]{2}\s*)+", line):
                v[name] += joined(line)
            else:
                name = None
        enc, cid = names[title[sec]], sec.lower().replace(".", "")
        base = {"enc": enc, "key": v["K"], "iv": v["IV"], "aad": v["A"]}
        derived = {"mac_key": v["MAC_KEY"], "enc_key": v["ENC_KEY"], "al": v["AL"], "m": v["M"]}
        cases.append(dict(base, id=f"{cid}-encrypt", op="cbc_hmac_encrypt", plaintext=v["P"], expect={"ok": True, "ciphertext": v["E"], "tag": v["T"], **derived}))
        dec = dict(base, op="cbc_hmac_decrypt", ciphertext=v["E"])
        bad = lambda h: ("0" if h[0] != "0" else "1") + h[1:]
        cases.append(dict(dec, id=f"{cid}-decrypt-valid", tag=v["T"], expect={"ok": True, "plaintext": v["P"]}))
        cases.append(dict(dec, id=f"{cid}-decrypt-tampered-tag", tag=bad(v["T"]), expect={"ok": False}))
        cases.append(dict(dec, id=f"{cid}-decrypt-tampered-ciphertext", ciphertext=bad(v["E"]), tag=v["T"], expect={"ok": False}))
        cases.append(dict(dec, id=f"{cid}-decrypt-tampered-aad", aad=bad(v["A"]), tag=v["T"], expect={"ok": False}))
    return {"source": "RFC 7518 appendix B.1 to B.3 (hex as given there); decrypt and tampered cases derived", "cases": cases}


def rfc7518_c(path):
    ps = sections(path)["C"]
    jwks = [v for p in ps if (v := json_at(p, '{"kty"')) is not None]
    alice, bob = [k for k in jwks if "d" in k]
    hdr = next(v for p in ps if (v := json_at(p, '{"alg"')) is not None)
    z = next(octets(p) for p in ps if p.startswith("Z\n"))
    other = next(octets(p) for p in ps if "OtherInfo value of" in p)
    cek = next(l.strip() for p in ps for l in p.split("\n") if re.fullmatch(r"\s*[\w-]{22}\s*", l))
    pub = lambda k: {m: k[m] for m in ("kty", "crv", "x", "y")}
    base = {"op": "ecdh_es_derive", "alg": hdr["alg"], "enc": hdr["enc"], "apu": hdr["apu"], "apv": hdr["apv"]}
    ok = {"ok": True, "z": z.hex(), "other_info": other.hex(), "cek": cek}
    y = alice["y"]
    off = dict(hdr["epk"], y=y[:-1] + ("A" if y[-1] != "A" else "B"))
    return {"source": "RFC 7518 appendix C (ECDH-ES with Concat KDF, A128GCM); byte arrays as hex; sender and off-curve cases derived", "cases": [
        dict(base, id="c-recipient", private_jwk=bob, public_jwk=hdr["epk"], expect=ok),
        dict(base, id="c-sender", private_jwk=alice, public_jwk=pub(bob), expect=ok),
        dict(base, id="c-recipient-off-curve-epk", private_jwk=bob, public_jwk=off, expect={"ok": False}, note="epk y edited so the point is off P-256; RFC 8725 section 3.4"),
    ]}


def rfc7520(path):
    f = figures(path)
    js = lambda n: as_json(f[n])
    pt = b"".join(re.sub(r"\\x([0-9a-f]{2})", lambda m: chr(int(m.group(1), 16)), l.strip()[1:-1]).encode("latin-1") for l in f[72].split("\n"))
    # example: (key figure, header figure, compact, general, flattened, refusal)
    ex = {
        "5.1": (73, 77, 81, 82, 83, "RSA1_5"), "5.2": (84, 88, 92, 93, 94, None), "5.3": (96, 101, 105, 106, 107, "PBES2"),
        "5.4": (108, 113, 117, 118, 119, None), "5.5": (120, 124, 128, 129, None, None), "5.6": (130, 132, 136, 137, None, None),
        "5.7": (138, 144, 148, 149, 150, None), "5.8": (151, 155, 159, 160, 161, None), "5.9": (151, 166, 170, 171, 172, "zip (DEFLATE)"),
        "5.10": (151, 178, None, 182, 183, None), "5.11": (151, (187, 191), None, 192, 193, None), "5.12": (151, 199, None, 200, 201, None),
    }
    cases = []
    for e, (kf, hf, cf, gf, ff, refuse) in ex.items():
        h = {k: v for n in (hf if isinstance(hf, tuple) else (hf,)) for k, v in js(n).items()}
        cid = "s" + e.replace(".", "_")
        key = {"password": f[kf]} if kf == 96 else {"jwk": js(kf)}
        base = {"op": "jwe_decrypt", "alg": h["alg"], "enc": h["enc"], **key}
        if refuse:
            base["expect"], base["note"] = {"ok": False}, f"must-refuse: {refuse} is a non-goal"
        else:
            base["expect"] = {"ok": True, "plaintext": b64(pt)}
        suffix = "-must-refuse" if refuse else ""
        for ser, n in (("compact", cf), ("general", gf), ("flattened", ff)):
            if n is None:
                continue
            c = dict(base, serialization=ser, jwe=joined(f[n]) if ser == "compact" else js(n))
            if ser == "compact" and not refuse:
                cases += compact_cases(f"{cid}-compact", c, c["jwe"])
            else:
                cases.append(dict(c, id=f"{cid}-{ser}" + ("-valid" if not refuse else suffix)))
    general = js(221)
    for r, (kf, hf) in enumerate(((73, 205), (108, 209), (138, 214)), 1):
        h = js(hf)
        c = {"op": "jwe_decrypt", "alg": h["alg"], "enc": js(216)["enc"], "jwk": js(kf), "serialization": "general", "jwe": general}
        if h["alg"] == "RSA1_5":
            cases.append(dict(c, id=f"s5_13-general-recipient-{r}-must-refuse", expect={"ok": False}, note="must-refuse: RSA1_5 is a non-goal; the other recipients are not for this key"))
        else:
            cases.append(dict(c, id=f"s5_13-general-recipient-{r}-valid", expect={"ok": True, "plaintext": b64(pt)}))
    return {"source": "RFC 7520 section 5.1 to 5.13, keys and serializations as given there; tampered compact cases derived; RSA1_5, PBES2 and zip examples are must-refuse", "cases": cases}


def write(out, rel, doc):
    p = os.path.join(out, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, ensure_ascii=False)
        fh.write("\n")


r16, r18, r20, out = sys.argv[1:5]
write(out, "rfc7516/jwe.json", rfc7516(r16))
write(out, "rfc7518/appendix-b.json", rfc7518_b(r18))
write(out, "rfc7518/appendix-c.json", rfc7518_c(r18))
write(out, "rfc7520/jwe-cases.json", rfc7520(r20))
