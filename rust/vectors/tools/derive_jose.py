#!/usr/bin/env python3
"""Derive the jose-derived case families from upstream keys already pinned in this directory.

usage: python3 -I derive_jose.py <vectors-dir> <out-dir>
reads rfc7515/jws.json, rfc7515/appendix-a4-a7.json, rfc7520/jwk.json, rfc7520/jwe.json, rfc8037/appendix-a.json;
writes <out-dir>/jose-derived/{header,keys,jwks,claims,thumbprint,limits}.json.
Deterministic: HS256 MACs use the RFC 7515 A.1 key, short RSA moduli come from fixed seeds. Every case
names the spec section it follows in `spec`. `expect.kind` appears only where the architecture contract
or a ruling names the refusal class; elsewhere a refusal is only `ok: false`.
Licence of this script: MIT OR Apache-2.0.
"""
import base64, hashlib, hmac, json, os, sys

V, OUT = sys.argv[1], sys.argv[2]
load = lambda p: json.load(open(os.path.join(V, p), encoding="utf-8"))
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

jws_cases = load("rfc7515/jws.json")["cases"]
HS = jws_cases[0]["jwk"]  # RFC 7515 A.1
RSA = jws_cases[5]["jwk"]  # RFC 7515 A.2
P256 = jws_cases[10]["jwk"]  # RFC 7515 A.3
blocks = [b["json"] for s in load("rfc7515/appendix-a4-a7.json")["sections"] for b in s["blocks"] if isinstance(b.get("json"), dict)]
P521 = {k: v for k, v in next(b for b in blocks if b.get("crv") == "P-521").items() if k != "d"}  # RFC 7515 A.4
f7520 = {f["figure"]: f.get("json") for f in load("rfc7520/jwk.json")["figures"]}
HS_KID = f7520[5]  # RFC 7520 3.5: kid, use sig, alg HS256
ENC_KEY = f7520[6]  # RFC 7520 3.6: use enc
RSA_KID = f7520[3]  # RFC 7520 3.3
P384 = next(f["json"] for f in load("rfc7520/jwe.json")["figures"] if f["figure"] == 108)  # RFC 7520 5.4.1
P384 = {k: P384[k] for k in ("kty", "crv", "x", "y")}
okp = [b["json"] for s in load("rfc8037/appendix-a.json")["sections"] for b in s["blocks"] if isinstance(b.get("json"), dict)]
ED = next(k for k in okp if k.get("crv") == "Ed25519" and "d" not in k)  # RFC 8037 A.2
X25519 = next(k for k in okp if k.get("crv") == "X25519" and k.get("kid") == "Bob")  # RFC 8037 A.6


def hs256(header_json, payload, key=HS):
    h = b64(header_json.encode()) if isinstance(header_json, str) else header_json
    p = b64(payload if isinstance(payload, bytes) else payload.encode())
    mac = hmac.new(unb64(key["k"]), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64(mac)}"


def case(cid, spec, expect, **kw):
    return {"id": cid, **kw, "spec": spec, "expect": expect}


OK, NO = {"ok": True}, {"ok": False}
kind = lambda k: {"ok": False, "kind": k}
PAYLOAD = '{"iss":"joe","exp":1300819380}'


def header():
    v = lambda cid, spec, h, expect, payload=PAYLOAD, **kw: case(cid, spec, expect, op="jws_verify", alg="HS256", jwk=HS, jws=hs256(h, payload), **kw)
    c = [
        v("control-valid", "RFC 7515 5.2", '{"alg":"HS256"}', OK),
        v("unknown-member-ignored", "RFC 7515 4 (unknown Header Parameters MUST be ignored)", '{"alg":"HS256","x-unregistered":1}', OK),
        v("dup-alg-different", "RFC 7515 4 and 5.2 step 4 (names MUST be unique; this oracle rejects)", '{"alg":"HS256","alg":"none"}', kind("DuplicateMember")),
        v("dup-alg-same", "RFC 7515 4 and 5.2 step 4", '{"alg":"HS256","alg":"HS256"}', kind("DuplicateMember")),
        v("dup-typ", "RFC 7515 4 and 5.2 step 4", '{"alg":"HS256","typ":"JWT","typ":"JWT"}', kind("DuplicateMember")),
        v("dup-escaped-name", "RFC 7515 4 with RFC 8259 7 (\\u0061lg names alg)", '{"alg":"HS256","\\u0061lg":"none"}', kind("DuplicateMember")),
        v("alg-missing", "RFC 7515 4.1.1 (alg MUST be present)", '{"typ":"JWT"}', kind("Malformed")),
        v("alg-not-string", "RFC 7515 4.1.1 (a case-sensitive string)", '{"alg":1}', kind("Malformed")),
        v("alg-case-differs", "RFC 7515 4.1.1 (case-sensitive) and RFC 8725 3.1", '{"alg":"hs256"}', kind("AlgMismatch")),
        v("alg-none-with-mac", "RFC 7518 3.6 and RFC 8725 3.1", '{"alg":"none"}', kind("AlgMismatch")),
        v("crit-unknown", "RFC 7515 4.1.11 (not understood: the JWS is invalid)", '{"alg":"HS256","crit":["exp-x"],"exp-x":1}', kind("CriticalHeader")),
        v("crit-empty", "RFC 7515 4.1.11 (MUST NOT be the empty list)", '{"alg":"HS256","crit":[]}', kind("Malformed")),
        v("crit-registered-name", "RFC 7515 4.1.11 (MUST NOT list names this spec defines)", '{"alg":"HS256","crit":["alg"]}', kind("Malformed")),
        v("crit-name-absent", "RFC 7515 4.1.11 (listed names MUST be present)", '{"alg":"HS256","crit":["exp-x"]}', kind("Malformed")),
        v("crit-not-array", "RFC 7515 4.1.11 (an array)", '{"alg":"HS256","crit":"exp-x"}', kind("Malformed")),
        v("crit-null", "RFC 7515 4.1.11 (an array; null is not an absent member)", '{"alg":"HS256","crit":null}', kind("Malformed")),
        v("b64-null", "RFC 7797 3 (b64 is a boolean; null is not an absent member)", '{"alg":"HS256","b64":null}', kind("Malformed")),
        v("header-array", "RFC 7515 5.2 step 3 (a JSON object)", '["alg","HS256"]', kind("Malformed")),
        v("header-not-json", "RFC 7515 5.2 step 3", '{alg:HS256}', kind("Malformed")),
    ]
    # RFC 7797: b64 false signs the raw payload; an implementation without RFC 7797 must refuse via crit
    raw = '{"iss":"joe"}'
    for cid, h, spec in (("b64-false-crit", '{"alg":"HS256","b64":false,"crit":["b64"]}', "RFC 7797 3 and 6 with RFC 7515 4.1.11 (this oracle does not implement RFC 7797)"),
                         ("b64-false-no-crit", '{"alg":"HS256","b64":false}', "RFC 7797 6 (b64 MUST be listed in crit)")):
        hb = b64(h.encode())
        mac = hmac.new(unb64(HS["k"]), hb.encode() + b"." + raw.encode(), hashlib.sha256).digest()
        c.append(case(cid, spec, kind("Malformed"), op="jws_verify", alg="HS256", jwk=HS, jws=f"{hb}.{raw}.{b64(mac)}"))
    good = hs256('{"alg":"HS256"}', PAYLOAD)
    h, p, s = good.split(".")
    c += [
        case("segment-padded", "RFC 7515 2 (base64url without padding) and 7.1", kind("Malformed"), op="jws_verify", alg="HS256", jwk=HS, jws=f"{h}.{p}.{s}="),
        case("segment-std-alphabet", "RFC 7515 2 (base64url alphabet only)", kind("Malformed"), op="jws_verify", alg="HS256", jwk=HS, jws=hs256('{"alg":"HS256"}', PAYLOAD).replace("-", "+").replace("_", "/")) if any(x in good for x in "-_") else None,
        case("four-segments", "RFC 7515 7.1 (three parts)", kind("Malformed"), op="jws_verify", alg="HS256", jwk=HS, jws=f"{h}.{p}.{s}.{s}"),
        case("two-segments", "RFC 7515 7.1", kind("Malformed"), op="jws_verify", alg="HS256", jwk=HS, jws=f"{h}.{p}"),
        case("whitespace-inside", "RFC 7515 7.1 (no whitespace)", kind("Malformed"), op="jws_verify", alg="HS256", jwk=HS, jws=f"{h}.\n{p}.{s}"),
    ]
    return [x for x in c if x]


def weak_rsa(bits, seed):
    """A deterministic RSA modulus of exactly `bits` bits (two primes from sha256-derived seeds)."""
    def prime(nbits, tag):
        x = int.from_bytes(hashlib.sha256(f"{seed}/{tag}".encode()).digest() * (nbits // 256 + 1), "big") >> (256 * (nbits // 256 + 1) - nbits)
        x |= (1 << (nbits - 1)) | (1 << (nbits - 2)) | 1
        while not all(pow(a, x - 1, x) == 1 for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)):
            x += 2
        return x
    p, q = prime(bits - bits // 2, "p"), prime(bits // 2, "q")
    n = p * q
    assert n.bit_length() == bits
    return {"kty": "RSA", "n": b64(n.to_bytes((bits + 7) // 8, "big")), "e": "AQAB"}


def keys():
    k = lambda cid, spec, alg, jwk, expect: case(cid, spec, expect, op="jwk_verify_key", alg=alg, jwk=jwk)
    off = dict(P256, y=b64(bytes([unb64(P256["y"])[0] ^ 1]) + unb64(P256["y"])[1:]))
    short_x = dict(P256, x=b64(unb64(P256["x"])[1:]))
    zero = dict(P256, x=b64(bytes(32)), y=b64(bytes(32)))
    oct_ = lambda n: {"kty": "oct", "k": b64(bytes(range(n)))}
    c = [
        k("es256-p256", "RFC 7518 3.4", "ES256", P256, OK),
        k("es256-p384-key", "RFC 7518 3.4 (ES256 is P-256) and RFC 8725 3.1", "ES256", P384, kind("AlgMismatch")),
        k("es256-p521-key", "RFC 7518 3.4 and RFC 8725 3.1", "ES256", P521, kind("AlgMismatch")),
        k("es384-p256-key", "RFC 7518 3.4 (ES384 is P-384)", "ES384", P256, kind("AlgMismatch")),
        k("es256-rsa-key", "RFC 7518 3.4 and RFC 8725 3.1", "ES256", RSA, kind("AlgMismatch")),
        k("es256-okp-key", "RFC 7518 3.4 and RFC 8037 3.1", "ES256", ED, kind("AlgMismatch")),
        k("rs256-ec-key", "RFC 7518 3.3 and RFC 8725 3.1", "RS256", P256, kind("AlgMismatch")),
        k("hs256-rsa-key", "RFC 7518 3.2 and RFC 8725 3.1 (RS-to-HS swap)", "HS256", RSA, kind("Malformed")),
        k("eddsa-x25519-key", "RFC 8037 3.1 (X25519 is not a signature curve) and ruling R-e", "EdDSA", X25519, kind("UnsupportedAlg")),
        k("eddsa-ed25519", "RFC 8037 3.1", "EdDSA", ED, OK),
        k("es256-off-curve", "RFC 8725 3.4 (validate the point)", "ES256", off, kind("Malformed")),
        k("es256-point-zero", "RFC 8725 3.4 and SEC 1 3.2.2", "ES256", zero, kind("Malformed")),
        k("es256-x-short", "RFC 7518 6.2.1.2 (x MUST be the full coordinate size)", "ES256", short_x, kind("Malformed")),
        k("es256-crv-missing", "RFC 7518 6.2.1.1 (crv is required)", "ES256", {kk: vv for kk, vv in P256.items() if kk != "crv"}, kind("Malformed")),
        k("es256-y-missing", "RFC 7518 6.2.1.3 (y is required for P-256)", "ES256", {kk: vv for kk, vv in P256.items() if kk != "y"}, kind("Malformed")),
        k("rs256-2048", "RFC 7518 3.3 (2048 bits or larger)", "RS256", RSA, OK),
        k("rs256-2047", "RFC 7518 3.3 (MUST be 2048 bits or larger)", "RS256", weak_rsa(2047, "jose-derived"), kind("WeakKey")),
        k("rs256-1024", "RFC 7518 3.3", "RS256", weak_rsa(1024, "jose-derived"), kind("WeakKey")),
        k("hs256-32-bytes", "RFC 7518 3.2 (a key as long as the hash output)", "HS256", oct_(32), OK),
        k("hs256-31-bytes", "RFC 7518 3.2 (MUST be at least the hash output size)", "HS256", oct_(31), kind("WeakKey")),
        k("hs384-47-bytes", "RFC 7518 3.2", "HS384", oct_(47), kind("WeakKey")),
        k("hs512-63-bytes", "RFC 7518 3.2", "HS512", oct_(63), kind("WeakKey")),
        k("hs256-use-enc", "RFC 7517 4.2 (use enc is not for signatures)", "HS256", dict(oct_(32), use="enc"), kind("KeyUse")),
        k("hs256-key-ops-encrypt", "RFC 7517 4.3 (key_ops without verify)", "HS256", dict(oct_(32), key_ops=["encrypt"]), kind("KeyUse")),
        k("hs256-use-key-ops-disagree", "RFC 7517 4.3 (use and key_ops SHOULD NOT both be used; when they disagree the key is refused: oracle choice)", "HS256", dict(oct_(32), use="sig", key_ops=["encrypt"]), kind("KeyUse")),
        k("hs256-key-ops-duplicate", "RFC 7517 4.3 (duplicate key_ops values MUST NOT be present)", "HS256", dict(oct_(32), key_ops=["verify", "verify"]), kind("KeyUse")),
        case("es256-escaped-members", "RFC 8259 7 (an escape spells the same string) with RFC 7518 6.2.1.1", OK, op="jwk_verify_key", alg="ES256", jwk_json=json.dumps(dict(P256, kty="EC"), separators=(",", ":")).replace('"EC"', '"E\\u0043"').replace('"P-256"', '"P\\u002d256"')),
    ]
    e = lambda cid, spec, alg, jwk, expect: case(cid, spec, expect, op="jwk_encrypt_key", alg=alg, jwk=jwk, direction="encrypt")
    d = lambda cid, spec, alg, jwk, expect: case(cid, spec, expect, op="jwk_encrypt_key", alg=alg, jwk=jwk, direction="decrypt")
    c += [
        e("a256kw-key-ops-wrap-key", "RFC 7517 4.3 (wrapKey: encrypt key)", "A256KW", dict(oct_(32), key_ops=["wrapKey"]), OK),
        d("a256kw-key-ops-unwrap-key", "RFC 7517 4.3 (unwrapKey: decrypt key)", "A256KW", dict(oct_(32), key_ops=["unwrapKey"]), OK),
        e("kw-key-ops-derive-only", "RFC 7517 4.3 (deriveKey is key agreement, not key wrapping)", "A256KW", dict(oct_(32), key_ops=["deriveKey"]), kind("KeyUse")),
        e("a256kw-key-ops-encrypt", "RFC 7517 4.3 (encrypt is for content, wrapKey for a key; this oracle follows the wording)", "A256KW", dict(oct_(32), key_ops=["encrypt"]), kind("KeyUse")),
        d("a256kw-key-ops-wrap-key-only", "RFC 7517 4.3 (a key that only wraps cannot unwrap)", "A256KW", dict(oct_(32), key_ops=["wrapKey"]), kind("KeyUse")),
        e("a256gcmkw-key-ops-encrypt", "RFC 7517 4.3 (AES GCM key wrapping wraps a key)", "A256GCMKW", dict(oct_(32), key_ops=["encrypt"]), kind("KeyUse")),
        e("dir-key-ops-encrypt", "RFC 7517 4.3 (dir encrypts the content with the key)", "dir", dict(oct_(32), key_ops=["encrypt"]), OK),
        e("dir-key-ops-wrap-key", "RFC 7517 4.3 (dir does not wrap a key)", "dir", dict(oct_(32), key_ops=["wrapKey"]), kind("KeyUse")),
        e("kw-key-ops-sign-only", "RFC 7517 4.3", "A256KW", dict(oct_(32), key_ops=["sign"]), kind("KeyUse")),
    ]
    a = lambda cid, spec, jwk, expect: case(cid, spec, expect, op="any_verify_key", jwk=jwk)
    c += [
        a("any-alg-bound", "RFC 7517 4.4 with RFC 8725 3.1 (the JWK alg binds)", HS_KID, OK),
        a("any-alg-missing", "RFC 8725 3.1 (a key used dynamically needs its alg)", {kk: vv for kk, vv in HS_KID.items() if kk != "alg"}, kind("KeyAlgMissing")),
        a("any-alg-kty-mismatch", "RFC 7518 3.1 and RFC 8725 3.1", dict(P256, alg="RS256"), kind("AlgMismatch")),
        a("any-enc-key", "RFC 7517 4.2", ENC_KEY, kind("KeyUse")),
    ]
    return c


def jwks():
    d = lambda cid, spec, ks, expect: case(cid, spec, expect, op="jwks_decode", jwks=ks)
    f = lambda cid, spec, ks, kid, expect: case(cid, spec, expect, op="jwks_find", jwks=ks, kid=kid)
    two = {"keys": [HS_KID, RSA_KID]}
    bad = lambda **kw: {"keys": [HS_KID, dict(HS_KID, kid="skipped", **kw), RSA_KID]}
    kept = lambda *ks: {"ok": True, "keys": len(ks), "kids": [k["kid"] for k in ks]}
    return [
        d("two-keys", "RFC 7517 5", two, kept(HS_KID, RSA_KID)),
        d("unknown-kty-skipped", "RFC 7517 5 (SHOULD ignore JWKs whose kty is not understood)", {"keys": [HS_KID, {"kty": "unknown-kty", "kid": "u"}]}, kept(HS_KID)),
        d("member-missing-y-skipped", "RFC 7517 5 (SHOULD ignore JWKs missing required members) with RFC 7518 6.2.1.3", {"keys": [HS_KID, {k: v for k, v in dict(P256, kid="skipped").items() if k != "y"}, RSA_KID]}, kept(HS_KID, RSA_KID)),
        d("unknown-use-skipped", "RFC 7517 5 (SHOULD ignore JWKs whose values are out of the supported ranges) with 4.2", bad(use="other"), kept(HS_KID, RSA_KID)),
        d("unknown-key-ops-skipped", "RFC 7517 5 (SHOULD ignore JWKs whose values are out of the supported ranges) with 4.3", bad(key_ops=["other"]), kept(HS_KID, RSA_KID)),
        d("key-ops-duplicate-skipped", "RFC 7517 4.3 (duplicate key_ops values MUST NOT be present) with 5 (SHOULD ignore)", bad(key_ops=["verify", "verify"]), kept(HS_KID, RSA_KID)),
        d("keys-missing", "RFC 7517 5.1 (keys is REQUIRED)", {"kids": []}, kind("Malformed")),
        d("keys-not-array", "RFC 7517 5.1 (an array of JWKs)", {"keys": HS_KID}, kind("Malformed")),
        d("member-not-object", "RFC 7517 5.1 (an array of JWKs) with 4 (a JWK is a JSON object)", {"keys": [HS_KID, 1]}, kind("Malformed")),
        d("dup-kid-skipped", "RFC 7517 4.5 (equal kids are allowed across key types) with 5 (SHOULD ignore what cannot be used): members that share a kid are skipped, since a lookup could not choose; house rule", {"keys": [HS_KID, dict(HS_KID, k=b64(bytes(range(32)))), RSA_KID]}, kept(RSA_KID)),
        case("dup-keys-member", "RFC 8259 4 with RFC 7517 5 (this oracle rejects duplicate names)", kind("DuplicateMember"), op="jwks_decode", jwks_json='{"keys":[],"keys":[]}'),
        f("find-by-kid", "RFC 7517 4.5", two, HS_KID["kid"], {"ok": True, "kty": "oct"}),
        f("find-absent-kid", "RFC 7517 4.5 (a kid the set lacks is no key, not an error)", two, "absent", {"ok": True, "found": False}),
    ]


NOW, LEEWAY, ISS, AUD, TYP = 1700000000, 60, "https://issuer.example", "client-1", "at+jwt"
POLICY = {"iss": ISS, "aud": AUD, "typ": TYP, "leeway": LEEWAY}


def claims():
    base = {"iss": ISS, "aud": AUD, "exp": NOW + 300, "iat": NOW - 10, "nbf": NOW - 10}

    def t(cid, spec, expect, claims=None, raw=None, hdr=None, drop=()):
        c = {k: v for k, v in dict(base, **(claims or {})).items() if k not in drop}
        body = raw if raw is not None else json.dumps(c, separators=(",", ":"))
        h = hdr if hdr is not None else json.dumps({"alg": "HS256", "typ": TYP}, separators=(",", ":"))
        return case(cid, spec, expect, op="jwt_claims", alg="HS256", jwk=HS, jwt=hs256(h, body), policy=POLICY, now=NOW)

    return [
        t("valid", "RFC 7519 7.2", OK),
        t("aud-array-contains", "RFC 7519 4.1.3 (an array of which one is ours)", OK, {"aud": ["other", AUD]}),
        t("exp-fractional", "RFC 7519 2 (NumericDate may be non-integer)", OK, {"exp": NOW + 300.5}),
        t("typ-application-prefix", "RFC 7515 4.1.9 (application/ prefix may be omitted) and RFC 9068 2.1", OK, hdr='{"alg":"HS256","typ":"application/at+jwt"}'),
        t("iss-wrong", "RFC 7519 4.1.1 and RFC 8725 3.8", kind("Issuer"), {"iss": "https://other.example"}),
        t("iss-missing", "RFC 8725 3.8", kind("MissingClaim"), drop=("iss",)),
        t("aud-wrong", "RFC 7519 4.1.3 (MUST be rejected)", kind("Audience"), {"aud": "other"}),
        t("aud-array-without", "RFC 7519 4.1.3", kind("Audience"), {"aud": ["other", "another"]}),
        t("aud-missing", "RFC 8725 3.9", kind("MissingClaim"), drop=("aud",)),
        t("exp-missing", "RFC 8725 3.10 with the contract (Expiry::Unchecked is opt-in)", kind("MissingClaim"), drop=("exp",)),
        t("exp-at-leeway-edge", "RFC 7519 4.1.4 (now MUST be before exp; leeway added)", kind("Expired"), {"exp": NOW - LEEWAY}),
        t("exp-inside-leeway", "RFC 7519 4.1.4 (small leeway allowed)", OK, {"exp": NOW - LEEWAY + 1}),
        t("exp-past", "RFC 7519 4.1.4", kind("Expired"), {"exp": NOW - 3600}),
        t("exp-string", "RFC 7519 2 (NumericDate is a JSON number)", kind("ClaimType"), {"exp": str(NOW + 300)}),
        t("nbf-at-leeway-edge", "RFC 7519 4.1.5 (now MUST be at or after nbf; leeway added)", OK, {"nbf": NOW + LEEWAY}),
        t("nbf-past-leeway", "RFC 7519 4.1.5", kind("NotYetValid"), {"nbf": NOW + LEEWAY + 1}),
        t("nbf-string", "RFC 7519 2", kind("ClaimType"), {"nbf": str(NOW)}),
        t("iat-string", "RFC 7519 2 and 4.1.6", kind("ClaimType"), {"iat": str(NOW)}),
        t("iat-future-past-leeway", "RFC 7519 4.1.6 with OIDC Core 3.1.3.7 step 10 (this oracle refuses an iat beyond now plus leeway)", kind("NotYetValid"), {"iat": NOW + LEEWAY + 1}),
        t("typ-wrong", "RFC 8725 3.11 (explicit typing)", kind("Type"), hdr='{"alg":"HS256","typ":"JWT"}'),
        t("typ-missing", "RFC 8725 3.11 and RFC 9068 4", kind("Type"), hdr='{"alg":"HS256"}'),
        t("dup-claim", "RFC 7519 4 (MUST reject or use the last; this oracle rejects)", kind("DuplicateMember"), raw=f'{{"iss":"https://other.example","iss":"{ISS}","aud":"{AUD}","exp":{NOW + 300}}}'),
        t("claims-array", "RFC 7519 7.2 step 10 (a JSON object)", kind("Malformed"), raw="[1]"),
        t("claims-leading-whitespace", "RFC 8259 2 (whitespace may precede a value) with RFC 7519 7.2 step 10", OK, raw=" \t\r\n" + json.dumps(base, separators=(",", ":"))),
        t("claims-whitespace-array", "RFC 8259 2 with RFC 7519 7.2 step 10 (a JSON object, not an array)", kind("Malformed"), raw=" \n[1]"),
    ]


def thumb(jwk, members):
    return b64(hashlib.sha256(json.dumps({m: jwk[m] for m in sorted(members)}, separators=(",", ":")).encode()).digest())


def thumbprint():
    t = lambda cid, spec, jwk, expect: case(cid, spec, expect, op="jwk_thumbprint", jwk=jwk)
    p384_priv = next(f["json"] for f in load("rfc7520/jwe.json")["figures"] if f["figure"] == 108)
    return [
        t("ec-p256", "RFC 7638 3.2 (crv, kty, x, y)", P256, {"out": thumb(P256, ("crv", "kty", "x", "y"))}),
        t("ec-p384-private-members-ignored", "RFC 7638 3.2 and 3.3 (only required public members)", p384_priv, {"out": thumb(p384_priv, ("crv", "kty", "x", "y"))}),
        t("rsa-optional-members-ignored", "RFC 7638 3.2 (e, kty, n)", RSA_KID, {"out": thumb(RSA_KID, ("e", "kty", "n"))}),
        t("oct", "RFC 7638 3.2 (k, kty)", HS_KID, {"out": thumb(HS_KID, ("k", "kty"))}),
        t("okp-ed25519", "RFC 8037 2 (crv, kty, x) and A.3", ED, {"out": thumb(ED, ("crv", "kty", "x"))}),
        t("ec-y-missing", "RFC 7638 3.2 (required members must be present)", {k: v for k, v in P256.items() if k != "y"}, kind("Malformed")),
        t("kty-unknown", "RFC 7638 3.2 (members are defined per kty)", {"kty": "unknown-kty", "x": "AA"}, kind("UnsupportedAlg")),
    ]


def limits():
    # each bound at the crate constant (excess 0: accepted) and one past it (excess 1: TooLarge); each case carries its exact input
    # the constants of rust/jose/CONTRACT.md, Signatures: MAX_COMPACT_LEN = 16_384, MAX_JSON_DEPTH = 32 (header, claims and JWK depth), MAX_JWKS_KEYS = 32
    MAX_COMPACT, MAX_DEPTH, MAX_KEYS = 16384, 32, 32
    l = lambda cid, spec, bound, ex, recipe, expect=None, **inp: case(cid, spec, expect or (OK if ex == 0 else kind("TooLarge")), op="limit", bound=bound, excess=ex, recipe=recipe, **inp, alg="HS256", jwk=HS)
    # a JWS is given as its header text and payload text (token = base64url(header) "." base64url(payload) "." base64url(HS256 MAC over those two parts with jwk)),
    # not as a ready token: a whole token reads as a credential to the repository secret scan
    jws = lambda header, payload: {"header_json": header, "payload_json": payload}

    def compact(total):
        for m in range(total * 3 // 4 - 200, total * 3 // 4 + 1):
            if len(hs256('{"alg":"HS256"}', b"a" * m)) == total:
                return {"header_json": '{"alg":"HS256"}', "payload_repeat": {"byte": "a", "count": m}, "token_len": total}
        raise ValueError(total)

    def nested(depth):
        return "[" * (depth - 1) + "]" * (depth - 1)

    out = []
    for ex in (0, 1):
        sfx = "" if ex else "-at-bound"
        tail = "" if ex else " (accepted: the input is exactly at the bound)"
        out += [
            l("compact-bytes" + sfx, "contract rule 5.7 (compact token bytes)" + tail, "jose::MAX_COMPACT_LEN", ex,
              "compact JWS, header {\"alg\":\"HS256\"}, payload the ASCII byte 'a' repeated, HS256 with jwk; the token is exactly the bound plus excess bytes long", **compact(MAX_COMPACT + ex)),
            l("header-depth" + sfx, "contract rule 5.7 (header JSON depth)" + tail, "jose::MAX_JSON_DEPTH", ex,
              "compact JWS whose header is {\"alg\":\"HS256\",\"x\":V} with V nested arrays [[...[]...]] so that the header's depth (the outer object is 1, each nested array or object adds 1) is the bound plus excess; payload {}, HS256 with jwk",
              **jws('{"alg":"HS256","x":' + nested(MAX_DEPTH + ex) + "}", "{}")),
            l("claims-depth" + sfx, "contract rule 5.7 (claims JSON depth)" + tail.replace("accepted", "not TooLarge"), "jose::MAX_JSON_DEPTH", ex,
              "compact JWS, header {\"alg\":\"HS256\"}, payload {\"x\":V} with V nested arrays so that the claims depth (counted as for the header) is the bound plus excess; HS256 with jwk; the claims are read through VerifiedJwt::claims with some Policy, so at excess 0 the expectation is {\"not_kind\": \"TooLarge\"}, not ok (a policy refusal such as MissingClaim is not the depth bound) and at excess 1 it is TooLarge",
              expect=None if ex else {"not_kind": "TooLarge"}, **jws('{"alg":"HS256"}', '{"x":' + nested(MAX_DEPTH + ex) + "}")),
            l("jwks-key-count" + sfx, "contract rule 5.7 (JWKS key count)" + tail, "jose::MAX_JWKS_KEYS", ex,
              "{\"keys\":[...]} holding the bound plus excess copies of jwk, the i-th (from 0) with kid \"k<i>\"",
              input=json.dumps({"keys": [dict(HS, kid=f"k{i}") for i in range(MAX_KEYS + ex)]}, separators=(",", ":"))),
        ]
    return out


def write(name, source, cases):
    p = os.path.join(OUT, "jose-derived", name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), name
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"source": source, "cases": cases}, fh, indent=1, ensure_ascii=False)
        fh.write("\n")


SRC = "derived by tools/derive_jose.py from keys pinned under vectors/ (RFC 7515 A.1-A.4, RFC 7520 3 and 5.4, RFC 8037 A); one spec section per case in `spec`"
write("header.json", "JOSE header rules; " + SRC, header())
write("keys.json", "key and algorithm binding; " + SRC, keys())
write("jwks.json", "JWK Set decoding and lookup; " + SRC, jwks())
write("claims.json", "JWT claims validation under a Policy (iss, aud, typ at+jwt, leeway 60, now 1700000000); " + SRC, claims())
write("thumbprint.json", "JWK thumbprints computed per RFC 7638 3.2 (SHA-256 of the required members, sorted, no whitespace); " + SRC, thumbprint())
write("limits.json", "each bound of contract rule 5.7 at the crate constant (excess 0, accepted by the reader the bound names; for claims-depth-at-bound, whose public reader VerifiedJwt::claims needs a Policy, the expectation is not_kind TooLarge: any outcome but TooLarge) and one past it (excess 1, TooLarge); the rule states no number, so `bound` names the crate constant, whose value is read from rust/jose/CONTRACT.md Signatures (MAX_COMPACT_LEN 16384, MAX_JSON_DEPTH 32 for header, claims and JWK depth, MAX_JWKS_KEYS 32), and each case carries its exact input (header_json and payload_json or payload_repeat for a JWS, `input` for the JWKS text) built per `recipe`", limits())
