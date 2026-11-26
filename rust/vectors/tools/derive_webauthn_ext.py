#!/usr/bin/env python3
"""Derive the extension families of webauthn-rp-derived from WebAuthn L3, RFC 8949, CTAP2 canonical CBOR, RFC 5280 and the TPM 2.0 structures.

usage: python3 -I derive_webauthn_ext.py <out-dir>
writes <out-dir>/webauthn-rp-derived/{cose,attestation-object,authentication,browser-binding,registration-ids,origins,
limits,chains,attestation,extensions,options-json,response-json}.json.
Every key is derived from a label at run time with RFC 6979 deterministic ECDSA, so the output is reproducible byte for
byte and no private key is stored in the repository or in a vector. tools/check_webauthn_ext.mjs re-verifies every
certificate and assertion signature with Node's crypto, so each refusal is for the one rule its case names.
`expect.kind` is set only for TooLarge, the class the architecture contract names for bounds.
Licence of this script: MIT OR Apache-2.0.
"""
import base64, hashlib, json, os, sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from webauthn_ext_lib import *  # noqa: E402,F403

OUT = sys.argv[1]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
sha = lambda b: hashlib.sha256(b).digest()
UP, UV, BE, BS, AT, ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80
RP, ORIGIN = "example.org", "https://example.org"
CHALLENGE = b64(sha(b"webauthn-rp-derived challenge"))
NOW = 1_800_000_000
OK, NO = {"ok": True}, {"ok": False}
TOO = {"ok": False, "kind": "TooLarge"}

CRED = Key("webauthn-rp-derived-ext credential", "p256")
PUB = CRED.pt


def cose_ec(pt, curve=P256, alg=-7):
    n = curve.size
    return c_map([(c_int(1), c_int(2)), (c_int(3), c_int(alg)), (c_int(-1), c_int(1 if curve is P256 else 2)),
                  (c_int(-2), c_bytes(int_bytes(pt[0], n))), (c_int(-3), c_bytes(int_bytes(pt[1], n)))])


COSE = cose_ec(PUB)
CRED_ID = sha(b"webauthn-rp-derived-ext credential id")
AAGUID = bytes.fromhex("00112233445566778899aabbccddeeff")


def client_data(**over):
    d = {"type": "webauthn.get", "challenge": CHALLENGE, "origin": ORIGIN, "crossOrigin": False}
    d.update(over)
    return json.dumps({k: v for k, v in d.items() if v is not None}, separators=(",", ":")).encode()


def auth_data(flags=UP | UV, count=6, rp=RP, ext=b"", rp_hash=None, attested=None):
    ad = (rp_hash or sha(rp.encode())) + bytes([flags | (ED if ext else 0) | (AT if attested else 0)]) + count.to_bytes(4, "big")
    return ad + (attested or b"") + ext


def attested(cred_id=CRED_ID, cose=None, aaguid=AAGUID):
    return aaguid + len(cred_id).to_bytes(2, "big") + cred_id + (cose or COSE)


def att_object(fmt="none", att_stmt=b"\xa0", flags=UP | UV, cred_id=CRED_ID, cose=None, ext=b"", aaguid=AAGUID, ad=None):
    ad = ad if ad is not None else auth_data(flags, 0, ext=ext, attested=attested(cred_id, cose, aaguid))
    return c_map([(c_text("fmt"), c_text(fmt)), (c_text("attStmt"), att_stmt), (c_text("authData"), c_bytes(ad))])


POLICY = {"rp_id": RP, "origin": ORIGIN, "challenge": CHALLENGE, "user_verification": "preferred", "counter_policy": "reject",
          "stored_counter": 5, "stored_backup_eligible": False, "cross_origin": "deny"}
REG_POLICY = {"rp_id": RP, "origin": ORIGIN, "challenge": CHALLENGE, "user_verification": "preferred", "pub_key_cred_params": [-7], "cross_origin": "deny"}
PUBJ = {"x": f"{PUB[0]:064x}", "y": f"{PUB[1]:064x}"}


def assertion(cid, spec, expect, cd=None, ad=None, **extra):
    cd = cd if cd is not None else client_data()
    ad = ad if ad is not None else auth_data()
    sig = CRED.sign(ad + sha(cd))
    return {"id": cid, "op": "webauthn_assert", "pub": PUBJ, "authenticator_data": ad.hex(), "client_data_json": cd.hex(), "signature": sig.hex(),
            **dict(POLICY, **extra), "spec": spec, "expect": expect}


def registration(cid, spec, expect, cd=None, ao=None, **extra):
    cd = cd if cd is not None else client_data(type="webauthn.create")
    ao = ao if ao is not None else att_object()
    return {"id": cid, "op": "webauthn_register", "attestation_object": ao.hex(), "client_data_json": cd.hex(), **dict(REG_POLICY, **extra), "spec": spec, "expect": expect}


REG_OK = lambda **kw: dict({"ok": True, "user_verified": True, "credential_id": CRED_ID.hex(), "public_key": PUBJ}, **kw)


def write(name, source, cases):
    cases = [x for x in cases if x]
    p = os.path.join(OUT, "webauthn-rp-derived", name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    assert len({x["id"] for x in cases}) == len(cases), name
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"source": source, "cases": cases}, fh, indent=1)
        fh.write("\n")
    print(name, len(cases))


CTX = ("assertions and attestation signed with a P-256 key derived from a label in tools/derive_webauthn_ext.py (RFC 6979 deterministic k); "
       "rp example.org, origin https://example.org, stored counter 5, BE stored clear, cross-origin denied unless the case says otherwise")


# ================================================================ cose.json (R5)
EP = 2**255 - 19
ED_D = -121665 * pow(121666, -1, EP) % EP


def ed_valid_point(enc):
    if len(enc) != 32:
        return False
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    if y >= EP:
        return False
    u, v = (y * y - 1) % EP, (ED_D * y * y + 1) % EP
    x2 = u * pow(v, -1, EP) % EP
    return x2 == 0 or pow(x2, (EP - 1) // 2, EP) == 1


ED_B = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
ED_RFC8032_1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
assert ed_valid_point(ED_B) and ed_valid_point(ED_RFC8032_1)
ED_BAD = next(bytes([i]) + bytes(31) for i in range(2, 256) if not ed_valid_point(bytes([i]) + bytes(31)))
PT384 = ec_key("webauthn-rp-derived-ext p384 cose", P384)[1]
PT256_B = ec_key("webauthn-rp-derived-ext p256 cose b", P256)[1]
RSA_C = Key("webauthn-rp-derived-ext rsa credential", "rsa").rsa


def odd_int(label, bits):
    return int.from_bytes(expand(label, (bits + 7) // 8), "big") % (1 << bits) | (1 << (bits - 1)) | 1


def cose_cases():
    ci = c_int
    m = lambda pairs: c_map([(ci(k) if isinstance(k, int) else c_text(k), v) for k, v in pairs])
    x, y = int_bytes(PUB[0], 32), int_bytes(PUB[1], 32)
    # helper: build from a dict of label -> encoded value, None removes
    def build(base, **ov):
        d = dict(base)
        for k, v in ov.items():
            lab = int(k[1:]) * (-1 if k[0] == "n" else 1)
            if v is None:
                d.pop(lab, None)
            else:
                d[lab] = v
        return m(list(d.items())).hex()

    E256 = {1: ci(2), 3: ci(-7), -1: ci(1), -2: c_bytes(x), -3: c_bytes(y)}
    E384 = {1: ci(2), 3: ci(-35), -1: ci(2), -2: c_bytes(int_bytes(PT384[0], 48)), -3: c_bytes(int_bytes(PT384[1], 48))}
    OKP = {1: ci(1), 3: ci(-8), -1: ci(6), -2: c_bytes(ED_B)}
    RSA = {1: ci(3), 3: ci(-257), -1: c_bytes(int_bytes(RSA_C["n"])), -2: c_bytes(b"\x01\x00\x01")}
    c = lambda cid, spec, hexs, expect: {"id": cid, "op": "cose_key", "input": hexs, "spec": spec, "expect": expect}
    R5 = "contract R5"
    bad = lambda cid, spec, hexs: c(cid, spec, hexs, NO)
    short = int_bytes(PUB[0], 32)[1:]
    off = (PUB[1] + 1) % P256.p
    return [
        c("es256-valid", "RFC 9053 7.1.1 and contract R5 (kty 2, crv 1, 32-byte x and y on the curve)", build(E256), {"ok": True, "alg": -7}),
        c("es384-valid", "RFC 9053 7.1.1 and contract R5 (crv 2, 48-byte x and y on the curve)", build(E384), {"ok": True, "alg": -35}),
        c("eddsa-valid", "RFC 9053 2.2 and contract R5 (kty 1, crv 6, a 32-byte valid point; the RFC 8032 base point)", build(OKP), {"ok": True, "alg": -8}),
        c("eddsa-rfc8032-key", "RFC 8032 7.1 test 1 public key as a COSE_Key (contract R5)", build(OKP, n2=c_bytes(ED_RFC8032_1)), {"ok": True, "alg": -8}),
        c("rs256-valid", "RFC 8812 2 and contract R5 (kty 3, a 2048-bit n, e 65537)", build(RSA), {"ok": True, "alg": -257}),
        c("rsa-4096-bit-n", "contract R5 (MAX_RSA_BITS 4096 is accepted; n is an odd 4096-bit integer, not a product of primes)", build(RSA, n1=c_bytes(int_bytes(odd_int("n4096", 4096)))), {"ok": True, "alg": -257}) | {"bound": "webauthn_rp::MAX_RSA_BITS", "excess": 0},
        c("unknown-label-ignored", "contract R5 (unknown labels are ignored)", build(E256, p99=ci(1)), {"ok": True, "alg": -7}),
        c("unknown-text-label-ignored", "contract R5 (unknown labels are ignored); a text label sorts after the integer labels", m(list(E256.items()) + [("extra", ci(1))]).hex(), {"ok": True, "alg": -7}),
        bad("es256-x-31-bytes", "contract R5 (x is 32 bytes)", build(E256, n2=c_bytes(short))),
        bad("es256-x-33-bytes", "contract R5 (x is 32 bytes)", build(E256, n2=c_bytes(b"\x00" + x))),
        bad("es256-y-31-bytes", "contract R5 (y is 32 bytes)", build(E256, n3=c_bytes(int_bytes(PUB[1], 32)[1:]))),
        bad("es256-off-curve", "contract R5 (the point is on the curve)", build(E256, n3=c_bytes(int_bytes(off, 32)))),
        bad("es256-x-zero-y-zero", "contract R5 (the point is on the curve: (0, 0) is not on P-256)", build(E256, n2=c_bytes(bytes(32)), n3=c_bytes(bytes(32)))),
        bad("es256-x-missing", "contract R5 (x is required)", build(E256, n2=None)),
        bad("es256-y-missing", "contract R5 (y is required)", build(E256, n3=None)),
        bad("es256-crv-missing", "contract R5 (crv is required)", build(E256, n1=None)),
        bad("es256-crv-p384-with-32-byte-coordinates", "contract R5 (crv 2 needs 48-byte coordinates)", build(E256, n1=ci(2))),
        bad("es256-alg-p384", "contract R5 (alg fits kty and crv: -35 is ES384, crv 1 is P-256)", build(E256, p3=ci(-35))),
        bad("es384-alg-es256", "contract R5 (alg -7 is ES256, crv 2 is P-384)", build(E384, p3=ci(-7))),
        bad("ec2-crv-ed25519", "contract R5 (kty 2 with crv 6 is not an EC2 curve)", build(E256, n1=ci(6))),
        bad("okp-crv-p256", "contract R5 (kty 1 with crv 1 is not an OKP curve)", build(OKP, n1=ci(1))),
        bad("alg-missing", "contract R5 (alg is present)", build(E256, p3=None)),
        bad("alg-rs256-on-ec2", "contract R5 (alg fits kty)", build(E256, p3=ci(-257))),
        bad("alg-es256-on-rsa", "contract R5 (alg fits kty)", build(RSA, p3=ci(-7))),
        bad("kty-text", "contract R5 (a defined label of the wrong type is Malformed)", build(E256, p1=c_text("EC2"))),
        bad("alg-text", "contract R5 (a defined label of the wrong type is Malformed)", build(E256, p3=c_text("ES256"))),
        bad("x-integer", "contract R5 (a defined label of the wrong type is Malformed)", build(E256, n2=ci(1))),
        bad("crv-text", "contract R5 (a defined label of the wrong type is Malformed)", build(E256, n1=c_text("P-256"))),
        bad("kty-symmetric", "RFC 9053 7.1 (kty 4 is not a public key type this crate reads)", build(E256, p1=ci(4))),
        bad("eddsa-point-not-on-curve", "contract R5 (a 32-byte valid point; the encoded y has no x on the curve)", build(OKP, n2=c_bytes(ED_BAD))),
        bad("eddsa-31-bytes", "contract R5 (a 32-byte point)", build(OKP, n2=c_bytes(ED_B[:31]))),
        bad("eddsa-33-bytes", "contract R5 (a 32-byte point)", build(OKP, n2=c_bytes(ED_B + b"\x00"))),
        bad("eddsa-y-not-reduced", "RFC 8032 5.1.3 (y must be below p; this is y = p, whose encoding is not canonical)", build(OKP, n2=c_bytes((EP).to_bytes(32, "little")))),
        bad("rsa-1024-bit-n", "contract R5 and RFC 8725 3.5 (n below MIN_RSA_BITS, taken as 2048; n is an odd 1024-bit integer)", build(RSA, n1=c_bytes(int_bytes(odd_int("n1024", 1024))))),
        c("rsa-4097-bit-n", "contract R1 and R5 (n past MAX_RSA_BITS 4096 is TooLarge; the excess is in bits; n is an odd 4097-bit integer)", build(RSA, n1=c_bytes(int_bytes(odd_int("n4097", 4097)))), TOO) | {"bound": "webauthn_rp::MAX_RSA_BITS", "excess": 1},
        bad("rsa-2047-bit-n", "contract R5 (n below MIN_RSA_BITS 2048 by one bit; n is an odd 2047-bit integer)", build(RSA, n1=c_bytes(int_bytes(odd_int("n2047", 2047))))),
        bad("rsa-e-3", "contract R5 (e is 65537)", build(RSA, n2=c_bytes(b"\x03"))),
        bad("rsa-e-65537-padded", "contract R5 (e is 65537; a leading zero byte is not the integer's minimal form)", build(RSA, n2=c_bytes(b"\x00\x01\x00\x01"))),
        bad("rsa-n-missing", "contract R5 (n is required)", build(RSA, n1=None)),
        bad("es512-p521", "N2 (ES512 is never offered; P-521 is outside the crate's curves)", build({1: ci(2), 3: ci(-36), -1: ci(3), -2: c_bytes(bytes([1]) * 66), -3: c_bytes(bytes([2]) * 66)})),
        bad("ed448", "N2 (Ed448 is never offered)", build({1: ci(1), 3: ci(-8), -1: ci(7), -2: c_bytes(bytes([1]) * 57)})),
        bad("x25519-ecdh", "contract R5 and ruling R-e (an OKP key for ECDH, crv 4, is not a signature key)", build({1: ci(1), 3: ci(-25), -1: ci(4), -2: c_bytes(ED_B)})),
        bad("ps256-alg", "N2 (PS256 is never offered)", build(RSA, p3=ci(-37))),
        bad("rs1-alg", "N2 (RS1 is never offered as a credential algorithm)", build(RSA, p3=ci(-65535))),
        bad("fully-specified-esp256", "N2 (the fully-specified -9 is never offered)", build(E256, p3=ci(-9))),
        bad("fully-specified-ed25519", "N2 (the fully-specified -19 is never offered)", build(OKP, p3=ci(-19))),
        bad("fully-specified-esp384", "N2 (the fully-specified -51 is never offered)", build(E384, p3=ci(-51))),
        bad("fully-specified-esp512", "N2 (the fully-specified -52 is never offered)", build(E256, p3=ci(-52))),
        bad("not-a-map", "RFC 9052 7 (a COSE_Key is a map)", c_array(ci(1), ci(2)).hex()),
        bad("empty-map", "contract R5 (kty is required)", "a0"),
    ]


# ================================================================ attestation-object.json (R40, R-n)
def attobj_cases():
    ad = auth_data(UP | UV, 0, attested=attested())
    t = lambda s: c_text(s)
    kv = lambda p: p[0] + p[1]
    fmt, stmt, adat = (t("fmt"), t("none")), (t("attStmt"), b"\xa0"), (t("authData"), c_bytes(ad))
    c = lambda cid, spec, raw, expect: {"id": cid, "op": "attestation_object", "input": raw.hex(), "spec": spec, "expect": expect}
    NOTE = "contract R40 (exactly fmt, attStmt, authData) with ruling R-n"
    return [
        c("canonical-order", "WebAuthn L3 6.5.4 and contract R40", c_map_raw([fmt, stmt, adat]), OK),
        c("authdata-first-order-tolerated", NOTE + " (the outer map is read order-tolerant: a client may re-encode it)", c_map_raw([adat, fmt, stmt]), OK),
        c("attstmt-first-order-tolerated", NOTE + " (attStmt first)", c_map_raw([stmt, fmt, adat]), OK),
        c("extra-member", NOTE, c_map([fmt, stmt, adat, (t("extra"), c_uint(1))]), NO),
        c("fmt-missing", NOTE, c_map([stmt, adat]), NO),
        c("attstmt-missing", NOTE, c_map([fmt, adat]), NO),
        c("authdata-missing", NOTE, c_map([fmt, stmt]), NO),
        c("fmt-bytes", NOTE + " (fmt is text)", c_map([(t("fmt"), c_bytes(b"none")), stmt, adat]), NO),
        c("attstmt-array", NOTE + " (attStmt is a map)", c_map([fmt, (t("attStmt"), c_array()), adat]), NO),
        c("attstmt-null", NOTE + " (attStmt is a map)", c_map([fmt, (t("attStmt"), b"\xf6"), adat]), NO),
        c("authdata-text", NOTE + " (authData is a byte string)", c_map([fmt, stmt, (t("authData"), c_text("x" * 37))]), NO),
        c("authdata-array-of-ints", NOTE + " (authData is a byte string, not an array of integers)", c_map([fmt, stmt, (t("authData"), c_array(*[c_uint(0)] * 37))]), NO),
        c("duplicate-fmt", "RFC 8949 5.6 (duplicate keys, even under an order-tolerant outer map)", cbor_head(5, 4) + kv(fmt) + kv(fmt) + kv(stmt) + kv(adat), NO),
        c("duplicate-key-three-members", "RFC 8949 5.6 (a map of three entries with a repeated key is not exactly fmt, attStmt, authData)", cbor_head(5, 3) + kv(fmt) + kv(fmt) + kv(adat), NO),
        c("indefinite-length-map", "RFC 8949 4.2.1 (no indefinite length, in the outer map too)", b"\xbf" + kv(fmt) + kv(stmt) + kv(adat) + b"\xff", NO),
        c("map-length-not-shortest", "RFC 8949 4.2.1 (shortest-form heads)", b"\xb8\x03" + kv(fmt) + kv(stmt) + kv(adat), NO),
        c("key-integer", NOTE, c_map([(c_uint(1), c_text("none")), stmt, adat]), NO),
        c("trailing-byte", "RFC 8949 5.1 with contract R2 (nothing after the top item)", c_map_raw([fmt, stmt, adat]) + b"\x00", NO),
        c("not-a-map", NOTE, c_array(c_text("none"), b"\xa0", c_bytes(ad)), NO),
        c("empty", "RFC 8949 5.1 (an item is required)", b"", NO),
        c("attstmt-noncanonical-order-refused", "ruling R-n (attStmt is authenticator-produced and read strict: its keys must be in canonical order; 'alg' then 'sig')",
          c_map_raw([(t("fmt"), t("packed")), (t("attStmt"), c_map_raw([(t("sig"), c_bytes(b"\x01")), (t("alg"), c_int(-7))])), adat]), NO),
        c("attstmt-canonical-order-read", "ruling R-n (an attStmt in canonical key order is read; structure only, the packed rules are checked in attestation.json)",
          c_map_raw([(t("fmt"), t("packed")), (t("attStmt"), c_map([(t("alg"), c_int(-7)), (t("sig"), c_bytes(b"\x01"))])), adat]), OK),
    ]


# ================================================================ authentication.json (R16, R64-R69)
UH = bytes([1]) * 32
UH2 = bytes([2]) * 32
OTHER_ID = sha(b"webauthn-rp-derived-ext other credential id")


def auth_cases():
    A = "WebAuthn L3 7.2 "
    cred = CRED_ID.hex()
    base = dict(raw_id=cred, stored_credential_id=cred, stored_user_handle=UH.hex())
    allow = lambda *ids: {"allow": {"credentials": [i.hex() for i in ids]}}
    user = lambda ident: {"allow": {"credentials": [], "identified_user": ident.hex()}}
    return [
        assertion("allow-listed", A + "step 5 (the credential is among allowCredentials)", OK | {"user_verified": True, "counter": 6}, **base, **allow(CRED_ID, OTHER_ID)),
        assertion("allow-not-listed", A + "step 5 (id not in allowCredentials; contract R64 NotAllowed)", NO, **base, **allow(OTHER_ID)),
        assertion("allow-list-of-one-other", A + "step 5 (a single listed credential that is not the response's; contract R64)", NO, **dict(base, raw_id=OTHER_ID.hex()), **allow(CRED_ID)),
        assertion("discoverable-no-list", A + "step 5 (an empty allow list adds no constraint; Allow::Discoverable)", OK | {"user_verified": True, "counter": 6}, **base, allow="discoverable", user_handle=UH.hex()),
        assertion("stored-credential-other-id", A + "step 6 (the stored credential's id is the response's; contract R65 CredentialMismatch)", NO, **dict(base, stored_credential_id=OTHER_ID.hex()), **allow(CRED_ID)),
        assertion("user-stored-other", A + "step 6 (the stored credential's user is the identified user; contract R66 UserHandleMismatch)", NO, **dict(base, stored_user_handle=UH2.hex()), **user(UH)),
        assertion("user-stored-same", A + "step 6 (contract R66)", OK | {"user_verified": True, "counter": 6}, **base, **user(UH)),
        assertion("user-handle-other", A + "step 6 (a present userHandle equals the identified user; contract R67 UserHandleMismatch)", NO, **base, **user(UH), user_handle=UH2.hex()),
        assertion("user-handle-same", A + "step 6 (contract R67)", OK | {"user_verified": True, "counter": 6}, **base, **user(UH), user_handle=UH.hex()),
        assertion("user-handle-absent-ok", A + "step 6 (contract R67: a userHandle may be absent under Allow::User)", OK | {"user_verified": True, "counter": 6}, **base, **user(UH)),
        assertion("user-handle-empty-reads-absent", "contract R16 (an empty userHandle reads as absent) with " + A + "step 6", OK | {"user_verified": True, "counter": 6}, **base, **user(UH), user_handle=""),
        assertion("discoverable-handle-missing", A + "step 6 (a discoverable response must carry userHandle; contract R68 UserHandleMismatch)", NO, **base, allow="discoverable"),
        assertion("discoverable-handle-empty", "contract R16 and R68 (an empty userHandle reads as absent, so a discoverable response is refused)", NO, **base, allow="discoverable", user_handle=""),
        assertion("discoverable-handle-other", A + "step 6 (the userHandle is the stored credential's user; contract R69 UserHandleMismatch)", NO, **base, allow="discoverable", user_handle=UH2.hex()),
        assertion("discoverable-handle-same", A + "step 6 (contract R69)", OK | {"user_verified": True, "counter": 6}, **base, allow="discoverable", user_handle=UH.hex()),
        assertion("discoverable-handle-one-bit", A + "step 6 (the handle compares in full: one bit differs; contract R69)", NO, **base, allow="discoverable", user_handle=(UH[:-1] + bytes([UH[-1] ^ 1])).hex()),
    ]


# ================================================================ browser-binding.json (R58, R63)
BIND = lambda label: sha(label.encode()).hex()


def binding_cases():
    a, b = BIND("browser a"), BIND("browser b")
    flipped = (bytes.fromhex(a)[:-1] + bytes([bytes.fromhex(a)[-1] ^ 1])).hex()
    R = "ruling R-d and contract R58 (BrowserMismatch)"
    S = "ruling R-d and contract R63 (BrowserMismatch)"
    return [
        registration("registration-same-browser", R, REG_OK(), binding=a, finish_binding=a),
        registration("registration-other-browser", R + ": the ceremony was started in another browser", NO, binding=a, finish_binding=b),
        registration("registration-one-bit-differs", R + ": one bit of the binding differs", NO, binding=a, finish_binding=flipped),
        registration("registration-zero-binding", R + ": an all-zero binding does not match a real one", NO, binding=a, finish_binding=bytes(32).hex()),
        assertion("authentication-same-browser", S, {"ok": True, "user_verified": True, "counter": 6}, binding=a, finish_binding=a),
        assertion("authentication-other-browser", S + ": the login was started in another browser (login CSRF)", NO, binding=a, finish_binding=b),
        assertion("authentication-one-bit-differs", S + ": one bit of the binding differs", NO, binding=a, finish_binding=flipped),
        assertion("authentication-zero-binding", S + ": an all-zero binding does not match a real one", NO, binding=a, finish_binding=bytes(32).hex()),
    ]


# ================================================================ registration-ids.json (R17)
def regid_cases():
    S = "contract R17 and WebAuthn L3 13.1 (the outer id is unsigned; the attested credential id is the credential's id; CredentialIdInvalid)"
    other = bytearray(CRED_ID)
    other[0] ^= 1
    return [
        registration("raw-id-equals-attested", S, REG_OK(), raw_id=CRED_ID.hex()),
        registration("raw-id-one-bit-differs", S, NO, raw_id=bytes(other).hex()),
        registration("raw-id-longer", S + ": raw id has one extra byte", NO, raw_id=(CRED_ID + b"\x00").hex()),
        registration("raw-id-prefix", S + ": raw id is a prefix of the attested id", NO, raw_id=CRED_ID[:-1].hex()),
        registration("raw-id-empty", S, NO, raw_id=""),
        registration("raw-id-unrelated", S, NO, raw_id=OTHER_ID.hex()),
    ]


# ================================================================ origins.json (R8, R9, R10)
def origin_cases():
    apk = ("AZaz09-_" * 6)[:42] + "A"  # low entropy on purpose, every base64url symbol present, the last symbol one of A Q g w so 43 symbols are a canonical 32-byte value: a real signer hash would read as a credential to the repository secret scan
    assert len(apk) == 43
    o = lambda cid, s, spec, ok: {"id": cid, "op": "origin_parse", "input": s, "spec": spec, "expect": OK if ok else NO}
    r = lambda cid, s, spec, ok: {"id": cid, "op": "rp_id_parse", "input": s, "spec": spec, "expect": OK if ok else NO}
    a = lambda cid, s, spec, ok: {"id": cid, "op": "app_id_parse", "input": s, "spec": spec, "expect": dict(OK, as_written=s) if ok else NO}
    R8, R9, R10 = "contract R8 ", "contract R9 ", "contract R10 "
    LDH = " (lowercase LDH labels, RFC 5890 2.3.1: a hyphen is not first or last)"
    cs = [
        o("origin-https", "https://example.org", R8 + "(https scheme and a host)", True),
        o("origin-https-port", "https://example.org:8443", R8 + "(a port that is not the scheme's default)", True),
        o("origin-https-subdomain", "https://login.example.org", R8 + "(several labels)", True),
        o("origin-https-port-1", "https://example.org:1", R8 + "(decimal port, lowest)", True),
        o("origin-https-port-65535", "https://example.org:65535", R8 + "(decimal port, highest)", True),
        o("origin-digit-label", "https://1example.org", R8 + LDH, True),
        o("origin-inner-hyphen", "https://a-b.example", R8 + LDH, True),
        o("origin-a-label", "https://xn--bcher-kva.example", R8 + "(A-labels as written, never converted)", True),
        o("origin-http-localhost", "http://localhost", R8 + "(http only for the host localhost)", True),
        o("origin-http-localhost-port", "http://localhost:8080", R8 + "(http for localhost with a port)", True),
        o("origin-https-localhost", "https://localhost", R8 + "(localhost over https)", True),
        o("origin-android", "android:apk-key-hash:" + apk, R8 + "(android:apk-key-hash: with 43 base64url symbols)", True),
        o("origin-http-other-host", "http://example.org", R8 + "(http is for localhost only)", False),
        o("origin-http-ip", "http://127.0.0.1", R8 + "(http is for the host localhost only, not an IP literal)", False),
        o("origin-http-localhost-suffix", "http://localhost.example", R8 + "(http only for the host localhost exactly)", False),
        o("origin-http-subdomain-of-localhost", "http://app.localhost", R8 + "(http only for the host localhost exactly)", False),
        o("origin-https-default-port", "https://example.org:443", R8 + "(a port that is not the scheme's default)", False),
        o("origin-http-localhost-default-port", "http://localhost:80", R8 + "(a port that is not the scheme's default)", False),
        o("origin-empty-port", "https://example.org:", R8 + "(a decimal port when a colon is written)", False),
        o("origin-port-zero", "https://example.org:0", R8 + "(a decimal port; 0 is not a port)", False),
        o("origin-port-65536", "https://example.org:65536", R8 + "(a decimal port of 16 bits)", False),
        o("origin-port-text", "https://example.org:http", R8 + "(a decimal port)", False),
        o("origin-two-ports", "https://example.org:8443:9", R8 + "(one optional port)", False),
        o("origin-uppercase-host", "https://Example.org", R8 + "(lowercase labels)", False),
        o("origin-uppercase-scheme", "HTTPS://example.org", R8 + "(the scheme is https, written as such)", False),
        o("origin-trailing-dot", "https://example.org.", R8 + "(no empty label)", False),
        o("origin-empty-label", "https://a..example.org", R8 + "(no empty label)", False),
        o("origin-leading-dot", "https://.example.org", R8 + "(no empty label)", False),
        o("origin-leading-hyphen", "https://-a.example.org", R8 + LDH, False),
        o("origin-trailing-hyphen", "https://a-.example.org", R8 + LDH, False),
        o("origin-underscore", "https://exa_mple.org", R8 + "(LDH labels: letters, digits, hyphen)", False),
        o("origin-u-label", "https://bücher.example", R8 + "(A-labels as written: a non-ASCII label is refused, never converted)", False),
        o("origin-ipv4", "https://192.168.0.1", R8 + "(an IP literal is refused)", False),
        o("origin-ipv4-port", "https://192.168.0.1:8443", R8 + "(an IP literal is refused)", False),
        o("origin-ipv6", "https://[::1]", R8 + "(an IP literal is refused)", False),
        o("origin-ipv6-port", "https://[::1]:8443", R8 + "(an IP literal is refused)", False),
        o("origin-path-slash", "https://example.org/", R8 + "(nothing after the host and port; an origin has no path)", False),
        o("origin-path", "https://example.org/login", R8 + "(no path)", False),
        o("origin-port-then-slash", "https://example.org:8443/", R8 + "(no path)", False),
        o("origin-query", "https://example.org?x=1", R8 + "(no query)", False),
        o("origin-fragment", "https://example.org#f", R8 + "(no fragment)", False),
        o("origin-userinfo", "https://user@example.org", R8 + "(no userinfo)", False),
        o("origin-userinfo-password", "https://user:pw@example.org", R8 + "(no userinfo)", False),
        o("origin-ftp", "ftp://example.org", R8 + "(any other scheme is refused)", False),
        o("origin-wss", "wss://example.org", R8 + "(any other scheme is refused)", False),
        o("origin-no-scheme", "example.org", R8 + "(a scheme is required)", False),
        o("origin-scheme-relative", "//example.org", R8 + "(a scheme is required)", False),
        o("origin-scheme-only", "https://", R8 + "(a host is required)", False),
        o("origin-empty", "", R8 + "(an origin is required)", False),
        o("origin-leading-space", " https://example.org", R8 + "(nothing around the origin)", False),
        o("origin-trailing-space", "https://example.org ", R8 + "(nothing after the host and port)", False),
        o("origin-percent-escape", "https://example%2eorg", R8 + "(LDH labels only)", False),
        o("origin-android-42-symbols", "android:apk-key-hash:" + apk[:42], R8 + "(exactly 43 base64url symbols)", False),
        o("origin-android-44-symbols", "android:apk-key-hash:" + apk + "A", R8 + "(exactly 43 base64url symbols)", False),
        o("origin-android-padded", "android:apk-key-hash:" + apk[:42] + "=", R8 + "(base64url symbols, no padding)", False),
        o("origin-android-standard-alphabet", "android:apk-key-hash:" + apk[:41].replace("-", "+").replace("_", "/") + "+A", R8 + "(base64url symbols: '+' is not one)", False),
        o("origin-android-empty-hash", "android:apk-key-hash:", R8 + "(exactly 43 base64url symbols)", False),
        o("origin-android-trailing-slash", "android:apk-key-hash:" + apk + "/", R8 + "(nothing after the hash)", False),
        o("origin-android-uppercase-scheme", "Android:apk-key-hash:" + apk, R8 + "(the scheme as written)", False),
        r("rp-id-registrable", "example.org", R9 + "(lowercase LDH labels)", True),
        r("rp-id-subdomain", "login.example.org", R9 + "(several labels)", True),
        r("rp-id-localhost", "localhost", R9 + "(localhost is accepted)", True),
        r("rp-id-a-label", "xn--bcher-kva.example", R9 + "(A-labels as written)", True),
        r("rp-id-uppercase", "Example.org", R9 + "(lowercase labels)", False),
        r("rp-id-trailing-dot", "example.org.", R9 + "(a trailing dot is refused)", False),
        r("rp-id-empty-label", "a..example.org", R9 + "(an empty label is refused)", False),
        r("rp-id-leading-dot", ".example.org", R9 + "(an empty label is refused)", False),
        r("rp-id-empty", "", R9 + "(an empty value where one is required is Malformed)", False),
        r("rp-id-ipv4", "192.168.0.1", R9 + "(an IP literal is refused)", False),
        r("rp-id-ipv6", "::1", R9 + "(an IP literal is refused)", False),
        r("rp-id-ipv6-bracketed", "[::1]", R9 + "(an IP literal is refused)", False),
        r("rp-id-with-port", "example.org:8443", R9 + "(an RP ID has no port)", False),
        r("rp-id-with-scheme", "https://example.org", R9 + "(an RP ID is a domain, not an origin)", False),
        r("rp-id-with-path", "example.org/", R9 + "(an RP ID has no path)", False),
        r("rp-id-leading-hyphen", "-a.example.org", R9 + LDH, False),
        r("rp-id-underscore", "exa_mple.org", R9 + "(LDH labels)", False),
        r("rp-id-u-label", "bücher.example", R9 + "(A-labels as written; a non-ASCII label is refused)", False),
        r("rp-id-trailing-space", "example.org ", R9 + "(LDH labels only)", False),
        a("app-id-https-json", "https://example.org/app-id.json", R10 + "(an https URL, hashed as written)", True),
        a("app-id-origin-only", "https://example.org", R10 + "(an https URL)", True),
        a("app-id-port-query", "https://example.org:8443/a/b?q=1", R10 + "(an https URL without fragment; a port and a query are allowed)", True),
        a("app-id-uppercase-kept", "https://EXAMPLE.org/App", R10 + "(hashed as written: no case folding)", True),
        a("app-id-http", "http://example.org/app-id.json", R10 + "(https only)", False),
        a("app-id-fragment", "https://example.org/app-id.json#f", R10 + "(without fragment)", False),
        a("app-id-empty-fragment", "https://example.org/app-id.json#", R10 + "(without fragment, an empty one included)", False),
        a("app-id-ftp", "ftp://example.org/app-id.json", R10 + "(https only)", False),
        a("app-id-no-scheme", "example.org/app-id.json", R10 + "(an https URL)", False),
        a("app-id-empty", "", R10 + "(an AppID is required)", False),
        a("app-id-scheme-only", "https://", R10 + "(an https URL has a host)", False),
        a("app-id-android", "android:apk-key-hash:" + apk, R10 + "(an https URL)", False),
    ]
    return cs


# ================================================================ PKI helpers and chains.json (R110-R117)
class Ent:
    def __init__(self, key, subject, der):
        self.key, self.subject, self.der = key, subject, der


def dn(cn, printable_all=False):
    if printable_all:
        return seq(sset(seq(oid("2.5.4.6"), printable("US"))), sset(seq(oid("2.5.4.10"), printable("Derived Test PKI"))), sset(seq(oid("2.5.4.3"), printable(cn))))
    return name(C="US", O="Derived Test PKI", CN=cn)


def issue(cn, issuer=None, kind="p256", ca=True, pathlen=None, ku="default", extra=(), bc=True, nb=1_700_000_000, na=1_900_000_000,
          hname=None, version=3, serial=None, issuer_subject=None, subject=None, key=None, label=None):
    key = key or Key(label or f"webauthn-rp-derived-ext pki {cn} {kind}", kind)
    subject = subject if subject is not None else dn(cn)
    exts = []
    if bc:
        exts.append(basic_constraints(ca, pathlen if ca else None))
    if ku == "default":
        ku = [5, 6] if ca else [0]
    if ku:
        exts.append(key_usage(ku))
    exts += list(extra)
    signer = issuer.key if issuer else key
    iss_name = issuer_subject if issuer_subject is not None else (issuer.subject if issuer else subject)
    serial = serial or int.from_bytes(sha(cn.encode() + kind.encode())[:8], "big")
    der = make_cert(subject, iss_name, key.spki, signer, exts, serial=serial, nb=nb, na=na, version=version, hname=hname)
    return Ent(key, subject, der)


CRIT_UNKNOWN = ext("1.3.6.1.4.1.99999.1.1", null(), True)
PLAIN_UNKNOWN = ext("1.3.6.1.4.1.99999.1.2", null(), False)
SAN_CRIT = ext("2.5.29.17", seq(ctx(4, dn("Derived SAN"))), True)
EKU_CRIT = ext("2.5.29.37", seq(oid("1.3.6.1.5.5.7.3.2")), True)

ROOT = issue("Derived Root", None, "p256", pathlen=None)
INT = issue("Derived Intermediate", ROOT, "p256", pathlen=0)
LEAF = issue("Derived Leaf", INT, "p256", ca=False)
DECOY = issue("Derived Root", None, "p256", label="webauthn-rp-derived-ext decoy root")  # same subject, another key
OTHER_ROOT = issue("Derived Other Root", None, "p256")


def chain(cid, spec, x5c, anchors, outcome, now=NOW, **kw):
    expect = {"ok": outcome == "Anchored", "outcome": outcome} if outcome != "TooLarge" else TOO
    return {"id": cid, "op": "x5c_walk", "x5c": [e.der.hex() for e in x5c], "anchors": [e.der.hex() for e in anchors], "now": now, "spec": spec, "expect": expect, **kw}


def flip_signature(der, offset=-3):
    b = bytearray(der)
    b[offset] ^= 0x01
    return bytes(b)


def chain_cases():
    Wk = "contract "
    ok, un, bad = "Anchored", "Unanchored", "AttestationInvalid"
    cs = []
    add = cs.append
    # --- shape and anchoring
    add(chain("anchored-leaf-int", Wk + "R111 (each signature verifies under the next certificate's key, the last under an anchor whose subject is its issuer)", [LEAF, INT], [ROOT], ok))
    add(chain("anchored-leaf-only", Wk + "R111 (a leaf issued directly by the anchor)", [issue("Derived Direct Leaf", ROOT, "p256", ca=False)], [ROOT], ok))
    add(chain("last-is-anchor-byte-for-byte", Wk + "R111 (or the last certificate is an anchor byte for byte)", [LEAF, INT, ROOT], [ROOT], ok))
    add(chain("last-matches-anchor-subject-only", Wk + "R111 (a last certificate that only shares an anchor's subject is not that anchor byte for byte; its signature is checked under the anchor)", [LEAF, INT, ROOT], [DECOY], un))
    add(chain("shared-subject-decoy-first", Wk + "R111 and ruling R-h W-S6 (every anchor whose subject matches is tried, in order: the decoy fails, the real root anchors)", [LEAF, INT], [DECOY, ROOT], ok))
    add(chain("shared-subject-decoy-last", Wk + "R111 and ruling R-h W-S6 (two anchors sharing a subject cannot hide each other)", [LEAF, INT], [ROOT, DECOY], ok))
    add(chain("shared-subject-decoy-only", Wk + "R111 and R117 (an internally valid chain that meets no anchor is Unanchored)", [LEAF, INT], [DECOY], un))
    add(chain("anchor-other-subject", Wk + "R117 (an internally valid chain that meets no anchor is Unanchored)", [LEAF, INT], [OTHER_ROOT], un))
    add(chain("anchors-empty", Wk + "R117 (no anchor at all)", [LEAF, INT], [], un))
    add(chain("missing-intermediate", Wk + "R110 (the walk follows x5c in order and never builds a path: the leaf's issuer names no anchor) with R117", [LEAF], [ROOT], un))
    add(chain("x5c-out-of-order", Wk + "R110 (x5c is followed in order, never reordered into a path) with R112 (the first certificate's issuer is not the second's subject)", [INT, LEAF], [ROOT], bad))
    add(chain("unrelated-second-certificate", Wk + "R110 and R112 (the second certificate is not the leaf's issuer)", [LEAF, OTHER_ROOT], [ROOT], bad))
    # --- names (R112)
    wrong_issuer = issue("Derived Leaf Wrong Issuer", INT, "p256", ca=False, issuer_subject=dn("Derived Intermediatf"))
    add(chain("issuer-name-differs-one-letter", Wk + "R112 (issuer and subject chain by exact DER equality)", [wrong_issuer, INT], [ROOT], bad))
    enc_issuer = issue("Derived Leaf Reencoded Issuer", INT, "p256", ca=False, issuer_subject=dn("Derived Intermediate", printable_all=True))
    add(chain("issuer-name-same-text-other-encoding", Wk + "R112 (exact DER equality: the same text as PrintableString is a different name from UTF8String)", [enc_issuer, INT], [ROOT], bad))
    # --- CA rules (R113)
    int_not_ca = issue("Derived Not CA", ROOT, "p256", ca=False)
    add(chain("intermediate-not-ca", Wk + "R113 (every certificate above the leaf has basicConstraints CA true)", [issue("Leaf Under Not CA", int_not_ca, "p256", ca=False), int_not_ca], [ROOT], bad))
    int_nobc = issue("Derived No BasicConstraints", ROOT, "p256", bc=False, ku=None)
    add(chain("intermediate-no-basic-constraints", Wk + "R113 (basicConstraints is required on a CA)", [issue("Leaf Under No BC", int_nobc, "p256", ca=False), int_nobc], [ROOT], bad))
    int_v1 = issue("Derived Version 1 CA", ROOT, "p256", version=1)
    add(chain("intermediate-version-1", Wk + "R113 (a version 1 certificate has no basicConstraints, so it is no CA)", [issue("Leaf Under V1", int_v1, "p256", ca=False), int_v1], [ROOT], bad))
    a0 = issue("Derived Int Path0", ROOT, "p256", pathlen=0)
    b1 = issue("Derived Int Below Path0", a0, "p256", pathlen=None)
    add(chain("path-length-zero-exceeded", Wk + "R113 (a path length its depth respects: pathLen 0 allows no CA below it)", [issue("Leaf Below B1", b1, "p256", ca=False), b1, a0], [ROOT], bad))
    a1 = issue("Derived Int Path1", ROOT, "p256", pathlen=1)
    b0 = issue("Derived Int Below Path1", a1, "p256", pathlen=0)
    add(chain("path-length-one-respected", Wk + "R113 (pathLen 1 allows one CA below it)", [issue("Leaf Below B0", b0, "p256", ca=False), b0, a1], [ROOT], ok))
    b_over = issue("Derived Int Below Path1 B", a1, "p256", pathlen=0)
    c_over = issue("Derived Int Below B0 C", b_over, "p256", pathlen=0)
    add(chain("path-length-one-exceeded-by-two", Wk + "R113 (pathLen 1 below which two CAs sit)", [issue("Leaf Below C", c_over, "p256", ca=False), c_over, b_over, a1], [ROOT], bad))
    int_ku_sig = issue("Derived Int Sig Only", ROOT, "p256", ku=[0])
    add(chain("intermediate-key-usage-no-cert-sign", Wk + "R113 (keyCertSign when keyUsage is present)", [issue("Leaf Under KU", int_ku_sig, "p256", ca=False), int_ku_sig], [ROOT], bad))
    int_noku = issue("Derived Int No KU", ROOT, "p256", ku=None)
    add(chain("intermediate-no-key-usage", Wk + "R113 (keyCertSign is required only when keyUsage is present)", [issue("Leaf Under No KU", int_noku, "p256", ca=False), int_noku], [ROOT], ok))
    # --- validity (R114)
    nb, na = 1_700_000_000, 1_900_000_000
    mk_int = lambda cn, **kw: issue(cn, ROOT, "p256", pathlen=0, **kw)
    add(chain("intermediate-expired", Wk + "R114 (every certificate's validity contains now)", [issue("Leaf Exp Int", e := mk_int("Derived Expired Int", na=NOW - 1), "p256", ca=False), e], [ROOT], bad))
    add(chain("intermediate-not-yet-valid", Wk + "R114", [issue("Leaf NYV Int", e := mk_int("Derived Future Int", nb=NOW + 1), "p256", ca=False), e], [ROOT], bad))
    add(chain("leaf-expired", Wk + "R114", [issue("Derived Expired Leaf", INT, "p256", ca=False, na=NOW - 1), INT], [ROOT], bad))
    add(chain("leaf-not-yet-valid", Wk + "R114", [issue("Derived Future Leaf", INT, "p256", ca=False, nb=NOW + 1), INT], [ROOT], bad))
    add(chain("leaf-not-before-equals-now", Wk + "R114 and RFC 5280 4.1.2.5 (the validity period includes notBefore)", [issue("Derived Boundary Leaf Nb", INT, "p256", ca=False, nb=NOW), INT], [ROOT], ok))
    add(chain("leaf-not-after-equals-now", Wk + "R114 and RFC 5280 4.1.2.5 (the validity period includes notAfter)", [issue("Derived Boundary Leaf Na", INT, "p256", ca=False, na=NOW), INT], [ROOT], ok))
    add(chain("leaf-one-second-past-not-after", Wk + "R114", [issue("Derived Boundary Leaf Past", INT, "p256", ca=False, na=NOW - 1), INT], [ROOT], bad))
    exp_root = issue("Derived Root", None, "p256", na=NOW - 1, label="webauthn-rp-derived-ext expired root")
    add(chain("anchor-expired", Wk + "R114 (every certificate's validity, an anchor's included; oracle choice: RFC 5280 6.1 does not check a trust anchor's validity, so this is stricter than the RFC)", [issue("Leaf Exp Root", INT0 := issue("Derived Int Under Exp Root", exp_root, "p256", pathlen=0), "p256", ca=False), INT0], [exp_root], bad))
    add(chain("leaf-validity-in-generalized-time", Wk + "R114 (a validity past 2049 is a GeneralizedTime, RFC 5280 4.1.2.5)", [issue("Derived Long Leaf", INT, "p256", ca=False, na=2_600_000_000), INT], [ROOT], ok))
    # --- critical extensions (R115)
    add(chain("leaf-critical-unknown-extension", Wk + "R115 (the leaf may carry critical extensions the walk does not read)", [issue("Derived Crit Leaf", INT, "p256", ca=False, extra=[CRIT_UNKNOWN]), INT], [ROOT], ok))
    add(chain("leaf-critical-san-eku", Wk + "R115 (the TPM leaf's critical SAN and EKU pass)", [issue("Derived Crit SAN Leaf", INT, "p256", ca=False, extra=[SAN_CRIT, EKU_CRIT]), INT], [ROOT], ok))
    crit_int = issue("Derived Crit Int", ROOT, "p256", pathlen=0, extra=[CRIT_UNKNOWN])
    add(chain("intermediate-critical-unknown-extension", Wk + "R115 (on a CA certificate a critical extension other than basicConstraints, keyUsage, extKeyUsage and subjectAltName fails the walk)", [issue("Leaf Crit Int", crit_int, "p256", ca=False), crit_int], [ROOT], bad))
    ok_int = issue("Derived Allowed Crit Int", ROOT, "p256", pathlen=0, extra=[SAN_CRIT, EKU_CRIT])
    add(chain("intermediate-critical-eku-san", Wk + "R115 (critical subjectAltName and extKeyUsage on a CA are among the allowed)", [issue("Leaf Allowed Crit Int", ok_int, "p256", ca=False), ok_int], [ROOT], ok))
    plain_int = issue("Derived Plain Ext Int", ROOT, "p256", pathlen=0, extra=[PLAIN_UNKNOWN])
    add(chain("intermediate-noncritical-unknown-extension", Wk + "R115 (only a critical extension fails)", [issue("Leaf Plain Ext Int", plain_int, "p256", ca=False), plain_int], [ROOT], ok))
    crit_root = issue("Derived Crit Root", None, "p256", extra=[CRIT_UNKNOWN])
    add(chain("anchor-critical-unknown-extension", Wk + "R115 (on an anchor too)", [issue("Leaf Crit Root", crit_root, "p256", ca=False)], [crit_root], bad))
    # --- signature algorithms (R116, R117)
    r384 = issue("Derived Root P384", None, "p384")
    i384 = issue("Derived Int P384", r384, "p384", pathlen=0)
    add(chain("p384-root-p384-intermediate", Wk + "R116 (ecdsa-with-SHA384 on P-384)", [issue("Derived Leaf Under P384", i384, "p256", ca=False), i384], [r384], ok))
    i_under_384 = issue("Derived P256 Int Under P384 Root", r384, "p256", pathlen=0)
    add(chain("p256-intermediate-under-p384-root", Wk + "R116 (a P-384 anchor signs a P-256 certificate with ecdsa-with-SHA384)", [issue("Derived Leaf Under Mixed", i_under_384, "p256", ca=False), i_under_384], [r384], ok))
    rsa_root = issue("Derived Root RSA", None, "rsa")
    for h in ("sha256", "sha384", "sha512"):
        ri = issue(f"Derived Int Under RSA {h}", rsa_root, "p256", pathlen=0, hname=h)
        add(chain(f"rsa-root-{h}", Wk + f"R116 ({h} with RSA of 2048 bits signs the intermediate)", [issue(f"Derived Leaf Under RSA {h}", ri, "p256", ca=False), ri], [rsa_root], ok))
    rsa_int = issue("Derived Int RSA", ROOT, "rsa", pathlen=0)
    add(chain("rsa-intermediate-signs-leaf", Wk + "R116 (sha256 with RSA signs the leaf)", [issue("Derived Leaf Under RSA Int", rsa_int, "p256", ca=False, hname="sha256"), rsa_int], [ROOT], ok))
    add(chain("ecdsa-sha1-leaf", Wk + "R117 (a chain signed by an algorithm outside R116, ecdsa-with-SHA1, is Unanchored)", [issue("Derived Leaf Sha1", INT, "p256", ca=False, hname="sha1"), INT], [ROOT], un))
    add(chain("ecdsa-sha512-on-p256-leaf", Wk + "R117 (ecdsa-with-SHA512 is outside R116)", [issue("Derived Leaf Sha512", INT, "p256", ca=False, hname="sha512"), INT], [ROOT], un))
    add(chain("rsa-sha1-intermediate", Wk + "R117 (sha1 with RSA is outside R116)", [issue("Derived Leaf Under RSA Sha1", s := issue("Derived Int RSA Sha1", rsa_root, "p256", pathlen=0, hname="sha1"), "p256", ca=False), s], [rsa_root], un))
    add(chain("ecdsa-sha1-to-anchor", Wk + "R117 (the last certificate's signature under the anchor is ecdsa-with-SHA1)", [issue("Derived Leaf Under Sha1 Int", s1 := issue("Derived Int Sha1 To Root", ROOT, "p256", pathlen=0, hname="sha1"), "p256", ca=False), s1], [ROOT], un))
    r521 = issue("Derived Root P521", None, "p521", hname="sha384")
    i521 = issue("Derived Int P521", ROOT, "p521", pathlen=0)
    add(chain("p521-intermediate", "N3 and R117 (the leaf's signature is made by a P-521 intermediate key: Unanchored)", [issue("Derived Leaf Under P521", i521, "p256", ca=False, hname="sha384"), i521], [ROOT], un))
    add(chain("p521-anchor", "N3 and R117 (the last certificate's signature under a P-521 anchor key: Unanchored)", [issue("Derived Leaf Under P521 Root", r521, "p256", ca=False, hname="sha384")], [r521], un))
    # --- signature failures
    tampered = Ent(LEAF.key, LEAF.subject, flip_signature(LEAF.der))
    add(chain("leaf-signature-tampered", Wk + "R111 (a signature that does not verify under the next certificate's key is AttestationInvalid, never Unanchored; R117)", [tampered, INT], [ROOT], bad))
    body = bytearray(LEAF.der)
    body[body.rindex(b"Derived Leaf") + 5] ^= 0x01
    add(chain("leaf-body-tampered", Wk + "R111 (a changed byte in the signed part)", [Ent(LEAF.key, LEAF.subject, bytes(body)), INT], [ROOT], bad))
    add(chain("intermediate-signature-tampered", Wk + "R111 and R117 (the intermediate's signature under the anchor fails while the anchor's subject matches: every matching anchor is tried, then Unanchored)", [LEAF, Ent(INT.key, INT.subject, flip_signature(INT.der))], [ROOT], un))
    # --- length (R110, MAX_X5C = 8)
    def long_chain(n_certs):
        prev, certs = ROOT, []
        for i in range(n_certs - 1):
            prev = issue(f"Derived Long Int {i}", prev, "p256", pathlen=None)
            certs.append(prev)
        leaf = issue("Derived Long Leaf End", prev, "p256", ca=False)
        return [leaf] + certs[::-1]
    add(chain("x5c-8-certificates", Wk + "R110 and R1 (MAX_X5C is 8: eight certificates and the anchor are walked)", long_chain(8), [ROOT], ok))
    add(chain("x5c-9-certificates", Wk + "R110 and R1 (MAX_X5C is 8: a ninth certificate is TooLarge)", long_chain(9), [ROOT], "TooLarge"))
    return cs


# ================================================================ limits.json (R1, R6, R18)
def sized(cid, op, bound, value, excess, spec, make, expect_ok=None, recipe=None, extra=None):
    data = make(value + excess)
    case = {"id": cid, "op": op, "bound": "webauthn_rp::" + bound, "excess": excess, "spec": spec}
    if isinstance(data, bytes):
        case["input_len"], case["input_sha256"] = len(data), sha(data).hex()
        if len(data) <= 4096:
            case["input"] = data.hex()
        else:
            case["input_b64url"] = b64(data)
    else:
        case["input"] = data
    if recipe:
        case["recipe"] = recipe
    case.update(extra or {})
    case["expect"] = (expect_ok or OK) if excess == 0 else TOO
    return case


def pad_to(target, build):
    n = max(target - len(build(0)), 0)
    for k in range(-40, 41):
        if n + k >= 0 and len(out := build(n + k)) == target:
            return out
    raise ValueError(target)


def make_client_json(total):
    base = client_data()
    k = total - (len(base) + len(b',"pad":""'))
    return base[:-1] + b',"pad":"' + b"a" * k + b'"}'


def make_client_depth(kind):
    def f(depth):
        base = client_data()
        if kind == "objects":
            return base[:-1] + b',"x":' + b'{"x":' * (depth - 2) + b"{}" + b"}" * (depth - 2) + b"}"
        return base[:-1] + b',"x":' + b"[" * (depth - 1) + b"]" * (depth - 1) + b"}"
    return f


def make_att_object(total):
    def build(k):
        return c_map([(c_text("fmt"), c_text("none")), (c_text("attStmt"), c_map([(c_text("pad"), c_bytes(bytes(k)))])), (c_text("authData"), c_bytes(auth_data(UP | UV, 0, attested=attested())))])
    return pad_to(total, build)


def make_authdata(total):
    def build(k):
        return auth_data(UP | UV, 6, ext=c_map([(c_text("pad"), c_bytes(bytes(k)))]))
    return pad_to(total, build)


def make_cbor_depth(depth):
    return b"\x81" * depth + b"\x00"


def make_cbor_items(items):
    return cbor_head(4, items - 1) + b"\x00" * (items - 1)


def make_anchor(total):
    # the ECDSA signature length varies with the content, so a serial number is tried until the DER is exactly the target
    for serial in range(1, 64):
        try:
            return pad_to(total, lambda k: issue("Derived Padded Anchor", None, "p256", extra=[ext("1.3.6.1.4.1.99999.1.3", octets(bytes(k)))], serial=serial).der)
        except ValueError:
            continue
    raise ValueError(total)


def make_rp_id(total):
    labels, left = [], total
    while left > 0:
        n = min(63, left if left < 64 else 63)
        if left - n == 1:
            n -= 1
        labels.append("a" * n)
        left -= n + 1
    s = ".".join(labels)
    assert len(s) == total and all(0 < len(x) <= 63 for x in s.split(".")), (total, len(s))
    return s


def limit_cases():
    L = "contract R1 (each bound is a public constant; input past it is TooLarge)"
    cs = []
    for ex in (0, 1):
        sfx = "at-bound" if ex == 0 else "one-past"
        cs.append(sized(f"client-data-json-{sfx}", "client_data", "MAX_CLIENT_DATA_JSON", 16384, ex, L + " and R6 (clientDataJSON size)", make_client_json,
                        recipe="the members type, challenge, origin and crossOrigin of a webauthn.get clientDataJSON, then a string member `pad` of 'a' bytes, the whole document exactly bound+excess bytes"))
    for kind in ("objects", "arrays"):
        for ex in (0, 1):
            sfx = "at-bound" if ex == 0 else "one-past"
            cs.append(sized(f"client-data-depth-{kind}-{sfx}", "client_data", "MAX_CLIENT_DATA_DEPTH", 8, ex, L + " and R6 (nesting past MAX_CLIENT_DATA_DEPTH is TooLarge; the top-level object is depth 1)", make_client_depth(kind),
                            recipe=f"a valid webauthn.get clientDataJSON with a member `x` holding nested {kind} so that the deepest container is at depth bound+excess"))
    for ex in (0, 1):
        sfx = "at-bound" if ex == 0 else "one-past"
        cs.append(sized(f"attestation-object-{sfx}", "attestation_object", "MAX_ATTESTATION_OBJECT", 65536, ex, L + " and R40 (the attestation object's size)", make_att_object,
                        recipe="a fmt none attestation object whose attStmt map holds one `pad` entry of zero bytes, the whole object exactly bound+excess bytes (shape only; the none rules are not applied)"))
        cs.append(sized(f"authenticator-data-{sfx}", "authenticator_data", "MAX_AUTHENTICATOR_DATA", 16384, ex, L + " and R4 (authenticator data's size)", make_authdata,
                        recipe="authenticator data of UP|UV|ED whose extensions map holds one `pad` entry of zero bytes, the whole value exactly bound+excess bytes (shape only)"))
        cs.append(sized(f"cbor-depth-{sfx}", "cbor_limit", "MAX_CBOR_DEPTH", 16, ex, L + " and R2 (CBOR nesting depth; the outer array is depth 1)", make_cbor_depth,
                        recipe="nested one-element arrays 0x81 ... 0x81 0x00 whose depth is bound+excess"))
        cs.append(sized(f"cbor-items-{sfx}", "cbor_limit", "MAX_CBOR_ITEMS", 1024, ex, L + " and R2 (CBOR item count, the array itself included)", make_cbor_items,
                        recipe="one definite array of bound+excess-1 items of 0x00, so the item count with the array itself is bound+excess"))
        cs.append(sized(f"trust-anchor-{sfx}", "trust_anchor_from_der", "MAX_CERTIFICATE", 8192, ex, L + " and R18 (TrustAnchor::from_der takes one DER certificate of at most MAX_CERTIFICATE bytes)", make_anchor,
                        expect_ok=dict(OK), recipe="a self-signed P-256 certificate whose non-critical private extension is padded so the DER is exactly bound+excess bytes"))
        if ex == 0:
            cs[-1]["expect"] = {"ok": True, "digest": sha(make_anchor(8192)).hex()}
        cs.append(sized(f"rp-id-{sfx}", "rp_id_parse", "MAX_RP_ID", 253, ex, L + " and R9 (an RP ID of at most MAX_RP_ID bytes in all)", make_rp_id, recipe="lowercase 'a' labels of at most 63 bytes joined by dots, bound+excess bytes in all"))
        cs.append(sized(f"app-id-{sfx}", "app_id_parse", "MAX_APP_ID", 2048, ex, L + " and R10 (an AppID of at most MAX_APP_ID bytes)", lambda n: "https://example.org/" + "a" * (n - len("https://example.org/")),
                        recipe="https://example.org/ then 'a' bytes, bound+excess bytes in all"))
        n = 64 + ex
        cs.append({"id": f"exclude-list-{sfx}", "op": "start_registration", "bound": "webauthn_rp::MAX_LISTED_CREDENTIALS", "excess": ex, "spec": L + " and R31 (an exclude list over MAX_LISTED_CREDENTIALS)",
                   "exclude_credentials": [sha(f"exclude {i}".encode())[:16].hex() for i in range(n)], "expect": OK if ex == 0 else TOO})
        cs.append({"id": f"allow-list-{sfx}", "op": "start_authentication", "bound": "webauthn_rp::MAX_LISTED_CREDENTIALS", "excess": ex, "spec": L + " and R1 (an Allow::User list over MAX_LISTED_CREDENTIALS)",
                   "allow_credentials": [sha(f"allow {i}".encode())[:16].hex() for i in range(n)], "expect": OK if ex == 0 else TOO})
        cs.append({"id": f"prf-salt-{sfx}", "op": "start_registration", "bound": "webauthn_rp::MAX_PRF_SALT", "excess": ex, "spec": L + " and R31 (a PRF salt over MAX_PRF_SALT)",
                   "extensions": {"prf": {"eval": {"first": b64(bytes([7]) * (256 + ex))}}}, "expect": OK if ex == 0 else TOO})
        cs.append({"id": f"prf-salt-auth-{sfx}", "op": "start_authentication", "bound": "webauthn_rp::MAX_PRF_SALT", "excess": ex, "spec": L + " and R61 (a PRF salt over MAX_PRF_SALT at start_authentication; the salt is base64url as in the other authentication extension requests)",
                   "allow": "discoverable", "extensions": {"prf": {"eval": {"first": b64(bytes([7]) * (256 + ex))}}}, "expect": OK if ex == 0 else TOO})
        cs.append({"id": f"origins-{sfx}", "op": "relying_party_build", "bound": "webauthn_rp::MAX_ORIGINS", "excess": ex, "spec": L + " and R19 (more than MAX_ORIGINS origins and top origins together)",
                   "origins": [f"https://o{i}.example.org" for i in range(32 + ex)], "expect": OK if ex == 0 else TOO})
        cs.append({"id": f"timeout-{sfx}", "op": "start_registration", "bound": "webauthn_rp::MAX_TIMEOUT_SECS", "excess": ex, "spec": L + " (a timeout over MAX_TIMEOUT_SECS seconds)",
                   "timeout_secs": 600 + ex, "expect": OK if ex == 0 else TOO})
        cs.append({"id": f"user-handle-{sfx}", "op": "user_handle_from_stored", "bound": "webauthn_rp::MAX_USER_HANDLE", "excess": ex, "spec": L + " and N16 (a stored handle is 1 to MAX_USER_HANDLE bytes)",
                   "input": (bytes([9]) * (64 + ex)).hex(), "expect": OK if ex == 0 else TOO})
        cs.append({"id": f"user-name-{sfx}", "op": "start_registration", "bound": "webauthn_rp::MAX_NAME", "excess": ex, "spec": L + " and N18 (name and display name are checked for length and emptiness only)",
                   "user": {"name": "n" * (256 + ex), "display_name": "d"}, "expect": OK if ex == 0 else TOO})
        cs.append({"id": f"signature-{sfx}", "op": "assertion_response", "bound": "webauthn_rp::MAX_SIGNATURE", "excess": ex, "spec": L + " (AuthenticationResponse::new reads a signature of at most MAX_SIGNATURE bytes; it is not verified at construction)",
                   "signature": (bytes([5]) * (1024 + ex)).hex(), "expect": OK if ex == 0 else TOO})
        cs.append({"id": f"large-blob-{sfx}", "op": "largeblob_result", "bound": "webauthn_rp::MAX_LARGE_BLOB", "excess": ex, "spec": L + " and R127 (a blob past MAX_LARGE_BLOB is TooLarge)",
                   "input_len": 65536 + ex, "input_sha256": sha(bytes([3]) * (65536 + ex)).hex(), "input_b64url": b64(bytes([3]) * (65536 + ex)), "recipe": "the byte 0x03 repeated bound+excess times, returned as the largeBlob `blob` after a Read request", "expect": OK if ex == 0 else TOO})
    cs += [
        {"id": "record-large-blob-half-bound", "op": "start_authentication", "bound": "webauthn_rp::MAX_RECORD", "blob_len": 4096,
         "spec": "contract R1, R15, R61 and R142 (a ceremony row well under MAX_RECORD: a largeBlob write of MAX_RECORD/2 bytes is accepted). Oracle choice, a disclosed gap: R15 and R142 do not say what the row keeps of the blob, so this case reads the row as keeping it at no more than its length plus a fixed overhead; the TooLarge record case stays dropped until the CONTRACT fixes that",
         "allow": "discoverable", "extensions": {"largeBlob": {"write": b64(bytes([3]) * 4096)}}, "expect": OK},
        {"id": "trust-anchor-one-certificate", "op": "trust_anchor_from_der", "input": ROOT.der.hex(), "spec": "contract R18 (exactly one DER certificate; digest is the SHA-256 of that DER)", "expect": {"ok": True, "digest": sha(ROOT.der).hex()}},
        {"id": "trust-anchor-two-certificates", "op": "trust_anchor_from_der", "input": (ROOT.der + INT.der).hex(), "spec": "contract R18 (exactly one DER certificate, not a concatenation)", "expect": NO},
        {"id": "trust-anchor-trailing-byte", "op": "trust_anchor_from_der", "input": (ROOT.der + b"\x00").hex(), "spec": "contract R18 (exactly one DER certificate: nothing after it)", "expect": NO},
        {"id": "trust-anchor-truncated", "op": "trust_anchor_from_der", "input": ROOT.der[:-1].hex(), "spec": "contract R18 and R3 (a DER length past the input)", "expect": NO},
        {"id": "trust-anchor-empty", "op": "trust_anchor_from_der", "input": "", "spec": "contract R1 (an empty value where one is required is Malformed)", "expect": NO},
        {"id": "trust-anchor-pem-text", "op": "trust_anchor_from_der", "input": b"-----BEGIN CERTIFICATE-----\n".hex(), "spec": "contract R18 (DER, not PEM)", "expect": NO},
        {"id": "trust-anchor-not-a-certificate", "op": "trust_anchor_from_der", "input": seq(integer(1)).hex(), "spec": "contract R18 (a certificate)", "expect": NO},
    ]
    return cs


# ================================================================ attestation.json (R92-R97)
ATT_ROOT = issue("Derived Attestation Root", None, "p256", label="webauthn-rp-derived-ext attestation root")
ATT_INT = issue("Derived Attestation CA", ATT_ROOT, "p256", pathlen=0, label="webauthn-rp-derived-ext attestation ca")
AAGUID_OID, SERNUM_OID = "1.3.6.1.4.1.45724.1.1.4", "1.3.6.1.4.1.45724.1.1.2"
AAGUID_EXT = lambda v=AAGUID, crit=False: ext(AAGUID_OID, octets(v), crit)
SERNUM_EXT = lambda crit=False: ext(SERNUM_OID, octets(b"derived-serial-0001"), crit)
CDJ_REG = client_data(type="webauthn.create")
CDH = sha(CDJ_REG)


def att_reg(cid, spec, expect, fmt, stmt, *, ad=None, cd=CDJ_REG, anchors=(ATT_ROOT,), cose=None, aaguid=AAGUID, **extra):
    ao = att_object(fmt=fmt, att_stmt=stmt, ad=ad, aaguid=aaguid, cose=cose)
    return registration(cid, spec, expect, cd=cd, ao=ao, trust_anchors=[a.der.hex() for a in anchors], now=NOW, **extra)


def registered_ad(cose=None, aaguid=AAGUID, cred_id=CRED_ID):
    return auth_data(UP | UV, 0, attested=attested(cred_id, cose, aaguid))


T = c_text
PACKED_AD = registered_ad()
PACKED_SIGDATA = PACKED_AD + CDH


def packed_leaf(cn="Derived Packed Attestation", exts=None, **kw):
    subj = kw.pop("subject", None) or name(C="US", O="Derived Vendor", OU="Authenticator Attestation", CN=cn)
    return issue(cn, ATT_INT, "p256", ca=False, subject=subj, extra=exts or [], label=f"webauthn-rp-derived-ext packed leaf {cn}", **kw)


def packed_stmt(leaf, alg=-7, sig=None, key=None, extra_chain=None, data=None):
    key = key or leaf.key
    sig = sig if sig is not None else key.sign(data if data is not None else PACKED_SIGDATA)
    return c_map([(T("alg"), c_int(alg)), (T("sig"), c_bytes(sig)), (T("x5c"), c_array(*[c_bytes(d) for d in [leaf.der] + (extra_chain or [ATT_INT.der])]))])


def packed_cases():
    P = "contract R92 and WebAuthn L3 8.2.1 "
    okp = lambda **kw: REG_OK(attestation=dict({"fmt": "packed", "type": "Uncertain", "trust": "Anchored"}, **kw))
    cs = []

    def add(cid, spec, expect, leaf, **kw):
        cs.append(att_reg(cid, P + spec, expect, "packed", packed_stmt(leaf, **kw)))

    add("packed-full-no-extensions", "(a full attestation certificate without the optional extensions)", okp(), packed_leaf())
    add("packed-aaguid-extension-matches", "(an AAGUID extension, non-critical, equal to the attested AAGUID)", okp(), packed_leaf("Derived Packed Aaguid", exts=[AAGUID_EXT()]))
    add("packed-aaguid-and-serial-extensions", "(AAGUID and serial-number extensions, both non-critical)", okp(), packed_leaf("Derived Packed Aaguid Serial", exts=[AAGUID_EXT(), SERNUM_EXT()]))
    add("packed-serial-extension-only", "(a non-critical serial-number extension)", okp(), packed_leaf("Derived Packed Serial", exts=[SERNUM_EXT()]))
    add("packed-aaguid-mismatch", "(an AAGUID extension that differs from the attested AAGUID is refused)", NO, packed_leaf("Derived Packed Aaguid Other", exts=[AAGUID_EXT(bytes(16))]))
    add("packed-aaguid-one-byte-short", "(the AAGUID extension holds 16 bytes)", NO, packed_leaf("Derived Packed Aaguid Short", exts=[AAGUID_EXT(AAGUID[:15])]))
    add("packed-aaguid-critical", "(the AAGUID extension MUST be non-critical)", NO, packed_leaf("Derived Packed Aaguid Critical", exts=[AAGUID_EXT(AAGUID, True)]))
    add("packed-serial-critical", "(the serial-number extension MUST be non-critical)", NO, packed_leaf("Derived Packed Serial Critical", exts=[SERNUM_EXT(True)]))
    add("packed-subject-ou-wrong", "(OU MUST be the literal string Authenticator Attestation)", NO, packed_leaf("Derived Packed OU", subject=name(C="US", O="Derived Vendor", OU="Authenticator Attestations", CN="Derived Packed OU")))
    add("packed-subject-no-c", "(the subject has C)", NO, packed_leaf("Derived Packed No C", subject=name(O="Derived Vendor", OU="Authenticator Attestation", CN="Derived Packed No C")))
    add("packed-subject-no-o", "(the subject has O)", NO, packed_leaf("Derived Packed No O", subject=name(C="US", OU="Authenticator Attestation", CN="Derived Packed No O")))
    add("packed-subject-no-ou", "(the subject has OU)", NO, packed_leaf("Derived Packed No OU", subject=name(C="US", O="Derived Vendor", CN="Derived Packed No OU")))
    add("packed-subject-no-cn", "(the subject has CN)", NO, packed_leaf("Derived Packed No CN", subject=name(C="US", O="Derived Vendor", OU="Authenticator Attestation")))
    cs.append(att_reg("packed-leaf-is-ca", P + "(basicConstraints CA MUST be false)", NO, "packed", packed_stmt(L := issue("Derived Packed CA Leaf", ATT_INT, "p256", ca=True, pathlen=0, subject=name(C="US", O="Derived Vendor", OU="Authenticator Attestation", CN="Derived Packed CA Leaf"), label="webauthn-rp-derived-ext packed ca leaf"))))
    cs.append(att_reg("packed-leaf-version-1", P + "(the certificate MUST be version 3)", NO, "packed", packed_stmt(issue("Derived Packed V1", ATT_INT, "p256", ca=False, version=1, subject=name(C="US", O="Derived Vendor", OU="Authenticator Attestation", CN="Derived Packed V1"), label="webauthn-rp-derived-ext packed v1"))))
    base = packed_leaf("Derived Packed Sig")
    add("packed-signature-other-data", "(sig covers authenticatorData and clientDataHash; this one covers authenticatorData alone)", NO, base, data=PACKED_AD)
    add("packed-signature-bit-flip", "(sig verifies with the x5c[0] key)", NO, base, sig=base.key.sign(PACKED_SIGDATA[:-1] + bytes([PACKED_SIGDATA[-1] ^ 1])))
    add("packed-signature-other-key", "(sig verifies with the x5c[0] key, not another key)", NO, base, key=CRED)
    add("packed-alg-not-the-leaf-key", "(sig is verified under alg: ES384 over a P-256 leaf fails)", NO, base, alg=-35)
    add("packed-leaf-expired", "with R114 (the leaf's validity contains now)", NO, issue("Derived Packed Expired", ATT_INT, "p256", ca=False, na=NOW - 1, subject=name(C="US", O="Derived Vendor", OU="Authenticator Attestation", CN="Derived Packed Expired"), label="webauthn-rp-derived-ext packed expired"))
    cs.append(att_reg("packed-x5c-empty", P + "(x5c is a non-empty array for a full attestation)", NO, "packed",
                      c_map([(T("alg"), c_int(-7)), (T("sig"), c_bytes(base.key.sign(PACKED_SIGDATA))), (T("x5c"), c_array())])))
    cs.append(att_reg("packed-unanchored-accepted", "contract R50 and R117 (under the default TrustPolicy::AcceptUntrusted a verified statement whose chain meets no anchor registers, reported Unanchored)", REG_OK(attestation={"fmt": "packed", "type": "Uncertain", "trust": "Unanchored"}),
                      "packed", packed_stmt(base), anchors=(OTHER_ROOT,)))
    cs.append(att_reg("packed-unanchored-require-trusted", "contract R50 (under TrustPolicy::RequireTrusted an unanchored statement is Untrusted)", NO, "packed", packed_stmt(base), anchors=(OTHER_ROOT,), trust_policy="require_trusted"))
    cs.append(att_reg("packed-anchored-require-trusted", "contract R50 (under RequireTrusted an anchored statement registers)", okp(), "packed", packed_stmt(base), trust_policy="require_trusted"))
    return cs


# ---- TPM (R93-R95)
def tpm_pub_ecc(pt, name_alg=0x000B, attrs=0x00060472, extra=b"", x=None, y=None):
    x = x if x is not None else int_bytes(pt[0], 32)
    y = y if y is not None else int_bytes(pt[1], 32)
    return (b"\x00\x23" + name_alg.to_bytes(2, "big") + attrs.to_bytes(4, "big") + b"\x00\x00" + b"\x00\x10" + b"\x00\x10" + b"\x00\x03" + b"\x00\x10"
            + len(x).to_bytes(2, "big") + x + len(y).to_bytes(2, "big") + y + extra)


def tpm_pub_rsa(n, name_alg=0x000B):
    nb = int_bytes(n)
    return b"\x00\x01" + name_alg.to_bytes(2, "big") + (0x00060472).to_bytes(4, "big") + b"\x00\x00" + b"\x00\x10" + b"\x00\x10" + (2048).to_bytes(2, "big") + b"\x00\x00\x00\x00" + len(nb).to_bytes(2, "big") + nb


def tpm_name(pub, name_alg=0x000B):
    h = {0x000B: hashlib.sha256, 0x0004: hashlib.sha1, 0x000C: hashlib.sha384}[name_alg]
    return name_alg.to_bytes(2, "big") + h(pub).digest()


def tpm_attest(extra, name, magic=0xFF544347, typ=0x8017, tail=b""):
    q = b"\x00\x0b" + bytes(32)
    return (magic.to_bytes(4, "big") + typ.to_bytes(2, "big") + len(q).to_bytes(2, "big") + q + len(extra).to_bytes(2, "big") + extra
            + (1234).to_bytes(8, "big") + (1).to_bytes(4, "big") + (2).to_bytes(4, "big") + b"\x01" + (0x0102030405060708).to_bytes(8, "big")
            + len(name).to_bytes(2, "big") + name + b"\x00\x00" + tail)


TPM_AIK_P = Key("webauthn-rp-derived-ext tpm aik p256", "p256")
TPM_AIK_R = Key("webauthn-rp-derived-ext tpm aik rsa", "rsa")
TPM_AIK_P384 = Key("webauthn-rp-derived-ext tpm aik p384", "p384")
TPM_OID_EKU = "2.23.133.8.3"
TPM_SAN = lambda: ext("2.5.29.17", seq(ctx(4, seq(sset(seq(oid("2.23.133.2.1"), utf8("id:4E544300"))), sset(seq(oid("2.23.133.2.2"), utf8("DerivedTPM"))), sset(seq(oid("2.23.133.2.3"), utf8("id:00010002")))))), True)


def aik_cert(key, cn, subject=None, san=True, eku=(TPM_OID_EKU,), ca=False, extra=(), **kw):
    exts = ([TPM_SAN()] if san else []) + ([ext("2.5.29.37", seq(*[oid(o) for o in eku]), True)] if eku else []) + list(extra)
    return issue(cn, ATT_ROOT, "p256", ca=ca, pathlen=0 if ca else None, subject=subject if subject is not None else seq(), key=key, ku=None, extra=exts, **kw)


def tpm_case(cid, spec, expect, *, aik=None, alg=-7, ver="2.0", pub=None, cert_info=None, data=None, sig_key=None, sig_hash=None, cose=None, params=None, name_alg=0x000B,
             pub_override=None, extra_ad=None, drop=()):
    """One TPM registration; every part defaults to the valid one and the case overrides one."""
    cose = cose or COSE
    ad = registered_ad(cose=cose)
    cdh = CDH
    hname = {-65535: "sha1", -35: "sha384"}.get(alg, "sha256")
    pa = pub_override if pub_override is not None else (pub if pub is not None else (tpm_pub_rsa(RSA_C["n"], name_alg) if cose is not COSE and params and params[0] == -257 else tpm_pub_ecc(PUB, name_alg)))
    aik = aik or (aik_cert(TPM_AIK_P, "Derived TPM AIK P256") if alg in (-7, -35) else aik_cert(TPM_AIK_R, "Derived TPM AIK RSA"))
    ci = cert_info if cert_info is not None else tpm_attest(hashlib.new(hname, ad + cdh).digest(), tpm_name(pa, name_alg))
    sk = sig_key or aik.key
    sg = sk.sign(data if data is not None else ci, hname)
    stmt = [(T("ver"), T(ver)), (T("alg"), c_int(alg)), (T("x5c"), c_array(c_bytes(aik.der))), (T("sig"), c_bytes(sg)), (T("certInfo"), c_bytes(ci)), (T("pubArea"), c_bytes(pa))]
    stmt = [kv for kv in stmt if kv[0] not in [T(d) for d in drop]]
    return att_reg(cid, "contract R93 to R95 and WebAuthn L3 8.3 " + spec, expect, "tpm", c_map(stmt), ad=ad, cose=cose, pub_key_cred_params=(params or [-7]))


def tpm_cases():
    okt = lambda **kw: REG_OK(attestation={"fmt": "tpm", "type": "AttCa", "trust": "Anchored"}, **kw)
    cs = []
    add = cs.append
    add(tpm_case("tpm-es256-aik", "(an ES256 AIK; critical SAN and EKU on the leaf pass)", okt()))
    add(tpm_case("tpm-rs256-aik", "(an RSA AIK with RS256)", okt(), alg=-257))
    add(tpm_case("tpm-rs1-aik", "(RS1: an RSA AIK signs SHA-1 over certInfo, extraData is SHA-1)", okt(), alg=-65535))
    rsa_cose = c_map([(c_int(1), c_int(3)), (c_int(3), c_int(-257)), (c_int(-1), c_bytes(int_bytes(RSA_C["n"]))), (c_int(-2), c_bytes(b"\x01\x00\x01"))])
    t = tpm_case("tpm-rsa-credential-key", "(an RSA credential key: TPMT_PUBLIC type RSA, 2048 bits, unique n)", REG_OK(public_key={"n": int_bytes(RSA_C["n"]).hex(), "e": "010001"}, attestation={"fmt": "tpm", "type": "AttCa", "trust": "Anchored"}), cose=rsa_cose, params=[-257])
    add(t)
    add(tpm_case("tpm-name-alg-sha1", "(nameAlg SHA-1: the attested name is 0004 then the SHA-1 of pubArea)", okt(), name_alg=0x0004))
    add(tpm_case("tpm-aik-aaguid-matches", "(an AAGUID extension on the AIK equals the attested AAGUID)", okt(), aik=aik_cert(TPM_AIK_P, "Derived TPM AIK Aaguid", extra=[AAGUID_EXT()])))
    add(tpm_case("tpm-ver-1-0", "(ver is 2.0)", NO, ver="1.0"))
    add(tpm_case("tpm-ver-missing", "(ver is required)", NO, drop=("ver",)))
    other = ec_key("webauthn-rp-derived-ext tpm other credential", P256)[1]
    add(tpm_case("tpm-pubarea-other-key", "(the pubArea key equals the credential key)", NO, pub=tpm_pub_ecc(other)))
    add(tpm_case("tpm-pubarea-y-differs", "(the pubArea key equals the credential key: y differs in one bit)", NO, pub=tpm_pub_ecc(PUB, y=int_bytes(PUB[1] ^ 1, 32))))
    add(tpm_case("tpm-pubarea-wrong-type", "(pubArea is an RSA or ECC TPMT_PUBLIC; type 0x0008 is KEYEDHASH)", NO, pub=b"\x00\x08" + tpm_pub_ecc(PUB)[2:]))
    add(tpm_case("tpm-pubarea-trailing-bytes", "(own bounded parser: nothing after the unique field)", NO, pub=tpm_pub_ecc(PUB, extra=b"\x00")))
    add(tpm_case("tpm-pubarea-truncated", "(own bounded parser: a declared length past the input)", NO, pub=tpm_pub_ecc(PUB)[:-1]))
    add(tpm_case("tpm-pubarea-name-alg-unsupported", "(nameAlg is SHA-256 or SHA-1; 0x000c is SHA-384, with the attested name and the pubArea otherwise consistent)", NO, name_alg=0x000C))
    pa = tpm_pub_ecc(PUB)
    ed = hashlib.sha256(PACKED_AD + CDH).digest()
    good_extra = hashlib.sha256(registered_ad() + CDH).digest()
    add(tpm_case("tpm-certinfo-magic", "(certInfo magic is TPM_GENERATED_VALUE)", NO, cert_info=tpm_attest(good_extra, tpm_name(pa), magic=0xFF544348)))
    add(tpm_case("tpm-certinfo-type-quote", "(certInfo type is TPM_ST_ATTEST_CERTIFY; 0x8018 is QUOTE)", NO, cert_info=tpm_attest(good_extra, tpm_name(pa), typ=0x8018)))
    add(tpm_case("tpm-certinfo-extradata-authdata-only", "(extraData is the hash of authData then the client data hash; this is authData alone)", NO, cert_info=tpm_attest(hashlib.sha256(registered_ad()).digest(), tpm_name(pa))))
    add(tpm_case("tpm-certinfo-extradata-sha1", "(extraData is the hash under alg's hash: SHA-1 under ES256 is wrong)", NO, cert_info=tpm_attest(hashlib.sha1(registered_ad() + CDH).digest(), tpm_name(pa))))
    add(tpm_case("tpm-certinfo-name-other-pubarea", "(the attested name is nameAlg then the hash of pubArea)", NO, cert_info=tpm_attest(good_extra, tpm_name(tpm_pub_ecc(other)))))
    add(tpm_case("tpm-certinfo-name-wrong-alg-prefix", "(the attested name's first two bytes are nameAlg: 0004 over a SHA-256 hash)", NO, cert_info=tpm_attest(good_extra, b"\x00\x04" + hashlib.sha256(pa).digest())))
    add(tpm_case("tpm-certinfo-truncated", "(own bounded parser: a declared length past the input)", NO, cert_info=tpm_attest(good_extra, tpm_name(pa))[:-5]))
    add(tpm_case("tpm-signature-over-other-data", "(sig verifies over certInfo)", NO, data=b"not certInfo"))
    add(tpm_case("tpm-signature-other-key", "(sig verifies with the AIK certificate key)", NO, sig_key=CRED))
    add(tpm_case("tpm-alg-es256-rsa-aik", "(alg ES256 with an RSA AIK: the signature cannot verify under alg)", NO, aik=aik_cert(TPM_AIK_R, "Derived TPM AIK RSA Mismatch"), alg=-7))
    add(tpm_case("tpm-alg-es384", "(alg is RS256, RS1 or ES256; ES384 is not accepted: the statement is otherwise valid under ES384 with SHA-384)", NO, alg=-35, aik=aik_cert(TPM_AIK_P384, "Derived TPM AIK P384")))
    add(tpm_case("tpm-aik-subject-not-empty", "and 8.3.1 (the AIK certificate subject is empty)", NO, aik=aik_cert(TPM_AIK_P, "Derived TPM AIK Subject", subject=dn("Derived TPM AIK Subject"))))
    add(tpm_case("tpm-aik-no-san", "and 8.3.1 (a subject alternative name is required)", NO, aik=aik_cert(TPM_AIK_P, "Derived TPM AIK No SAN", san=False)))
    add(tpm_case("tpm-aik-no-eku", "and 8.3.1 (extended key usage 2.23.133.8.3 is required)", NO, aik=aik_cert(TPM_AIK_P, "Derived TPM AIK No EKU", eku=())))
    add(tpm_case("tpm-aik-eku-other", "and 8.3.1 (extended key usage 2.23.133.8.3 is required; this one carries clientAuth only)", NO, aik=aik_cert(TPM_AIK_P, "Derived TPM AIK Other EKU", eku=("1.3.6.1.5.5.7.3.2",))))
    add(tpm_case("tpm-aik-eku-among-others", "and 8.3.1 (2.23.133.8.3 among other purposes is enough)", okt(), aik=aik_cert(TPM_AIK_P, "Derived TPM AIK EKU Several", eku=("1.3.6.1.5.5.7.3.2", TPM_OID_EKU))))
    add(tpm_case("tpm-aik-ca-true", "and 8.3.1 (basicConstraints CA is false)", NO, aik=aik_cert(TPM_AIK_P, "Derived TPM AIK CA", ca=True)))
    add(tpm_case("tpm-aik-aaguid-mismatch", "and 8.3.1 (a present AAGUID extension equals the attested AAGUID)", NO, aik=aik_cert(TPM_AIK_P, "Derived TPM AIK Aaguid Other", extra=[AAGUID_EXT(bytes(16))])))
    add(tpm_case("tpm-aik-aaguid-critical", "and 8.3.1 (the AAGUID extension is non-critical)", NO, aik=aik_cert(TPM_AIK_P, "Derived TPM AIK Aaguid Critical", extra=[AAGUID_EXT(AAGUID, True)])))
    add(tpm_case("tpm-aik-version-1", "and 8.3.1 (the AIK certificate is version 3)", NO, aik=aik_cert(TPM_AIK_P, "Derived TPM AIK V1", version=1)))
    return cs


# ---- android-key (R96, R97)
def auth_list(purpose=(2,), origin=0, all_apps=False, extra=b""):
    parts = []
    if purpose is not None:
        parts.append(ctx(1, sset(*[integer(p) for p in purpose])))
    parts.append(ctx(3, integer(256)))  # keySize, an unrelated entry the walk skips
    if all_apps:
        parts.append(ctx(600, null()))
    if origin is not None:
        parts.append(ctx(702, integer(origin)))
    return seq(*parts, extra)


def key_description(challenge=CDH, software=None, tee=None, version=4, tail=b""):
    return seq(integer(version), enum(1), integer(version), enum(1), octets(challenge), octets(b""),
               software if software is not None else auth_list(purpose=None, origin=None), tee if tee is not None else auth_list(), tail)


AK_OID = "1.3.6.1.4.1.11129.2.1.17"
AK_INT = issue("Derived Android Int", ATT_ROOT, "p256", pathlen=0, label="webauthn-rp-derived-ext android int")


def android_leaf(cn, desc, key=None, **kw):
    return issue(cn, AK_INT, "p256", ca=False, key=key or CRED, extra=[ext(AK_OID, desc)] if desc is not None else [], ku=[0], **kw)


def android_cases():
    A = "contract R96/R97 and WebAuthn L3 8.4 "
    cs = []
    oka = REG_OK(attestation={"fmt": "android-key", "type": "Basic", "trust": "Anchored"})
    cdh = CDH

    def add(cid, spec, expect, leaf, key_enforcement=None, sign_key=None, chain=None, **kw):
        stmt = c_map([(T("alg"), c_int(-7)), (T("sig"), c_bytes((sign_key or CRED).sign(PACKED_SIGDATA))), (T("x5c"), c_array(*[c_bytes(d) for d in [leaf.der, AK_INT.der]]))])
        extra = {"key_enforcement": key_enforcement} if key_enforcement else {}
        cs.append(att_reg(cid, A + spec, expect, "android-key", stmt, **extra, **kw))

    add("android-key-tee-enforced", "(origin GENERATED and purpose SIGN in teeEnforced; type Basic)", oka, android_leaf("Derived Android Leaf", key_description()))
    add("android-key-purpose-among-several", "(purpose SIGN among other purposes)", oka, android_leaf("Derived Android Leaf Purposes", key_description(tee=auth_list(purpose=(0, 2, 3)))))
    add("android-key-later-schema-version", "(read by a tolerant header walk so later schema versions parse: version 400 and an extra trailing element)", oka,
        android_leaf("Derived Android Leaf V400", key_description(version=400, tail=seq(integer(1)))))
    add("android-key-leaf-expired", "with N14 (the android-key leaf's validity dates are not checked)", oka, android_leaf("Derived Android Leaf Expired", key_description(), na=NOW - 1))
    add("android-key-challenge-mismatch", "(attestationChallenge equals the client data hash)", NO, android_leaf("Derived Android Leaf Challenge", key_description(challenge=sha(b"other"))))
    add("android-key-challenge-authdata-hash", "(attestationChallenge is the client data hash, not the hash of authenticator data)", NO, android_leaf("Derived Android Leaf Challenge AD", key_description(challenge=sha(PACKED_AD))))
    add("android-key-all-applications-tee", "(allApplications is absent from both lists: present in teeEnforced)", NO, android_leaf("Derived Android Leaf AllApps Tee", key_description(tee=auth_list(all_apps=True))))
    add("android-key-all-applications-software", "(allApplications is absent from both lists: present in softwareEnforced)", NO, android_leaf("Derived Android Leaf AllApps Sw", key_description(software=auth_list(purpose=None, origin=None, all_apps=True))))
    add("android-key-origin-missing", "(origin GENERATED appears in teeEnforced)", NO, android_leaf("Derived Android Leaf No Origin", key_description(tee=auth_list(origin=None))))
    add("android-key-origin-imported", "(origin GENERATED, not IMPORTED (2))", NO, android_leaf("Derived Android Leaf Imported", key_description(tee=auth_list(origin=2))))
    add("android-key-purpose-missing", "(purpose SIGN appears in teeEnforced)", NO, android_leaf("Derived Android Leaf No Purpose", key_description(tee=auth_list(purpose=None))))
    add("android-key-purpose-verify-only", "(purpose SIGN (2), not VERIFY (3))", NO, android_leaf("Derived Android Leaf Verify", key_description(tee=auth_list(purpose=(3,)))))
    sw_only = key_description(software=auth_list(), tee=auth_list(purpose=None, origin=None))
    add("android-key-software-only-default", "(under the default KeyEnforcement the entries must be in teeEnforced; softwareEnforced alone is refused)", NO, android_leaf("Derived Android Leaf Sw Default", sw_only))
    add("android-key-software-only-any-list", "(under KeyEnforcement::AnyList either list carries the entries)", oka, android_leaf("Derived Android Leaf Sw Any", sw_only), key_enforcement="any_list")
    split = key_description(software=auth_list(purpose=(2,), origin=None), tee=auth_list(purpose=None, origin=0))
    add("android-key-split-lists-any-list", "(under AnyList the origin and the purpose may sit in different lists)", oka, android_leaf("Derived Android Leaf Split", split), key_enforcement="any_list")
    add("android-key-split-lists-default", "(under the default each of origin and purpose must be in teeEnforced)", NO, android_leaf("Derived Android Leaf Split Default", split))
    add("android-key-all-applications-any-list", "(allApplications is refused under every KeyEnforcement)", NO, android_leaf("Derived Android Leaf AllApps Any", key_description(tee=auth_list(all_apps=True))), key_enforcement="any_list")
    add("android-key-extension-missing", "(the leaf carries the key description extension)", NO, android_leaf("Derived Android Leaf No Ext", None))
    add("android-key-leaf-key-not-credential", "(the leaf key equals the credential key)", NO, android_leaf("Derived Android Leaf Other Key", key_description(), key=Key("webauthn-rp-derived-ext android other leaf", "p256")),
        sign_key=Key("webauthn-rp-derived-ext android other leaf", "p256"))
    add("android-key-signature-other-key", "(sig verifies with the leaf key)", NO, android_leaf("Derived Android Leaf Sig", key_description()), sign_key=Key("webauthn-rp-derived-ext android sig other", "p256"))
    return cs


# ================================================================ extensions.json (R120-R128)
APPID = "https://example.org/app-id.json"
F32, S32 = sha(b"prf first"), sha(b"prf second")
CP = lambda v: {"credProps": v}


def ext_cases():
    cs = []

    def a(cid, spec, expect, request=None, results=None, unsol=None, ad=None, **kw):
        extra = {}
        if request is not None:
            extra["extensions_requested"] = request
        if results is not None:
            extra["client_extension_results"] = results
        if unsol:
            extra["unsolicited"] = unsol
        cs.append(assertion(cid, spec, expect, ad=ad, **extra, **kw))

    def r(cid, spec, expect, request=None, results=None, unsol=None, ao=None, **kw):
        extra = {}
        if request is not None:
            extra["extensions_requested"] = request
        if results is not None:
            extra["client_extension_results"] = results
        if unsol:
            extra["unsolicited"] = unsol
        cs.append(registration(cid, spec, expect, ao=ao, **extra, **kw))

    G = lambda **o: {"ok": True, "user_verified": True, "counter": 6, "outputs": o}
    REGX = lambda **o: REG_OK(outputs=o)
    ad_app = auth_data(rp_hash=sha(APPID.encode()))
    # appid (R120)
    a("appid-used", "contract R120 and WebAuthn L3 10.1.1 (appid true: rpIdHash is the hash of the AppID, step 15)", G(appid=True), {"appid": APPID}, {"appid": True}, ad=ad_app)
    a("appid-not-used", "contract R120 (appid false: rpIdHash is the hash of the RP ID)", G(appid=False), {"appid": APPID}, {"appid": False})
    a("appid-not-reported", "contract R120 (no output: the RP ID hash applies; the output reads Unreported)", G(appid="Unreported"), {"appid": APPID})
    a("appid-true-with-rp-hash", "contract R120 (appid true selects the AppID hash: the RP ID hash fails step 15)", NO, {"appid": APPID}, {"appid": True})
    a("appid-false-with-appid-hash", "contract R120 (appid false selects the RP ID hash)", NO, {"appid": APPID}, {"appid": False}, ad=ad_app)
    a("appid-not-reported-with-appid-hash", "contract R120 (no output: the AppID hash is not selected)", NO, {"appid": APPID}, ad=ad_app)
    a("appid-output-not-boolean", "contract R120 (the output is a boolean)", NO, {"appid": APPID}, {"appid": "true"})
    a("appid-unrequested-reject", "contract R120 and R128 (an unrequested output is refused by default)", NO, None, {"appid": True})
    a("appid-unrequested-ignore", "contract R128 (an unrequested output is dropped under Ignore; the RP ID hash applies)", G(appid="NotRequested"), None, {"appid": True}, unsol="ignore")
    a("appid-unrequested-ignore-appid-hash", "contract R128 (a dropped output selects nothing: the AppID hash fails step 15)", NO, None, {"appid": True}, unsol="ignore", ad=ad_app)
    # appidExclude (R121)
    r("appid-exclude-true", "contract R121 (the output is read and ignored when requested)", REGX(appidExclude=True), {"appidExclude": APPID}, {"appidExclude": True})
    r("appid-exclude-false", "contract R121", REGX(appidExclude=False), {"appidExclude": APPID}, {"appidExclude": False})
    r("appid-exclude-unrequested-reject", "contract R121 and R128", NO, None, {"appidExclude": True})
    r("appid-exclude-unrequested-ignore", "contract R128", REGX(appidExclude="NotRequested"), None, {"appidExclude": True}, unsol="ignore")
    r("appid-exclude-not-boolean", "contract R121 (the output is a boolean)", NO, {"appidExclude": APPID}, {"appidExclude": 1})
    # credProps (R123, R122)
    r("cred-props-discoverable", "contract R123 (rk true is Discoverable)", REGX(credProps="Discoverable"), {"credProps": True}, CP({"rk": True}))
    r("cred-props-non-discoverable", "contract R123 (rk false is NonDiscoverable)", REGX(credProps="NonDiscoverable"), {"credProps": True}, CP({"rk": False}))
    r("cred-props-no-rk", "contract R122 (requested and rk absent reads Unreported)", REGX(credProps="Unreported"), {"credProps": True}, CP({}))
    r("cred-props-no-output", "contract R122 (requested and no output reads Unreported)", REGX(credProps="Unreported"), {"credProps": True}, {})
    r("cred-props-not-requested", "contract R122 (not requested reads NotRequested)", REGX(credProps="NotRequested"), None, {})
    r("cred-props-rk-not-boolean", "contract R123 (rk is a boolean)", NO, {"credProps": True}, CP({"rk": "yes"}))
    r("cred-props-unrequested-reject", "contract R128 (an unrequested client output is Extension by default)", NO, None, CP({"rk": True}))
    r("cred-props-unrequested-ignore", "contract R128 (dropped under Ignore)", REGX(credProps="NotRequested"), None, CP({"rk": True}), unsol="ignore")
    # prf at registration (R124)
    PR = lambda **o: {"prf": o}
    r("prf-reg-enabled", "contract R124 (Enable emits prf {}; enabled becomes PrfResult)", REGX(prf={"enabled": True, "first": None, "second": None}), PR(enable=True), PR(enabled=True))
    r("prf-reg-not-enabled", "contract R124 (enabled false)", REGX(prf={"enabled": False, "first": None, "second": None}), PR(enable=True), PR(enabled=False))
    r("prf-reg-no-output", "contract R122 (requested and no output reads Unreported)", REGX(prf="Unreported"), PR(enable=True), {})
    r("prf-reg-not-requested", "contract R122 (not requested reads NotRequested)", REGX(prf="NotRequested"), None, {})
    r("prf-reg-eval-first", "contract R124 (Eval: results become PrfResult)", REGX(prf={"enabled": True, "first": F32.hex(), "second": None}), PR(eval={"first": b64(b"salt one")}), PR(enabled=True, results={"first": b64(F32)}))
    r("prf-reg-eval-both", "contract R124 (two salts, two results)", REGX(prf={"enabled": True, "first": F32.hex(), "second": S32.hex()}), PR(eval={"first": b64(b"salt one"), "second": b64(b"salt two")}), PR(enabled=True, results={"first": b64(F32), "second": b64(S32)}))
    r("prf-reg-eval-no-results", "contract R124 (Eval requested but the client returned only enabled)", REGX(prf={"enabled": True, "first": None, "second": None}), PR(eval={"first": b64(b"salt one")}), PR(enabled=True))
    r("prf-reg-results-without-eval", "contract R124 (results without Eval are Extension)", NO, PR(enable=True), PR(enabled=True, results={"first": b64(F32)}))
    r("prf-reg-second-without-second-salt", "contract R124 (a second result without a second salt is Extension)", NO, PR(eval={"first": b64(b"salt one")}), PR(enabled=True, results={"first": b64(F32), "second": b64(S32)}))
    r("prf-reg-first-31-bytes", "contract R124 (a result that is not 32 bytes is Malformed)", NO, PR(eval={"first": b64(b"salt one")}), PR(enabled=True, results={"first": b64(F32[:31])}))
    r("prf-reg-first-33-bytes", "contract R124 (a result that is not 32 bytes is Malformed)", NO, PR(eval={"first": b64(b"salt one")}), PR(enabled=True, results={"first": b64(F32 + b"\x00")}))
    r("prf-reg-first-padded-base64", "contract R124 and R132 (base64url members are canonical: no padding)", NO, PR(eval={"first": b64(b"salt one")}), PR(enabled=True, results={"first": b64(F32) + "="}))
    r("prf-reg-unrequested-reject", "contract R128", NO, None, PR(enabled=True))
    r("prf-reg-unrequested-ignore", "contract R128", REGX(prf="NotRequested"), None, PR(enabled=True), unsol="ignore")
    # prf at authentication (R125)
    CRID = b64(CRED_ID)
    a("prf-auth-eval", "contract R125 (eval: results become PrfResult)", G(prf={"enabled": None, "first": F32.hex(), "second": None}), PR(eval={"first": b64(b"salt one")}), PR(results={"first": b64(F32)}))
    a("prf-auth-eval-both", "contract R125", G(prf={"enabled": None, "first": F32.hex(), "second": S32.hex()}), PR(eval={"first": b64(b"salt one"), "second": b64(b"salt two")}), PR(results={"first": b64(F32), "second": b64(S32)}))
    a("prf-auth-by-credential", "contract R125 (evalByCredential keyed by a listed credential id)", G(prf={"enabled": None, "first": F32.hex(), "second": None}),
      PR(evalByCredential={CRID: {"first": b64(b"salt one")}}), PR(results={"first": b64(F32)}), allow={"credentials": [CRED_ID.hex()]})
    a("prf-auth-no-results", "contract R122 (requested and no output reads Unreported)", G(prf="Unreported"), PR(eval={"first": b64(b"salt one")}), {})
    a("prf-auth-second-without-second-salt", "contract R125 and R124 (a second result without a second salt)", NO, PR(eval={"first": b64(b"salt one")}), PR(results={"first": b64(F32), "second": b64(S32)}))
    a("prf-auth-result-31-bytes", "contract R125 and R124 (a result of 31 bytes is Malformed)", NO, PR(eval={"first": b64(b"salt one")}), PR(results={"first": b64(F32[:31])}))
    a("prf-auth-unrequested-reject", "contract R128", NO, None, PR(results={"first": b64(F32)}))
    cs.append({"id": "prf-auth-by-credential-unlisted-key", "op": "start_authentication", "allow_credentials": [CRED_ID.hex()],
               "extensions": PR(evalByCredential={b64(OTHER_ID): {"first": b64(b"salt one")}}), "spec": "contract R125 (an evalByCredential key that is not in Allow::User is Extension at start_authentication)", "expect": NO})
    cs.append({"id": "prf-auth-by-credential-discoverable", "op": "start_authentication", "allow": "discoverable",
               "extensions": PR(evalByCredential={CRID: {"first": b64(b"salt one")}}), "spec": "contract R125 (keys must be listed in Allow::User; Allow::Discoverable lists none)", "expect": NO})
    cs.append({"id": "prf-auth-by-credential-not-base64url", "op": "start_authentication", "allow_credentials": [CRED_ID.hex()],
               "extensions": PR(evalByCredential={"not base64url!": {"first": b64(b"salt one")}}), "spec": "contract R125 (the keys are base64url credential ids)", "expect": NO})
    cs.append({"id": "prf-auth-eval-and-by-credential", "op": "start_authentication", "allow_credentials": [CRED_ID.hex()],
               "extensions": PR(eval={"first": b64(b"default salt")}, evalByCredential={CRID: {"first": b64(b"salt one")}}), "spec": "contract R125 and WebAuthn L3 10.1.4 (eval is the default for credentials without an evalByCredential entry)", "expect": OK})
    # largeBlob (R126, R127)
    LB = lambda **o: {"largeBlob": o}
    BLOB = b"derived large blob"
    r("large-blob-reg-supported", "contract R126 (supported true)", REGX(largeBlob="Supported"), LB(support="required"), LB(supported=True))
    r("large-blob-reg-not-supported", "contract R126 (supported false)", REGX(largeBlob="NotSupported"), LB(support="preferred"), LB(supported=False))
    r("large-blob-reg-no-output", "contract R122 (requested and no output reads Unreported)", REGX(largeBlob="Unreported"), LB(support="preferred"), {})
    r("large-blob-reg-not-requested", "contract R122", REGX(largeBlob="NotRequested"), None, {})
    r("large-blob-reg-written", "contract R126 (only supported is a registration output)", NO, LB(support="required"), LB(supported=True, written=True))
    r("large-blob-reg-unrequested-reject", "contract R128", NO, None, LB(supported=True))
    a("large-blob-read", "contract R127 (blob only after Read)", G(largeBlob={"blob": BLOB.hex()}), LB(read=True), LB(blob=b64(BLOB)))
    a("large-blob-read-no-blob", "contract R122 (requested and no output reads Unreported)", G(largeBlob="Unreported"), LB(read=True), {})
    a("large-blob-read-written", "contract R127 (written only after Write: it follows a Read here)", NO, LB(read=True), LB(written=True))
    a("large-blob-write-written", "contract R127 (written only after Write)", G(largeBlob={"written": True}), LB(write=b64(BLOB)), LB(written=True))
    a("large-blob-write-not-written", "contract R127 (written false is reported)", G(largeBlob={"written": False}), LB(write=b64(BLOB)), LB(written=False))
    a("large-blob-write-blob", "contract R127 (blob only after Read: it follows a Write here)", NO, LB(write=b64(BLOB)), LB(blob=b64(BLOB)))
    a("large-blob-read-not-base64url", "contract R127 and R132 (the blob is canonical base64url)", NO, LB(read=True), LB(blob="!!!!"))
    a("large-blob-unrequested-reject", "contract R128", NO, None, LB(blob=b64(BLOB)))
    # authenticator extension outputs (R128, N6)
    ED_MAP = c_map([(T("credProtect"), c_uint(1))])
    a("authenticator-output-reject", "contract R128 and N6 (this crate requests no authenticator extension, so each output is unsolicited: Extension by default)", NO, ad=auth_data(ext=ED_MAP))
    a("authenticator-output-ignore", "contract R128 (dropped under Ignore)", G(), unsol="ignore", ad=auth_data(ext=ED_MAP))
    a("authenticator-output-integer-key", "contract R128 (authenticator outputs are a CBOR map with text keys), even under Ignore", NO, unsol="ignore", ad=auth_data(ext=c_map([(c_uint(1), c_uint(1))])))
    a("authenticator-output-not-a-map", "contract R128 (a CBOR map), even under Ignore", NO, unsol="ignore", ad=auth_data(ext=c_array(c_uint(1))))
    a("authenticator-output-unordered", "ruling R-n (authenticator-produced CBOR is read in CTAP2 canonical order: the keys 'bb' then 'a')", NO, unsol="ignore", ad=auth_data(ext=c_map_raw([(T("bb"), c_uint(1)), (T("a"), c_uint(1))])))
    a("authenticator-output-trailing-byte", "contract R4 (nothing after the extensions map)", NO, unsol="ignore", ad=auth_data(ext=ED_MAP + b"\x00"))
    r("authenticator-output-registration-reject", "contract R128 (an extensions map in a registration's authenticator data is unsolicited too)", NO,
      ao=att_object(ad=auth_data(UP | UV, 0, attested=attested(), ext=ED_MAP)))
    r("authenticator-output-registration-ignore", "contract R128 (dropped under Ignore)", REG_OK(), unsol="ignore",
      ao=att_object(ad=auth_data(UP | UV, 0, attested=attested(), ext=ED_MAP)))
    return cs


# ================================================================ options-json.json (R30, R31, R60, R121, R130, R131, R134, R135)
ENTROPY = sha(b"webauthn-rp-derived-ext challenge entropy")
HANDLE = sha(b"webauthn-rp-derived-ext user handle")
CRED_B, CRED_C = sha(b"webauthn-rp-derived-ext exclude b")[:16], sha(b"webauthn-rp-derived-ext exclude c")[:24]
PK = lambda alg: {"type": "public-key", "alg": alg}
DEFAULT_ALGS = [PK(-7), PK(-8), PK(-35), PK(-257)]


def creation(cid, spec, opts=None, exclude=None, user=None, rp_name="Example", expect_json=None, timeout=300, **ov):
    o = {"user_verification": "preferred", "resident_key": "preferred", "timeout_secs": timeout}
    o.update(opts or {})
    u = user or {"handle": HANDLE.hex(), "name": "alice", "display_name": "Alice Example"}
    secs = o["timeout_secs"]
    rk = o["resident_key"]
    sel = {"residentKey": rk, "requireResidentKey": rk == "required", "userVerification": o["user_verification"]}
    if "attachment" in o:
        sel["authenticatorAttachment"] = o["attachment"]
    js = {"rp": {"id": RP, "name": rp_name}, "user": {"id": b64(bytes.fromhex(u["handle"])), "name": u["name"], "displayName": u["display_name"]},
          "challenge": b64(ENTROPY), "pubKeyCredParams": DEFAULT_ALGS, "timeout": secs * 1000, "excludeCredentials": [], "authenticatorSelection": sel, "attestation": o.get("attestation", "none")}
    js.update(expect_json or {})
    return {"id": cid, "op": "creation_options_json", "rp": {"id": RP, "name": rp_name, "origins": [ORIGIN]}, "user": u, "exclude_credentials": exclude or [], "options": o,
            "entropy": ENTROPY.hex(), "now": NOW, "spec": spec,
            "expect": {"ok": True, "json": js, "effect": {"ceremony_row": sha(ENTROPY).hex(), "expiry": NOW + secs}}, **ov}


def request(cid, spec, opts=None, allow=None, expect_json=None, timeout=300):
    o = {"user_verification": "preferred", "timeout_secs": timeout}
    o.update(opts or {})
    js = {"challenge": b64(ENTROPY), "rpId": RP, "timeout": o["timeout_secs"] * 1000, "allowCredentials": [], "userVerification": o["user_verification"]}
    js.update(expect_json or {})
    return {"id": cid, "op": "request_options_json", "rp": {"id": RP, "name": "Example", "origins": [ORIGIN]}, "allow": allow if allow is not None else "discoverable", "options": o,
            "entropy": ENTROPY.hex(), "now": NOW, "spec": spec,
            "expect": {"ok": True, "json": js, "effect": {"ceremony_row": sha(ENTROPY).hex(), "expiry": NOW + o["timeout_secs"]}}}


def options_cases():
    C, R = "contract R30 and R130 (PublicKeyCredentialCreationOptionsJSON, WebAuthn L3 5.1.8) ", "contract R60 and R131 (PublicKeyCredentialRequestOptionsJSON, WebAuthn L3 5.1.9) "
    desc = lambda cid, transports=(): {"id": cid.hex(), "transports": list(transports)}
    jd = lambda cid, transports=(): dict({"type": "public-key", "id": b64(cid)}, **({"transports": list(transports)} if transports else {}))
    cs = [
        creation("creation-defaults", C + "(base64url for the challenge and user id; ES256, EdDSA, ES384, RS256 by default; timeout in milliseconds; oracle choice: excludeCredentials and allowCredentials are always emitted, empty when none, while hints and attestationFormats are emitted only when set)"),
        creation("creation-resident-required", C + "(requireResidentKey is true exactly when residentKey is required)", opts={"resident_key": "required"}),
        creation("creation-resident-discouraged", C + "(requireResidentKey is false unless residentKey is required)", opts={"resident_key": "discouraged"}),
        creation("creation-user-verification-required", C + "(userVerification in authenticatorSelection)", opts={"user_verification": "required"}),
        creation("creation-attachment", C + "(authenticatorAttachment in authenticatorSelection)", opts={"attachment": "platform"}),
        creation("creation-algorithms-set", C + "(algorithms offered replace the default, in preference order)", opts={"algorithms": [-257, -7]}, expect_json={"pubKeyCredParams": [PK(-257), PK(-7)]}),
        creation("creation-algorithms-repeated-once", C + "and R15 (the setters keep each algorithm once)", opts={"algorithms": [-7, -257, -7]}, expect_json={"pubKeyCredParams": [PK(-7), PK(-257)]}),
        creation("creation-attestation-direct", C + "(attestation conveyance)", opts={"attestation": "direct"}),
        creation("creation-attestation-formats-ordered", C + "(attestationFormats in order, without repeats)", opts={"attestation": "direct", "attestation_formats": ["packed", "tpm", "packed"]}, expect_json={"attestation": "direct", "attestationFormats": ["packed", "tpm"]}),
        creation("creation-hints-ordered", C + "(hints in order, without repeats)", opts={"hints": ["hybrid", "security-key", "hybrid"]}, expect_json={"hints": ["hybrid", "security-key"]}),
        creation("creation-exclude-credentials", C + "(excludeCredentials as base64url ids; a repeated transport is kept once, in order)", exclude=[desc(CRED_B, ["usb", "nfc", "usb"]), desc(CRED_C)],
                 expect_json={"excludeCredentials": [jd(CRED_B, ["usb", "nfc"]), jd(CRED_C)]}),
        creation("creation-ext-cred-props", C + "(extensions: credProps)", opts={"extensions": {"credProps": True}}, expect_json={"extensions": {"credProps": True}}),
        creation("creation-ext-appid-exclude", "contract R121 and " + C + "(extensions: appidExclude carries the AppID)", opts={"extensions": {"appidExclude": APPID}}, expect_json={"extensions": {"appidExclude": APPID}}),
        creation("creation-ext-prf-enable", "contract R124 (Enable emits prf: {})", opts={"extensions": {"prf": {"enable": True}}}, expect_json={"extensions": {"prf": {}}}),
        creation("creation-ext-prf-eval", "contract R124 (Eval emits base64url eval.first and eval.second)", opts={"extensions": {"prf": {"eval": {"first": b"salt one".hex(), "second": b"salt two".hex()}}}},
                 expect_json={"extensions": {"prf": {"eval": {"first": b64(b"salt one"), "second": b64(b"salt two")}}}}),
        creation("creation-ext-prf-eval-first-only", "contract R124", opts={"extensions": {"prf": {"eval": {"first": b"salt one".hex()}}}}, expect_json={"extensions": {"prf": {"eval": {"first": b64(b"salt one")}}}}),
        creation("creation-ext-large-blob", "contract R126 (support is emitted)", opts={"extensions": {"largeBlob": {"support": "required"}}}, expect_json={"extensions": {"largeBlob": {"support": "required"}}}),
        creation("creation-ext-all", C + "(several extensions in one object)", opts={"extensions": {"credProps": True, "prf": {"enable": True}, "largeBlob": {"support": "preferred"}}},
                 expect_json={"extensions": {"credProps": True, "prf": {}, "largeBlob": {"support": "preferred"}}}),
        creation("creation-timeout-max", C + "(timeout in milliseconds: MAX_TIMEOUT_SECS 600 is 600000)", opts={"timeout_secs": 600}, timeout=600),
        creation("creation-short-user-handle", C + "(any 1 to 64 byte handle, base64url)", user={"handle": "01", "name": "bob", "display_name": "Bob"}),
        creation("creation-non-ascii-names", C + "(names are UTF-8 text, not escaped away)", user={"handle": HANDLE.hex(), "name": "zoë", "display_name": "Zoë 日本"}, rp_name="Café"),
        request("request-discoverable", R + "(allowCredentials is empty for Allow::Discoverable and present; rpId; userVerification; timeout in milliseconds)"),
        request("request-allow-user", R + "(allowCredentials lists the Allow::User list with transports, once each)", allow=[desc(CRED_B, ["internal", "internal", "hybrid"]), desc(CRED_C)],
                expect_json={"allowCredentials": [jd(CRED_B, ["internal", "hybrid"]), jd(CRED_C)]}),
        request("request-user-verification-required", R + "(userVerification)", opts={"user_verification": "required"}),
        request("request-hints-ordered", R + "(hints in order, without repeats)", opts={"hints": ["client-device", "hybrid", "client-device"]}, expect_json={"hints": ["client-device", "hybrid"]}),
        request("request-ext-appid", "contract R120 and " + R + "(extensions: appid carries the AppID)", opts={"extensions": {"appid": APPID}}, expect_json={"extensions": {"appid": APPID}}),
        request("request-ext-prf-eval", "contract R125 (eval: base64url salts)", opts={"extensions": {"prf": {"eval": {"first": b"salt one".hex()}}}}, expect_json={"extensions": {"prf": {"eval": {"first": b64(b"salt one")}}}}),
        request("request-ext-prf-by-credential", "contract R125 (evalByCredential keyed by base64url credential id)", allow=[desc(CRED_B)],
                opts={"extensions": {"prf": {"evalByCredential": {CRED_B.hex(): {"first": b"salt one".hex()}}}}},
                expect_json={"allowCredentials": [jd(CRED_B)], "extensions": {"prf": {"evalByCredential": {b64(CRED_B): {"first": b64(b"salt one")}}}}}),
        request("request-ext-large-blob-read", "contract R127 (the one LargeBlobOp: read)", opts={"extensions": {"largeBlob": {"read": True}}}, expect_json={"extensions": {"largeBlob": {"read": True}}}),
        request("request-ext-large-blob-write", "contract R127 (the one LargeBlobOp: write, base64url)", opts={"extensions": {"largeBlob": {"write": b"blob".hex()}}}, expect_json={"extensions": {"largeBlob": {"write": b64(b"blob")}}}),
    ]
    # related origins (R134)
    rel = lambda cid, spec, origins, out, rp="example.org": {"id": cid, "op": "related_origins_json", "rp_id": rp, "origins": origins, "spec": "contract R134 and WebAuthn L3 5.11 " + spec, "expect": {"ok": True, "json": {"origins": out}}}
    cs += [
        rel("related-origins-others-in-order", "(every configured origin whose host is neither the RP ID nor under it, in configuration order)",
            ["https://example.org", "https://example.net", "https://app.example.org:8443", "https://shop.example.com"], ["https://example.net", "https://shop.example.com"]),
        rel("related-origins-none", "(no related origin: an empty list)", ["https://example.org", "https://login.example.org"], []),
        rel("related-origins-suffix-lookalike", "(a host that merely ends in the RP ID text is not under it: notexample.org)", ["https://example.org", "https://notexample.org"], ["https://notexample.org"]),
        rel("related-origins-all", "(none of the origins is under the RP ID)", ["https://example.net", "https://example.com"], ["https://example.net", "https://example.com"]),
        rel("related-origins-port-kept", "(an origin is listed as configured, port included)", ["https://example.org", "https://example.net:8443"], ["https://example.net:8443"]),
    ]
    # signals (R135)
    cid = CRED_B
    sig = lambda cid_, spec, kind, args, js: {"id": cid_, "op": "signal_json", "kind": kind, **args, "rp_id": RP, "spec": "contract R135 and WebAuthn L3 5.1.10 " + spec, "expect": {"ok": True, "json": js}}
    cs += [
        sig("signal-unknown-credential", "(5.1.10.2: the RP ID is filled in; {rpId, credentialId})", "unknown_credential", {"credential_id": cid.hex()}, {"rpId": RP, "credentialId": b64(cid)}),
        sig("signal-all-accepted-credentials", "(5.1.10.3: {rpId, userId, allAcceptedCredentialIds})", "all_accepted_credentials", {"user_id": HANDLE.hex(), "credential_ids": [CRED_B.hex(), CRED_C.hex()]},
            {"rpId": RP, "userId": b64(HANDLE), "allAcceptedCredentialIds": [b64(CRED_B), b64(CRED_C)]}),
        sig("signal-all-accepted-none", "(5.1.10.3: an empty list tells the client to remove every credential of the user)", "all_accepted_credentials", {"user_id": HANDLE.hex(), "credential_ids": []},
            {"rpId": RP, "userId": b64(HANDLE), "allAcceptedCredentialIds": []}),
        sig("signal-current-user-details", "(5.1.10.4: {rpId, userId, name, displayName})", "current_user_details", {"user_id": HANDLE.hex(), "name": "alice", "display_name": "Alice Example"},
            {"rpId": RP, "userId": b64(HANDLE), "name": "alice", "displayName": "Alice Example"}),
    ]
    # refusals
    cs += [
        {"id": "creation-user-name-empty", "op": "user_entity", "name": "", "display_name": "Alice", "spec": "contract N18 (the crate checks length and emptiness only: an empty name is Malformed)", "expect": NO},
        {"id": "creation-display-name-empty", "op": "user_entity", "name": "alice", "display_name": "", "spec": "contract N18 (an empty display name is Malformed)", "expect": NO},
        {"id": "creation-timeout-zero", "op": "timeout_from_secs", "secs": 0, "spec": "contract Timeout::from_secs (zero is Malformed)", "expect": NO},
    ]
    return cs


# ================================================================ response-json.json (R132)
B64A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def noncanonical_tail(raw):
    """Unpadded base64url of raw with the unused trailing bits of the last symbol set."""
    s = b64(raw)
    assert len(raw) % 3 != 0
    return s[:-1] + B64A[B64A.index(s[-1]) ^ 1]


def response_cases():
    S = "contract R132 and WebAuthn L3 5.1.7 "
    cdj, ao = CDJ_REG, att_object()
    reg = lambda **o: dict({"id": b64(CRED_ID), "rawId": b64(CRED_ID), "type": "public-key", "response": {"clientDataJSON": b64(cdj), "attestationObject": b64(ao)}, "clientExtensionResults": {}}, **o)
    rresp = lambda **o: dict(reg()["response"], **o)
    ad = auth_data()
    cda = client_data()
    asig = CRED.sign(ad + sha(cda))
    aut = lambda **o: dict({"id": b64(CRED_ID), "rawId": b64(CRED_ID), "type": "public-key", "response": {"clientDataJSON": b64(cda), "authenticatorData": b64(ad), "signature": b64(asig), "userHandle": b64(UH)}, "clientExtensionResults": {}}, **o)
    aresp = lambda **o: dict(aut()["response"], **o)
    # the JSON travels as text, as a client sends it: a structured member named authenticatorData holding base64url reads as a credential to the repository secret scan
    txt = lambda obj: json.dumps(obj, separators=(",", ":"))
    r = lambda cid, spec, obj, expect: {"id": cid, "op": "registration_response_json", "input_text": txt(obj), "spec": S + spec, "expect": expect}
    a = lambda cid, spec, obj, expect: {"id": cid, "op": "authentication_response_json", "input_text": txt(obj), "spec": S + spec, "expect": expect}
    rt = lambda cid, spec, text, expect, op="registration_response_json": {"id": cid, "op": op, "input_text": text, "spec": S + spec, "expect": expect}
    ok_r = {"ok": True, "credential_id": CRED_ID.hex()}
    ok_a = {"ok": True, "credential_id": CRED_ID.hex(), "user_handle": UH.hex()}
    with_ext = lambda obj, results: dict(obj, clientExtensionResults=results)
    cs = [
        r("registration-valid", "(RegistrationResponseJSON)", reg(), ok_r),
        r("registration-transports", "(transports are read; an unknown transport name is dropped)", reg(response=rresp(transports=["usb", "carrier-pigeon", "internal"])), dict(ok_r, transports=["usb", "internal"])),
        r("registration-unknown-members-ignored", "(other unknown members are ignored)", dict(reg(response=rresp(extraMember=1)), authenticatorAttachment="platform", future="x"), ok_r),
        r("registration-id-differs-from-raw-id", "(id equals base64url of rawId)", reg(id=b64(OTHER_ID)), {"ok": False, "kind": "Malformed"}),
        r("registration-id-missing", "(id is required)", {k: v for k, v in reg().items() if k != "id"}, NO),
        r("registration-raw-id-missing", "(rawId is required)", {k: v for k, v in reg().items() if k != "rawId"}, NO),
        r("registration-type-other", "(type is public-key)", reg(type="password"), NO),
        r("registration-type-missing", "(type is required)", {k: v for k, v in reg().items() if k != "type"}, NO),
        r("registration-id-padded", "(base64url members are canonical: no padding)", reg(id=b64(CRED_ID) + "=", rawId=b64(CRED_ID) + "="), NO),
        r("registration-id-standard-alphabet", "(base64url members use the URL alphabet; this id was written with '+' for '-')", reg(id=b64(CRED_ID).replace("-", "+").replace("_", "/") if any(c in b64(CRED_ID) for c in "-_") else b64(CRED_ID) + "+", rawId=b64(CRED_ID).replace("-", "+").replace("_", "/") if any(c in b64(CRED_ID) for c in "-_") else b64(CRED_ID) + "+"), NO),
        r("registration-client-data-noncanonical-tail", "(base64url members are canonical: the unused bits of the last symbol are zero)", reg(response=rresp(clientDataJSON=noncanonical_tail(cdj))) if len(cdj) % 3 else reg(response=rresp(clientDataJSON=noncanonical_tail(cdj + b" "))), NO),
        r("registration-attestation-object-noncanonical-tail", "(base64url members are canonical)", reg(response=rresp(attestationObject=noncanonical_tail(ao + b"\x00" * ((1 - len(ao)) % 3 or 3)))), NO),
        r("registration-response-missing", "(response is required)", {k: v for k, v in reg().items() if k != "response"}, NO),
        r("registration-client-data-missing", "(clientDataJSON is required)", reg(response={"attestationObject": b64(ao)}), NO),
        r("registration-attestation-object-missing", "(attestationObject is required)", reg(response={"clientDataJSON": b64(cdj)}), NO),
        r("registration-response-not-object", "(response is an object)", reg(response="x"), NO),
        r("registration-client-data-not-string", "(clientDataJSON is a base64url string)", reg(response=rresp(clientDataJSON=1)), NO),
        r("registration-ext-cred-props", "(clientExtensionResults typed per R123)", with_ext(reg(), {"credProps": {"rk": True}}), dict(ok_r, extensions={"credProps": {"rk": True}})),
        r("registration-ext-unknown-kept-unsolicited", "(unknown clientExtensionResults members are kept as unsolicited, for R128 to judge)", with_ext(reg(), {"vendorThing": {"a": 1}}), dict(ok_r, unsolicited=["vendorThing"])),
        r("registration-ext-not-object", "(clientExtensionResults is an object)", with_ext(reg(), []), NO),
        r("registration-ext-cred-props-rk-not-boolean", "(credProps.rk is a boolean)", with_ext(reg(), {"credProps": {"rk": "yes"}}), NO),
        r("registration-ext-prf-result-31-bytes", "(a PRF result that is not 32 bytes is Malformed, R124)", with_ext(reg(), {"prf": {"enabled": True, "results": {"first": b64(F32[:31])}}}), NO),
        r("registration-ext-large-blob-supported", "(clientExtensionResults typed per R126)", with_ext(reg(), {"largeBlob": {"supported": True}}), dict(ok_r, extensions={"largeBlob": {"supported": True}})),
        r("registration-client-data-too-large", "(a clientDataJSON past MAX_CLIENT_DATA_JSON stays TooLarge, apart from Malformed)", reg(response=rresp(clientDataJSON=b64(make_client_json(16385)))), TOO),
        rt("registration-not-json", "(a JSON object)", "not json", NO),
        rt("registration-top-level-array", "(a JSON object)", "[]", NO),
        rt("registration-empty-text", "(a JSON object)", "", NO),
        a("authentication-valid", "(AuthenticationResponseJSON)", aut(), ok_a),
        a("authentication-user-handle-absent", "(userHandle is optional)", aut(response={k: v for k, v in aresp().items() if k != "userHandle"}), {"ok": True, "credential_id": CRED_ID.hex(), "user_handle": None}),
        a("authentication-user-handle-empty", "and R16 (an empty userHandle reads as absent)", aut(response=aresp(userHandle="")), {"ok": True, "credential_id": CRED_ID.hex(), "user_handle": None}),
        a("authentication-user-handle-not-base64url", "(userHandle is base64url)", aut(response=aresp(userHandle="***")), NO),
        a("authentication-user-handle-padded", "(base64url members are canonical)", aut(response=aresp(userHandle=b64(UH[:31]) + "=")), NO),
        a("authentication-signature-missing", "(signature is required)", aut(response={k: v for k, v in aresp().items() if k != "signature"}), NO),
        a("authentication-authenticator-data-missing", "(authenticatorData is required)", aut(response={k: v for k, v in aresp().items() if k != "authenticatorData"}), NO),
        a("authentication-id-differs-from-raw-id", "(id equals base64url of rawId)", aut(id=b64(OTHER_ID)), {"ok": False, "kind": "Malformed"}),
        a("authentication-type-other", "(type is public-key)", aut(type="x"), NO),
        a("authentication-signature-padded", "(base64url members are canonical)", aut(response=aresp(signature=b64(asig) + "=")), NO),
        a("authentication-unknown-members-ignored", "(other unknown members are ignored)", dict(aut(response=aresp(extra=1)), authenticatorAttachment="cross-platform"), ok_a),
        a("authentication-ext-appid", "(clientExtensionResults typed per R120)", with_ext(aut(), {"appid": True}), dict(ok_a, extensions={"appid": True})),
        a("authentication-ext-appid-not-boolean", "(appid is a boolean)", with_ext(aut(), {"appid": "true"}), NO),
        a("authentication-ext-large-blob-written", "(clientExtensionResults typed per R127)", with_ext(aut(), {"largeBlob": {"written": True}}), dict(ok_a, extensions={"largeBlob": {"written": True}})),
        a("authentication-ext-prf-first", "(clientExtensionResults typed per R125)", with_ext(aut(), {"prf": {"results": {"first": b64(F32)}}}), dict(ok_a, extensions={"prf": {"first": F32.hex()}})),
        a("authentication-ext-unknown-kept-unsolicited", "(unknown clientExtensionResults members are kept as unsolicited)", with_ext(aut(), {"vendorThing": 1}), dict(ok_a, unsolicited=["vendorThing"])),
    ]
    return cs


# ================================================================ write
FAMILY = "webauthn-rp-derived"
write("cose.json", "COSE_Key reading (RFC 9053 7.1.1, 2.2, RFC 8812; contract R5 and N2); the key bytes are public values derived from labels, hex CBOR written by tools/derive_webauthn_ext.py", cose_cases())
write("attestation-object.json", "attestation object shape (WebAuthn L3 6.5.4, 7.1 step 13; contract R40, ruling R-n); hex CBOR", attobj_cases())
write("authentication.json", "authentication steps 5 and 6 (WebAuthn L3 7.2; contract R16, R64-R69); " + CTX + "; allow is {credentials, identified_user} or discoverable", auth_cases())
write("browser-binding.json", "browser binding on finish (ruling R-d, contract R58 and R63); binding and finish_binding are the 32-byte binding digests; " + CTX, binding_cases())
write("registration-ids.json", "registration raw id against the attested credential id (WebAuthn L3 13.1, contract R17); " + CTX, regid_cases())
write("origins.json", "Origin, RpId and AppId parsing (contract R8-R10; RFC 5890 2.3.1 for LDH labels)", origin_cases())
write("limits.json", "input bounds (contract R1, R6, R18, R19, R31). An excess 0 case is well formed apart from its size and is accepted by the reader its op names; excess 1 is TooLarge. Every case carries its bytes: hex in `input` up to 4096 bytes, base64url in `input_b64url` above, with input_len and input_sha256 and a recipe saying how they were built", limit_cases())
write("chains.json", "x5c chain walk (contract R110-R117, ruling R-h W-S6); certificates are built by tools/derive_webauthn_ext.py with RFC 6979 ECDSA and PKCS#1 v1.5 from keys derived from labels; now is a fixed unix time; outcome is Anchored, Unanchored or AttestationInvalid", chain_cases())
write("attestation.json", "attestation statements (WebAuthn L3 8.2-8.4, contract R92-R97); " + CTX + "; trust_anchors are DER certificates, now is a fixed unix time", packed_cases() + tpm_cases() + android_cases())
write("extensions.json", "client and authenticator extension outputs (WebAuthn L3 10.1, contract R120-R128); " + CTX + "; unsolicited defaults to reject", ext_cases())
write("options-json.json", "options JSON shapes, related origins and signals (WebAuthn L3 5.1.8-5.1.10, 5.11; contract R30, R31, R60, R121, R130, R131, R134, R135); the challenge is the first 32 bytes the Entropy yields; JSON is compared as a value, member order aside", options_cases())
write("response-json.json", "registration and authentication response JSON (WebAuthn L3 5.1.7, contract R132, R16)", response_cases())
