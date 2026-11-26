#!/usr/bin/env python3
"""Derive the webauthn-rp-derived case families from WebAuthn L3, RFC 8949 and CTAP2 canonical CBOR rules.

usage: python3 -I derive_webauthn.py <out-dir>
writes <out-dir>/webauthn-rp-derived/{cbor,client-data,authenticator-data}.json.
Assertions are signed with the RFC 6979 A.2.5 P-256 key and RFC 6979 deterministic k (SHA-256), so every
signature reproduces byte for byte; the script checks the key's public point and the A.2.5 "sample"
signature against the RFC before using them. `expect.kind` is set only for CounterRegressed and TooLarge,
the classes the architecture contract names.
Licence of this script: MIT OR Apache-2.0.
"""
import base64, hashlib, hmac, json, os, sys

OUT = sys.argv[1]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# P-256 (SEC 2 2.4.2 / FIPS 186-4 D.1.2.3)
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296, 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    l = (3 * p[0] * p[0] + A) * pow(2 * p[1], -1, P) if p == q else (q[1] - p[1]) * pow(q[0] - p[0], -1, P)
    x = (l * l - p[0] - q[0]) % P
    return x, (l * (p[0] - x) - p[1]) % P


def mul(k, p):
    r = None
    while k:
        if k & 1:
            r = add(r, p)
        p, k = add(p, p), k >> 1
    return r


def rfc6979_k(x, h1):
    # RFC 6979 3.2 with SHA-256, qlen = 256
    bx = x.to_bytes(32, "big") + (int.from_bytes(h1, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, "big")
        if 1 <= t < N:
            return t
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(x, msg):
    h = hashlib.sha256(msg).digest()
    k = rfc6979_k(x, h)
    r = mul(k, G)[0] % N
    s = pow(k, -1, N) * (int.from_bytes(h, "big") + r * x) % N
    return r, s


def der(r, s):
    enc = lambda i: (lambda b: b"\x02" + bytes([len(b)]) + b)(i.to_bytes((i.bit_length() + 8) // 8, "big"))
    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body


# RFC 6979 A.2.5: the key and the SHA-256 signature of "sample"
X = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
PUB = mul(X, G)
assert PUB == (0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6, 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299)
assert sign(X, b"sample") == (0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716, 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8)

RP, ORIGIN = "example.org", "https://example.org"
CHALLENGE = b64(hashlib.sha256(b"webauthn-rp-derived challenge").digest())
UP, UV, BE, BS = 0x01, 0x04, 0x08, 0x10


def client_data(**over):
    d = {"type": "webauthn.get", "challenge": CHALLENGE, "origin": ORIGIN, "crossOrigin": False}
    d.update(over)
    return json.dumps({k: v for k, v in d.items() if v is not None}, separators=(",", ":")).encode()


def auth_data(flags=UP | UV, count=6, rp=RP):
    return hashlib.sha256(rp.encode()).digest() + bytes([flags]) + count.to_bytes(4, "big")


POLICY = {"rp_id": RP, "origin": ORIGIN, "challenge": CHALLENGE, "user_verification": "preferred", "counter_policy": "reject",
          "stored_counter": 5, "stored_backup_eligible": False, "cross_origin": "deny"}


def assertion(cid, spec, expect, cd=None, ad=None, **policy):
    cd = cd if cd is not None else client_data()
    ad = ad if ad is not None else auth_data()
    sig = der(*sign(X, ad + hashlib.sha256(cd).digest()))
    return {"id": cid, "op": "webauthn_assert", "pub": {"x": f"{PUB[0]:064x}", "y": f"{PUB[1]:064x}"}, "authenticator_data": ad.hex(),
            "client_data_json": cd.hex(), "signature": sig.hex(), **dict(POLICY, **policy), "spec": spec, "expect": expect}


OK = lambda uv=True, counter=6: {"ok": True, "user_verified": uv, "counter": counter}
NO = {"ok": False}


def client_cases():
    return [
        assertion("control-valid", "WebAuthn L3 7.2", OK()),
        assertion("extra-member-ignored", "WebAuthn L3 5.8.1.2 (unknown members are ignored)", OK(), cd=client_data(other_keys_can_be_added_here="x")),
        assertion("cross-origin-absent", "WebAuthn L3 5.8.1 (crossOrigin may be absent)", OK(), cd=client_data(crossOrigin=None)),
        assertion("type-create", "WebAuthn L3 7.2 step 10 (type MUST be webauthn.get)", NO, cd=client_data(type="webauthn.create")),
        assertion("type-missing", "WebAuthn L3 7.2 step 10", NO, cd=client_data(type=None)),
        assertion("type-case", "WebAuthn L3 7.2 step 10 (an exact string)", NO, cd=client_data(type="WebAuthn.get")),
        assertion("challenge-other", "WebAuthn L3 7.2 step 11", NO, cd=client_data(challenge=b64(hashlib.sha256(b"other").digest()))),
        assertion("challenge-padded", "WebAuthn L3 7.2 step 11 with 5.8.1 (base64url, no padding)", NO, cd=client_data(challenge=CHALLENGE + "=")),
        assertion("challenge-std-alphabet", "WebAuthn L3 7.2 step 11", NO, cd=client_data(challenge=CHALLENGE.replace("-", "+").replace("_", "/"))) if any(c in CHALLENGE for c in "-_") else None,
        assertion("challenge-missing", "WebAuthn L3 7.2 step 11", NO, cd=client_data(challenge=None)),
        assertion("origin-other", "WebAuthn L3 7.2 step 12", NO, cd=client_data(origin="https://evil.example")),
        assertion("origin-trailing-slash", "WebAuthn L3 7.2 step 12 and 13.4.9 (an origin, compared exactly)", NO, cd=client_data(origin=ORIGIN + "/")),
        assertion("origin-http", "WebAuthn L3 7.2 step 12 and 13.4.9", NO, cd=client_data(origin="http://example.org")),
        assertion("origin-port", "WebAuthn L3 7.2 step 12", NO, cd=client_data(origin=ORIGIN + ":8443")),
        assertion("origin-subdomain", "WebAuthn L3 7.2 step 12 (subdomains are not expected unless listed)", NO, cd=client_data(origin="https://login.example.org")),
        assertion("cross-origin-denied", "WebAuthn L3 7.2 step 13 with the contract (cross-origin is deny-by-default)", NO, cd=client_data(crossOrigin=True, topOrigin="https://top.example")),
        assertion("cross-origin-allowed", "WebAuthn L3 7.2 steps 13 and 14 (topOrigin is an expected top-level origin)", OK(), cd=client_data(crossOrigin=True, topOrigin="https://top.example"), cross_origin={"top_origins": ["https://top.example"]}),
        assertion("top-origin-other", "WebAuthn L3 7.2 step 14", NO, cd=client_data(crossOrigin=True, topOrigin="https://evil.example"), cross_origin={"top_origins": ["https://top.example"]}),
        assertion("top-origin-without-cross-origin", "WebAuthn L3 5.8.1 (topOrigin only when crossOrigin is true) with the contract", NO, cd=client_data(topOrigin="https://top.example")),
        assertion("client-data-not-json", "WebAuthn L3 7.2 step 9", NO, cd=b"type=webauthn.get"),
    ]


def authdata_cases():
    return [
        assertion("rp-id-hash-other", "WebAuthn L3 7.2 step 15", NO, ad=auth_data(rp="evil.example")),
        assertion("rp-id-hash-of-origin", "WebAuthn L3 7.2 step 15 (the hash is of the RP ID, not the origin)", NO, ad=auth_data(rp=ORIGIN)),
        assertion("up-clear", "WebAuthn L3 7.2 step 16 (UP MUST be set)", NO, ad=auth_data(flags=UV)),
        assertion("uv-clear-required", "WebAuthn L3 7.2 step 17 (UV required)", NO, ad=auth_data(flags=UP), user_verification="required"),
        assertion("uv-clear-preferred", "WebAuthn L3 7.2 step 17 (only required checks UV)", OK(uv=False), ad=auth_data(flags=UP)),
        assertion("uv-set-required", "WebAuthn L3 7.2 step 17", OK(), user_verification="required"),
        assertion("bs-without-be", "WebAuthn L3 6.1 (BS MUST be 0 when BE is 0) and 7.2 step 18", NO, ad=auth_data(flags=UP | UV | BS)),
        assertion("be-stored-clear-now-set", "WebAuthn L3 7.2 step 19 (backupEligible MUST NOT change)", NO, ad=auth_data(flags=UP | UV | BE)),
        assertion("be-stored-set-now-clear", "WebAuthn L3 7.2 step 19", NO, ad=auth_data(flags=UP | UV), stored_backup_eligible=True),
        assertion("be-bs-set-eligible", "WebAuthn L3 7.2 steps 18 and 19 (BS may change while BE is set)", OK(), ad=auth_data(flags=UP | UV | BE | BS), stored_backup_eligible=True),
        assertion("counter-advanced", "WebAuthn L3 7.2 step 22", OK()),
        assertion("counter-regressed", "WebAuthn L3 7.2 step 22 with the contract (Reject)", {"ok": False, "kind": "CounterRegressed"}, ad=auth_data(count=3)),
        assertion("counter-equal", "WebAuthn L3 7.2 step 22 (MUST be greater than the stored value)", {"ok": False, "kind": "CounterRegressed"}, ad=auth_data(count=5)),
        assertion("counter-zero-after-nonzero", "WebAuthn L3 7.2 step 22", {"ok": False, "kind": "CounterRegressed"}, ad=auth_data(count=0)),
        assertion("counter-both-zero", "WebAuthn L3 7.2 step 22 (no counter on either side)", OK(counter=0), ad=auth_data(count=0), stored_counter=0),
        assertion("counter-regressed-tolerate", "WebAuthn L3 7.2 step 22 with the contract (Tolerate reports, never drops)", {"ok": True, "user_verified": True, "counter": {"regressed": {"stored": 5, "seen": 3}}}, ad=auth_data(count=3), counter_policy="tolerate"),
        assertion("authdata-truncated", "WebAuthn L3 6.1 (37 bytes at least)", NO, ad=auth_data()[:36]),
        assertion("authdata-at-flag-no-data", "WebAuthn L3 6.1 (AT set needs attested credential data)", NO, ad=auth_data(flags=UP | UV | 0x40)),
        assertion("authdata-ed-flag-no-data", "WebAuthn L3 6.1 (ED set needs extensions)", NO, ad=auth_data(flags=UP | UV | 0x80)),
        assertion("authdata-trailing-bytes", "WebAuthn L3 6.1 (no bytes after the declared parts)", NO, ad=auth_data() + b"\x00"),
    ]


def cbor_cases():
    c = lambda cid, spec, hexs, expect: {"id": cid, "op": "cbor_decode", "input": hexs, "spec": spec, "expect": expect}
    OKC = {"ok": True}
    # a canonical COSE_Key (RFC 9053 7.1.1, RFC 8152 13.1.1) for the RFC 6979 key: {1:2, 3:-7, -1:1, -2:x, -3:y}
    x, y = PUB[0].to_bytes(32, "big").hex(), PUB[1].to_bytes(32, "big").hex()
    cose = "a5" + "0102" + "0326" + "2001" + "215820" + x + "225820" + y
    return [
        c("cose-key-canonical", "CTAP2 canonical CBOR (WebAuthn L3 6.5.6, CTAP 2.2 8)", cose, OKC),
        c("map-keys-unsorted", "CTAP2 canonical CBOR (keys sorted, shortest first then bytewise)", "a5" + "0326" + "0102" + "2001" + "215820" + x + "225820" + y, NO),
        c("map-duplicate-key", "RFC 8949 5.6 (duplicate keys are invalid)", "a2" + "0102" + "0102", NO),
        c("int-not-shortest", "RFC 8949 4.2.1 (preferred serialization)", "1805", NO),
        c("int-16-for-8", "RFC 8949 4.2.1", "190017", NO),
        c("neg-int-not-shortest", "RFC 8949 4.2.1", "3806", NO),
        c("length-not-shortest", "RFC 8949 4.2.1 (lengths in shortest form)", "7803616263", NO),
        c("indefinite-bytes", "RFC 8949 4.2.1 (no indefinite length)", "5f42010243030405ff", NO),
        c("indefinite-array", "RFC 8949 4.2.1", "9f0102ff", NO),
        c("indefinite-map", "RFC 8949 4.2.1", "bf0102ff", NO),
        c("break-outside-indefinite", "RFC 8949 3.2.1 (not well-formed)", "ff", NO),
        c("reserved-additional-info", "RFC 8949 3 (additional information 28-30 is not well-formed)", "1c", NO),
        c("simple-two-byte-low", "RFC 8949 3.3 (simple values below 32 in two bytes are not well-formed)", "f818", NO),
        c("text-invalid-utf8", "RFC 8949 3.1 major type 3 (valid UTF-8)", "62c328", NO),
        c("truncated-bytes", "RFC 8949 3 (the declared length exceeds the input)", "44010203", NO),
        c("huge-declared-length", "contract rule 5.7 (a declared length is checked against the remaining input before allocating)", "5b" + "ffffffffffffffff" + "00", NO),
        c("trailing-bytes", "RFC 8949 5.1 with WebAuthn L3 6.5 (one item, nothing after it)", "0100", NO),
        c("tag-unexpected", "CTAP2 canonical CBOR (tags are not used)", "c11a514b67b0", NO),
        c("float-key", "CTAP2 canonical CBOR (COSE_Key labels are integers or text)", "a1f93c0001", NO),
        {"id": "depth-bound", "op": "cbor_limit", "bound": "webauthn_rp::MAX_CBOR_DEPTH", "excess": 1, "recipe": "nested one-element arrays 0x81 ... 0x81 0x00 whose depth (the outer array is 1) is the bound plus one",
         "spec": "contract rule 5.7 (CBOR nesting depth)", "expect": {"ok": False, "kind": "TooLarge"}},
        {"id": "item-bound", "op": "cbor_limit", "bound": "webauthn_rp::MAX_CBOR_ITEMS", "excess": 1, "recipe": "one definite array of the bound items of 0x00, so the item count with the array itself is the bound plus one",
         "spec": "contract rule 5.7 (CBOR item count)", "expect": {"ok": False, "kind": "TooLarge"}},
    ]


def cbor_head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)


def cbor_text(t):
    return cbor_head(3, len(t.encode())) + t.encode()


COSE = bytes.fromhex("a5010203262001215820") + PUB[0].to_bytes(32, "big") + bytes.fromhex("225820") + PUB[1].to_bytes(32, "big")


def att_object(flags=UP | UV | 0x40, rp=RP, cred_id=None, fmt="none", att_stmt=b"\xa0", count=0):
    cred_id = cred_id if cred_id is not None else hashlib.sha256(b"webauthn-rp-derived credential").digest()
    ad = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + count.to_bytes(4, "big")
    if flags & 0x40:
        ad += bytes(16) + len(cred_id).to_bytes(2, "big") + cred_id + COSE
    # CTAP2 canonical order of the text keys: fmt, attStmt, authData
    return b"\xa3" + cbor_text("fmt") + cbor_text(fmt) + cbor_text("attStmt") + att_stmt + cbor_text("authData") + cbor_head(2, len(ad)) + ad


REG_POLICY = {"rp_id": RP, "origin": ORIGIN, "challenge": CHALLENGE, "user_verification": "preferred", "pub_key_cred_params": [-7], "cross_origin": "deny"}


def registration(cid, spec, expect, cd=None, ao=None, **policy):
    cd = cd if cd is not None else client_data(type="webauthn.create")
    ao = ao if ao is not None else att_object()
    return {"id": cid, "op": "webauthn_register", "attestation_object": ao.hex(), "client_data_json": cd.hex(), **dict(REG_POLICY, **policy), "spec": spec, "expect": expect}


def registration_cases():
    ok = {"ok": True, "user_verified": True, "credential_id": hashlib.sha256(b"webauthn-rp-derived credential").digest().hex(), "public_key": {"x": f"{PUB[0]:064x}", "y": f"{PUB[1]:064x}"}}
    cd = lambda **o: client_data(**dict({"type": "webauthn.create"}, **o))
    return [
        registration("control-none-es256", "WebAuthn L3 7.1 and 8.7 (none attestation)", ok),
        registration("type-get", "WebAuthn L3 7.1 step 7 (type MUST be webauthn.create)", NO, cd=client_data()),
        registration("challenge-other", "WebAuthn L3 7.1 step 8", NO, cd=cd(challenge=b64(hashlib.sha256(b"other").digest()))),
        registration("origin-other", "WebAuthn L3 7.1 step 9", NO, cd=cd(origin="https://evil.example")),
        registration("cross-origin-denied", "WebAuthn L3 7.1 step 10 with the contract (deny-by-default)", NO, cd=cd(crossOrigin=True, topOrigin="https://top.example")),
        registration("top-origin-other", "WebAuthn L3 7.1 step 11", NO, cd=cd(crossOrigin=True, topOrigin="https://evil.example"), cross_origin={"top_origins": ["https://top.example"]}),
        registration("rp-id-hash-other", "WebAuthn L3 7.1 step 14", NO, ao=att_object(rp="evil.example")),
        registration("up-clear", "WebAuthn L3 7.1 step 15 (mediation not conditional)", NO, ao=att_object(flags=UV | 0x40)),
        registration("uv-clear-required", "WebAuthn L3 7.1 step 16", NO, ao=att_object(flags=UP | 0x40), user_verification="required"),
        registration("uv-clear-preferred", "WebAuthn L3 7.1 step 16", dict(ok, user_verified=False), ao=att_object(flags=UP | 0x40)),
        registration("bs-without-be", "WebAuthn L3 7.1 step 17", NO, ao=att_object(flags=UP | UV | BS | 0x40)),
        registration("alg-not-requested", "WebAuthn L3 7.1 step 20 (alg among pubKeyCredParams)", NO, pub_key_cred_params=[-257]),
        registration("fmt-unknown", "WebAuthn L3 7.1 step 21 (case-sensitive match against supported formats)", NO, ao=att_object(fmt="None")),
        registration("none-with-statement", "WebAuthn L3 8.7 (the none attStmt is the empty map)", NO, ao=att_object(att_stmt=b"\xa1" + cbor_text("x") + b"\x00")),
        registration("at-clear", "WebAuthn L3 7.1 step 13 and 6.5.1 (registration carries attested credential data)", NO, ao=att_object(flags=UP | UV)),
        registration("credential-id-1023", "WebAuthn L3 7.1 step 25", dict(ok, credential_id=(bytes(range(256)) * 4)[:1023].hex()), ao=att_object(cred_id=(bytes(range(256)) * 4)[:1023])),
        registration("credential-id-1024", "WebAuthn L3 7.1 step 25 (MUST be at most 1023 bytes)", NO, ao=att_object(cred_id=bytes(range(256)) * 4)),
    ]


def write(name, source, cases):
    cases = [x for x in cases if x]
    p = os.path.join(OUT, "webauthn-rp-derived", name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    assert len({x["id"] for x in cases}) == len(cases)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"source": source, "cases": cases}, fh, indent=1)
        fh.write("\n")


SIG = "assertions signed by tools/derive_webauthn.py with the RFC 6979 A.2.5 P-256 key (deterministic k); rp example.org, origin https://example.org, stored counter 5, BE stored clear, cross-origin denied unless the case lists top_origins"
write("client-data.json", "clientDataJSON checks (WebAuthn L3 7.2 steps 8-14); " + SIG, client_cases())
write("authenticator-data.json", "authenticator data checks (WebAuthn L3 6.1, 7.2 steps 15-22); " + SIG, authdata_cases())
write("registration.json", "registration checks with none attestation (WebAuthn L3 7.1, 8.7); credential key is the RFC 6979 A.2.5 P-256 key as a canonical COSE_Key; rp example.org, origin https://example.org, pubKeyCredParams [-7] unless the case lists others", registration_cases())
write("cbor.json", "strict CBOR decoding (RFC 8949 4.2.1 and CTAP2 canonical form, as WebAuthn L3 6.5.6 requires of authenticators); hex inputs written by hand per the rule named in `spec`", cbor_cases())
