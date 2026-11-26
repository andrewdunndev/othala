#!/usr/bin/env python3
"""Derive the factor-derived case families from the RFC 4226 and RFC 6238 seeds pinned in this directory.

usage: python3 -I derive_factor.py <vectors-dir> <out-dir>
reads rfc4226/hotp.json and rfc6238/totp.json; writes <out-dir>/factor-derived/{totp,hotp}.json.
Codes are computed per RFC 4226 5.3 and RFC 6238 4 and cross-checked against every upstream value first.
`expect.kind` is set only for Replayed, the refusal the architecture contract names (RFC 6238 5.2).
Licence of this script: MIT OR Apache-2.0.
"""
import hashlib, hmac, json, os, struct, sys

V, OUT = sys.argv[1], sys.argv[2]
load = lambda p: json.load(open(os.path.join(V, p), encoding="utf-8"))


def hotp(secret_hex, counter, digits, alg="sha1"):
    mac = hmac.new(bytes.fromhex(secret_hex), struct.pack(">Q", counter), getattr(hashlib, alg)).digest()
    o = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[o : o + 4])[0] & 0x7FFFFFFF) % 10**digits).zfill(digits)


up_h = load("rfc4226/hotp.json")["cases"]
for c in up_h:
    assert hotp(c["secret"], c["counter"], c["digits"]) == c["expect"]["out"], c["id"]
up_t = [c for c in load("rfc6238/totp.json")["cases"] if c["id"].startswith("b-")]
for c in up_t:
    assert hotp(c["secret"], c["time"] // c["step"], c["digits"], c["alg"]) == c["code"], c["id"]
SEED = {c["alg"]: c["secret"] for c in up_t}
OK, NO = {"ok": True}, {"ok": False}
REPLAYED = {"ok": False, "kind": "Replayed"}


def totp():
    out = []

    def t(cid, spec, expect, alg="sha1", digits=8, time=1111111109, code_step=None, code=None, skew=1, last=None):
        s = time // 30
        code = code if code is not None else hotp(SEED[alg], s if code_step is None else code_step, digits, alg)
        e = dict(expect, step=code_step if code_step is not None else s) if expect.get("ok") else expect
        out.append({"id": cid, "op": "totp", "secret": SEED[alg], "alg": alg, "digits": digits, "step": 30, "time": time,
                    "window": skew, "last_step": last, "code": code, "spec": spec, "expect": e})

    S = 1111111109 // 30
    t("current-step", "RFC 6238 4.2", OK)
    t("skew-one-previous-step", "RFC 6238 5.2 (one step of delay allowed)", OK, code_step=S - 1)
    t("skew-one-next-step", "RFC 6238 5.2 and 6 (drift)", OK, code_step=S + 1)
    t("skew-one-two-back", "RFC 6238 5.2", NO, code_step=S - 2)
    t("skew-one-two-ahead", "RFC 6238 5.2", NO, code_step=S + 2)
    t("skew-none-previous-step", "RFC 6238 5.2", NO, code_step=S - 1, skew=0)
    t("skew-none-next-step", "RFC 6238 5.2", NO, code_step=S + 1, skew=0)
    t("replay-same-step", "RFC 6238 5.2 (MUST NOT accept the second attempt of the same OTP)", REPLAYED, last=S)
    t("replay-older-step-in-window", "RFC 6238 5.2 with the contract (a step at or below last is Replayed)", REPLAYED, code_step=S - 1, last=S)
    t("newer-step-after-last", "RFC 6238 5.2", OK, code_step=S + 1, last=S)
    t("current-after-previous-last", "RFC 6238 5.2", OK, last=S - 1)
    t("last-ahead-of-clock", "RFC 6238 5.2 with the contract (a stored step after the current one still bars it)", REPLAYED, last=S + 1)
    t("step-start-boundary", "RFC 6238 4.2 (T = floor((now - T0) / X))", OK, time=S * 30)
    t("step-end-boundary", "RFC 6238 4.2", OK, time=S * 30 + 29)
    t("t59-at-t60-skew-none", "RFC 6238 4.2 and appendix B (59 and 60 are different steps)", NO, time=60, code_step=1, skew=0)
    t("t59-at-t60-skew-one", "RFC 6238 5.2", OK, time=60, code_step=1)
    t("sha256-replay", "RFC 6238 1.2 and 5.2", REPLAYED, alg="sha256", last=S)
    t("sha512-replay", "RFC 6238 1.2 and 5.2", REPLAYED, alg="sha512", last=S)
    # six digits: find the first step from S whose code starts with 0, so leading zeros are kept (RFC 4226 5.3)
    z = next(n for n in range(S, S + 10000) if hotp(SEED["sha1"], n, 6).startswith("0"))
    t("six-digit-leading-zero", "RFC 4226 5.3 (the value is zero-padded to Digit digits)", OK, digits=6, time=z * 30)
    t("six-digit-leading-zero-stripped", "RFC 4226 5.3", NO, digits=6, time=z * 30, code=hotp(SEED["sha1"], z, 6).lstrip("0"))
    t("eight-digit-code-for-six", "RFC 4226 5.3 (Digit is fixed per key)", NO, digits=6, code=hotp(SEED["sha1"], S, 8))
    t("non-digit-code", "RFC 4226 5.3 (decimal digits)", NO, code="9428708a")
    t("code-with-space", "RFC 4226 5.3", NO, code=" " + hotp(SEED["sha1"], S, 8)[1:])
    return out


def hotps():
    sec, out = up_h[0]["secret"], []

    def h(cid, spec, expect, counter, at, s, code=None):
        code = code if code is not None else hotp(sec, at, 6)
        out.append({"id": cid, "op": "hotp_verify", "secret": sec, "digits": 6, "counter": counter, "look_ahead": s,
                    "code": code, "spec": spec, "expect": dict(expect, next_counter=at + 1) if expect.get("ok") else expect})

    h("expected-counter", "RFC 4226 7.2", OK, 3, 3, 3)
    h("look-ahead-edge", "RFC 4226 7.4 (look-ahead window s)", OK, 3, 6, 3)
    h("look-ahead-past-edge", "RFC 4226 7.4", NO, 3, 7, 3)
    h("look-ahead-zero-next", "RFC 4226 7.4", NO, 3, 4, 0)
    h("previous-counter", "RFC 4226 7.2 (the counter only moves forward after a success)", NO, 3, 2, 3)
    h("counter-zero", "RFC 4226 appendix D", OK, 0, 0, 0)
    h("wrong-code", "RFC 4226 7.2", NO, 3, 3, 3, code="000000" if hotp(sec, 3, 6) != "000000" else "000001")
    r = lambda cid, spec, expect, counter, s, ats: out.append({"id": cid, "op": "hotp_resync", "secret": sec, "digits": 6, "counter": counter, "look_ahead": s,
                                                             "codes": [hotp(sec, a, 6) for a in ats], "spec": spec, "expect": dict(expect, next_counter=ats[-1] + 1) if expect.get("ok") else expect})
    r("resync-two-consecutive", "RFC 4226 E.4 (resynchronization with consecutive values)", OK, 0, 9, [7, 8])
    r("resync-not-consecutive", "RFC 4226 E.4", NO, 0, 9, [7, 9])
    r("resync-past-window", "RFC 4226 E.4 and 7.4", NO, 0, 5, [7, 8])
    return out


def write(name, source, cases):
    p = os.path.join(OUT, "factor-derived", name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    assert len({c["id"] for c in cases}) == len(cases)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"source": source, "cases": cases}, fh, indent=1)
        fh.write("\n")


write("totp.json", "TOTP window, skew and replay; derived by tools/derive_factor.py from the RFC 6238 appendix B seeds (step 30, T0 0); `step` on success is the matched step", totp())
write("hotp.json", "HOTP look-ahead and resynchronization; derived by tools/derive_factor.py from the RFC 4226 appendix D secret; `next_counter` on success is the matched counter plus one", hotps())
