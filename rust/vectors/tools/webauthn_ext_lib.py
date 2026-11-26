"""Pure-Python primitives for derive_webauthn_ext.py: P-256/P-384 ECDSA (RFC 6979), RSA PKCS#1 v1.5, DER and X.509 building.

Every key is derived from a label at generation time, so no private key is stored in the repository or written to a vector.
Licence: MIT OR Apache-2.0.
"""
import hashlib
import hmac


def expand(label, nbytes):
    out, i = b"", 0
    while len(out) < nbytes:
        out += hashlib.sha256(label.encode() + i.to_bytes(4, "big")).digest()
        i += 1
    return out[:nbytes]


# ---------------------------------------------------------------- elliptic curves
class Curve:
    def __init__(self, name, p, n, gx, gy, size, oid, h):
        self.name, self.p, self.a, self.n, self.G, self.size, self.oid, self.h = name, p, p - 3, n, (gx, gy), size, oid, h

    def add(self, p, q):
        if p is None:
            return q
        if q is None:
            return p
        P = self.p
        if p[0] == q[0] and (p[1] + q[1]) % P == 0:
            return None
        lam = (3 * p[0] * p[0] + self.a) * pow(2 * p[1], -1, P) if p == q else (q[1] - p[1]) * pow(q[0] - p[0], -1, P)
        x = (lam * lam - p[0] - q[0]) % P
        return x, (lam * (p[0] - x) - p[1]) % P

    def mul(self, k, p=None):
        p, r = p or self.G, None
        while k:
            if k & 1:
                r = self.add(r, p)
            p, k = self.add(p, p), k >> 1
        return r

    def on_curve(self, x, y):
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0


P256 = Curve("P-256", 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
             0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
             0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
             0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5, 32, "1.2.840.10045.3.1.7", hashlib.sha256)
P256.b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P384 = Curve("P-384", 2**384 - 2**128 - 2**96 + 2**32 - 1,
             0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
             0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
             0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F, 48, "1.3.132.0.34", hashlib.sha384)
P384.b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF

_N521 = "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"
P521 = Curve("P-521", 2**521 - 1, int("01FF" + "F" * (132 - 4 - len(_N521)) + _N521, 16),
             0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
             0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650, 66, "1.3.132.0.35", hashlib.sha512)
P521.b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00


def ec_key(label, curve):
    d = int.from_bytes(expand(label, curve.size + 8), "big") % (curve.n - 1) + 1
    return d, curve.mul(d)


def rfc6979_k(curve, x, h1, hashfn):
    qlen = curve.n.bit_length()
    rlen = (qlen + 7) // 8
    z = int.from_bytes(h1, "big")
    if len(h1) * 8 > qlen:
        z >>= len(h1) * 8 - qlen
    bx = x.to_bytes(rlen, "big") + (z % curve.n).to_bytes(rlen, "big")
    hl = hashfn().digest_size
    v, k = b"\x01" * hl, b"\x00" * hl
    k = hmac.new(k, v + b"\x00" + bx, hashfn).digest()
    v = hmac.new(k, v, hashfn).digest()
    k = hmac.new(k, v + b"\x01" + bx, hashfn).digest()
    v = hmac.new(k, v, hashfn).digest()
    while True:
        t = b""
        while len(t) < rlen:
            v = hmac.new(k, v, hashfn).digest()
            t += v
        c = int.from_bytes(t[:rlen], "big")
        if len(t[:rlen]) * 8 > qlen:
            c >>= len(t[:rlen]) * 8 - qlen
        if 1 <= c < curve.n:
            return c
        k = hmac.new(k, v + b"\x00", hashfn).digest()
        v = hmac.new(k, v, hashfn).digest()


def ecdsa_sign(curve, x, msg, hashfn=None):
    hashfn = hashfn or curve.h
    h = hashfn(msg).digest()
    k = rfc6979_k(curve, x, h, hashfn)
    r = curve.mul(k)[0] % curve.n
    z = int.from_bytes(h, "big")
    if len(h) * 8 > curve.n.bit_length():
        z >>= len(h) * 8 - curve.n.bit_length()
    s = pow(k, -1, curve.n) * (z + r * x) % curve.n
    return r, s


# ---------------------------------------------------------------- DER
def tlv(tag, body):
    n = len(body)
    if n < 128:
        ln = bytes([n])
    else:
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(nb)]) + nb
    return bytes([tag]) + ln + body


def seq(*parts):
    return tlv(0x30, b"".join(parts))


def sset(*parts):
    return tlv(0x31, b"".join(parts))


def integer(i):
    return tlv(0x02, i.to_bytes((i.bit_length() + 8) // 8, "big"))


def octets(b):
    return tlv(0x04, b)


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def null():
    return b"\x05\x00"


def enum(i):
    return tlv(0x0A, bytes([i]))


def bitstring(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


def oid(s):
    a = [int(x) for x in s.split(".")]
    out = bytes([a[0] * 40 + a[1]])
    for n in a[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, out)


def utf8(s):
    return tlv(0x0C, s.encode())


def printable(s):
    return tlv(0x13, s.encode())


def ctx(n, body, constructed=True):
    """Context tag n (any size) over body."""
    first = 0xA0 if constructed else 0x80
    if n < 31:
        return tlv(first | n, body)
    parts = [n & 0x7F]
    n >>= 7
    while n:
        parts.append(0x80 | (n & 0x7F))
        n >>= 7
    head = bytes([first | 0x1F]) + bytes(reversed(parts))
    ln = tlv(0, body)[1:]
    return head + ln


def utc(t):
    import time
    return tlv(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(t)).encode())


def gentime(t):
    import time
    return tlv(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(t)).encode())


def when(t):
    import time
    return utc(t) if time.gmtime(t).tm_year < 2050 else gentime(t)


def name(**rdn):
    """Distinguished name from ordered attribute pairs: C, O, OU, CN."""
    oids = {"C": "2.5.4.6", "O": "2.5.4.10", "OU": "2.5.4.11", "CN": "2.5.4.3"}
    return seq(*[sset(seq(oid(oids[k]), printable(v) if k == "C" else utf8(v))) for k, v in rdn.items()])


# ---------------------------------------------------------------- RSA
def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rsa_key(label, bits=2048, e=65537):
    primes, i = [], 0
    while len(primes) < 2:
        cand = int.from_bytes(expand(f"{label}/{len(primes)}/{i}", bits // 16), "big")
        cand |= (3 << (bits // 2 - 2)) | 1
        i += 1
        if is_prime(cand) and (cand - 1) % e:
            primes.append(cand)
    p, q = primes
    if p == q:
        raise ValueError
    return {"n": p * q, "e": e, "d": pow(e, -1, (p - 1) * (q - 1)), "bits": bits}


DIGEST_INFO = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def rsa_sign(key, msg, hname):
    k = (key["n"].bit_length() + 7) // 8
    t = DIGEST_INFO[hname] + hashlib.new(hname, msg).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), key["d"], key["n"]).to_bytes(k, "big")


def int_bytes(i, size=None):
    return i.to_bytes(size or (i.bit_length() + 7) // 8, "big")


# ---------------------------------------------------------------- X.509
ECDSA_ALG = {"sha1": "1.2.840.10045.4.1", "sha256": "1.2.840.10045.4.3.2", "sha384": "1.2.840.10045.4.3.3", "sha512": "1.2.840.10045.4.3.4"}
RSA_ALG = {"sha1": "1.2.840.113549.1.1.5", "sha256": "1.2.840.113549.1.1.11", "sha384": "1.2.840.113549.1.1.12", "sha512": "1.2.840.113549.1.1.13"}


class Key:
    """A signing key and its SubjectPublicKeyInfo: an EC key (curve, d, point) or an RSA key."""

    def __init__(self, label, kind="p256"):
        self.kind = kind
        if kind in ("p256", "p384", "p521"):
            self.curve = {"p256": P256, "p384": P384, "p521": P521}[kind]
            self.d, self.pt = ec_key(label, self.curve)
            self.spki = seq(seq(oid("1.2.840.10045.2.1"), oid(self.curve.oid)), bitstring(b"\x04" + int_bytes(self.pt[0], self.curve.size) + int_bytes(self.pt[1], self.curve.size)))
        else:
            self.rsa = rsa_key(label)
            self.spki = seq(seq(oid("1.2.840.113549.1.1.1"), null()), bitstring(seq(integer(self.rsa["n"]), integer(self.rsa["e"]))))

    def sign_alg(self, hname=None):
        if self.kind == "rsa":
            return seq(oid(RSA_ALG[hname or "sha256"]), null())
        return seq(oid(ECDSA_ALG[hname or self.curve.h().name]))

    def sign(self, msg, hname=None):
        if self.kind == "rsa":
            return rsa_sign(self.rsa, msg, hname or "sha256")
        hname = hname or self.curve.h().name
        r, s = ecdsa_sign(self.curve, self.d, msg, lambda b=b"": hashlib.new(hname, b))
        return seq(integer(r), integer(s))


def ext(o, value_der, critical=False):
    return seq(oid(o), *( [boolean(True)] if critical else [] ), octets(value_der))


def basic_constraints(ca, pathlen=None, critical=True):
    body = (boolean(True) if ca else b"") + (integer(pathlen) if pathlen is not None else b"")
    return ext("2.5.29.19", seq(body), critical)


def key_usage(bits, critical=True):
    """bits: digitalSignature=0 ... keyCertSign=5, cRLSign=6; DER trims trailing zero bits."""
    v = 0
    for b in bits:
        v |= 0x80 >> b
    last = max(bits)
    return ext("2.5.29.15", bitstring(bytes([v]), 7 - last), critical)


def eku(oids, critical=False):
    return ext("2.5.29.37", seq(*[oid(o) for o in oids]), critical)


def make_cert(subject, issuer, spki, issuer_key, exts=(), serial=1, nb=1_700_000_000, na=1_900_000_000, version=3, hname=None, sig_alg_override=None):
    """The DER certificate. `version` 1 omits the version and extensions fields."""
    alg = issuer_key.sign_alg(hname)
    tbs = seq(
        *([ctx(0, integer(version - 1))] if version != 1 else []),
        integer(serial), alg, issuer, seq(when(nb), when(na)), subject, spki,
        *([ctx(3, seq(*exts))] if exts and version == 3 else []),
    )
    sig = issuer_key.sign(tbs, hname)
    return seq(tbs, sig_alg_override or alg, bitstring(sig))


# ---------------------------------------------------------------- CBOR writer (canonical)
def cbor_head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)


def c_uint(n):
    return cbor_head(0, n)


def c_int(n):
    return cbor_head(0, n) if n >= 0 else cbor_head(1, -1 - n)


def c_bytes(b):
    return cbor_head(2, len(b)) + b


def c_text(t):
    return cbor_head(3, len(t.encode())) + t.encode()


def c_array(*items):
    return cbor_head(4, len(items)) + b"".join(items)


def c_map(pairs):
    """pairs of (key bytes, value bytes), written in CTAP2 canonical order (shorter encoding first, then bytewise)."""
    pairs = sorted(pairs, key=lambda kv: (len(kv[0]), kv[0]))
    return cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def c_map_raw(pairs):
    """pairs in the order given."""
    return cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
