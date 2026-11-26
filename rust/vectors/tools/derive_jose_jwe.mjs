// Derive jose-derived/jwe-header.json from values pinned under vectors/ (RFC 7516 A.2, RFC 7520 5.3, 5.8, 5.9, RFC 8037 A.6).
// usage: node derive_jose_jwe.mjs <vectors-dir> <out-dir>
// Deterministic: CEK and IV are RFC 7520 5.8's, so every built JWE is reproducible byte for byte.
// Node because the standard library has AES; Python's does not. Licence of this script: MIT OR Apache-2.0.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createCipheriv, createHash, diffieHellman, createPrivateKey, createPublicKey } from "node:crypto";
import { deflateRawSync } from "node:zlib";

const [V, OUT] = process.argv.slice(2);
const load = (p) => JSON.parse(readFileSync(join(V, p), "utf8"));
const b64 = (b) => Buffer.from(b).toString("base64url");
const ub = (s) => Buffer.from(s, "base64url");
const fig = Object.fromEntries(load("rfc7520/jwe.json").figures.map((f) => [f.figure, f]));
const jsonFrom = (t) => JSON.parse(t.slice(t.indexOf("{")).replace(/([^\s,{\[:"])\n\s*(?=[^\s"{}\[\]])/g, "$1"));
const KEY = jsonFrom(fig[151].text); // RFC 7520 5.8.1, A128KW
const CEK = ub(fig[152].joined), IV = ub(fig[153].joined);
const PT = Buffer.from(load("rfc7520/jwe-cases.json").cases.find((c) => c.id === "s5_8-compact-valid").expect.plaintext, "base64url");

function kw(kek, key) { // RFC 3394 2.2.1
  const n = key.length / 8, r = [];
  for (let i = 0; i < n; i++) r.push(key.subarray(8 * i, 8 * i + 8));
  let a = Buffer.from("a6a6a6a6a6a6a6a6", "hex");
  for (let j = 0; j < 6; j++) for (let i = 0; i < n; i++) {
    const c = createCipheriv(`aes-${kek.length * 8}-ecb`, kek, null).setAutoPadding(false);
    const b = Buffer.concat([c.update(Buffer.concat([a, r[i]])), c.final()]);
    const t = BigInt(n * j + i + 1);
    a = Buffer.from((b.readBigUInt64BE(0) ^ t).toString(16).padStart(16, "0"), "hex");
    r[i] = b.subarray(8);
  }
  return Buffer.concat([a, ...r]);
}
function gcm(cek, iv, pt, aad) {
  const c = createCipheriv(`aes-${cek.length * 8}-gcm`, cek, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  return [ct, c.getAuthTag()];
}
function compact(header, ek, pt, cek = CEK) {
  const h = b64(Buffer.from(header));
  const [ct, tag] = gcm(cek, IV, pt, Buffer.from(h));
  return [h, b64(ek), b64(IV), b64(ct), b64(tag)].join(".");
}
function concatKdf(z, alg, bits, apu = Buffer.alloc(0), apv = Buffer.alloc(0)) { // RFC 7518 4.6.2
  const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  const lp = (b) => Buffer.concat([u32(b.length), b]);
  const info = Buffer.concat([lp(Buffer.from(alg)), lp(apu), lp(apv), u32(bits)]);
  return createHash("sha256").update(Buffer.concat([u32(1), z, info])).digest().subarray(0, bits / 8);
}
const hexOf = (t) => Buffer.from(t.replace(/\s+/g, ""), "hex");

const OK = { ok: true, plaintext: b64(PT) }, NO = { ok: false };
const c = (id, spec, expect, f) => ({ id, op: "jwe_decrypt", serialization: "compact", ...f, spec, expect });
const kwk = (hdr, pt = PT) => compact(hdr, kw(ub(KEY.k), CEK), pt);
const cases = [
  c("control-a128kw-a128gcm", "RFC 7516 5.2 (the generator's own positive control)", OK, { alg: "A128KW", enc: "A128GCM", jwk: KEY, jwe: kwk('{"alg":"A128KW","enc":"A128GCM"}') }),
  c("zip-def", "RFC 7516 4.1.3 (zip DEF; a non-goal, must-refuse)", NO, { alg: "A128KW", enc: "A128GCM", jwk: KEY, jwe: kwk('{"alg":"A128KW","enc":"A128GCM","zip":"DEF"}', deflateRawSync(PT, { level: 9 })), note: "must-refuse: JWE zip is a non-goal" }),
  c("zip-unknown", "RFC 7516 4.1.3", NO, { alg: "A128KW", enc: "A128GCM", jwk: KEY, jwe: kwk('{"alg":"A128KW","enc":"A128GCM","zip":"XYZ"}') }),
  c("crit-unknown", "RFC 7516 4.1.13 with RFC 7515 4.1.11", { ok: false, kind: "CriticalHeader" }, { alg: "A128KW", enc: "A128GCM", jwk: KEY, jwe: kwk('{"alg":"A128KW","enc":"A128GCM","crit":["exp-x"],"exp-x":1}') }),
  c("dup-enc", "RFC 7516 4 (names MUST be unique; this oracle rejects)", { ok: false, kind: "DuplicateMember" }, { alg: "A128KW", enc: "A128GCM", jwk: KEY, jwe: kwk('{"alg":"A128KW","enc":"A128GCM","enc":"A256GCM"}') }),
  c("enc-missing", "RFC 7516 4.1.2 (enc is REQUIRED)", NO, { alg: "A128KW", enc: "A128GCM", jwk: KEY, jwe: kwk('{"alg":"A128KW"}') }),
  c("alg-none", "RFC 7516 4.1.1 with RFC 7518 4.1 (none is not a key management alg)", NO, { alg: "A128KW", enc: "A128GCM", jwk: KEY, jwe: kwk('{"alg":"none","enc":"A128GCM"}') }),
  c("alg-mismatch", "RFC 8725 3.1 (expected A128KW, header says dir)", NO, { alg: "A128KW", enc: "A128GCM", jwk: KEY, jwe: compact('{"alg":"dir","enc":"A128GCM"}', Buffer.alloc(0), PT, ub(KEY.k)) }),
];
const a2 = load("rfc7516/jwe.json").cases.find((x) => x.id.startsWith("a2-"));
cases.push(c("rsa1_5", "RFC 7516 A.2 (RSA1_5; a non-goal, must-refuse)", NO, { alg: "RSA1_5", enc: a2.enc, jwk: a2.jwk, jwe: a2.jwe, note: "must-refuse: RSA1_5 is a non-goal" }));
const s53 = load("rfc7520/jwe-cases.json").cases.find((x) => x.id === "s5_3-compact-must-refuse");
cases.push(c("pbes2", "RFC 7520 5.3 (PBES2; a non-goal, must-refuse)", NO, { alg: s53.alg, enc: s53.enc, password: s53.password, jwe: s53.jwe, note: "must-refuse: PBES2 is a non-goal" }));

// RFC 8037 A.6: Z = X25519(ephemeral secret, Bob's public); reversing the roles makes the A.6 ephemeral key the
// recipient, Bob's public the epk, and the same published Z
const a6 = load("rfc8037/appendix-a.json").sections.find((s) => s.section === "A.6").blocks;
const after = (label) => a6[a6.findIndex((b) => b.text.startsWith(label)) + 1].text;
const bob = a6.find((b) => b.json?.kid === "Bob").json;
const ephSecret = hexOf(after("The ephemeral secret happens to be"));
const ephPub = a6.find((b) => b.json?.crv === "X25519" && !b.json.kid).json;
const z = hexOf(after("And the sender computes the DH Z value"));
const recipient = { kty: "OKP", crv: "X25519", x: ephPub.x, d: b64(ephSecret) };
const check = diffieHellman({ privateKey: createPrivateKey({ key: recipient, format: "jwk" }), publicKey: createPublicKey({ key: { kty: "OKP", crv: "X25519", x: bob.x }, format: "jwk" }) });
if (!check.equals(z)) throw new Error("RFC 8037 A.6 Z does not reproduce");
const hdr = JSON.stringify({ alg: "ECDH-ES+A128KW", enc: "A128GCM", epk: { kty: "OKP", crv: "X25519", x: bob.x } });
cases.push(c("x25519-ecdh-es-a128kw", "RFC 8037 3.2 and A.6 (ECDH-ES over OKP; a non-goal under ruling R-e)", { ok: false, kind: "UnsupportedAlg" },
  { alg: "ECDH-ES+A128KW", enc: "A128GCM", jwk: recipient, jwe: compact(hdr, kw(concatKdf(z, "ECDH-ES+A128KW", 128), CEK), PT), note: "must-refuse: X25519 is a non-goal (R-e); the JWE is valid, so only the refusal of the curve can make the case pass" }));

const out = join(OUT, "jose-derived");
mkdirSync(out, { recursive: true });
writeFileSync(join(out, "jwe-header.json"), JSON.stringify({ source: "JWE header refusals; derived by tools/derive_jose_jwe.mjs from RFC 7520 5.8 (key, CEK, IV, plaintext), RFC 7516 A.2, RFC 7520 5.3 and RFC 8037 A.6; built JWEs are otherwise valid, so each refusal is for the header alone", cases }, null, 1) + "\n");
