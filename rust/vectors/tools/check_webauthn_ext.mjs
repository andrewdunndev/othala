// usage: node check_webauthn_ext.mjs <out-dir>
// Re-verifies the generated webauthn-rp-derived extension families with Node's crypto, independent of the generator:
// every certificate parses; every assertion signature verifies; each chains.json case's expected outcome agrees with the
// signatures it contains (including ecdsa-with-SHA1, sha1 with RSA, ecdsa-with-SHA512 and P-521, which the walk refuses by
// policy although they verify, and which must expect Unanchored); Anchored needs every link's issuer name equal to the next subject (DER bytes), every
// signature, validity, CA rule and anchor, Unanchored needs all of those but the anchor, AttestationInvalid needs at
// least one name, signature, CA-rule or validity fault; every attestation.json x5c chain verifies link by link (names too) and to its anchor; statement
// signatures, TPM extraData and the TPM attested name verify or fail exactly where the case id names that fault, both ways.
// Licence: MIT OR Apache-2.0.
import { X509Certificate, createPublicKey, verify, createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const dir = process.argv[2] + "/webauthn-rp-derived/";
const load = (f) => JSON.parse(readFileSync(dir + f, "utf8")).cases;
let bad = 0;
const fail = (m) => { bad++; console.log("FAIL", m); };
const sha = (b) => createHash("sha256").update(b).digest();
const cert = (hex) => new X509Certificate(Buffer.from(hex, "hex"));

// assertions: signature over authData || SHA-256(clientDataJSON)
let assertions = 0;
for (const f of ["authentication.json", "extensions.json", "browser-binding.json"]) {
  for (const c of load(f)) {
    if (c.op !== "webauthn_assert") continue;
    const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: Buffer.from(c.pub.x, "hex").toString("base64url"), y: Buffer.from(c.pub.y, "hex").toString("base64url") }, format: "jwk" });
    const data = Buffer.concat([Buffer.from(c.authenticator_data, "hex"), sha(Buffer.from(c.client_data_json, "hex"))]);
    if (!verify("sha256", data, { key, dsaEncoding: "der" }, Buffer.from(c.signature, "hex"))) fail(`${f}#${c.id}: assertion signature`);
    assertions++;
  }
}

// X.509 fields Node does not expose, read with a small DER reader: the exact issuer and subject DER, version, extensions
const der = (b, o) => {
  let l = b[o + 1], h = 2;
  if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = l * 256 + b[o + 2 + i]; h = 2 + n; }
  return { tag: b[o], s: o, vs: o + h, e: o + h + l };
};
const kids = (b, n) => { const r = []; for (let o = n.vs; o < n.e;) { const k = der(b, o); r.push(k); o = k.e; } return r; };
const oidStr = (b) => { const v = [...b]; const a = [Math.floor(v[0] / 40), v[0] % 40]; let x = 0; for (const c of v.slice(1)) { x = x * 128 + (c & 127); if (!(c & 128)) { a.push(x); x = 0; } } return a.join("."); };
function parts(c) {
  const raw = c.raw, t = kids(raw, kids(raw, der(raw, 0))[0]);
  let i = 0, version = 1;
  if (t[0].tag === 0xa0) { version = raw[t[0].vs + 2] + 1; i = 1; }
  const exts = {};
  const e = t.find((x) => x.tag === 0xa3);
  if (e) for (const x of kids(raw, kids(raw, e)[0])) {
    const f = kids(raw, x);
    exts[oidStr(raw.subarray(f[0].vs, f[0].e))] = { crit: f.length === 3 && raw[f[1].vs] !== 0, val: raw.subarray(f[f.length - 1].vs, f[f.length - 1].e) };
  }
  const sigAlg = oidStr(raw.subarray(kids(raw, kids(raw, der(raw, 0))[1])[0].vs, kids(raw, kids(raw, der(raw, 0))[1])[0].e));
  return { sigAlg, version, issuer: raw.subarray(t[i + 2].s, t[i + 2].e), subject: raw.subarray(t[i + 4].s, t[i + 4].e), exts };
}
const okVerify = (c, by) => { try { return c.verify(by.publicKey); } catch { return false; } };
// link faults: the issuer name is byte for byte the next certificate's subject, and the signature verifies under its key
function linkFaults(x) {
  const out = [];
  x.slice(0, -1).forEach((e, i) => {
    if (!parts(e).issuer.equals(parts(x[i + 1]).subject)) out.push(`link ${i} issuer name differs from the next subject`);
    if (!okVerify(e, x[i + 1])) out.push(`link ${i} signature fails`);
  });
  return out;
}
// R116: chain signatures are ecdsa-with-SHA256 or -SHA384 on P-256 or P-384, or sha256, sha384, sha512 with RSA of 2048 to 4096 bits; anything else that verifies is refused by policy (R117)
const R116_ECDSA = new Set(["1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3"]);
const R116_CURVES = new Set(["prime256v1", "secp384r1"]);
const R116_RSA = new Set(["1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13"]);
const R116_RSA_BITS = [2048, 4096];
function r116Refusal(c, signer) {
  const oid = parts(c).sigAlg, k = signer.publicKey, d = k.asymmetricKeyDetails;
  if (k.asymmetricKeyType === "ec") return R116_ECDSA.has(oid) && R116_CURVES.has(d.namedCurve) ? null : `signature ${oid} under ${d.namedCurve} is outside R116`;
  if (k.asymmetricKeyType === "rsa") return R116_RSA.has(oid) && d.modulusLength >= R116_RSA_BITS[0] && d.modulusLength <= R116_RSA_BITS[1] ? null : `signature ${oid} under RSA-${d.modulusLength} is outside R116`;
  return `signature ${oid} under ${k.asymmetricKeyType} is outside R116`;
}
const CA_CRIT_OK = new Set(["2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.17"]);
// a certificate used as a CA: version 3, basicConstraints CA true, keyCertSign if keyUsage, critical extensions in the allowed set, pathLen respected
function caFaults(c, below) {
  const p = parts(c), out = [];
  const bc = p.exts["2.5.29.19"];
  let ca = false, pathLen = null;
  if (p.version === 3 && bc) { const f = kids(bc.val, der(bc.val, 0)); ca = f.length > 0 && f[0].tag === 1 && bc.val[f[0].vs] !== 0; const n = f.find((k) => k.tag === 2); if (n) pathLen = bc.val[n.vs]; }
  if (!ca) out.push("not a CA");
  const ku = p.exts["2.5.29.15"];
  if (ku && !(ku.val[3] & 0x04)) out.push("keyUsage lacks keyCertSign");
  if (pathLen !== null && pathLen < below) out.push("pathLen exceeded");
  for (const [o, v] of Object.entries(p.exts)) if (v.crit && !CA_CRIT_OK.has(o)) out.push(`critical extension ${o}`);
  return out;
}
const validAt = (c, now) => { const ms = now * 1000; return Date.parse(c.validFrom) <= ms && ms <= Date.parse(c.validTo); };

// chains: expected outcome against names, signatures, CA rules and validity in the chain
let chains = 0;
for (const c of load("chains.json")) {
  if (c.expect.kind) continue;
  const x = c.x5c.map(cert);
  const anchors = c.anchors.map(cert);
  const faults = linkFaults(x);
  x.forEach((e, i) => { if (!validAt(e, c.now)) faults.push(`certificate ${i} outside its validity`); if (i > 0) faults.push(...caFaults(e, i - 1).map((m) => `certificate ${i}: ${m}`)); });
  const last = x[x.length - 1];
  const exact = anchors.some((a) => a.raw.equals(last.raw));
  const matching = anchors.filter((a) => parts(a).subject.equals(parts(last).issuer) && okVerify(last, a));
  if (!exact && matching.length > 0 && matching.every((a) => !validAt(a, c.now) || caFaults(a, x.length - 1).length > 0)) faults.push("every matching anchor is unusable");
  const viaAnchor = exact || matching.length > 0;
  const out = c.expect.outcome;
  // chains refused by algorithm policy alone (a verifying link outside the R116 table): every name, signature and rule holds, the walk still reports Unanchored (R117)
  const signers = x.slice(0, -1).map((_, i) => x[i + 1]).concat(exact ? [] : matching.slice(0, 1));
  const refusals = signers.flatMap((s, i) => (okVerify(x[i], s) ? [r116Refusal(x[i], s)] : [])).filter(Boolean);
  const policy = refusals.length > 0 && faults.length === 0;
  if (policy) { if (out !== "Unanchored") fail(`chains#${c.id}: policy case must expect Unanchored, expects ${out}`); if (faults.length || !viaAnchor) fail(`chains#${c.id}: policy case whose chain does not verify (${faults.join("; ") || "no anchor"})`); chains++; continue; }
  if (out === "Anchored" && (faults.length || !viaAnchor)) fail(`chains#${c.id}: expected Anchored, found ${faults.join("; ") || "no anchor"}`);
  if (out === "Unanchored" && (faults.length || viaAnchor)) fail(`chains#${c.id}: expected Unanchored, ${faults.length ? "found " + faults.join("; ") : "the chain anchors"}`);
  if (out === "AttestationInvalid" && faults.length === 0) fail(`chains#${c.id}: expected AttestationInvalid but no name, signature, CA or validity fault exists`);
  if (/tampered/.test(c.id) && !(faults.length || !viaAnchor)) fail(`chains#${c.id}: tampered chain verifies`);
  chains++;
}

// attestation: statement signatures verify in every case that expects ok, and fail only in the cases that name a signature fault
function cbor(buf, o = { i: 0 }) {
  const b = buf[o.i++], major = b >> 5, ai = b & 31;
  let n = ai;
  if (ai === 24) n = buf[o.i++]; else if (ai === 25) { n = buf.readUInt16BE(o.i); o.i += 2; } else if (ai === 26) { n = buf.readUInt32BE(o.i); o.i += 4; }
  if (major === 0) return n;
  if (major === 1) return -1 - n;
  if (major === 2 || major === 3) { const v = buf.subarray(o.i, o.i + n); o.i += n; return major === 3 ? v.toString() : v; }
  if (major === 4) return Array.from({ length: n }, () => cbor(buf, o));
  if (major === 5) { const m = {}; for (let k = 0; k < n; k++) { const key = cbor(buf, o); m[key] = cbor(buf, o); } return m; }
  throw new Error("cbor " + b);
}
let atts = 0, tpms = 0, chainsChecked = 0;
// ids that name a fault; each must produce exactly that fault, and no other case may
const sigFault = /signature-(over-other-data|other-data|bit-flip|other-key)|packed-alg-not-the-leaf-key|android-key-signature-other-key/;
// TPM alg table (R95): RS256, RS1 or ES256 only, each with the key it needs; a case names a fault by id, any other mismatch is a finding of its own
const TPM_ALG = { [-7]: { kty: "ec", curve: "prime256v1", hash: "sha256" }, [-257]: { kty: "rsa", hash: "sha256" }, [-65535]: { kty: "rsa", hash: "sha1" } };
const tpmAlgKeyFault = /tpm-alg-es256-rsa-aik/;
const tpmAlgUnlistedFault = /tpm-alg-es384/;
const extraFault = /certinfo-extradata/;
const nameFault = /certinfo-name-(other-pubarea|wrong-alg-prefix)/;
const unparsable = /certinfo-(magic|type-quote|truncated)|pubarea-(truncated|wrong-type)/;
const nameHash = { 4: "sha1", 11: "sha256", 12: "sha384" };
function certInfo(b) {
  let o = 6;
  const u16 = () => { const v = b.readUInt16BE(o); o += 2; return v; };
  if (b.readUInt32BE(0) !== 0xff544347 || b.readUInt16BE(4) !== 0x8017) return null;
  const q = u16(); o += q; // qualifiedSigner
  const n = u16(); const extra = b.subarray(o, o + n); o += n;
  o += 8 + 4 + 4 + 1 + 8; // clockInfo and firmwareVersion
  const m = u16(); const name = b.subarray(o, o + m);
  if (name.length !== m) return null;
  return { extra, name };
}
for (const c of load("attestation.json")) {
  const anchors = c.trust_anchors.map(cert);
  const ao = cbor(Buffer.from(c.attestation_object, "hex"));
  const st = ao.attStmt, cdh = sha(Buffer.from(c.client_data_json, "hex"));
  let ok = false;
  if (!st.x5c || st.x5c.length === 0) { atts++; continue; }
  const x = st.x5c.map((d) => cert(d.toString("hex")));
  // every link verifies under the next certificate; the last verifies under an anchor naming its issuer, except in the unanchored cases
  const lf = linkFaults(x);
  const last = x[x.length - 1];
  const anchored = anchors.some((a) => parts(a).subject.equals(parts(last).issuer) && okVerify(last, a));
  if (lf.length) fail(`attestation#${c.id}: x5c links do not verify (${lf.join("; ")})`);
  if (anchored === /^packed-unanchored/.test(c.id)) fail(`attestation#${c.id}: chain ${anchored ? "reaches" : "misses"} an anchor against the case id`);
  chainsChecked++;
  const key = x[0].publicKey;
  if (ao.fmt === "packed" || ao.fmt === "android-key") {
    ok = verify(st.alg === -7 ? "sha256" : "sha384", Buffer.concat([ao.authData, cdh]), { key, dsaEncoding: "der" }, st.sig);
  } else if (ao.fmt === "tpm") {
    const h = TPM_ALG[st.alg]?.hash || { [-35]: "sha384" }[st.alg] || "sha256";
    ok = verify(h, st.certInfo, { key, dsaEncoding: "der" }, st.sig);
    const ci = (() => { try { return certInfo(st.certInfo); } catch { return null; } })();
    if (ci === null) { if (!unparsable.test(c.id)) fail(`attestation#${c.id}: certInfo does not parse and the id names no parse fault`); }
    else {
      const extraOk = ci.extra.equals(createHash(h).update(Buffer.concat([ao.authData, cdh])).digest());
      let nameOk = false;
      try { nameOk = ci.name.equals(Buffer.concat([st.pubArea.subarray(2, 4), createHash(nameHash[st.pubArea.readUInt16BE(2)]).update(st.pubArea).digest()])); } catch { /* unknown nameAlg */ }
      if (extraOk === extraFault.test(c.id)) fail(`attestation#${c.id}: extraData ${extraOk ? "matches" : "differs"} against the case id (R94)`);
      if (nameOk === nameFault.test(c.id)) fail(`attestation#${c.id}: attested name ${nameOk ? "matches" : "differs"} against the case id (R94)`);
    }
    const row = TPM_ALG[st.alg];
    const fits = !!row && row.kty === key.asymmetricKeyType && (row.curve === undefined || row.curve === key.asymmetricKeyDetails?.namedCurve);
    if (tpmAlgUnlistedFault.test(c.id) === !!row) fail(`attestation#${c.id}: fault tpm-alg-not-in-r95: alg ${st.alg} ${row ? "is" : "is not"} one of RS256, RS1, ES256 against the case id`);
    else if (row && fits === tpmAlgKeyFault.test(c.id)) fail(`attestation#${c.id}: fault tpm-alg-key-mismatch: alg ${st.alg} needs ${row.kty}${row.curve ? " on " + row.curve : ""}, the AIK is ${key.asymmetricKeyType}${key.asymmetricKeyDetails?.namedCurve ? " on " + key.asymmetricKeyDetails.namedCurve : ""} against the case id (R95)`);
    if (c.expect.ok && !ok) fail(`attestation#${c.id}: expected ok but the statement signature does not verify`);
    if (ok === sigFault.test(c.id)) fail(`attestation#${c.id}: signature ${ok ? "verifies" : "fails"} against the case id`);
    tpms++; atts++;
    continue;
  }
  if (({ [-7]: "ec", [-35]: "ec", [-257]: "rsa", [-65535]: "rsa" })[st.alg] !== key.asymmetricKeyType) ok = false; // alg must fit the key type
  if (st.alg === -7 && key.asymmetricKeyDetails?.namedCurve !== "prime256v1") ok = false; // ES256 needs P-256
  if (st.alg === -35 && key.asymmetricKeyDetails?.namedCurve !== "secp384r1") ok = false; // ES384 needs P-384
  if (c.expect.ok && !ok) fail(`attestation#${c.id}: expected ok but the statement signature does not verify`);
  if (ok === sigFault.test(c.id)) fail(`attestation#${c.id}: signature ${ok ? "verifies" : "fails"} against the case id`);
  atts++;
}
console.log(`assertions ${assertions}, chains ${chains}, attestations ${atts} (x5c chains ${chainsChecked}, tpm ${tpms}), failures ${bad}`);
process.exit(bad ? 1 : 0);
