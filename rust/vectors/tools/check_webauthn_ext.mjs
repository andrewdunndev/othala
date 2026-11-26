// usage: node check_webauthn_ext.mjs <out-dir>
// Re-verifies the generated webauthn-rp-derived extension families with Node's crypto, independent of the generator:
// every certificate parses; every assertion signature verifies; each chains.json case's expected outcome agrees with the
// signatures it contains (including ecdsa-with-SHA1, sha1 with RSA, ecdsa-with-SHA512 and P-521, which the walk refuses by
// policy although they verify); every attestation.json x5c chain verifies link by link and to its anchor; statement
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

// chains: expected outcome against the signatures in the chain
let chains = 0;
for (const c of load("chains.json")) {
  if (c.expect.kind) continue;
  const x = c.x5c.map(cert);
  const anchors = c.anchors.map(cert);
  const linkOk = x.slice(0, -1).map((e, i) => { try { return e.verify(x[i + 1].publicKey); } catch { return false; } });
  const last = x[x.length - 1];
  const viaAnchor = anchors.some((a) => a.raw.equals(last.raw) || (a.subject === last.issuer && (() => { try { return last.verify(a.publicKey); } catch { return false; } })()));
  const all = linkOk.every(Boolean) && viaAnchor;
  const out = c.expect.outcome;
  // chains refused by algorithm policy alone: every signature verifies, the walk still reports Unanchored (R117)
  const policy = ["ecdsa-sha1-leaf", "ecdsa-sha512-on-p256-leaf", "rsa-sha1-intermediate", "ecdsa-sha1-to-anchor", "p521-anchor"].includes(c.id);
  if (policy) { if (!all) fail(`chains#${c.id}: policy case whose chain does not verify (links ${linkOk} anchor ${viaAnchor})`); chains++; continue; }
  if (out === "Anchored" && !all) fail(`chains#${c.id}: expected Anchored, links ${linkOk} anchor ${viaAnchor}`);
  if (/tampered/.test(c.id) && all) fail(`chains#${c.id}: tampered chain verifies`);
  if (out === "Unanchored" && all) fail(`chains#${c.id}: expected Unanchored but the chain anchors`);
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
const sigFault = /signature-(over-other-data|other-data|bit-flip|other-key)|packed-alg-not-the-leaf-key|tpm-alg-es256-rsa-aik|android-key-signature-other-key/;
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
  const links = x.slice(0, -1).every((e, i) => { try { return e.verify(x[i + 1].publicKey); } catch { return false; } });
  const last = x[x.length - 1];
  const anchored = anchors.some((a) => a.subject === last.issuer && (() => { try { return last.verify(a.publicKey); } catch { return false; } })());
  if (!links) fail(`attestation#${c.id}: x5c links do not verify`);
  if (anchored === /^packed-unanchored/.test(c.id)) fail(`attestation#${c.id}: chain ${anchored ? "reaches" : "misses"} an anchor against the case id`);
  chainsChecked++;
  const key = x[0].publicKey;
  if (ao.fmt === "packed" || ao.fmt === "android-key") {
    ok = verify(st.alg === -7 ? "sha256" : "sha384", Buffer.concat([ao.authData, cdh]), { key, dsaEncoding: "der" }, st.sig);
  } else if (ao.fmt === "tpm") {
    const h = { [-65535]: "sha1", [-35]: "sha384" }[st.alg] || "sha256";
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
    tpms++;
  }
  if (({ [-7]: "ec", [-35]: "ec", [-257]: "rsa", [-65535]: "rsa" })[st.alg] !== key.asymmetricKeyType) ok = false; // alg must fit the key type
  if (c.expect.ok && !ok) fail(`attestation#${c.id}: expected ok but the statement signature does not verify`);
  if (ok === sigFault.test(c.id)) fail(`attestation#${c.id}: signature ${ok ? "verifies" : "fails"} against the case id`);
  atts++;
}
console.log(`assertions ${assertions}, chains ${chains}, attestations ${atts} (x5c chains ${chainsChecked}, tpm ${tpms}), failures ${bad}`);
process.exit(bad ? 1 : 0);
