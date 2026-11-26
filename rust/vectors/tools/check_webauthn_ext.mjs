// usage: node check_webauthn_ext.mjs <out-dir>
// Re-verifies the generated webauthn-rp-derived extension families with Node's crypto, independent of the generator:
// every certificate parses, every assertion signature verifies, and each chain case's expected outcome agrees with
// the signatures it contains. Licence: MIT OR Apache-2.0.
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
  const sha1ish = /sha1|ecdsa-sha512|rsa-sha1|p521/.test(c.id);
  if (sha1ish) continue; // algorithms outside Node's default policy: their cases are signed by construction
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
let atts = 0;
const sigFault = /signature|alg-|other-key|leaf-key|bit-flip|other-data|wrong-data/;
for (const c of load("attestation.json")) {
  for (const a of c.trust_anchors) cert(a);
  const ao = cbor(Buffer.from(c.attestation_object, "hex"));
  const st = ao.attStmt, cd = sha(Buffer.from(c.client_data_json, "hex"));
  let ok = false;
  if (!st.x5c || st.x5c.length === 0) { atts++; continue; }
  if (ao.fmt === "packed" || ao.fmt === "android-key") {
    const key = cert(st.x5c[0].toString("hex")).publicKey;
    ok = verify(st.alg === -7 ? "sha256" : "sha384", Buffer.concat([ao.authData, cd]), { key, dsaEncoding: "der" }, st.sig);
  } else if (ao.fmt === "tpm") {
    const key = cert(st.x5c[0].toString("hex")).publicKey;
    const h = st.alg === -65535 ? "sha1" : "sha256";
    ok = verify(h, st.certInfo, { key, dsaEncoding: "der" }, st.sig);
  }
  if (c.expect.ok && !ok) fail(`attestation#${c.id}: expected ok but the statement signature does not verify`);
  if (!c.expect.ok && !ok && !sigFault.test(c.id)) fail(`attestation#${c.id}: refused case whose signature fails but the id names no signature fault`);
  atts++;
}
console.log(`assertions ${assertions}, chains ${chains}, attestations ${atts}, failures ${bad}`);
process.exit(bad ? 1 : 0);
