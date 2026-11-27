# webauthn-rp contract

One claim per line, each naming the check that proves it. Tags follow the claims ledger: *Type* (the program does not compile), *Runtime* (a check returns an error or a value), *Obligation* (the host's or the consumer's, proven against every `Store` or in the consumer's contract), *Build*, *Non-goal* (named, with its reason).
This file supersedes the webauthn-rp block of architecture section 2, which shows the pre-contract signatures; the amendments it records are listed under Amendments.
Step numbers are those of https://www.w3.org/TR/2026/REC-webauthn-3-20260825/ (the dated HTML whose SHA-256 `vectors/SOURCES.toml` records), as its ordered lists number them; `Error::spec_step` returns the same number as a `SpecStep`.

Checks:
- `ui:x` is `tests/ui/fail/x.rs` with its committed `.stderr` (rustc code given) and the compiling twin `tests/ui/pass/x.rs` one line and one token away (`just twins`); `just ledger` runs with every feature on, pins the case count, requires every `ui:` name here to be a case on disk and the reverse, and each `.stderr` to open with its code. A case marked *illustrates* is a named guess: it shows one plausible spelling fails, so `api` is the real check of that claim.
- `api` is the committed `public-api.txt` from rustdoc JSON on the pinned nightly through the workspace `api.jq` (`just api`).
- `row:f` is `tests/row_f.rs`, one file per vector family, run as one `primitives/rows.json` row; it reads its family through the one `testkit` vector runner (total and checked floor asserted). Families: `w3c_none`, `w3c_packed`, `w3c_attestation_root`, `w3c_tpm`, `w3c_android_key`, `w3c_apple`, `w3c_fido_u2f`, `w3c_prf` read `vectors/w3c-webauthn-3/<name>.json`; `exam_spike` reads `w3c-webauthn-3/exam-spike/assertion-none-es256.json`; `android_key_attestation` reads the four committed `android-key-attestation` chains; `derived` reads `vectors/webauthn-rp-derived/`; `roundtrip` drives the virtual authenticator; `race` runs the `testkit` snapshot-race harness over `store::MemStore`.
- `w3c:f#s` is section `s` of `vectors/w3c-webauthn-3/f`. `oracle:f#c` is case `c` of `vectors/webauthn-rp-derived/f`, the oracle lane's family (ruling R-b); `oracle:f` alone is the whole file. `oracle-pending:f` names a family file the oracle lane has not pushed; its claim is pending until it lands, and no case is written here.
- `prop:t` is a proptest in `tests/props.rs` (fixed seed; the one property so far, the record round trip, runs inside `src/record.rs` as `unit:record::record_round_trip`); `fuzz-pending:t` names the fuzz target `t`: no queue item yet, and libFuzzer needs a clang this zone lacks, so the claim is pending until the target and its corpus land under `fuzz/`; `mutants:m` is `cargo mutants` over `src/m.rs` (`src/attestation/x.rs` for `attestation::x`), every mutant caught or listed with a reason in `mutants.toml`; `unit:m::t` is a test in `src/m.rs`; `unit-pending:m::t` names a test of behaviour not built yet (trust dispatch, unassigned): pending, with no queue item yet.

Stages: the types, traits, constants, module layout and the bodies of items webauthn-02 to webauthn-07 (CBOR, COSE ES256, client data, authenticator data, the record codec, authentication, `none` registration, the virtual-authenticator round trip and the races) are in `src/`. Every public function and trait impl is stated under Signatures, verbatim. The attestation formats other than `none`, trust dispatch, extensions and JSON shapes are not built: their types exist with `#[expect(dead_code)]` naming the item that first reads them, and the `row:` files for them hold no test, so those rows read red (`running 0 tests`) until built.

## Signatures
Functions and trait impls, by the file and item that land them. `BrowserBinding` is `base::BrowserBinding` (ruling R-d), a newtype built from `&Secret<32>` that lands as a base item; every signature naming it waits on that item.

### `src/error.rs` (webauthn-02)
```rust
impl Error {
    /// What failed.
    pub fn kind(&self) -> ErrorKind;
    /// The L3 7.1 or 7.2 step that failed, when the failure is a ceremony step.
    pub fn spec_step(&self) -> Option<SpecStep>;
}
impl fmt::Display for Error { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
impl core::error::Error for Error {}
```
### `src/policy.rs` (webauthn-03)
```rust
impl RpId {
    /// Parse an RP ID; anything but a lowercase ASCII domain is `Malformed`, past `MAX_RP_ID` is `TooLarge`.
    pub fn parse(text: &str) -> Result<Self, Error>;
    /// The RP ID as text.
    pub fn as_str(&self) -> &str;
}
impl Origin {
    /// Parse an origin in the form a client serializes it; any other spelling is `Malformed`.
    pub fn parse(text: &str) -> Result<Self, Error>;
    /// The origin as text.
    pub fn as_str(&self) -> &str;
}
impl RelyingParty {
    /// Start from the RP ID, its display name, its first origin and the counter policy.
    pub fn builder(id: RpId, name: DisplayName, origin: Origin, counter: CounterPolicy) -> RelyingPartyBuilder;
    /// The RP ID every ceremony hashes.
    pub fn id(&self) -> &RpId;
}
impl RelyingPartyBuilder {
    /// Accept one more origin.
    pub fn origin(self, origin: Origin) -> Self;
    /// Set the cross-origin policy; the default is `CrossOrigin::Deny`.
    pub fn cross_origin(self, policy: CrossOrigin) -> Self;
    /// Set the unsolicited-extension policy; the default is `UnsolicitedExtensions::Reject`.
    pub fn unsolicited(self, policy: UnsolicitedExtensions) -> Self;
    /// Set the attestation trust policy; the default is `TrustPolicy::AcceptUntrusted`, since most ceremonies convey no attestation, and a `TrustDecision::Denied` fails under either.
    pub fn trust(self, policy: TrustPolicy) -> Self;
    /// Set the android-key list policy; the default is `KeyEnforcement::TrustedEnvironment`.
    pub fn android_key(self, policy: KeyEnforcement) -> Self;
    /// Finish; a repeated origin is `Malformed`, more than `MAX_ORIGINS` is `TooLarge`.
    pub fn build(self) -> Result<RelyingParty, Error>;
}
impl fmt::Debug for RelyingParty { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
impl fmt::Debug for RelyingPartyBuilder { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
```
### `src/options.rs` (webauthn-04 and webauthn-05)
```rust
impl UserHandle {
    /// Draw a new handle: 32 bytes of `Entropy`.
    pub fn generate(e: &mut impl Entropy) -> Self;
    /// Read a handle back from storage; empty is `Malformed`, longer than `MAX_USER_HANDLE` is `TooLarge`.
    pub fn from_stored(bytes: &[u8]) -> Result<Self, Error>;
    /// The handle's bytes.
    pub fn as_bytes(&self) -> &[u8];
}
impl UserName {
    /// Parse a user name.
    pub fn parse(text: &str) -> Result<Self, Error>;
    /// The name as text.
    pub fn as_str(&self) -> &str;
}
impl DisplayName {
    /// Parse a display name.
    pub fn parse(text: &str) -> Result<Self, Error>;
    /// The name as text.
    pub fn as_str(&self) -> &str;
}
impl UserEntity {
    /// Name the user.
    pub fn new(handle: UserHandle, name: UserName, display_name: DisplayName) -> Self;
    /// The user's handle.
    pub fn handle(&self) -> &UserHandle;
}
impl fmt::Debug for UserName { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
impl fmt::Debug for DisplayName { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
impl fmt::Debug for UserEntity { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
impl fmt::Debug for CreationOptions { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
impl Transport {
    /// The L3 5.8.4 name.
    pub fn as_str(&self) -> &'static str;
    /// Read a name back; any other text is `Malformed`.
    pub fn parse(text: &str) -> Result<Self, Error>;
}
impl CredentialDescriptor {
    /// Name a credential and the transports it was registered with; a repeated transport is kept once.
    pub fn new(id: CredentialId, transports: &[Transport]) -> Self;
    /// The credential id.
    pub fn id(&self) -> &CredentialId;
    /// The transports, without repeats.
    pub fn transports(&self) -> &[Transport];
}
impl Timeout {
    /// Zero is `Malformed`, past `MAX_TIMEOUT_SECS` is `TooLarge`.
    pub fn from_secs(secs: u32) -> Result<Self, Error>;
    /// The timeout in seconds.
    pub fn secs(&self) -> u32;
}
impl RegistrationOptions {
    /// User verification and resident key are always chosen by the caller.
    pub fn new(user_verification: Requirement, resident_key: ResidentKey, timeout: Timeout) -> Self;
    /// Offer one more algorithm, in preference order; with none offered, ES256, EdDSA, ES384 and RS256.
    pub fn algorithm(self, alg: CoseAlgorithm) -> Self;
    /// Ask for an authenticator attachment.
    pub fn attachment(self, attachment: Attachment) -> Self;
    /// Set the attestation conveyance preference; the default is `Conveyance::None`.
    pub fn attestation(self, conveyance: Conveyance) -> Self;
    /// Prefer one more attestation format (`attestationFormats`), in order.
    pub fn attestation_format(self, format: Format) -> Self;
    /// Add a user-agent hint, in order.
    pub fn hint(self, hint: Hint) -> Self;
    /// Set the mediation the client will be called with.
    pub fn mediation(self, mediation: Mediation) -> Self;
}
impl AuthenticationOptions {
    /// User verification is always chosen by the caller.
    pub fn new(user_verification: Requirement, timeout: Timeout) -> Self;
    /// Add a user-agent hint, in order.
    pub fn hint(self, hint: Hint) -> Self;
}
```
### `src/record.rs` (webauthn-04)
```rust
impl CredentialId {
    /// Empty is `Malformed`, longer than `MAX_CREDENTIAL_ID` is `TooLarge`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;
    /// The id's bytes.
    pub fn as_bytes(&self) -> &[u8];
}
impl Aaguid {
    /// From its 16 bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self;
    /// Its 16 bytes.
    pub fn as_bytes(&self) -> &[u8; 16];
}
impl StoreKey for Key { fn scope(&self) -> Scope; }
impl Record {
    /// The row's bytes, version-tagged.
    pub fn encode(&self) -> Result<Vec<u8>, Error>;
    /// Read a row back; an unknown version or shape is `Corrupt`, past `MAX_RECORD` is `TooLarge`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error>;
}
impl RegistrationCeremony {
    /// Narrow a consumer's row to this ceremony, keeping its version; any other record is `Corrupt`.
    pub fn from_row<R>(row: &Row<R>, record: impl FnOnce(&R) -> Option<&Record>) -> Result<Row<Self>, Error>;
}
impl AuthenticationCeremony {
    /// Narrow a consumer's row to this ceremony, keeping its version; any other record is `Corrupt`.
    pub fn from_row<R>(row: &Row<R>, record: impl FnOnce(&R) -> Option<&Record>) -> Result<Row<Self>, Error>;
}
impl Credential {
    /// Narrow a consumer's row to this credential, keeping its version; any other record is `Corrupt`.
    pub fn from_row<R>(row: &Row<R>, record: impl FnOnce(&R) -> Option<&Record>) -> Result<Row<Self>, Error>;
    /// The credential id.
    pub fn id(&self) -> &CredentialId;
    /// The user the credential was registered for.
    pub fn user(&self) -> &UserHandle;
    /// The id with its transports, for an allow or exclude list.
    pub fn descriptor(&self) -> CredentialDescriptor;
    /// The credential public key's algorithm.
    pub fn algorithm(&self) -> CoseAlgorithm;
    /// The last accepted signature counter.
    pub fn sign_count(&self) -> u32;
    /// Backup eligibility and the last seen backup state.
    pub fn backup(&self) -> Backup;
    /// `uvInitialized`: set by a user-verified registration or by `RelyingParty::confirm_user_verification`.
    pub fn uv_initialized(&self) -> UserVerification;
    /// The transports the client reported at registration.
    pub fn transports(&self) -> &[Transport];
    /// The AAGUID the authenticator reported: the model only when `attestation().trust()` is `Anchored`, else self-asserted.
    pub fn aaguid(&self) -> Aaguid;
    /// How the registration was attested.
    pub fn attestation(&self) -> &Attestation;
}
```
### `src/response.rs` (webauthn-04 and webauthn-05)
```rust
impl RegistrationResponse {
    /// Parse the raw parts; each is bounded, a raw id that is not the attested credential id is `CredentialIdInvalid`, an unknown transport name is dropped, and client extension results arrive only through the `serde` shape.
    pub fn new(raw_id: &[u8], client_data_json: &[u8], attestation_object: &[u8], transports: &[Transport]) -> Result<Self, Error>;
    /// The ceremony key the response names, `Key::Ceremony` of the challenge's SHA-256, for the host to load.
    pub fn locate(&self) -> Key;
    /// The new credential's id, from the attested credential data.
    pub fn id(&self) -> &CredentialId;
}
impl AuthenticationResponse {
    /// Parse the raw parts; each is bounded, an empty user handle reads as absent, and client extension results arrive only through the `serde` shape.
    pub fn new(raw_id: &[u8], client_data_json: &[u8], authenticator_data: &[u8], signature: &[u8], user_handle: Option<&[u8]>) -> Result<Self, Error>;
    /// The rows the host loads before finishing; no I/O.
    pub fn locate(&self) -> Lookup;
}
impl fmt::Debug for RegistrationResponse { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
impl fmt::Debug for AuthenticationResponse { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
impl Lookup {
    /// The ceremony row: `Key::Ceremony` of the challenge's SHA-256.
    pub fn ceremony(&self) -> &Key;
    /// The credential row: `Key::Credential` of the raw id.
    pub fn credential(&self) -> &Key;
    /// The user handle the response carries, if any.
    pub fn user(&self) -> Option<&UserHandle>;
}
```
### `src/verify.rs` (start and finish of authentication with webauthn-04, of registration with webauthn-05)
```rust
impl RelyingParty {
    /// L3 7.1 step 1, bound to the starting browser: options for the client, and the effect that creates the ceremony row under its challenge's digest, expiring at its deadline; an over-long list or salt is `TooLarge`.
    pub fn start_registration(&self, user: &UserEntity, exclude: &[CredentialDescriptor], opts: &RegistrationOptions, browser: &BrowserBinding, now: UnixTime, e: &mut impl Entropy) -> Result<(CreationOptions, Effect), Error>;
    /// L3 7.2 step 1, bound to the starting browser: options for the client, and the effect that creates the ceremony row.
    pub fn start_authentication(&self, allow: Allow<'_>, opts: &AuthenticationOptions, browser: &BrowserBinding, now: UnixTime, e: &mut impl Entropy) -> Result<(RequestOptions, Effect), Error>;
    /// L3 7.1 steps 5-29, in the browser the ceremony started in. Every failure, expiry included, is inside the verdict; the effect always deletes the seen ceremony row, and on `Ok` also reserves the credential id.
    pub fn finish_registration(&self, state: Row<RegistrationCeremony>, response: &RegistrationResponse, browser: &BrowserBinding, trust: &dyn TrustSource, now: UnixTime, e: &mut impl Entropy) -> Verdict<Registered>;
    /// L3 7.2 steps 5-24, in the browser the ceremony started in. Every failure is inside the verdict; the effect always deletes the seen ceremony row, and on `Ok` also updates the seen credential row.
    pub fn finish_authentication(&self, state: Row<AuthenticationCeremony>, stored: Row<Credential>, response: &AuthenticationResponse, browser: &BrowserBinding, now: UnixTime, e: &mut impl Entropy) -> Verdict<Assertion>;
    /// Raise the credential's `uvInitialized`, the step L3 7.2 step 24 says to skip unless an extra factor authorized it: an `update` of the seen row (O11).
    pub fn confirm_user_verification(&self, stored: &Row<Credential>, e: &mut impl Entropy) -> Effect;
}
impl Registered {
    /// The credential record the effect reserves.
    pub fn credential(&self) -> &Credential;
    /// Whether the registration was user-verified; this becomes `uvInitialized`.
    pub fn user_verification(&self) -> UserVerification;
}
impl Assertion {
    /// The credential that signed.
    pub fn credential_id(&self) -> &CredentialId;
    /// The credential's user.
    pub fn user(&self) -> &UserHandle;
    /// The UV flag read against the credential's `uvInitialized`.
    pub fn user_verification(&self) -> AssertionVerification;
    /// Backup eligibility and the current backup state.
    pub fn backup(&self) -> Backup;
    /// What the signature counter did.
    pub fn counter(&self) -> Counter;
}
```
### `src/trust.rs` (webauthn-05; `impl TrustAnchor` with webauthn-09)
```rust
impl Attestation {
    /// The statement format.
    pub fn format(&self) -> Format;
    /// The attestation type.
    pub fn kind(&self) -> AttestationType;
    /// Whether it chained to an anchor.
    pub fn trust(&self) -> Trust;
    /// The SHA-256 of each `x5c` certificate, leaf first; empty for none and self.
    pub fn chain(&self) -> &[Digest];
    /// The SHA-256 of the anchor the chain met, when `Anchored`.
    pub fn anchor(&self) -> Option<&Digest>;
}
impl TrustQuery<'_> {
    /// The statement format.
    pub fn format(&self) -> Format;
    /// The AAGUID from the attested credential data, not yet authenticated.
    pub fn aaguid(&self) -> Aaguid;
    /// The SHA-256 of each `x5c` certificate, leaf first, for a revocation or deny list.
    pub fn chain(&self) -> &[Digest];
}
impl TrustAnchor {
    /// Parse one DER certificate; past `MAX_CERTIFICATE` is `TooLarge`, anything but one certificate is `Malformed`.
    pub fn from_der(der: &[u8]) -> Result<Self, Error>;
    /// The SHA-256 of the certificate's DER, as `Attestation::anchor` reports it.
    pub fn digest(&self) -> Digest;
}
```
`TrustSource::decide(&self, query: &TrustQuery<'_>) -> TrustDecision<'_>` is a trait method, declared in `src/trust.rs` now.
### `src/extensions.rs` (webauthn-14)
```rust
impl AppId {
    /// Parse an AppID; anything but an `https` URL of at most `MAX_APP_ID` bytes is `Malformed` or `TooLarge`.
    pub fn parse(text: &str) -> Result<Self, Error>;
    /// The AppID as text.
    pub fn as_str(&self) -> &str;
}
impl PrfEval {
    /// Evaluate one salt.
    pub fn new(first: &[u8]) -> Self;
    /// Evaluate a second salt as well.
    pub fn second(self, second: &[u8]) -> Self;
}
impl PrfOutputs {
    /// The output for the first salt.
    pub fn first(&self) -> &Secret<32>;
    /// The output for the second salt, when one was given.
    pub fn second(&self) -> Option<&Secret<32>>;
}
impl RegistrationOptions {
    /// Request `credProps`.
    pub fn cred_props(self) -> Self;
    /// Request `prf`.
    pub fn prf(self, prf: PrfRequest) -> Self;
    /// Request `largeBlob` support.
    pub fn large_blob(self, support: LargeBlobRequest) -> Self;
    /// Request `appidExclude`.
    pub fn app_id_exclude(self, app_id: AppId) -> Self;
}
impl AuthenticationOptions {
    /// Request `appid`.
    pub fn app_id(self, app_id: AppId) -> Self;
    /// Request `prf` with salts for any credential.
    pub fn prf(self, eval: PrfEval) -> Self;
    /// Request `prf` with salts for one listed credential (`evalByCredential`).
    pub fn prf_for(self, credential: CredentialId, eval: PrfEval) -> Self;
    /// Request a `largeBlob` read or write.
    pub fn large_blob(self, op: LargeBlobOp) -> Self;
}
impl Registered {
    /// `credProps.rk`.
    pub fn discoverability(&self) -> Discoverability;
    /// The `prf` output.
    pub fn prf(&self) -> &PrfResult;
    /// The `largeBlob` output.
    pub fn large_blob(&self) -> LargeBlobSupport;
}
impl Assertion {
    /// Whether the `appid` hash was used.
    pub fn app_id(&self) -> AppIdUsed;
    /// The `prf` output.
    pub fn prf(&self) -> &PrfResult;
    /// The `largeBlob` output.
    pub fn large_blob(&self) -> &LargeBlobOutcome;
}
```
### `src/json.rs` (webauthn-15; the serde impls under feature `serde`)
```rust
impl RelyingParty {
    /// The document to serve at `/.well-known/webauthn` (L3 5.11).
    pub fn related_origins(&self) -> RelatedOrigins;
    /// The options for one of the client's signal methods (L3 5.1.10).
    pub fn signal(&self, signal: Signal) -> SignalOptions;
}
impl fmt::Debug for Signal { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
impl fmt::Debug for SignalOptions { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result; }
impl Serialize for CreationOptions { fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error>; }
impl Serialize for RequestOptions { fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error>; }
impl Serialize for SignalOptions { fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error>; }
impl Serialize for RelatedOrigins { fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error>; }
impl<'de> Deserialize<'de> for RegistrationResponse { fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error>; }
impl<'de> Deserialize<'de> for AuthenticationResponse { fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error>; }
```
Private modules with no public function: `cbor`, `cose` (webauthn-02; `cose` gains ES384, EdDSA and RS256 with webauthn-08), `client_data` (webauthn-03), `authdata` (webauthn-04), `attestation` (dispatch and `none` with webauthn-05), `attestation::packed` (self with webauthn-08, full with webauthn-09), `attestation::chain` (webauthn-09), `attestation::tpm` (webauthn-10), `attestation::android_key` (webauthn-11), `attestation::apple` (webauthn-12), `attestation::fido_u2f` (webauthn-13).

## Files per item
Each later item edits its own files and row file; where it must touch another item's file, the line says where and why.
- webauthn-02: `cbor.rs`, `cose.rs` (ES256), `error.rs`; row:derived (cbor).
- webauthn-03: `client_data.rs`, `policy.rs`; row:derived (client data).
- webauthn-04: `authdata.rs`, `record.rs`, `response.rs`, `verify.rs`, `options.rs`; row:exam_spike, row:derived (authenticator data).
- webauthn-05: `attestation/mod.rs`, `trust.rs`, and the registration halves of `response.rs`, `verify.rs` and `options.rs`, which webauthn-04 opened (the brief pairs 04 and 05 on these files, so they run in sequence); row:w3c_none, row:derived (registration).
- webauthn-06: row:roundtrip only (the virtual authenticator lives in the test, on the signing dev-dependencies).
- webauthn-07: row:race only.
- webauthn-08: `attestation/packed.rs` (self); it also adds ES384, EdDSA and RS256 to `cose.rs` (webauthn-02's) and one dispatch arm to `attestation/mod.rs` (webauthn-05's), because a format is reachable only through the dispatch and stub arms are forbidden (R-a); row:w3c_packed.
- webauthn-09: `attestation/chain.rs`, `attestation/packed.rs` (full); it also adds `impl TrustAnchor` to `trust.rs` (webauthn-05's), because `chain.rs` compiles only under a certificate format and `TrustAnchor::from_der` stays in the API under every feature set (N20); row:w3c_attestation_root, row:w3c_packed.
- webauthn-10 to webauthn-13: each its format file plus one dispatch arm in `attestation/mod.rs`, as webauthn-08; rows w3c_tpm; w3c_android_key and android_key_attestation; w3c_apple; w3c_fido_u2f. With the arms in one `match`, these four can run in parallel only if each arm is its own line and a conflict is rebased, never hand-merged.
- webauthn-14: `extensions.rs` (the setters, accessors and output processing are inherent impls there); it also adds the calls at L3 7.1 step 28 and 7.2 step 23 and the PRF and large-blob bounds of R31 and R61 in `verify.rs` (webauthn-04's and webauthn-05's), since those steps sit inside the finishes; row:w3c_prf.
- webauthn-15: `json.rs` (the deserializers build responses through the byte constructors, then fill `extensions::ClientOutputs`).
- row:derived is shared by 02 to 05, one test function per oracle file, so those four items add disjoint functions to one file.

## Amendments (ruling R-h)
- W-S1: `Allow::User` names the identified user and its list; finishes return `Verdict`; both `start_*` return `Result`; registration and authentication ceremonies are split records (`RegistrationCeremony`, `AuthenticationCeremony`), so one cannot finish the other (T10).
- R-d: both ceremonies take a `base::BrowserBinding` at start and at finish, replacing the browser `Digest` of the draft (R31, R61, R63, O12).
- W-S4: L3 7.2 step 17 is followed as written; `uvInitialized` is reported, never refused, so `ErrorKind::UserNotVerified` means only a clear UV flag under `Required` (R77).
- W-S5: `clientDataJSON` has its own nesting bound, `MAX_CLIENT_DATA_DEPTH`, apart from the CBOR bound (R1, R6).
- W-S6: every anchor whose subject is the last certificate's issuer is tried before the walk reports `Unanchored` (R111).
- W-S7: a named-guess ui case is marked *illustrates*, and its claim names `api` as the real check.
- W-S8: `Error` is a kind plus an optional `SpecStep`, nothing else (R145).
- The oracle settles two choices: a `topOrigin` without `crossOrigin: true` is refused under every policy (R38), and a change in BE is refused (R79, L3 7.2 step 19). It also enforces canonical CBOR map key order (R2), which replaces the draft's non-goal on key order.

## Type
- T1 A `UserHandle` is never built from a string: no `From<String>` or `From<&str>`; `generate` and `from_stored` are the only constructors: api (the real check), ui:user_handle_from_string (E0308).
- T2 An `Origin` comes only from `Origin::parse`: api (the real check), ui:origin_from_string (E0308).
- T3 An `RpId` comes only from `RpId::parse`: api (the real check), ui:rp_id_from_string (E0308).
- T4 `start_registration` and `start_authentication` return no ceremony state: the client options carry no accessor and convert to no ceremony type, and the ceremony row exists only inside the returned `Effect`: ui:options_carry_no_state (E0277, the creation side), api (both options types).
- T5 Records have no serde: `Record`, `RegistrationCeremony`, `AuthenticationCeremony` and `Credential` are neither `Serialize` nor `Deserialize`; bytes go only through `Record::encode` and `Record::decode`: api (all four); the cases `record_serialize` and `record_deserialize`, whose twins need a serializable type of this crate, land with webauthn-15.
- T6 An `Assertion` is made only by `finish_authentication`: no public field, constructor, `Default` or `From`: api (the real check), ui:assertion_new (E0599) illustrates.
- T7 A `Registered` is made only by `finish_registration`: api (the real check), ui:registered_new (E0599) illustrates.
- T8 Ceremony values have no public constructor; they arise from a `start_*` effect, `Record::decode` or `from_row` over a decoded record (O6): api (the real check), ui:ceremony_new (E0599) illustrates.
- T9 A verdict leaves its `Verdict` only through `base::Pending::settle` with the store's `Receipt` (base T10); `finish_*` return `Verdict` with no outer `Result`: api; the case `verdict_unsettled` lands with webauthn-04, whose `impl StoreKey for Key` its twin needs.
- T10 A registration ceremony row cannot finish an authentication, nor the reverse: the ceremony types differ: api; the case `ceremony_kind` lands with webauthn-04.
- T11 BS without BE is unrepresentable: `Backup::SingleDevice` carries no `BackupState`: ui:backup_single_device (E0618), api.
- T12 No development defaults: `RelyingParty` has no `Default` and is built only from an `RpId`, a `DisplayName`, an `Origin` and a `CounterPolicy`; the one stated default that admits more, `TrustPolicy::AcceptUntrusted`, is named in the builder's doc: api (the real check), ui:relying_party_default (E0599) illustrates.
- T13 User verification and resident key are always the caller's choice: neither options type has `Default`, and both `new` take the `Requirement`: api (the real check), ui:registration_options_default (E0599) and ui:authentication_options_default (E0599) illustrate.
- T14 PRF results are `base::Secret<32>`, so never printed, cloned, serialized or compared with `==` (base T1, T3, T5, T7): api; the case `prf_output_display` lands with webauthn-14.
- T15 X.509, DER, SPKI and OID types never appear in the public API; a trust anchor is opaque: api (no match for `\bder::|x509_cert|\bspki|const_oid` in `public-api.txt`), ui:trust_anchor_certificate (E0599) illustrates.
- T16 Every public enum is `#[non_exhaustive]`: ui:error_kind_exhaustive (E0004), api (one `attr ... non_exhaustive` per enum).
- T17 No `bool` parameter, field or accessor (rule 5.4): api (no `bool` token in `public-api.txt`).
- T18 One finish per direction: discoverable and identified authentication differ only in `Allow`, never in the finish called: api.
- T19 Store keys hold the challenge's `Digest` and a bounded `CredentialId`, never the challenge: api (`Key` variants).
- T20 User verification (`Requirement`) and resident key (`ResidentKey`) are distinct types, so the two `RegistrationOptions::new` arguments cannot swap: api; the case `registration_options_swap` lands with webauthn-05.
- T21 A `largeBlob` request is one `LargeBlobOp`, so a ceremony cannot ask to read and write: api (one `AuthenticationOptions::large_blob` setter).

## Runtime: bounds and parsers (rule 5.7)
- R1 Each input bound is a public constant, and input past it is `TooLarge`; an empty value where one is required is `Malformed`: `MAX_CREDENTIAL_ID` 1023, `MAX_USER_HANDLE` 64, `MAX_NAME` 256, `MAX_RP_ID` 253, `MAX_CLIENT_DATA_JSON` 16,384, `MAX_CLIENT_DATA_DEPTH` 8, `MAX_ATTESTATION_OBJECT` 65,536, `MAX_AUTHENTICATOR_DATA` 16,384, `MAX_SIGNATURE` 1,024, `MAX_CBOR_DEPTH` 16, `MAX_CBOR_ITEMS` 1,024, `MAX_X5C` 8, `MAX_CERTIFICATE` 8,192, `MAX_LISTED_CREDENTIALS` 64, `MAX_ORIGINS` 32, `MAX_APP_ID` 2,048, `MAX_PRF_SALT` 256, `MAX_LARGE_BLOB` 65,536, `MAX_RECORD` 8,192, `MAX_TIMEOUT_SECS` 600, `MAX_RSA_BITS` 4,096: api (the values); row:derived over oracle:cbor.json#depth-bound and #item-bound (`webauthn_rp::MAX_CBOR_DEPTH` and `webauthn_rp::MAX_CBOR_ITEMS` plus one, `TooLarge`) and oracle:registration.json#credential-id-1024; the other bounds, `MAX_CLIENT_DATA_DEPTH` among them: oracle:limits.json.
- R2 The CBOR reader is strict: definite lengths only, shortest-form heads and lengths, no tags, no floats, no simple values but `false`, `true` and `null`, map keys unique and in CTAP2 canonical order (shorter encoding first, then bytewise), text strings valid UTF-8, no reserved additional information, nothing after the top item; any of these is `Malformed`: row:derived over oracle:cbor.json (19 `cbor_decode` cases), fuzz-pending:attestation_object (no queue item yet: fuzz targets), mutants:cbor.
- R3 A declared CBOR or DER length is compared with the remaining input before anything is copied or allocated for it: row:derived over oracle:cbor.json#truncated-bytes and #huge-declared-length, unit:cbor::declared_length_past_input, fuzz-pending:attestation_object (no queue item yet: fuzz targets), fuzz-pending:authenticator_data (no queue item yet: fuzz targets).
- R4 Authenticator data: at least 37 bytes; AT set and attested credential data present in a registration, AT clear in an assertion; ED set exactly when an extensions map follows; nothing trailing: row:derived over oracle:authenticator-data.json#authdata-truncated, #authdata-at-flag-no-data, #authdata-ed-flag-no-data, #authdata-trailing-bytes and oracle:registration.json#at-clear (L3 7.1 step 13), fuzz-pending:authenticator_data (no queue item yet: fuzz targets), mutants:authdata.
- R5 COSE keys: ES256 is kty 2, crv 1, 32-byte x and y on the curve; ES384 is kty 2, crv 2, 48-byte x and y on the curve; EdDSA is kty 1, crv 6, a 32-byte valid point; RS256 is kty 3 with n of `MIN_RSA_BITS` to `MAX_RSA_BITS` bits and e 65537; `alg` is present and fits `kty`; a defined label of the wrong type is `Malformed`, unknown labels are ignored: row:derived over oracle:cbor.json#cose-key-canonical, oracle:cose.json, mutants:cose.
- R6 `clientDataJSON` is read by an own bounded reader of one RFC 8259 object: UTF-8 with one leading BOM stripped (7.1 step 5, 7.2 step 8), string escapes decoded, a duplicate member name `Malformed`, nesting past `MAX_CLIENT_DATA_DEPTH` `TooLarge`, `type`, `challenge`, `origin` and `topOrigin` strings, `crossOrigin` a boolean or absent, other members skipped: row:derived over oracle:client-data.json#client-data-not-json (7.2 step 9), #extra-member-ignored and #cross-origin-absent, oracle:limits.json (the depth bound), unit:client_data::nesting_and_size_are_bounded, fuzz-pending:client_data (no queue item yet: fuzz targets), mutants:client_data.
- R7 `C.challenge` is canonical unpadded base64url (`base::b64url_decode`) of exactly 32 bytes, else `ChallengeMismatch`: row:derived over oracle:client-data.json#challenge-padded, #challenge-std-alphabet and #challenge-missing.
- R8 `Origin::parse` accepts `https://` or, for host `localhost` only, `http://`, then a host of lowercase LDH labels (A-labels as written, never converted), then an optional decimal port that is not the scheme's default, and nothing after; or `android:apk-key-hash:` with 43 base64url symbols. Uppercase, an IP literal, a path, query, fragment, userinfo or any other scheme is `Malformed`: oracle:origins.json, mutants:policy.
- R9 `RpId::parse` accepts lowercase LDH labels of at most `MAX_RP_ID` bytes in all, `localhost` included, and refuses a trailing dot, an IP literal or an empty label: oracle:origins.json, mutants:policy.
- R10 `AppId::parse` accepts an `https` URL without fragment of at most `MAX_APP_ID` bytes, hashed as written: oracle:origins.json.
- R11 `UserName` is non-empty and `DisplayName` may be empty; both are at most `MAX_NAME` bytes; `UserEntity::new` joins a handle and both names: unit:options::names_are_bounded_and_never_printed.
- R12 `UserHandle::generate` draws exactly 32 bytes; `from_stored` takes 1 to 64 bytes: unit:options::user_handles_are_32_drawn_bytes_or_1_to_64_stored.
- R13 `Timeout::from_secs` takes 1 to `MAX_TIMEOUT_SECS`; zero is `Malformed`: unit:options::timeouts_are_1_to_the_maximum.
- R14 `Transport::as_str` is the L3 5.8.4 name and `Transport::parse` reads exactly those six names back; `CredentialDescriptor::new` keeps each transport once, in the order given: unit:options::transports_have_their_l3_names, unit:options::descriptors_keep_each_transport_once_in_order.
- R15 `Record::encode` writes a version tag and `decode` reads it back to an equal record (`PartialEq`); `encode` is `TooLarge` if and only if a list is past 255 entries or the row is past `MAX_RECORD`, and every other row decodes back to itself, the setters keep each hint, algorithm and format once, and an unknown version, shape or non-canonical `cred_props` byte is `Corrupt`: unit:record::record_round_trip (every requirement, resident key, attachment, conveyance, mediation and user-verification value), unit:record::every_table_entry_encodes_as_its_index_and_decodes_back, fuzz-pending:record (no queue item yet: fuzz targets), mutants:record.
- R16 `RegistrationResponse::new` and `AuthenticationResponse::new` parse everything they are given (client data, CBOR, authenticator data, statement shape) before any finish runs; an empty `userHandle` reads as absent: fuzz-pending:attestation_object (no queue item yet: fuzz targets), fuzz-pending:authenticator_data (no queue item yet: fuzz targets), oracle:authentication.json (empty user handle).
- R17 A registration's raw id must equal the attested `credentialId` byte for byte, else `CredentialIdInvalid`; `Key::Credential`, `RegistrationResponse::id` and `Credential::id` are the attested id (L3 13.1: the outer id is unsigned): oracle:registration-ids.json.
- R18 `TrustAnchor::from_der` takes exactly one DER certificate of at most `MAX_CERTIFICATE` bytes; `TrustAnchor::digest` is the SHA-256 of that DER: row:w3c_attestation_root over w3c:attestation-root.json#16.1, oracle:limits.json, fuzz-pending:trust_anchor (no queue item yet: fuzz targets).
- R19 `RelyingPartyBuilder::build` refuses a repeated origin (`Malformed`) and more than `MAX_ORIGINS` origins and top origins together (`TooLarge`): unit:policy::the_builder_defaults_and_bounds.
- R20 `RegistrationResponse::locate` is `Key::Ceremony` of SHA-256 of the decoded `C.challenge`; `AuthenticationResponse::locate` is a `Lookup` of that key, `Key::Credential` of the raw id and the user handle, if any; both do no I/O and cannot fail after `new`: unit:response::parts_are_parsed_and_located, unit:response::a_registration_is_parsed_and_located.
- R21 `RegistrationCeremony::from_row`, `AuthenticationCeremony::from_row` and `Credential::from_row` narrow a consumer's row through its projection to this crate's `Record`, keeping the row's version; a projection that yields nothing, or another variant, is `Corrupt`: unit:record::rows_narrow_to_their_kind_and_keep_their_version, mutants:record.

## Runtime: registration (L3 7.1)
- R30 Step 1: `start_registration` draws a 32-byte challenge from `Entropy` and emits it with `rp`, `user`, `pubKeyCredParams` (ES256, EdDSA, ES384, RS256 unless set), `timeout` in milliseconds, `excludeCredentials`, `authenticatorSelection`, `attestation`, `attestationFormats`, `hints` and `extensions`: oracle:options-json.json, unit:verify::start_registration_emits_the_row_and_the_options.
- R31 `start_registration` is `TooLarge` for an exclude list over `MAX_LISTED_CREDENTIALS` or a PRF salt over `MAX_PRF_SALT` or a ceremony row that `Record::encode` refuses past `MAX_RECORD`, and its effect is `Effect::created` of `Key::Ceremony(SHA-256(challenge))` with expiry at the deadline (`now` plus the timeout) and nothing else; the row keeps the browser binding: unit:verify::start_registration_emits_the_row_and_the_options, unit:verify::every_effect_is_one_transaction_of_at_most_two_guards_and_two_writes, mutants:verify.
- R32 Steps 2 to 4 happen in the client; their outputs are the `RegistrationResponse` constructor's arguments, and client extension results arrive only through the `serde` response shape: R132, N5.
- R33 Every refusal below, `Expired` included, is the `Err` inside the returned `Verdict`, whose effect is the delete of the seen ceremony row alone: row:derived over oracle:registration.json (every refusal case asserts that effect), unit:verify::a_valid_registration_reserves_the_credential_and_deletes_the_ceremony, unit:verify::each_registration_check_names_its_kind_and_step. Under the current caps (id at most `MAX_CREDENTIAL_ID`, user handle `MAX_USER_HANDLE`, six transports, `MAX_X5C` certificate digests, the widest accepted key) a credential row never reaches `MAX_RECORD`: unit:record::the_widest_credential_row_fits_the_record_bound. `finish_registration` still checks the row with `Record::encode` and refuses `TooLarge` with the ceremony spent, as defense in depth against a later cap change; that check is not proven by a test.
- R34 Step 7: `C.type` is `webauthn.create`, else `Type`: row:derived over oracle:registration.json#type-get.
- R35 Step 8: SHA-256 of the decoded `C.challenge` equals the challenge digest the ceremony record holds, else `ChallengeMismatch`; so a row loaded under another key cannot finish this response: row:derived over oracle:registration.json#challenge-other, unit:verify::each_registration_check_names_its_kind_and_step.
- R36 Step 9: `C.origin` equals a configured origin exactly, else `OriginMismatch`: row:derived over oracle:registration.json#origin-other.
- R37 Step 10: `crossOrigin: true` is `CrossOriginDenied` under `CrossOrigin::Deny` and accepted under `AnyTop` or `Listed`: row:derived over oracle:registration.json#cross-origin-denied, row:w3c_none over w3c:none.json#16.4 (refused under the default, registered under `AnyTop`).
- R38 Step 11: a present `topOrigin` is `TopOriginDenied` unless `crossOrigin` is true, under every policy (L3 5.8.1 sends it only then); with `crossOrigin: true` it is `TopOriginDenied` under `Deny`, accepted under `AnyTop`, and under `Listed` only when listed; `crossOrigin: true` without `topOrigin` is `TopOriginDenied` under `Listed`: row:derived over oracle:registration.json#top-origin-other and oracle:client-data.json#top-origin-without-cross-origin, row:w3c_none over w3c:none.json#16.5.
- R39 Step 12: the client data hash is SHA-256 over `clientDataJSON` exactly as received: row:w3c_packed over w3c:packed.json (every attested signature covers it).
- R40 Step 13: the attestation object is a CBOR map of exactly `fmt` (text), `attStmt` (map) and `authData` (bytes), else `Malformed`: row:derived over oracle:registration.json#at-clear, oracle:attestation-object.json.
- R41 Step 14: `rpIdHash` is SHA-256 of the RP ID, else `RpIdHash`: row:derived over oracle:registration.json#rp-id-hash-other.
- R42 Step 15: UP must be set unless the options named `Mediation::Conditional`, else `UserNotPresent`: row:derived over oracle:registration.json#up-clear, unit:verify::registration_options_choose_flags_and_algorithms.
- R43 Step 16: UV must be set when user verification is `Required`, else `UserNotVerified`; under `Preferred` a clear UV registers as `PresenceOnly`: row:derived over oracle:registration.json#uv-clear-required and #uv-clear-preferred.
- R44 Step 17: BS without BE is `BackupStateWithoutEligibility`: row:derived over oracle:registration.json#bs-without-be.
- R45 Steps 18 and 19: BE and BS are recorded as `Credential::backup` and the crate applies no other backup policy; BS without BE is refused at step 17 (R44), BE must equal the stored BE at authentication (R79), BS may change either way and is recorded on each `Ok` (R83), and anything beyond that is consumer policy: row:w3c_none over w3c:none.json#16.2 (UP, BE and BS set, UV clear).
- R46 Step 20: the credential key's `alg` is one the options offered, else `Algorithm`: row:derived over oracle:registration.json#alg-not-requested, row:w3c_packed over w3c:packed.json#16.9 and #16.12 (ES512 and Ed448, never offered: `Algorithm`).
- R47 Step 21: `fmt` matches one of the six identifiers byte for byte; any other is `UnknownFormat`, and one whose feature is off is `FormatDisabled`: row:derived over oracle:registration.json#fmt-unknown, unit:attestation::a_format_whose_feature_is_off_is_disabled_not_unknown, unit:attestation::a_listed_format_with_no_procedure_is_refused. Pending, no verification yet: `packed`, `tpm`, `android-key`, `apple` and `fido-u2f` are listed identifiers only when their procedures land (R90 to R99).
- R48 Step 22: the statement verifies by its format's procedure (R90 to R99), else `AttestationInvalid`.
- R49 Step 23: the `TrustSource` is asked once for a statement with a trust path, with its format, the attested AAGUID and the `x5c` digests, and never for none or self: unit-pending:verify::trust_source_asked_once (trust dispatch, unassigned).
- R50 Step 24: `TrustDecision::Denied` is `Untrusted` under every policy; otherwise under `TrustPolicy::AcceptUntrusted` every verified statement registers and `Attestation::trust` reports `Anchored` or `Unanchored`, and under `RequireTrusted` none, self and unanchored statements are `Untrusted`: row:w3c_packed over w3c:packed.json#16.7 (anchored to 16.1, unanchored on `Unknown`, `Untrusted` on `Denied`), row:w3c_none over w3c:none.json#16.2 (`Untrusted` under `RequireTrusted`).
- R51 Step 25: an attested credential id over `MAX_CREDENTIAL_ID` bytes is `CredentialIdInvalid` at step 25: row:derived over oracle:registration.json#credential-id-1023 (registers) and #credential-id-1024 (refused), row:w3c_none over w3c:none.json#16.6.
- R52 Step 26: uniqueness is the effect's `Absent` guard on `Key::Credential` (O3); the crate reads no credential row to register.
- R53 Step 27: the credential record holds id, public key, `signCount`, `uvInitialized`, transports, BE, BS, the ceremony's user handle, the AAGUID and the `Attestation` (format, type, trust, the `x5c` digests and the anchor's): unit:record::credential_fields_are_readable, row:derived over oracle:registration.json#control-none-es256 (its expected credential id).
- R54 Step 28: extension outputs are processed by R120 to R128.
- R55 Step 29: on `Ok` the effect is the delete of the seen ceremony row plus `create` of the credential row (`Absent` plus put); its two keys are distinct, it has a guard, and its two guards and two writes are far under `MAX_EFFECT_SIZE`, so base's `Overlap`, `Empty` and `TooLarge` cannot arise: unit:verify::every_effect_is_one_transaction_of_at_most_two_guards_and_two_writes, unit:verify::a_valid_registration_reserves_the_credential_and_deletes_the_ceremony, mutants:verify.
- R56 A registration finished at or after the ceremony's deadline (`now >= deadline`, as the store treats expiry) is `Expired`, decided from the record's deadline, never from store expiry: unit:verify::each_registration_check_names_its_kind_and_step (`now == deadline`), unit:verify::a_registration_past_its_deadline_is_expired, unit:verify::the_deadline_is_exclusive, row:race.
- R57 The AAGUID authenticates the model only when `Attestation::trust` is `Anchored`; for none, self and unanchored statements it is what the client sent, and `Credential::aaguid` says so: api (the doc), unit-pending:verify::aaguid_follows_trust (trust dispatch, unassigned).
- R58 The finishing browser's binding equals the one `start_registration` stored, else `BrowserMismatch`, so a registration cannot be finished into another browser's session: oracle:browser-binding.json, mutants:verify.

## Runtime: authentication (L3 7.2)
- R60 Step 1: `start_authentication` draws a 32-byte challenge and emits it with `rpId`, `allowCredentials` (the `Allow::User` list; empty for `Discoverable`), `userVerification`, `timeout`, `hints` and `extensions`: oracle:options-json.json.
- R61 `start_authentication` is `TooLarge` for an allow list over `MAX_LISTED_CREDENTIALS`, a PRF salt over `MAX_PRF_SALT` or a large blob over `MAX_LARGE_BLOB`, or a ceremony row that `Record::encode` refuses past `MAX_RECORD` (the host could not decode it); its effect is `Effect::created` of the ceremony row with expiry at the deadline; the row keeps the challenge digest, the browser binding, the SHA-256 of each allowed id and the identified user's handle: unit:verify::start_authentication_emits_the_row_and_the_options, unit:verify::start_authentication_is_bounded, unit:verify::the_ceremony_row_holds_the_challenge_digest_and_never_the_challenge, unit:verify::the_registration_row_holds_the_challenge_digest_and_never_the_challenge.
- R62 Steps 2 to 4 happen in the client, as R32; every refusal below is inside the `Verdict` with the delete alone, as R33: row:derived over oracle:client-data.json and oracle:authenticator-data.json (every refusal case), unit:verify::a_valid_assertion_updates_the_credential_and_deletes_the_ceremony, unit:verify::each_check_names_its_kind_and_step.
- R63 The finishing browser's binding equals the one the ceremony started with, else `BrowserMismatch`, so a response finished from another browser fails (login CSRF): oracle:browser-binding.json, mutants:verify.
- R64 Step 5: with a non-empty allow list the response's credential id must be listed, else `NotAllowed`: oracle:authentication.json.
- R65 Step 6: the stored credential's id is the response's, else `CredentialMismatch`: oracle:authentication.json.
- R66 Step 6: under `Allow::User` the stored credential's user is the identified user, else `UserHandleMismatch`: oracle:authentication.json.
- R67 Step 6: under `Allow::User` a present `userHandle` equals the identified user, else `UserHandleMismatch`: oracle:authentication.json.
- R68 Step 6: under `Allow::Discoverable` `userHandle` is present, else `UserHandleMismatch`: oracle:authentication.json.
- R69 Step 6: under `Allow::Discoverable` `userHandle` equals the stored credential's user, else `UserHandleMismatch`: oracle:authentication.json, mutants:verify.
- R70 Steps 7 to 9: client data is read as R6: row:derived over oracle:client-data.json#client-data-not-json.
- R71 Step 10: `C.type` is `webauthn.get`, exactly, else `Type`: row:derived over oracle:client-data.json#type-create, #type-missing and #type-case.
- R72 Step 11: challenge as R35: row:derived over oracle:client-data.json#challenge-other, unit:verify::each_check_names_its_kind_and_step.
- R73 Step 12: origin as R36, compared exactly: row:derived over oracle:client-data.json#origin-other, #origin-trailing-slash, #origin-http, #origin-port and #origin-subdomain.
- R74 Steps 13 and 14: cross-origin and top origin as R37 and R38: row:derived over oracle:client-data.json#cross-origin-denied, #cross-origin-allowed, #top-origin-other and #top-origin-without-cross-origin, row:w3c_none over w3c:none.json#16.4 and #16.5 (the authentication halves).
- R75 Step 15: `rpIdHash` is SHA-256 of the RP ID, or of the AppID when `appid` was requested and the client reported it used, else `RpIdHash`: row:derived over oracle:authenticator-data.json#rp-id-hash-other and #rp-id-hash-of-origin, oracle:extensions.json (appid).
- R76 Step 16: UP must be set, with no conditional exemption, else `UserNotPresent`: row:derived over oracle:authenticator-data.json#up-clear.
- R77 Step 17: under `Required` the UV flag must be set, else `UserNotVerified`; nothing else is refused here. `Assertion::user_verification` reports `Verified` (UV set, `uvInitialized` true), `FirstUse` (UV set, `uvInitialized` false; not yet an authentication factor, L3 6.1) or `PresenceOnly`; what a host accepts as a factor is its policy (O11): row:derived over oracle:authenticator-data.json#uv-clear-required, #uv-clear-preferred and #uv-set-required, unit:verify::user_verification_and_backup_are_reported.
- R78 Step 18: BS without BE is `BackupStateWithoutEligibility`: row:derived over oracle:authenticator-data.json#bs-without-be.
- R79 Step 19: BE must equal the stored BE, else `BackupEligibilityChanged`; BS may change while BE is set: row:derived over oracle:authenticator-data.json#be-stored-clear-now-set, #be-stored-set-now-clear and #be-bs-set-eligible.
- R80 Steps 20 and 21: the signature over authenticator data then SHA-256 of `clientDataJSON` verifies with the stored key: ES256 and ES384 as strict DER (high S accepted), EdDSA by strict Ed25519 verification, RS256 as PKCS#1 v1.5; anything else is `Signature`: row:exam_spike over `w3c-webauthn-3/exam-spike/assertion-none-es256.json`, row:w3c_none over w3c:none.json, unit:cose::es256_signatures_are_strict_der_and_the_algorithm_is_reported (ES256 strict DER). Pending, no test yet (row:w3c_packed has 0 tests): ES384, RS256 and EdDSA verification, which the oracle sections 16.8, 16.10 and 16.11 of the packed file will check. row:derived over oracle:client-data.json#control-valid, unit:verify::each_check_names_its_kind_and_step, mutants:verify.
- R81 Step 22: both counts zero is `Counter::Unsupported`; a greater count is `Advanced` and stored; otherwise `CounterPolicy::Reject` is `CounterRegressed` and `Tolerate` reports `Regressed { stored, seen }` and keeps the stored count: row:derived over oracle:authenticator-data.json#counter-advanced, #counter-regressed, #counter-equal, #counter-zero-after-nonzero, #counter-both-zero and #counter-regressed-tolerate, unit:verify::counters_follow_the_policy, unit:verify::each_check_names_its_kind_and_step, mutants:verify.
- R82 Step 23: extension outputs are processed by R120 to R128.
- R83 Step 24: on `Ok` the effect is the delete of the seen ceremony row plus `update` of the seen credential row (new count unless regressed, current BS); `finish_authentication` never raises `uvInitialized`, which is the step's skip when no extra factor authorized it: unit:verify::a_valid_assertion_updates_the_credential_and_deletes_the_ceremony, unit:verify::user_verification_and_backup_are_reported, mutants:verify.
- R84 `confirm_user_verification` is `Effect::updated` of the seen credential row with `uvInitialized` raised and nothing else changed: unit:verify::confirming_raises_uv_initialized_alone.
- R85 An authentication finished at or after the deadline is `Expired`, as R56: unit:verify::each_check_names_its_kind_and_step (`now == deadline`), unit:verify::an_assertion_past_its_deadline_is_expired, unit:verify::the_deadline_is_exclusive.

## Runtime: attestation formats (L3 section 8), one cargo feature each
- R90 `none` (8.7): `attStmt` is an empty map, else `Malformed`; type `None`: row:w3c_none over w3c:none.json#16.2, #16.4, #16.5 and #16.6, row:derived over oracle:registration.json#control-none-es256 and #none-with-statement.
- R91 `packed` self (8.2): no `x5c`, `alg` equals the credential key's, and `sig` verifies with the credential key; type `SelfAttestation`: row:w3c_packed over w3c:packed.json#16.3, mutants:attestation::packed.
- R92 `packed` full (8.2, 8.2.1, 8.2.2): `sig` verifies with the `x5c[0]` key under `alg`; that certificate is version 3, its subject has C, O, OU `Authenticator Attestation` and CN, basicConstraints CA is false, an AAGUID extension (1.3.6.1.4.1.45724.1.1.4), when present, is non-critical and equals the attested AAGUID, and a serial-number extension (1.3.6.1.4.1.45724.1.1.2), when present, is non-critical; type `Uncertain`, trust path `x5c`: row:w3c_packed over w3c:packed.json#16.7, #16.10 and #16.11, oracle:attestation.json (packed AAGUID and serial number), mutants:attestation::packed.
- R93 `tpm` (8.3): `ver` is `2.0`; own bounded parsers read `pubArea` (TPMT_PUBLIC, RSA or ECC, nameAlg SHA-256 or SHA-1) and `certInfo` (TPMS_ATTEST); the `pubArea` key equals the credential key: row:w3c_tpm over w3c:tpm.json#16.13, oracle:attestation.json (pubArea), fuzz-pending:attestation_object (tpm seeds), mutants:attestation::tpm.
- R94 `tpm` `certInfo` (8.3): magic TPM_GENERATED_VALUE, type TPM_ST_ATTEST_CERTIFY, `extraData` equal to the hash of authenticator data then client data hash under `alg`'s hash, and an attested name equal to nameAlg then the nameAlg hash of `pubArea`: row:w3c_tpm over w3c:tpm.json#16.13, oracle:attestation.json (certInfo), mutants:attestation::tpm.
- R95 `tpm` signature and AIK certificate (8.3, 8.3.1): `sig` verifies over `certInfo` with the AIK certificate key under `alg` (RS256, RS1 with SHA-1, or ES256); the AIK certificate is version 3 with an empty subject, a SAN, EKU 2.23.133.8.3, basicConstraints CA false and a matching AAGUID extension when present; type `AttCa`: row:w3c_tpm over w3c:tpm.json#16.13, oracle:attestation.json (AIK, RS1), mutants:attestation::tpm.
- R96 `android-key` (8.4): `sig` verifies with the leaf key, and the leaf key equals the credential key; type `Basic`: row:w3c_android_key over w3c:android-key.json#16.14, mutants:attestation::android_key.
- R97 `android-key` key description (8.4.1, 1.3.6.1.4.1.11129.2.1.17), read by a tolerant header walk so later schema versions parse: `attestationChallenge` equals the client data hash, `allApplications` is absent from both lists, and origin GENERATED and purpose SIGN appear in `teeEnforced` (or either list under `KeyEnforcement::AnyList`): row:w3c_android_key over w3c:android-key.json#16.14, row:android_key_attestation (each committed leaf's key description parses), oracle:attestation.json (android-key lists), mutants:attestation::android_key.
- R98 `apple` (8.8): SHA-256 of authenticator data then client data hash equals the nonce in extension 1.2.840.113635.100.8.2 of the leaf, and the leaf key equals the credential key; type `AnonCa`: row:w3c_apple over w3c:apple.json#16.15, mutants:attestation::apple.
- R99 `fido-u2f` (8.6): `x5c` is one certificate with a P-256 key, the credential key is EC2 P-256, and `sig` verifies over 0x00, `rpIdHash`, client data hash, credential id and the uncompressed point; type `Uncertain`: row:w3c_fido_u2f over w3c:fido-u2f.json#16.16, mutants:attestation::fido_u2f.
- R100 Each format's module compiles only under its own feature, and `none` pulls in no X.509 crate: `just wasm` (each format feature alone, from `gates.json`), and the inverse-tree check that `none` alone has no `x509-cert` is a shared-recipe need, pending.

## Runtime: the attestation chain walk (own, over x509-cert; D6 ruling)
- R110 The walk follows `x5c` in order, never builds a path, and stops at `MAX_X5C` certificates plus one anchor: oracle:chains.json (too long), oracle:limits.json (x5c).
- R111 Each certificate's signature verifies under the next one's key, and the last under an anchor whose subject is its issuer, or the last is an anchor byte for byte; every anchor whose subject matches is tried, in the `TrustSource`'s order, before the walk reports `Unanchored`, so two anchors sharing a subject cannot hide each other: row:w3c_packed over w3c:packed.json#16.7 (to the 16.1 root), row:android_key_attestation (the four committed chains, each `Anchored` to its own root at the `now` the row pins inside every certificate's validity), oracle:chains.json (shared subject), mutants:attestation::chain.
- R112 Issuer and subject chain by exact DER equality: oracle:chains.json (name mismatch).
- R113 Every certificate above the leaf has basicConstraints CA true and a path length its depth respects, and keyCertSign when keyUsage is present: oracle:chains.json (not CA, path length, key usage).
- R114 Every certificate's validity contains `now`, except the android-key leaf (N14); `now` is the finish's argument: row:android_key_attestation, oracle:chains.json (expired, not yet valid).
- R115 The leaf may carry critical extensions the walk does not read (the TPM leaf's critical SAN and EKU: the reason the walk is own); on a CA certificate or an anchor, a critical extension other than basicConstraints, keyUsage, extKeyUsage and subjectAltName fails the walk: row:w3c_tpm over w3c:tpm.json#16.13 (its critical leaf extensions pass), oracle:chains.json (CA critical extension).
- R116 Chain signatures verify as ecdsa-with-SHA256 or ecdsa-with-SHA384 on P-256 or P-384, or sha256, sha384 or sha512 with RSA of `MIN_RSA_BITS` to `MAX_RSA_BITS` bits: row:android_key_attestation (EC and RSA chains), oracle:chains.json (P-384 root), mutants:attestation::chain.
- R117 Outcomes: a chain signed by an algorithm outside R116 is `Unanchored`; an internally valid chain that meets no anchor is `Unanchored`; every other failure of R110 to R115 is `AttestationInvalid`, never `Unanchored`: oracle:chains.json (each case states its outcome), mutants:attestation::chain.

## Runtime: extensions (L3 10.1)
- R120 `appid`: requested by `AuthenticationOptions::app_id`; `appid: true` selects the AppID hash for step 15; the output without the request is unsolicited (R128): oracle:extensions.json.
- R121 `appidExclude`: emitted by `RegistrationOptions::app_id_exclude`; its output is read and ignored when requested: oracle:extensions.json, oracle:options-json.json.
- R122 Every requested client output reads `NotRequested` without the request and `Unreported` when requested and absent (always without the `serde` response shape): `Discoverability`, `PrfResult`, `LargeBlobSupport` and `LargeBlobOutcome`: oracle:extensions.json.
- R123 `credProps`: `rk` becomes `Discoverability::Discoverable` or `NonDiscoverable`: oracle:extensions.json.
- R124 `prf` at registration: `Enable` emits `prf: {}`, `Eval` emits base64url `eval.first` and `eval.second`; `enabled` and results become `PrfResult`; results without `Eval`, or a second result without a second salt, are `Extension`; a result that is not 32 bytes is `Malformed`: row:w3c_prf over w3c:prf.json#16.17.1.1, oracle:extensions.json.
- R125 `prf` at authentication: `eval` and `evalByCredential`, whose keys must be listed in `Allow::User` (else `start_authentication` is `Extension`); results as R124: row:w3c_prf over w3c:prf.json#16.17.1.1, oracle:extensions.json.
- R126 `largeBlob` at registration: `support` emitted; `supported` becomes `LargeBlobSupport`: oracle:extensions.json.
- R127 `largeBlob` at authentication: the one `LargeBlobOp`; `blob` only after `Read` and `written` only after `Write`, else `Extension`; a blob past `MAX_LARGE_BLOB` is `TooLarge`: oracle:extensions.json.
- R128 An unrequested client or authenticator extension output is `Extension` under `UnsolicitedExtensions::Reject` (the default) and dropped under `Ignore`; authenticator outputs (the ED map) are a CBOR map with text keys, and this crate requests none, so each is unsolicited: oracle:extensions.json.

## Runtime: JSON shapes, related origins and signals (feature `serde`)
- R130 `CreationOptions` serializes as `PublicKeyCredentialCreationOptionsJSON` (5.1.8): base64url for the challenge, user id, listed ids and PRF salts; absent members omitted; `requireResidentKey` true exactly when `residentKey` is required; `timeout` in milliseconds; hints and attestation formats in order, without repeats: oracle:options-json.json.
- R131 `RequestOptions` serializes as `PublicKeyCredentialRequestOptionsJSON` (5.1.9): oracle:options-json.json.
- R132 `RegistrationResponse` and `AuthenticationResponse` deserialize from `RegistrationResponseJSON` and `AuthenticationResponseJSON`: `id` equals base64url of `rawId`, `type` is `public-key`, base64url members canonical, `clientExtensionResults` typed per R120 to R127 with unknown members kept as unsolicited, other unknown members ignored; a refusal is `de::Error::custom` of this crate's `Error` `Display` (kind and step, never input), so `TooLarge` and `Malformed` stay apart: oracle:response-json.json.
- R133 Verification never needs `serde`: the section 16 and derived rows run with `--no-default-features --features none,packed,tpm,android-key,apple,fido-u2f` through the byte constructors: the rows' commands (a `primitives/rows.json` need).
- R134 `related_origins` lists, in configuration order, every configured origin whose host is neither the RP ID nor under it, as `{"origins": [...]}` (5.11): oracle:options-json.json.
- R135 `signal` fills in the RP ID and emits `{rpId, credentialId}`, `{rpId, userId, allAcceptedCredentialIds}` or `{rpId, userId, name, displayName}` (5.1.10.2 to 5.1.10.4): oracle:options-json.json.

## Runtime: keys, records, effects and errors
- R140 `Key::scope` is `Scope::Global` for both kinds, so `base::Effect::lift` refuses any consumer key map that qualifies them (base R15): unit:record::keys_are_global, mutants:record.
- R141 Every effect this crate emits holds only `Ceremony` and `Credential` keys, at most two guards and two writes, so it lies in one transaction domain (the passkeys domain of architecture section 3): unit:verify::every_effect_is_one_transaction_of_at_most_two_guards_and_two_writes.
- R142 The ceremony row holds no challenge byte: only the challenge's SHA-256 (its own key), the deadline, the browser binding and the options its finish checks: unit:verify::the_ceremony_row_holds_the_challenge_digest_and_never_the_challenge, unit:verify::the_registration_row_holds_the_challenge_digest_and_never_the_challenge.
- R143 A consumer composes through `base`: a `start_*` effect and a `finish_*` verdict lift into the consumer's key and record types with the same id, apply on `store::MemStore`, and settle with its receipt: row:roundtrip.
- R144 The virtual authenticator registers and authenticates through every enabled format and algorithm it supports, and any one-byte change to a response fails: row:roundtrip.
- R145 `Error` is exactly a kind and an optional `SpecStep`; each failure of a ceremony step returns its kind and step, and the step of every refusal is data in the vector file (the oracle's `spec`), never generated by the crate; `kind` is compared only where the oracle names one (`CounterRegressed`, `TooLarge`): row:derived over oracle:authenticator-data.json#counter-regressed and oracle:cbor.json#depth-bound, unit:error::display_names_kind_and_step, unit:verify::each_check_names_its_kind_and_step.
- R146 `Display` of an `Error` reads "<what failed> at <ceremony> step N; <next action>" from fixed text per kind, never input bytes, and is for operators and logs, never shown to the client (O10); the sentences are pairwise distinct; `Debug` of `UserName`, `DisplayName`, `UserEntity`, `Signal` and both responses prints no name and no input byte: unit:error::each_kind_reads_distinctly, unit:error::display_names_kind_and_step, unit:options::names_are_bounded_and_never_printed, unit:options::creation_options_print_no_name and unit:response::debug_prints_no_part (a marker planted in each input field never appears in a `Display` or `Debug`; `Signal` has no `Debug` until webauthn-15).

## Obligation
- O1 The host applies every effect under the base obligations (`testkit::store_conformance` on its exact apply path).
- O2 A ceremony is finished at most once: the finish effect deletes the seen ceremony row, so a second finish, concurrent or replaying the same response, loses as `Conflict` (`Missing` or `Changed`), which is why no `Replayed` error kind exists here: row:race (pairs, and the same response twice).
- O3 A credential id is reserved at most once across all users: two registrations of one id both decide `Ok` and one loses on the `Absent` guard as `Present`; that `Present` on `Key::Credential` is the step 26 failure and is not re-decided; this holds only while the consumer keeps `Key` global (R140): row:race.
- O4 Two assertions of one credential read one row version; one wins and the other re-decides against the new count, so a counter regression is never `Ok` under `Reject`: row:race.
- O5 After `Conflict` the consumer reloads the ceremony and credential rows and finishes again at most `base::REDECIDE` times; a ceremony row now missing ends the ceremony as failed: row:race.
- O6 Ceremony rows are written only to the store: `Effect::puts` exposes the `Record` and `Record::encode` is public, so a host could park one in a cookie; nothing but review stops it (architecture E12).
- O7 The host loads the ceremony row under the key `locate` names; R35 refuses any other row, and the `Consume` guard of the delete covers the load: pending othala-core's contract (its finish case).
- O8 A stored row that fails `Record::decode` is reported through `base::Rows::corrupt`, and the consumer fails the ceremony rather than reading it as absent: pending othala-core's contract (its corrupt-row case).
- O9 The credential reservation is inert until the consumer grants it: per architecture section 3, `PasskeysOf(Subject)` in the account domain is the authority; the consumer's grant guards its session and identity rows, and its login effect `expect`s a `PasskeysOf` naming `Assertion::credential_id`; this crate supplies `Registered::credential`, `Assertion::credential_id` and `Assertion::user` for that: api, and pending othala-core's contract.
- O10 The host shows the client one refusal for every ceremony failure, so a bad signature, an unknown credential and an unknown user look alike (L3 14.6.2, 13.4.7); `Error::kind` and `Display` are for logs; for an unknown user it serves `Allow::User` with decoy descriptors rather than `Discoverable`, and it throttles unauthenticated `start_*` calls, since each creates a row that only store expiry removes: pending othala-core's contract.
- O11 The host decides whether `AssertionVerification::FirstUse` counts as a factor; it calls `confirm_user_verification` only after an extra factor succeeded for the same login, and commits it against the credential row the finish wrote: pending othala-core's contract.
- O12 The `BrowserBinding` passed to each `start_*` and `finish_*` is built from a secret the host keeps in that browser's cookie (ruling R-d); a host that passes a constant disables R58 and R63: pending othala-core's contract and the base `BrowserBinding` item.
- O13 `UserHandle::from_stored` is fed only handles the host stored, and the host maps handles to subjects: pending othala-core's contract.

## Build
- B1 `no_std` + `alloc` for wasm32-unknown-unknown with default features off, every feature on, and each feature alone, and for thumbv7em-none-eabi with default features off and every feature but `std`: `just wasm`, `just thumb` (the feature sets in `gates.json`).
- B2 Each format feature, `serde` and `std` builds alone; `std` only forwards `base/std` (so `UnixTime` comes from `SystemTime`), and nothing in this crate needs it: `just wasm` (one build per feature in `gates.json`).
- B3 MSRV 1.89 against the committed lock, workspace-wide: `just msrv`.
- B4 Runtime dependencies are exactly the adopted ones this crate needs: base, p256, p384, ed25519-dalek, rsa (0.10, `pkcs1v15`, verify only), sha2, sha1 (feature `tpm` only), serde (feature `serde`), x509-cert, der, spki, const-oid; the X.509 crates are optional and enabled only by the five certificate formats: `just deps` (`deps.txt`), `just deny`.
- B5 `rsa` is used only to verify PKCS#1 v1.5 signatures: no `RsaPrivateKey` or `SigningKey` in `src/`: review, until a clippy.toml path for this crate is a shared-file need met.
- B6 The workspace lints (rule 5.3) apply unchanged and every deny-list lint is `forbid` here; `src/` holds no lint attribute: `just canary`, `just lint`.

## Non-goal
- N1 `android-safetynet` (8.5) and `compound` (8.9): L3 section 16 has no vector for either; their `fmt` is `UnknownFormat`.
- N2 Credential algorithms ES512, Ed448, PS256 and RS1, and the fully-specified -9, -19, -51 and -52: never offered, and `Algorithm` at step 20 (R46); ES512 needs p521, outside this crate's list.
- N3 Chain signatures on P-521 keys: `Unanchored` (R117).
- N4 Revocation fetching (CRL, OCSP, the Android status list) and FIDO MDS download: a `TrustSource` turns them into `TrustDecision::Denied` by AAGUID or by any `x5c` digest (`webauthn-mds`); nothing is fetched here.
- N5 Client-side work: `getClientCapabilities` (5.1.7), the navigator calls of 7.1 and 7.2 steps 2 to 4, and the CTAP2 hmac-secret exchange (w3c:prf.json#16.17.1.2 counts as not applicable).
- N6 Authenticator extensions of 10.2 and non-core extensions (credProtect, devicePubKey and the like): treated only as unsolicited outputs (R128).
- N7 Passkey classes (6.2) as types: reported only through `Backup`.
- N8 Registrable-domain arithmetic: the related-origins label limit (5.11) is the client's and needs a public suffix list; it is not computed.
- N9 The optional record contents of 7.1 step 27 (`attestationObject`, `attestationClientDataJSON`, `rpId`) are not stored.
- N10 Vendor roots are not embedded; the host or `webauthn-mds` supplies every anchor.
- N11 A `uvInitialized` policy: whether `FirstUse` is a factor is the consumer's (R77, O11; ruling R-h W-S4).
- N12 The real-authenticator corpus beyond the committed Android chains: the `[wanted]` items of `vectors/SOURCES.toml`; each lands with its own row.
- N13 TPM manufacturer, model and version are parsed from the SAN, not checked against the TCG vendor registry.
- N14 The android-key leaf's validity dates are not checked.
- N15 Zeroize of PRF results and large blobs is best effort (base's non-claim).
- N16 `UserHandle::from_stored` accepts any 1 to 64 bytes, since the spec allows imported handles; that a handle carries no PII rests on O13. Generated handles are 32 bytes, above the 16 bytes of entropy L3 14.6.1 asks for.
- N17 Own parsers, for stated reasons: the CBOR reader (no adopted decoder checks shortest form, canonical order and duplicates), the `clientDataJSON` reader (verification works without `serde`, R133), and the `Origin`, `RpId` and `AppId` parsers (`http` is std-only, D10, and `url` is rejected, so neither fits B1's `no_std`).
- N18 PRECIS enforcement of user and display names (RFC 8265, 8266; a SHOULD in 5.4.3) is the host's: the crate checks only length and emptiness.
- N19 Credential removal: the consumer deletes `Key::Credential` through `base` with a guard on the seen row, which also releases the id; the crate emits no removal effect.
- N20 The public API is the same under every feature set; a disabled format is `FormatDisabled` at step 21, so no per-feature API snapshot is kept.
- N21 `Error` has no source chain by design: a cause would be an oracle (O10, R146), so `Error::source` is `None`.

## Coverage
| Area | Lines |
|---|---|
| 7.1 registration | R30 to R58, R90 to R100, R110 to R117, O2, O3, O7 |
| 7.2 assertion | R60 to R85, O2, O4, O5, O7, O11, O12 |
| 8 formats | R90 to R99, one feature each (R100); N1 non-goals |
| 10.1 client extensions | R120 to R128 |
| 10.2 authenticator extensions | R128, N6 |
| 6.1.3 BE/BS | T11, R44, R45, R78, R79 |
| 6.1 uvInitialized | R77, R83, R84, O11, N11 |
| 6.2 passkey classes | N7 |
| 5.1.7 capabilities | N5 |
| 5.1.8-9 JSON | R130 to R133 |
| 5.1.10 signals | R135 |
| 5.11 related origins | R134, R36, N8 |
| topOrigin and cross-origin | R37, R38, R74 |
| conditional mediation | R42 (create); `Allow::Discoverable` for get (R68, R69) |
| 5.8.8 hints | R30, R60, R130 |
| 15.1 timeout | R13, R56, R85 |
| MDS | `TrustSource` (R49, R50), N4, N10 |
| 13.4.5 attestation CA compromise | R53 (`Attestation::chain`, `anchor`), R50 (`Denied`) |
| 14.6 privacy (enumeration, credential id leakage) | O10 |
| login and registration CSRF | R58, R63, O12 |
| counter and clone policy | R81, O4 |
