# Architecture contract: identity primitives and Othala as their consumer (2026-11-24)
## 1. Crate set
| Crate | Purpose | Publish | Ambition |
|---|---|---|---|
| base | Shared vocabulary: UnixTime, Entropy, secrets, Digest, strict base64url, and the one store-effect contract (Effect, Guard, Pending, Receipt) | yes | minimal |
| jose | JWS, JWK/JWKS, JWA, JWT, thumbprints with algorithm bound to key type | yes | comprehensive |
| webauthn-rp | WebAuthn L3 relying-party ceremonies and verifier, strict CBOR/COSE inside | yes | comprehensive |
| webauthn-mds | FIDO MDS trust anchors and AAGUID status as a TrustSource | yes, later | comprehensive, deferred |
| oidc-provider | OAuth2/OIDC provider protocol as a pure state machine with typed interaction outcomes | yes | comprehensive |
| factor | Password (PHC/Argon2id policy), HOTP/TOTP, recovery codes, attempt throttle | yes | minimal |
| othala-core | Identities, sessions, login orchestration, authentication provenance, Ory-shaped compatibility surface | internal | opinionated |
| othala-native, othala-worker | The two shells: sockets/SQLite, and workers-rs/Durable Object | internal | thin |
| testkit | Vector runner, ChaCha-seeded Entropy, in-memory Store, snapshot-race and store-conformance harnesses; dev-dependency only | internal | minimal |
Coverage (each row becomes a CONTRACT.md line as covered, feature-gated, or named non-goal):
- jose: RFC 7515 compact, flattened and general; 7517; 7518 signature algs HS/RS/PS/ES plus EdDSA via 8037; 7519; 7638; every RFC 8725 3.1-3.12 practice mapped to a rule or a non-goal; optional 7797, 9278, 9864; JWE (7516) now in scope (D3). Open slot: no Rust crate has compile-time binding, this breadth, pure-Rust crypto and 8725 defaults together.
- webauthn-rp: L3 7.1 and 7.2 in full; six attestation formats, one feature each, each with a published vector: none (16.2), packed (16.7-16.12), tpm (16.13), android-key (16.14), apple (16.15), fido-u2f (16.16). Named non-goals until a corpus exists: android-safetynet (8.5) and compound (8.9). Extensions appid, appidExclude, credProps, prf (16.17.1), largeBlob; BE/BS; JSON option shapes (5.1.8-9); signal data (5.1.10); related origins (5.11); topOrigin; conditional mediation; hints; server-side timeout. Open slot: no library advertises a sans-IO, wasm-clean, full-L3 verifier.
- oidc-provider: NOW rows (Core code flow, Discovery/8414, RFC 6749 code and refresh with basic/post/none, 7636, 8628, 8707, 9700 defaults, back-channel and RP-initiated logout) in the default feature set; SOON rows (7009, 7662, 9068, 9207) next; COMP rows (implicit/hybrid, PAR, DPoP, front-channel, DCR, token exchange, mTLS) as separate features.
- factor: RFC 4226/6238, NIST SP 800-63B look-up secrets and length rules, OWASP Argon2id floor; hashing via RustCrypto argon2.
DAG: othala-native and othala-worker -> othala-core -> {oidc-provider -> jose, webauthn-rp, factor} -> base; webauthn-mds -> webauthn-rp; testkit is a dev-dependency of every crate and depends on base only. No publishable crate depends on an Othala crate, on another crate's internals, or on an I/O crate.

## 2. Public contracts (signatures only)
Rules for all: every public struct has private fields, a named constructor and accessors; every public enum is #[non_exhaustive]; no all-pub structs. Traits are sealed unless extension is their purpose. Errors are Error { kind: ErrorKind, .. } with a fieldless Copy kind; Display never carries secret-derived detail. Every parser takes input bounded by rule 5.7.
Claims ledger: each claim is tagged by what carries it, and section 4 gives the proof each tag requires. Type: the program does not compile. Runtime: a check returns an error. Obligation: the caller must do something the crate cannot see; it is named in CONTRACT.md and tested against every store. Nothing is called unrepresentable unless it is Type.
### base
pub struct UnixTime(u64);  // seconds; From<SystemTime> only behind std
pub trait Entropy { fn fill(&mut self, out: &mut [u8]); }  // the only way randomness enters (D11)
pub struct Secret<const N: usize>; pub struct SecretBytes;  // SecretBytes: imported TOTP and HS keys
impl Secret<N> { generate(e: &mut impl Entropy) -> Self; expose(&self) -> &[u8; N] /*behind the base feature `expose` (R-j)*/; ct_eq(&self, &Self) -> bool; digest(&self) -> Digest /*SHA-256*/ }  // expose is the single greppable read, and exists only behind base/expose, which a crate enables only if its gates.json declares `expose` (R-j)
pub struct Digest([u8; 32]);  // Eq, Ord, Hash, Serialize: safe to store and index
pub fn b64url_encode(&[u8]) -> String; pub fn b64url_decode(&str) -> Result<Vec<u8>, Error>;  // Malformed on padding or a non-canonical tail
pub enum ErrorKind { Malformed, Overlap, TooLarge, Empty, ScopeChanged, SpansDomains, WrongReceipt }
pub trait StoreKey: Ord + Clone { fn scope(&self) -> Scope; }  // Scope::{Global, Subject}: a consumer qualifies Subject keys with the subject, never Global ones
pub struct Version(u64);  // never repeats for a key, across deletes too
pub struct Row<R>;  // Row::new(record, version)
pub struct Rows<K, R>;  // insert(K, Option<Row<R>>), corrupt(K), get(&K)
pub enum Guard<K> { Consume(K), Unchanged(K, Version), Absent(K) }  // Consume: the row must exist and is deleted
pub struct Effect<K, R>;  // id(), guards(), puts() -> (K, R, Option<UnixTime> expiry), deletes()
impl Effect { builder(e: &mut impl Entropy) -> Builder  // the only constructor; the id is 16 bytes of Entropy
  lift<K2,R2>(self, key: impl Fn(K)->K2, record: impl Fn(R)->R2) -> Result<Effect<K2,R2>, Error>  // same id; a non-injective map is Overlap, a scope change is ScopeChanged
  merge(self, other) -> Result<Self, Error>  // Overlap if a key is in both, TooLarge past the bound; the merged id is the digest of both ids
  domain<D: Eq>(&self, of: impl Fn(&K)->D) -> Result<D, Error>  // SpansDomains unless every key maps to one domain
  host_applied(&self) -> Receipt }  // the one Receipt mint; confined to the stores of testkit and the two shells (the phase-0 store crate is where this goes)
impl Builder { create(k, r, expiry) /*Absent+put*/; update(k, seen: &Row, r, expiry) /*Unchanged+put*/; consume(k); delete(k, seen); expect(k, seen); expect_absent(k); build() -> Result<Effect, Error> /*Overlap, TooLarge, Empty*/ }  // every write is paired with a guard on its own key. dc441b29 also adds Effect::created/updated/consumed/deleted shorthands.
pub struct Receipt;  // a store committed this one Effect; not Clone
pub struct Conflict<K>;  // failures() -> &[(K, Failure)], Failure::{Missing, Changed, Present}; nothing was applied
#[must_use] pub struct Pending<T, K, R>;  // a verdict void until settled with its effect's Receipt
impl Pending { effect(&self) -> &Effect; settle(self, Receipt) -> Result<T, Error> /*WrongReceipt, and the verdict is gone*/; lift(..); join<U>(self, Pending<U,K,R>) -> Result<Pending<(T,U),K,R>, Error> }  // Pending::map was REMOVED: it let a verdict escape without a receipt
pub trait Store<K, R> { type Error;  // Error means outcome unknown; a store's own constraint failure is Conflict, never Error
  fn load(&mut self, keys: &[K], now: UnixTime) -> Result<Rows<K,R>, Self::Error>;
  fn apply(&mut self, effect: &Effect<K,R>, now: UnixTime) -> Result<Result<Receipt, Conflict<K>>, Self::Error>; }
pub struct Retry; pub const REDECIDE: u8 = 3;  // re-applies of one Effect after Error; re-decisions after Conflict
- Type: a secret printed, cloned, serialized or compared with == (no Display, Clone, Serialize or PartialEq; Debug redacts); a bearer value as a store key or record field without expose (store-facing types take Digest, never Secret; expose is confined to the modules each CONTRACT.md names); a verdict out of Pending without a Receipt; a put or delete with no guard on its key.
- Runtime: a key named twice in one effect, merge or lift (Overlap); a lift that changes a key's scope (ScopeChanged); an effect with no guard (Empty); an effect past the bound (TooLarge); an effect spanning transaction domains (SpansDomains, before anything is written); a receipt for another effect (WrongReceipt).
- Obligation (the only one the three protocol crates place on a host; proof: testkit::store_conformance against every Store, on the exact apply path each shell uses):
  - Apply an Effect in one transaction: every guard holds or nothing is applied, and the answer is a Conflict naming each failed guard.
  - Two effects conflict when one writes a row the other guards or writes. Concurrent applies equal some serial order.
  - A Receipt is minted only after commit: host_applied is lint-confined.
  - Re-applying an applied id returns Ok with its receipt for at least the retry window. The applied-id row is written in the same transaction and domain, and checked before any guard.
  - A row at or after its expiry is absent to load and to every guard; every decision also checks the deadline in its record.
  - A version never repeats for a key.
- Retry rule: Conflict is not a verdict. The decider re-loads and re-decides, at most REDECIDE times, then answers ServerError (except a crate's named reuse rule, oidc-provider below). Error from apply means the outcome is unknown: the host re-applies the same Effect with the decision's now, within Retry, and never re-decides; when Retry is spent the verdict is void. Error from load is retried freely.
- Not claimed: zeroize on drop (best effort). dc441b29 does test the owned-buffer wipe.
### jose
pub trait Alg: sealed { const NAME; type Signature: AsRef<[u8]>; }  pub struct Es256; Es384; EdDsa; Rs256; Ps256; Hs256;  // one feature each
pub struct VerifyKey<A>;  // rejects RSA under 2048 bits and HMAC keys shorter than the hash
pub struct AnyVerifyKey;  // from_jwk(&Jwk): the JWK's alg is required and binding
pub trait Signer<A> { fn sign(&self, input: &[u8]) -> A::Signature; }
pub struct Jws<'a>;  // parsed, not verified: no payload accessor
impl Jws { parse(&str) -> Result<Self>; kid() -> Option<&str> /*a lookup hint only*/; verify<A>(self, &VerifyKey<A>) -> Result<Payload>; verify_any(self, &AnyVerifyKey) -> Result<Payload> /*header alg compared, never used to choose*/ }
impl Payload { bytes() -> &[u8] }  // signature verified, content unvalidated
pub struct Jwt<'a>;  // same parse/verify; verification yields VerifiedJwt
impl VerifiedJwt { claims<K: TokenKind>(self, &Policy<K>, now) -> Result<K::Claims> }  // no payload accessor: the only way out
pub struct Unsigned<A>;  new(Header<A>, payload) ; signing_input() ; finish(signature) -> Compact  // WebCrypto, KMS or HSM signs; the Worker's RS256 path
pub trait TokenKind { const TYP; type Claims: DeserializeOwned; }
impl Policy<K> { new(Issuer, Audience, Leeway) }  // private fields, no Default
pub enum Jwk { Ec, Rsa, Okp, Oct }  // JwkSet::decode bounded; find(kid); Jwk::thumbprint(); Jwk::verify_key<A>()
pub enum ErrorKind { Malformed, TooLarge, DuplicateMember, UnsupportedAlg, AlgMismatch, KeyAlgMissing, CriticalHeader, WeakKey, KeyUse, BadSignature, Expired, NotYetValid, Issuer, Audience, Type, MissingClaim, ClaimType }
- Type: a payload or claims read before verification; JWT claims read without a Policy carrying issuer, audience and typ; an ID token accepted as an access token (TokenKind::TYP, 8725 3.11); fetching jku/x5u/jwk (no fetch exists); an Ed25519 key in ECDH, or an X25519 key signing.
- Runtime: none and the RS-to-HS swap (AlgMismatch; header alg compared, never selecting code; 8725 3.1); claims mismatched or absent (Issuer, Audience, Type, MissingClaim); a non-numeric exp treated as absent (ClaimType; GHSA-h395-gr6q-cpjc); a JWK without alg used dynamically (KeyAlgMissing); weak keys (WeakKey).
Note: D3 (JWE now) and the rsa-sign/rsa-decrypt features postdate this text. The jose draft at 10a23867 carries them.

### webauthn-rp
pub struct RelyingParty(/* private */);  // new(RpId, NonEmpty<Origin>, CounterPolicy); cross-origin, topOrigin and unsolicited extensions are deny-by-default builder options
pub enum CounterPolicy { Reject, Tolerate }  // Reject: a regressed counter is Err(CounterRegressed)
pub struct UserHandle;  // 32 random bytes; UserHandle::generate(&mut impl Entropy) | from_stored(&[u8])
pub enum Key { Ceremony(Digest), Credential(CredentialId) }  // ceremony key = digest of the challenge; both Scope::Global
pub enum Record { Ceremony(Ceremony), Credential(Credential) }  // encode()/decode(): opaque versioned bytes, no serde derive
pub type Pending<T> = base::Pending<T, Key, Record>; pub type Effect = base::Effect<Key, Record>;
impl RelyingParty {
  start_registration(&self, user: &UserEntity, exclude: &[CredentialId], opts: &RegistrationOptions, now, e) -> (CreationOptions, Effect);  // effect: Absent(Ceremony) + put, with the deadline as expiry
  start_authentication(&self, allow: Allow, opts: &AuthenticationOptions, now, e) -> (RequestOptions, Effect);
  locate(&self, response: &Response) -> Result<Lookup, Error>;  // Lookup: ceremony Key, credential Key, Option<UserHandle>
  finish_registration(&self, state: Row<Ceremony>, response: &RegistrationResponse, trust: &dyn TrustSource, now, e) -> Pending<Result<Registered, Error>>;  // effect: Consume(Ceremony) always; on Ok also Absent(Credential) + put
  finish_authentication(&self, state: Row<Ceremony>, stored: Row<Credential>, response: &AuthenticationResponse, now, e) -> Pending<Result<Assertion, Error>>; }  // effect: Consume(Ceremony) always; on Ok also Unchanged(Credential) + put
pub enum Allow<'a> { Credentials(&'a [CredentialId]), Discoverable }
impl Assertion { user() -> UserVerification; backup() -> BackupState; counter() -> Counter }  // private constructor
pub enum UserVerification { Verified, PresenceOnly } pub enum Counter { Unsupported, Advanced(u32), Regressed { stored, seen } }
pub struct Error; impl Error { kind() -> ErrorKind; spec_step() -> SpecStep }  // L3 7.1/7.2 step number
Wire JSON types sit behind a serde feature, separate from verification.
- Type: a PII string as the user handle; ceremony state returned to the caller (start_* returns no state value, only an Effect that stores it under its digest key; this closes the webauthn-rs "danger" case); a second finish variant for discoverable credentials (one finish; locate comes first); state that breaks under a generic serializer; an Assertion or Registered value made outside a finished ceremony.
- Runtime: an expired challenge (state carries its deadline, and finish takes now); counter regression under CounterPolicy::Reject. Under Tolerate it is reported in Assertion::counter, never dropped.
- Obligation (the base one, plus):
  - A ceremony finished twice (concurrently, or by replaying the same response) and a credential id stored twice (spec step 19) both fail as Conflict through the Consume and Absent guards, provided the consumer keeps both keys global (Scope::Global, never qualified by subject).
  - Ceremony rows are written only to the store. puts() exposes the Record and encode is public, so a host could park them in a cookie; only review stops that.

### oidc-provider
pub struct Provider;  // Provider::new(Issuer, Capabilities, Lifetimes, SigningKeys) is the single source for routing, refusals, metadata and JWKS. SigningKeys: a NonEmpty set of public Jwk with kid and alg.
impl Provider { metadata() -> Metadata; jwks() -> JwkSet;  // both derive from the constructor arguments; there is no other constructor
  handle(&self, req: &HttpRequest, browser: Option<&Browser>, now, e) -> Step;
  resume(&self, ticket: Ticket, binding: &BrowserBinding, decision: Decision, now, e) -> Step;
  end_session(&self, sid: &SessionId, now) -> Step; }
pub struct Browser;  // BrowserBinding plus Option<AuthnClaim>; BrowserBinding::from(&Secret<32>) is a labelled digest of a secret the host must derive from its cookie secret (base O16)
pub enum Step { Load(Query, AwaitRows), Sign(SignRequest, AwaitSignature), Commit(Effect<Key,Record>, AwaitCommit), Done(Outcome) }  // each wait state accepts exactly one reply type; SignRequest names a kid from SigningKeys
AwaitRows::resume(rows) -> Step; AwaitSignature::resume(Vec<u8>) -> Step; AwaitCommit::resume(Result<Receipt, Conflict<Key>>) -> Step  // on Conflict: load again, or apply the reuse rule
pub enum Outcome { Respond(HttpResponse), NeedLogin { ticket, reauth: Reauth::{Required,NotRequired}, min_acr, login_hint }, NeedConsent { ticket, client, scopes, audience }, Logout { response, backchannel: Vec<LogoutDelivery> } }  // backchannel: signed logout_tokens for the shell to POST
pub struct AuthnClaim;  // AuthnClaim::new(Subject, SessionId, auth_time, Acr, Amr): the host's statement
pub enum Decision { LoggedIn(AuthnClaim), Consented(Grant), Denied(DenyReason) }
pub enum Client { Public(PublicClient), Confidential(ConfidentialClient) }  // the host supplies it in Rows
ConfidentialClient::generate(reg, e) -> (Self, Secret<32>)  // stores only the Digest
pub struct RedirectUri;  // exact comparison only; no normalising PartialEq against str
pub enum Record { Client, Code(CodeGrant), Refresh(RefreshGrant), Family(GrantFamily), Device(DeviceGrant), Interaction(Interaction) }
pub enum Key { Client(ClientId), Code(Digest), Refresh(Digest), Family(FamilyId), Device(Digest), UserCode(Digest), Ticket(Digest), Sid(SessionId) }  // all Global; Sid indexes families
pub enum ErrorKind { InvalidRequest, InvalidClient, InvalidGrant, UnauthorizedClient, UnsupportedGrantType, InvalidScope, InvalidTarget, AccessDenied, LoginRequired, ConsentRequired, InteractionRequired, AuthorizationPending, SlowDown, ExpiredToken, ServerError, Corrupt }  // 1:1 with the OAuth error registry, plus Corrupt
pub fn drive<S: Store<Key,Record>>(step, store: &mut S, signer: &impl Sign, retry: &Retry, now) -> Result<Outcome, S::Error>;  // for sync hosts; Err once Retry is spent
- Type:
  - discovery or JWKS built from anything but the Provider that routes;
  - a signature requested for a key that is not advertised;
  - untyped rows and string keys (serde_json::Value is a denied type);
  - a reply of the wrong kind or order to the state machine (typestate);
  - a secret used as a store key;
  - plain PKCE (CodeChallenge has only S256);
  - a client secret or its hash supplied by admin input (generate is the only constructor outside Record::decode).
- Runtime:
  - An auth_time the request cannot accept; the crate makes no provenance claim. The Interaction row records its issue time and the request's max_age and prompt. handle and resume(LoggedIn) answer LoginRequired for an auth_time after now, older than now - max_age, or earlier than the ticket's issue under prompt=login. acr_values is checked the same way; this closes the gap Fosite leaves to integrators.
  - A ticket resumed from another browser (binding digest mismatch; the role of Hydra's login CSRF cookie).
  - A row reported through Rows::corrupt answers Corrupt, never absent. That the host reports every decode failure that way is an Obligation.
  - An authorization request without S256 from any client, public or confidential, unless that client row carries Pkce::Exempt (RFC 9700 2.1.1).
- Obligation (the base one):
  - Every row a decision read appears in its Effect as Unchanged (found) or Absent (missing), and single-use rows as Consume. So a code or refresh token redeemed twice, a refresh racing a logout that deleted its family, and a ticket resumed twice all lose as Conflict.
  - Reuse rule: only a Missing failure on the Consume of the code or refresh token this request presented revokes (the code's tokens, or the refresh family). Every other failure re-loads and re-decides. A lost commit result is re-applied as the same effect, so within one host attempt it never reads as reuse.
  - Not claimed: when the host attempt ends after the commit, the client's resend of that refresh token reads Missing and revokes the family. That is the RFC 9700 4.14 rotation trade-off; no grace rule weakens reuse detection to hide it.
  - No decision reads a range: end_session finds families through the Sid index row.

### factor
pub enum Key { Attempts, TotpStep, Recovery(Digest) }  // all Scope::Subject: the host qualifies them with the subject
pub enum Record { Attempts(Attempts), TotpStep(TotpStep), Recovery(RecoveryHash) }
pub struct Throttle;  // Throttle::new(policy) | Throttle::unlimited(), the greppable opt-out
impl Throttle { check(&self, attempts: Option<&Row<Attempts>>, now) -> Result<Permit, ClosedUntil>; reset(&self, attempts: &Row<Attempts>, e) -> base::Effect<Key,Record> }  // reset is the only reset; the consumer merges it into its login-complete effect
pub struct Permit;  // private: the attempts version it was issued against; not Clone; consumed by exactly one verify
pub struct Totp;  // key: SecretBytes, alg, Digits::{Six,Eight}, Period, Skew::{None,One}
Totp::verify(&self, permit, code: &OtpCode, now, last: Option<&Row<TotpStep>>, e) -> Pending<Result<OtpMatch, Rejected>>
recovery_generate(n, e) -> Vec<(RecoveryCode, RecoveryHash)>; password_hash(pw, cost, e) -> Phc
recovery_verify(permit, code, stored: &[RecoveryHash], e) -> Pending<Result<RecoveryMatch, Rejected>>
password_verify(permit, pw, phc, e) -> Pending<Result<PasswordMatch, Rejected>>  // PasswordMatch::rehash() -> Rehash::{Needed, Current}
Every verdict's effect, a match included, guards Unchanged(Attempts) (or Absent) and puts the incremented count, never a reset. A reset on a correct password would reopen the throttle for the OTP guess that follows it. A TOTP match also guards the step row and puts the new step; a recovery match adds Consume(Recovery). Two factors therefore never merge (both guard Attempts); a consumer applies them in sequence.
- Type: a verifier called without a Permit (private field, made only by Throttle::check); a Permit used twice; an OtpMatch, RecoveryMatch or PasswordMatch made outside a verify.
- Runtime: OTP replay (a step at or below last is Rejected::Replayed, an RFC 6238 MUST); a Cost below the OWASP Argon2id floor, or a Password outside the NIST length bounds (validated constructors).
- Obligation (the base one):
  - Two concurrent submissions of one code, or two guesses against one attempt count, read the same version, so exactly one effect applies and the other verdict is void.
  - Correct passwords interleaved with wrong OTPs still close the throttle.
  - That every verdict a host reads was counted rests on the base receipt obligation.

### othala-core (internal)
pub enum Proof { Passkey(Assertion), Password(PasswordMatch), Otp(OtpMatch), Recovery(RecoveryMatch) }  // in memory only: no encode
pub struct Settled;  // ProofKind, the credential id for a passkey, verified-at; Settled::of(&Proof) | decode: how a proof crosses requests
AuthnEvent::from_proofs(subject, sid, earlier: &[Settled], proofs: NonEmpty<Proof>, now) -> Self  // the only constructor
AuthnEvent::claim(&self) -> AuthnClaim  // acr and amr derive from earlier plus proofs; auth_time is now at settlement
pub enum Record { Identity, Session, Login(Vec<Settled>), Passkey(webauthn_rp::Record), PasskeysOf(PasskeyIndex), Factor(factor::Record), Oidc(oidc_provider::Record) }
pub enum Key { Identity(Subject), Session(Digest), Login(Digest), Passkey(webauthn_rp::Key), PasskeysOf(Subject), Factor(Subject, factor::Key), Oidc(oidc_provider::Key) }  // Login: the ticket digest; Passkey stays Global; PasskeysOf is the authority
- Type: an auth_time that does not come from a settled credential verification (a Proof holds only values with private constructors in the verifier crates, obtained through Pending::settle, so only against a Receipt), for the proofs of the request that completes the login; a session token stored in clear (Key::Session holds the Digest of a Secret<32>); an untyped identity row.
- Obligation (the base one, plus):
  - Two subjects registering one credential id: one loses (a snapshot case).
  - Every split of the login sequence in section 3 fails closed under crash and retry, and the testkit read-set check runs over those sequences.
  - A Settled in a Login row came from a settled Proof of that subject, and the session create consumes the row.
  - A recovery that deletes sessions and prunes PasskeysOf in one effect is never overtaken by a registration whose session was read before it.
  - Correct passwords interleaved with wrong OTPs across requests close the throttle.
  - In both shells, Argon2 and every decision run with no store transaction open, and in the Worker outside any Durable Object.

## 3. Sans-IO model
- Time is a UnixTime argument on every call that needs it; no crate reads a clock (str0m passes time per call).
- Randomness is &mut impl Entropy; getrandom and its wasm_js feature exist only in the shells.
- Storage is one shape in every crate: the caller loads Rows, the crate decides purely, and the result carries one Effect to apply atomically. webauthn-rp and factor return it directly or inside Pending. oidc-provider, whose read set depends on the request, sequences it as Step (Load, pure decision, Commit). A verdict leaves Pending only against the Receipt the store returned. No crate calls a store.
- Signing is an effect (Step::Sign, Unsigned::finish), because the Worker signs RS256 through async WebCrypto; a native shell answers it inline with a Signer.
- Network (back-channel logout POSTs, MDS download) is returned as data (LogoutDelivery, a blob handed to webauthn-mds) for the shell to perform.
- Composition:
  - othala-core owns identity and session rows and the login state machine. On NeedLogin, for each submitted factor in order, it runs check (loading Attempts afresh), verify, apply and settle, so the second factor's check reads what the first wrote.
  - A request that does not complete the login appends Settled::of each proof to the Login(ticket digest) row, which expires with the ticket.
  - The completing request builds an AuthnEvent from that row and its own proofs, and applies one account-domain session effect. It creates the session, Consumes Login if present, expects Identity and, for a passkey, a PasskeysOf that names the credential, and merges Throttle::reset lifted into Factor when an Attempts row exists (the only reset). Then it calls resume with its claim().
  - Every split is fail-closed:
    - a crash after a factor's apply leaves a counted attempt and no session;
    - after a Login append, a partial login that expires;
    - after the session commit, a session row no cookie names, which expires;
    - after resume's commit, a code the RP never received, which expires.
  - A passkey registration is two effects, uniqueness first. finish_registration's effect, lifted into Key::Passkey, reserves the credential id (with its key and counter) in the passkeys domain. The grant, in the account domain, guards Unchanged(Session) and Unchanged(Identity) and updates PasskeysOf(Subject). A reservation with no grant is inert, since no login accepts a credential its subject's PasskeysOf does not name. No row read in one domain is acted on in another.
  - It exposes the same Step shape upward, so a shell has one loop to write. The Ory-shaped surface the portal calls today (spike crates/surface) is an adapter over it, internal only.
- Shells:
  - othala-native uses drive with a SQLite Store, one transaction per apply, opened with BEGIN IMMEDIATE so the write lock is taken before any guard is read. SQLITE_BUSY is Error, re-applied by id.
  - othala-worker runs the Step loop by hand in the Worker. Every decision runs there, never inside a Durable Object. Load and Commit go to the object Effect::domain names, whose apply is a sync Store inside ctx.storage.transactionSync; that exact function is the conformance subject.
  - workers-rs worker 0.9 binds only the async Storage::transaction, so the shell binds transactionSync itself on Storage::as_raw. A Conflict leaves the callback as a thrown exception (the closure returns Err(JsValue)), because the transaction rolls back only when the callback throws and sql.exec cannot run BEGIN or SAVEPOINT (https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).
  - Sign is awaited on WebCrypto.
  - Argon2 runs between load and apply, so never inside an open transaction in either shell. A shell test proves both, with a store wrapper that fails if a transaction is open while a decision runs.
  - Neither shell contains protocol decisions; the clippy disallowed_methods list enforces the seam.
- Transaction domains. One Effect is one transaction, so its keys belong to one domain. The host's partition function maps keys to domains, and Effect::domain refuses a spanning effect before any write.
  - Each crate's CONTRACT.md lists the key kinds one of its effects holds together (webauthn-rp: ceremony with credential; factor: one subject's rows; oidc-provider: any of its keys), and the table keeps each such set in one domain.
  - A Scope::Global key kind lives in exactly one domain and is never split per account; that is how Absent(Credential) stays global across Durable Objects.
  - Work that must touch two domains is a sequence of single-domain effects, each prefix fail-closed (single-use and uniqueness claims before grants), retried with the same effect ids.
  - othala-core owns the one partition function, and both shells pass it to Effect::domain. Native maps every domain to its one database, so a spanning effect fails the native exam too.
| Domain | Key kinds (emitted by) | othala-native | othala-worker |
| account | Identity, Session, Login, PasskeysOf(Subject), Factor(Subject, _) (othala-core, factor) | the one SQLite database | the per-account Durable Object; the session cookie names its object beside the secret; which passkeys a subject has is decided here only |
| passkeys | Passkey(_): ceremonies and credential-id reservations (webauthn-rp) | same database | one global DO: ceremonies precede the account, and credential ids are unique across accounts |
| provider | Oidc(_): Client, Code, Refresh, Family, Sid, Device, UserCode, Ticket (oidc-provider) | same database | one global DO: a client edit, an exchange and a logout sweep meet in one transaction |
DO patterns survey adds: name account objects by a random account id (never an email or username), plus an identifier-to-account directory; the object exposes RPC load and apply only, with no fetch; treat the Worker and the object as version-skewed; read-time expiry, with the alarm as an idempotent sweeper; no private keys or plaintext tokens in object storage (PITR keeps history); a scheduled R2 export (DO has no export); a Rate Limiting binding in front of the global objects, with strict throttles in the account object; decide jurisdiction before the first object exists.

## 4. Test contract (done-criteria per crate)
A crate is done when every line of its CONTRACT.md names the check that proves it and CI shows that check green. Vectors are files read by one testkit runner that asserts its total and a non-vacuity floor; adding a vector adds no test code.
| Crate | Vectors | Mutants 100% caught on | Invariants (proptest, plus snapshot race) | Fuzz targets | Golden files |
| base | RFC 4648 s10 | secret, b64url, effect | Effect against the reference store: all guards or nothing; a builder, merge or lift never yields an unguarded write or a duplicated key | b64url_decode | redacted Debug output |
| jose | RFC 7515 App A, RFC 7520, RFC 7638 3.1, RFC 8037 App A, Wycheproof ECDSA/EdDSA/RSA/HMAC, one oversize input per limit | verify, claims, key | property: verify(sign(x)) round-trips and any one-byte change fails | Jws::parse, Jwk and JwkSet decode | error-kind table per 8725 section |
| webauthn-rp | W3C L3 s16 per format, a real-authenticator corpus, the passkey software authenticator, oversize CBOR | verify, authdata, cbor, policy | a ceremony finished at most once, including the same response replayed; never after its deadline; a credential id inserted at most once; counter regression never Ok under Reject | cbor::decode, authdata::parse, each attstmt format | options JSON per L3 5.1.8-9 |
| oidc-provider | RFC 7636 App B, RFC 8628 and OIDC Core examples, oversize request | authorize, token, rotation, logout, metadata | with a crash and retry between every Step: a code redeemed at most once; refresh reuse revokes the family, and nothing else revokes one; no token outlives its family; the auth_time bounds; a ticket bound to one browser; every advertised endpoint, grant and alg is routed and signable | HttpRequest parse, form decode, Record::decode | metadata and JWKS documents; error body per ErrorKind |
| factor | RFC 4226 App D, RFC 6238 App B, RFC 9106 s5 | otp, recovery, throttle | the accepted TOTP step strictly increases; one code submitted twice at once is accepted once; a recovery code is consumed at most once; the attempts count never loses an increment and never falls without reset | OtpCode and Phc parse | none |
Also binding:
- Ledger proofs: each Type claim is a trybuild case with a committed .stderr and a compiling twin one token away. The ledger names the rustc error code each expects. .stderr changes are reviewed, never blessed, and the toolchain is pinned. A "no X exists" claim is also held by a committed public-API snapshot (cargo-public-api over rustdoc JSON). Each Runtime claim names its vector or the mutant that must be caught. Each Obligation is covered by the two harnesses below.
- Concurrency without threads: testkit interleaves a competing commit at every Step boundary of every operation, for pairs and triples, and applies the effects in every order. The outcome must equal some serial order; the loser is re-decided against the winner's state; disjoint effects both win; the same effect applied twice applies once; and the invariants hold after every order. The testkit store records the keys each decision loaded and fails the test if one is unguarded in its effect.
- testkit::store_conformance proves a concrete store honours Effect. Its cases: a commit whose result is lost and is re-applied; a guard that fails after a write in the same effect, leaving nothing applied; a constraint violation that must surface as Conflict; an expired unpurged row; a delete and recreate under a stale Unchanged; an oversize effect. Both shells run it on their exact apply path. The reference store fails on any put over an existing row the same effect does not guard.
- Fuzz: each target has a committed corpus replayed as a stable test on every pipeline, and runs 10 minutes on nightly in scheduled CI. Done means zero crashes and zero unreproduced findings.
- Spec values come from vector files, and deployment settings from one constant. A test never reads a spec-fixed value from src, and never restates a deployment setting.
- The OpenID conformance plans (Config, Basic, logout) are othala-native done-criteria, not oidc-provider's.
- wasm32-unknown-unknown and no_std + alloc builds in CI for the five publishable crates (oidc-provider is std-only per D10); cargo-semver-checks on release; every mutant skip listed in a committed mutants.toml with a reason.

## 5. Elegance rules that bind
1. Reported, not budgeted. CI prints per crate: production lines (src only), test lines, contract lines, production and test lines per contract line, vector count, mutants caught/missed/skipped, and public item count. A change that raises production or test lines without adding a contract line needs a stated reason in the MR. The spike's totals (jose 243 src / 271 tests; authn 388/917; wire 275/250; core 2,082/2,182; surface 966/2,596; host 469/1,116) are reference only, not a baseline.
2. Allowed runtime dependencies: SUPERSEDED by the D6 ruling and the dependencies under Rulings.
3. Lint deny list: unsafe_code (forbid), missing_docs, unreachable_pub, clippy unwrap_used, expect_used, panic, indexing_slicing, as_conversions, print_stdout and dbg_macro, plus disallowed_methods (clock, OS randomness, sockets, files) and disallowed_types (serde_json::Value outside wire-decoding modules). Enforcement is your phase-0 forbid.
4. No stringly-typed core. A public function takes &str or String only if it is a parser returning a validated type. No bool parameters, fields or accessors; use two-variant enums (C-CUSTOM-TYPE). One error type per crate.
5. One implementation per concept. Helpers duplicated across crates move to base or are deleted.
6. Contract before code. CONTRACT.md and the compiling signatures merge before any function body.
7. Limits. Every parser has a stated bound and one oversize vector per bound: compact token bytes, header and claims JSON depth, JWKS key count, CBOR nesting depth and item count, HTTP body and form field count, and an Effect's guards plus writes (128; end_session sweeps more families as a resumable sequence of bounded effects over the Sid index). A declared length is checked against the remaining input before anything is allocated. Exceeding a bound is TooLarge, never a panic or an allocation.

## 6. What we learn from Ory and others
1. Interaction is a return value, not a second service. Hydra's login needs a redirect with login_challenge, an admin-API fetch, an accept call and a redirect_to follow. We return NeedLogin/NeedConsent and take a Decision, and the host still owns the UI, as in Duende's split.
2. Session policy is protocol logic and ships inside the core. Fosite leaves prompt, max_age, id_token_hint and session management to the integrator, and the spike then got auth_time wrong. AuthnClaim goes in and a verdict comes out. What the provider cannot see (where the claim came from) it does not claim; the opinionated consumer closes that by type.
3. One storage seam, shaped around atomic consume. panva's adapter requires an atomic consume; Duende exposes eight or more store interfaces. We emit one Effect type across three crates and ship drive plus an in-memory store, where Fosite ships storage only as a reference.
4. What is enabled is one value, and there are no development defaults. panva's devInteractions is on by default and must be turned off for production. Capabilities has no Default, and metadata derives from it.
5. Extension points are stable or absent. Keycloak documents its Authentication SPI as internal and subject to change. We seal traits, keep fields private, and gate releases on semver checks.

## 7. Migration from the spike (origin/spike/rust-core 67477e8; raw material only)
- Reusable as-is: the clippy.toml disallowed-methods list, deny.toml, the Wycheproof runner with its total assertion (into testkit, which is done), all vector files (done, in rust/vectors), and budget.sh once it counts production lines only.
- Raw material, to be re-typed:
  - crates/jose (alg pinned to key type, refuses crit/jku/x5u) becomes jose's ES256 path;
  - crates/wire/src/cbor.rs (159 lines, a strict reader) moves inside webauthn-rp;
  - crates/authn otp and password (Totp::verify already takes last_step) become factor;
  - crates/surface and crates/host become othala-core's compatibility adapter and othala-native.
- Rewritten against the contract: crates/core (its sync Store trait with string keys and JSON bytes cannot express a guarded commit or typed records; its refusal tests become oracle cases), and crates/authn/src/webauthn.rs (146 lines, none and packed-self only) against the L3 matrix.
- Original order: base; the effect review (done); the contract pass with othala-core written against the signatures; implementations jose, factor, webauthn-rp, then oidc-provider; then othala-core bodies, othala-native, the exam; othala-worker last; publication after done-criteria and a release pass. The operator-accepted process now reorders this into milestones M1-M7 under the queue.

## 9. Review dispositions (condensed)
- Everything the architecture review raised was applied; nothing was rejected. M3, M4, M5 and S1 are closed by the one base::Effect/Guard/Pending type (S1 became an Absent guard). Conformance moved to othala-native (S9). android-safetynet and compound are non-goals (S10). Spec values versus settings stays review-checked (S8). Shell race tests were replaced by the snapshot-race harness plus store conformance.
- Effect review E1-E18 is all applied:
  - E1 in part: settle takes a Receipt, but the receipt-after-commit guarantee is lint plus conformance, not Type, because host_applied serves every store.
  - E4: login is a sequence (check, verify, apply per factor), not a reshaped throttle.
- Second analysis F1-F10 is all applied:
  - F3 is a non-claim (no grace rule).
  - F8: a re-apply uses the decision's now.
  - F10: a Login row holds Settled entries.
- Designer calls kept: one global DO each for passkeys and provider; the session cookie names its account object.

## Open items from the contract rounds (what to pick up first)
- oidc-provider must be re-cut on jose's types. These move: Issuer, Audience, Kid, SigningAlg, and the signing types.
- oidc-provider asks base for Rows::lift / Conflict::lift, and either Effect: Clone or Effect::lift(&self), so othala-core can drive one unified store. Until then its CONTRACT says shells lower rows and conflicts per crate key type.
- The round-2 owner fixes on primitives/jose 10a23867, webauthn-rp c5eb4e7c, oidc-provider 60d71813 and factor 799b1e29 were never re-reviewed. Integration failed on the shared justfile, which phase 0 step 2 removes.
- base nits still open (low): the reference store's reused-id check compares key sets only, so the same keys with different ops answer Ok. Fingerprint guards and writes per id, or narrow O15.
- Exam (the containers run in a separate session; the decisions are made here):
  - E2 at spike/exam f303e7b. Acceptance is green: 115/115 e2e and the trace checks pass. Gaps:
    - probes do not kill the header-name branch or 15 of the 18 SECRET_KEY words;
    - request paths are not redacted;
    - the upstream-error log branch is unprobed;
    - surface-tolerance.tsv tolerates a proxy-synthesised 502 and a 400. Recommended: remove it; three runs never needed it.
  - E6 at spike/exam-oidf 256e131: one oidf run passes 27 with 4 xfail out of 49 cases. The determinism loop and the probe have not run.
  - E3, E4, E7 and the exit check have not started. Exam items E1-E7 and their acceptance live in the exam design on spike/exam (exam/README and the items there).
- Upstream: rustls/webpki#485 is the only relevant thread. A use-case comment there would be the operator's, hand-written.

## Rulings
Settled; not reopened without the operator.
- D1: a `rust/` workspace in this repo, MIT OR Apache-2.0. The root LICENSE is the MIT text and `rust/LICENSE-APACHE` exists. Never add a file that names the holder; check-purity fails on it. Package names are working names until the operator decides them.
- D2: own JWK types. D3: JWE is in scope. D4: effects as data (`base::Effect`/`Guard`/`Pending`/`Step`); no crate calls a store. D6: review a dependency before adding it.
- D8: jose and webauthn-rp are the first recognition targets. D10: the standard http 1.x types, so oidc-provider is std-only and the other crates are `no_std` plus alloc. D11: own `Entropy` plus a `rand_core` feature. MSRV is 1.89.
- Use the standard crate unless a technical reason rules it out.
- Adopted dependencies: the RustCrypto 0.14/0.11 line (p256, p384, p521 behind es512, ecdsa, ed25519-dalek, rsa 0.10 verify, aes-gcm, aes, cbc, aes-kw, one-step-kdf, hmac, sha1, sha2, argon2); x509-cert, der, spki and const-oid, with x509 types never in the public API; base64ct, subtle, zeroize, serde/serde_json and http. A dependency that forces a workaround or a compromise comes back out.
- Features: `rsa-decrypt` (RSA-OAEP) is off by default and carries a Marvin warning. `rsa-sign` (RS256/PS256, which OIDC requires of an OP) is off by default. webauthn-rp may use p384, and sha1 behind its `tpm` feature.
- Non-goals: RSA1_5, PBES2, JWE zip, a third-party CBOR crate (we write our own strict reader), and webpki for attestation (we write our own short chain walk over x509-cert).
- `url` is replaced by `http::Uri`, after a test shows it accepts private-use redirect schemes such as `com.example.app:///`.
- Designer calls: account Durable Objects are named by a random account id; objects are RPC-only; expiry is checked at read time; there is one global object each for passkey reservations and provider rows; `PasskeysOf` lives in the account domain; every factor verdict only increments `Attempts`, and the session effect does the one reset.

### Designer rulings, 2026-11-26
They bind every lane.

**R-a** Stubs. `todo!` stays forbidden, and so do fail-closed fake bodies. A crate's -01 item lands:
- CONTRACT.md, with every public signature verbatim;
- the private module layout, one file per later item (so no later item touches lib.rs, Cargo.toml or a shared module);
- the types and traits, which need no bodies;
- the crate's gate data.
Each function lands with the item whose row it turns green.

**R-b** Derived cases. Every derived or must-refuse case lives in rust/vectors as a `<crate>-derived` or `<source>-derived` family, with provenance, and is added only by the oracle lane, from the specs and never from our code. Implementers cite them; they never author them. The drafts' `new:` files, `expect.kind` edits, own/ files and factor's argon2id-openssl and rfc6238-derived files are dropped from the crate branches and re-made by the oracle lane. Error-kind checks compare a kind only where the oracle names one.

**R-c** A row may read any vector family. SOURCES.toml `feeds` is informational.

**R-d** BrowserBinding. WebAuthn registration and authentication both take a browser binding: a `BrowserBinding` newtype in base, built from `&Secret<32>`. It lands as a base item, and webauthn-rp and oidc-provider use it.

**R-e** X25519 (ECDH-ES over OKP) stays a non-goal (N6). Oracle X25519 cases are must-refuse: UnsupportedAlg.

**R-f** jose amendments:
- S1 rejected: `Unsigned<A>` and `Header<A>` stay typed, so issuing is Type-bound like verifying.
- S2 accepted in part: `Alg` keeps `type Signature`, and `Signer::sign` returns `Result<A::Signature, Error>`, because KMS and HSM signers fail.
- S3 is moot under R-e.
- S4 accepted: the struct Jwk plus SecretJwk, with opaque material.
- S5: reword T14.
- C7 accepted: `read_back` only for kinds that implement an opt-in `ReadBack: TokenKind`, with a ui case. The same marker gates `Expiry::Unchecked` (S9).
- RSA-OAEP decrypt takes one path, substituting a random CEK on OAEP failure (RFC 7516 11.5).
- The Marvin warning goes in rustdoc and in the feature docs.
- EdDSA uses verify_strict, and says so.
- jose owns the alg-to-hash mapping for at_hash and c_hash.
- Issuer's URL check is oidc-provider's checked constructor, over jose's type.

**R-g** factor amendments:
- F-S1 rejected. Keep the architecture contract's keys {Attempts, TotpStep, Recovery(Digest)}, so the row holding the OTP key is never rewritten on a match. Recovery uses per-code Consume(Recovery(Digest)).
- The outer `Result` on verifiers is accepted: it carries Error only, never a verdict.
- R34: one pub(crate) Argon2id mapping function, called by both password_hash and the RFC 9106 test.
- Drop PartialEq on Phc.
- Typed parameters for Backoff and Cost.
- Host obligation: render Replayed the same as Wrong.
- Lockout (F-S2), operator ruling of 2026-11-26: no permanent lock. Failures grow the wait exponentially up to a cap (a policy value, e.g. 1h). A successful session effect does the one reset; there is no operator reset path. Closed::Locked becomes Closed::Wait(until).

**R-h** webauthn-rp amendments:
- W-S1 accepted, recorded in its CONTRACT: Allow::User, Verdict, start_* returning Result, and split records. The browser digest is replaced by BrowserBinding (R-d).
- W-S4: follow L3 7.2; no uvInitialized refusal, which is a consumer policy.
- W-S5: clientDataJSON gets its own JSON bound.
- W-S6: try every anchor whose subject matches.
- W-S7 and W-S8 as stated.

**R-i** The score runs jose rows with every feature on, plus one run with every feature off (rows that must refuse with features off).

The rulings R-j to R-o were added on 2026-11-26. Where a ruling differs from sections 2 to 5, the ruling supersedes the section (R-f, R-g and R-m are known cases).

**R-j** Secret exposure is confined per crate, by the compiler. `Secret::expose` and `SecretBytes::expose` exist only behind a base feature `expose`, and are no longer in clippy.toml's disallowed list. A crate may read secret bytes only if its Cargo.toml enables `base/expose` and its gates.json declares `"expose": ["<module>", ...]`. The canary fails if the cargo metadata feature graph enables `expose` for a crate whose gates.json does not declare it. Within the crate, the named modules are an Obligation that review checks, named in its CONTRACT. Crates never keep their own secret buffers: imported OTP and HS keys are `SecretBytes`. User-supplied inputs (a password, an OTP code, a recovery code) are crate types that wrap `SecretBytes`.

**R-k** HOTP verification with a stored counter (look-ahead, resync) is a non-goal. HOTP is the primitive under TOTP. Row tests count the oracle's hotp_verify and hotp_resync cases as not applicable, under the total assertion.

**R-l** A row may be a `--lib` filter where the claim needs crate-internal code: R34's Argon2id mapping, and HOTP before TOTP lands.

**R-m** Lockout cap floor is 1 h. othala-core carries an Obligation to alert on a subject's sustained backoff. NIST 800-63B-4 3.2.2 is met on rate, not by disabling; CONTRACT N6 states this.

**R-n** CBOR key order. The strict reader enforces CTAP2 canonical order on authenticator-produced CBOR: the credential public key and extensions inside authData, and attStmt. The outer attestationObject map, which a client may re-encode (none conveyance), is read order-tolerant. It still refuses duplicate keys, indefinite lengths and non-shortest integers.

**R-o** A -01 item may land derives (Debug, Clone, PartialEq, Hash, Eq) on bodiless types. Placeholder fields carry no meaning until the item that adds a constructor lands, and that item owns the derive's correctness.

Tracked: the canary's check of the cargo metadata feature graph for R-j is item base-expose.
