# factor contract

One claim per line, each naming the check that proves it. Tags follow the claims ledger: *Type* (the program does not compile), *Runtime* (a check returns an error or a verdict), *Obligation* (the host's or the consumer's, proven where it is named); *Build* lines are gate claims and *Non-claim* lines claim nothing.
Checks: `ui:x` is `tests/ui/fail/x.rs` with its committed `.stderr` (rustc code given) and its compiling twin `tests/ui/pass/x.rs`, one line and one token away (`just ledger`, `just twins`); `api` is the committed `public-api.txt` (`just api`); `row:f` is `tests/row_f.rs`; `unit:m::t` is a test in `src/m.rs`; `prop:t` and `race:t` are `tests/props.rs` and `tests/race.rs` over `testkit::MemStore` and `testkit::race`; `vec:p` is `vectors/p` read through `testkit::vectors`, which asserts the file's hash and the case count `SOURCES.toml` declares; `vec:factor-derived/*` is the oracle's family under R-b (`Replayed` is its kind name for a replay), and `oracle: factor-derived/x.json` one still pending from the oracle lane; an error kind is compared only where the oracle names one; `mutants:m` is `just mutants` over `src/m.rs`; `fuzz:t` is `fuzz/fuzz_targets/t.rs` with its corpus replayed on every pipeline.
State: live now are every `ui:` check, `api`, R1, R2 and B1 to B6. Every other check lands with the item in brackets, which also lands the bodies of the signatures it names; until then the line is the specification its check is written to.
Shape: every verifier takes the one `Permit` from `Throttle::check`, the presented secret and the factor row it read, and returns `Result<Pending<Result<Match, Rejected>>, Error>`. The outer `Result` carries `Error` only, never a verdict (R-g); the verdict leaves `Pending` only against the receipt of its effect (base T10). The consumer runs check, verify, apply and settle per factor, in sequence, never merged (architecture section 3, E4).

## Signatures
Every public item, verbatim; the types are in `src/` now, and each function lands with its item.
```rust
// lib.rs [factor-01]
pub enum ErrorKind { Malformed, TooLarge, Unsupported, WeakCost, WeakKey, PasswordLength, OutOfRange, OutOfMemory, Internal }
pub struct Error;
impl Error { pub const fn kind(&self) -> ErrorKind }
impl fmt::Display for Error; impl core::error::Error for Error

// store.rs [factor-01 types and scope; factor-04 codec]
pub enum Key { Attempts, TotpStep, Recovery(Digest) }
impl StoreKey for Key
pub enum Record { Attempts(Attempts), TotpStep(TotpStep), Recovery(RecoveryHash) }
pub type Pending<T> = base::Pending<T, Key, Record>;
pub type Effect = base::Effect<Key, Record>;
pub enum Rejected { Wrong, Replayed }
impl Record { pub fn encode(&self) -> Vec<u8>; pub fn decode(bytes: &[u8]) -> Result<Self, Error> }

// throttle.rs [factor-03]
pub struct Attempts; pub struct FreeAttempts; pub struct Wait; pub struct Cap; pub struct Backoff;
pub struct Throttle; pub enum Closed { Wait(UnixTime) } pub struct Permit;
impl FreeAttempts { pub const fn new(attempts: u32) -> Result<Self, Error> }
impl Wait { pub const fn new(secs: u64) -> Result<Self, Error> }
impl Cap { pub const fn new(secs: u64) -> Result<Self, Error> }
impl Backoff { pub const fn new(free: FreeAttempts, first: Wait, cap: Cap) -> Self }
impl Throttle {
    pub const fn new(policy: Backoff) -> Self;
    pub const fn unlimited() -> Self;
    pub fn check(&self, attempts: Option<Row<&Attempts>>, now: UnixTime) -> Result<Permit, Closed>;
    pub fn reset(attempts: Row<&Attempts>, e: &mut impl Entropy) -> Effect;
}

// otp.rs [factor-02: HOTP and OtpKey::import; factor-06: the rest]
pub enum OtpAlg { Sha1, Sha256, Sha512 } pub enum Digits { Six, Eight } pub enum Skew { Exact, One }
pub struct Period; pub struct OtpKey; pub struct Totp; pub struct TotpStep; pub struct OtpCode; pub struct OtpMatch;
pub(crate) fn hotp(key: &OtpKey, alg: OtpAlg, counter: u64, digits: Digits) -> u32;
impl OtpKey {
    pub fn import(key: Vec<u8>) -> Result<Self, Error>;
    pub fn generate(alg: OtpAlg, e: &mut impl Entropy) -> Self;
    pub fn export(&self) -> SecretBytes;
}
impl fmt::Debug for OtpKey
impl Period { pub const fn new(secs: u32) -> Result<Self, Error> }
impl OtpCode { pub fn parse(text: &str) -> Result<Self, Error> }
impl fmt::Debug for OtpCode
impl Totp {
    pub const fn new(key: OtpKey, alg: OtpAlg, digits: Digits, period: Period, skew: Skew) -> Self;
    pub fn verify(&self, permit: Permit, code: &OtpCode, last: Option<Row<&TotpStep>>, e: &mut impl Entropy) -> Result<Pending<Result<OtpMatch, Rejected>>, Error>;
    pub fn confirm(&self, code: &OtpCode, now: UnixTime, last: Option<Row<&TotpStep>>, e: &mut impl Entropy) -> Result<Effect, Rejected>;
}
impl fmt::Debug for Totp
impl OtpMatch { pub const fn step(&self) -> u64 }

// password.rs [factor-05: the mapping, costs, NewPassword, password_hash, Phc::as_str; factor-07: the rest]
pub enum Minimum { SingleFactor, MultiFactor } pub enum Rehash { Current, Needed(Phc) }
pub struct Password; pub struct NewPassword; pub struct Memory; pub struct Passes; pub struct Lanes; pub struct Cost;
pub struct Phc; pub struct PasswordMatch;
pub(crate) fn argon2id<'k>(memory: Memory, passes: Passes, lanes: Lanes, tag: usize, secret: &'k [u8], ad: &[u8]) -> Result<argon2::Argon2<'k>, Error>;
impl Memory { pub const fn kib(kib: u32) -> Self }
impl Passes { pub const fn new(passes: u32) -> Self }
impl Lanes { pub const fn new(lanes: u32) -> Self }
impl Cost { pub const fn new(memory: Memory, passes: Passes, lanes: Lanes) -> Result<Self, Error> }
impl NewPassword { pub fn new(text: &str, minimum: Minimum) -> Result<Self, Error> }
impl Password { pub fn presented(text: &str) -> Result<Self, Error> }
impl fmt::Debug for Password; impl fmt::Debug for NewPassword
impl Phc { pub fn parse(text: &str) -> Result<Self, Error>; pub fn as_str(&self) -> &str }
impl fmt::Debug for Phc
pub fn password_hash(password: &NewPassword, cost: Cost, e: &mut impl Entropy) -> Result<Phc, Error>;
pub fn password_verify(permit: Permit, password: &Password, stored: &Phc, cost: Cost, e: &mut impl Entropy) -> Result<Pending<Result<PasswordMatch, Rejected>>, Error>;
impl PasswordMatch { pub const fn rehash(&self) -> &Rehash }

// recovery.rs [factor-08]
pub struct RecoveryCount; pub struct RecoveryCode; pub struct RecoveryHash; pub struct RecoveryMatch;
impl RecoveryCount { pub const fn new(codes: u8) -> Result<Self, Error> }
impl RecoveryCode {
    pub fn parse(text: &str) -> Result<Self, Error>;
    pub fn display(&self) -> impl fmt::Display + '_;
    pub fn key(&self) -> Key;
}
impl fmt::Debug for RecoveryCode
pub fn recovery_generate(count: RecoveryCount, e: &mut impl Entropy) -> Result<Pending<Vec<RecoveryCode>>, Error>;
pub fn recovery_verify(permit: Permit, code: &RecoveryCode, stored: Option<Row<&RecoveryHash>>, e: &mut impl Entropy) -> Result<Pending<Result<RecoveryMatch, Rejected>>, Error>;
```

## Type
- T1 `Password` has no `Display`, `Clone` or `PartialEq`: ui:password_display, ui:password_clone, ui:password_eq (E0277 each), api.
- T2 `NewPassword` has no `Display`, `Clone` or `PartialEq`: ui:new_password_display, ui:new_password_clone, ui:new_password_eq (E0277 each), api.
- T3 `OtpKey` has no `Display`, `Clone` or `PartialEq`: ui:otp_key_display, ui:otp_key_clone, ui:otp_key_eq (E0277 each), api.
- T4 `OtpCode` has no `Display`, `Clone` or `PartialEq`: ui:otp_code_display, ui:otp_code_clone, ui:otp_code_eq (E0277 each), api.
- T5 `RecoveryCode` has no `Display`, `Clone` or `PartialEq`; `display`, written on demand from the code, is its one text form: ui:recovery_code_display, ui:recovery_code_clone, ui:recovery_code_eq (E0277 each), api.
- T6 `Totp`, which holds its key, has no `Clone` or `PartialEq`: ui:totp_clone, ui:totp_eq (E0277 each), api.
- T7 `Phc` has no `PartialEq`, so no hash is compared with `==` (R-g), and no `Display`, so a hash reaches text only through `as_str`: ui:phc_eq, ui:phc_display (E0277 each), api.
- T8 `Permit` has no public constructor or field, so only `Throttle::check` issues one: ui:permit_forge (E0451), api.
- T9 `Permit` is not `Clone`, and each verifier takes it by value, so one permit pays for one verify: ui:permit_clone (E0277), api; the by-value cases land with each verifier, ui:permit_twice_totp [factor-06], ui:permit_twice_password [factor-07], ui:permit_twice_recovery [factor-08] (E0382 each).
- T10 `OtpMatch`, `PasswordMatch` and `RecoveryMatch` are made only inside their verifiers: ui:otp_match_forge, ui:password_match_forge (E0451 each), ui:recovery_match_forge (E0423), api.
- T11 `Attempts`, `TotpStep` and `RecoveryHash` have no public constructor or field, so a stored value enters only through a verdict or `Record::decode`: ui:attempts_forge (E0451), ui:totp_step_forge, ui:recovery_hash_forge (E0423 each), api.
- T12 `Error` has no public constructor or field: ui:error_forge (E0451), api.
- T13 Every public enum is `#[non_exhaustive]`: ui:error_kind_exhaustive (E0004), api (each `enum` line has its `attr` line).
- T14 Every verdict, and the codes `recovery_generate` draws, is a `base::Pending`, so base T10 (settle only) and `must_use` hold for it: api (each return type) [factor-06, -07, -08].
- T15 A presented `Password` does not convert to a `NewPassword`, so only a password held to its length rule is hashed by `password_hash`: api (no `From` between them) [factor-07].
- T16 No factor type implements `Serialize`: the crate has no serde dependency (B3), api.

## Runtime
Store (architecture section 2, R-g)
- R1 Every `Key` is `Scope::Subject`: unit:store::every_key_is_subject.
- R2 `Error`'s `Display` names its kind only, one fixed phrase per kind with no secret-derived detail: unit:tests::display_names_the_kind_only.
- R3 A verdict's effect holds `Attempts` and exactly the factor row it read: a TOTP match updates `TotpStep` (or creates it under `Absent`), a recovery match is `Consume(Recovery(d))`, every rejection `expect`s the factor row read (or `expect_absent`s it), and a password verdict holds `Attempts` only; no verdict writes the row holding an OTP key or a hash, since the host stores those: unit:store::verdict_effects, race:read_set [factor-09].
- R4 No put carries a store expiry: unit:store::no_expiry [factor-09].
- R5 A record is a version byte (1), a tag byte (0 `Attempts`, 1 `TotpStep`, 2 `Recovery`) and its fields in big-endian: `Attempts` is the count as a u32 then the time as a u64 (14 bytes), `TotpStep` the step as a u64 (10), `Recovery` the 32 digest bytes (34). `Record::decode(r.encode())` is `r` for every variant, one committed encoding per variant decodes to its stated `Debug` text, and `decode` is `TooLarge` over 64 bytes before reading and `Malformed` for a truncated row, trailing bytes, an unknown version or an unknown tag; the fuzz oracle is that a decoded row re-encodes to its input: unit:store::round_trip, row:record (`tests/row_record.rs`, goldens in `tests/golden/`), mutants:store, fuzz:record_decode [factor-04].
- R6 `Internal` is never returned for inputs the constructors accepted, except by `recovery_generate` under a repeating `Entropy` (O10): prop:no_internal [factor-09].

Throttle (F1: verdicts only increment; the session effect does the one reset; operator ruling of 2026-11-26)
- R7 `FreeAttempts::new` accepts 0 to 10, `Wait::new` 1 to 3,600 seconds and `Cap::new` 3,600 (1 hour) to 86,400 (1 day), each `OutOfRange` otherwise, so every `Wait` is at most every `Cap` and `Backoff::new` cannot fail: row:throttle (each bound and its neighbour, as literals), mutants:throttle [factor-03].
- R8 `check` permits with no row and at a count `c` below `free`; from `free` up it is `Closed::Wait(last + min(first * 2^(c - free), cap))` while `now` is earlier and permits at or after it, in saturating arithmetic (counts past 63 and `last` near `u64::MAX` neither panic nor wrap); there is no count at which it stays closed at every `now`: row:throttle (rows m3.inv.throttle-schedule), mutants:throttle [factor-03].
- R9 `Throttle::unlimited` permits at every count, and its verdicts still count: row:throttle [factor-03].
- R10 Every verdict's effect from every verifier, a match included, guards `Unchanged(Attempts)` at the permit's version (`Absent` when none was loaded) and puts `count + 1`, saturating, stamped with the permit's time; none lowers or deletes the count: row:throttle [factor-03, each verifier's row as it lands], mutants:throttle.
- R11 `Throttle::reset` is base's one-op `Effect::deleted` of `Attempts` against the row read, and nothing else: row:throttle (rows m3.inv.reset-only) [factor-03].
- R12 Over any sequence of verifies applied to one store the count rises by one per applied verdict and falls only at a `reset`, and correct passwords interleaved with wrong codes still lengthen the wait: prop:count_never_falls_without_reset, prop:interleaved_matches_still_count [factor-09].

HOTP and TOTP (RFC 4226, RFC 6238)
- R13 `hotp` (HMAC, dynamic truncation, modulo `10^digits`) agrees with RFC 4226 appendix D: vec:rfc4226/hotp.json (10 cases) in unit:otp::rfc4226 (row m3.rfc4226.hotp), mutants:otp [factor-02]; of vec:factor-derived/hotp.json (10 cases) only the values its cases name are this check's, since its `hotp_verify` and `hotp_resync` ops have no subject here (N5).
- R14 `OtpKey::import` is `WeakKey` under 16 bytes (RFC 4226 R6) and `TooLarge` over 64; `generate` draws 20, 32 or 64 bytes for SHA-1, SHA-256 or SHA-512; `export` is the key byte for byte: unit:otp::tests::key_bounds, unit:otp::tests::generate_draws_the_hash_size_and_export_returns_it [factor-02, generate and export factor-06].
- R15 `Totp::verify` agrees with RFC 6238 appendix B for SHA-1, SHA-256 and SHA-512 and with the file's window and `last_step` cases (window 0 is `Skew::Exact`, 1 is `Skew::One`): vec:rfc6238/totp.json (45 cases) in row:rfc6238 (rows m3.rfc6238.*), vec:factor-derived/totp.json (23 cases) [factor-06].
- R16 The step is the permit's time divided by the period, T0 at the epoch, so one attempt has one clock; candidates are `T - skew ..= T + skew`, saturating at 0: row:rfc6238, mutants:otp [factor-06].
- R17 A code that matches only candidates at or before the last accepted step is `Rejected::Replayed` (RFC 6238 5.2 MUST), counted; a match takes the earliest candidate after the last, and the accepted step strictly increases over any sequence of applied verdicts: row:rfc6238, vec:factor-derived/totp.json (23 cases), prop:accepted_step_strictly_increases [factor-06, prop factor-09].
- R18 A code of the other length than the authenticator's `Digits`, or one differing from every candidate in any one digit position, is `Rejected::Wrong`, counted; the compare is `subtle`'s constant-time equality over the full digit text: row:rfc6238, mutants:otp [factor-06].
- R19 `OtpCode::parse` is `TooLarge` over 16 bytes before any other check, then `Malformed` unless six or eight ASCII digits: row:rfc6238, fuzz:otp_code_parse [factor-06, fuzz factor-10].
- R20 `Period::new` accepts 15 to 300 seconds, `OutOfRange` otherwise: row:rfc6238 [factor-06].
- R21 `Totp::confirm` matches `code` at `now` under the authenticator's own window and returns an uncounted effect that records the matched step, so the confirming code is never accepted at the first login; it is `Rejected::Replayed` at or before `last`: row:rfc6238 [factor-06].

Passwords (RFC 9106, NIST SP 800-63B-4 3.1.1.2, OWASP Password Storage)
- R22 One crate-internal `argon2id` maps memory, passes, lanes, version 19 and tag length onto `argon2`, and is the only path to it: `password_hash` and `password_verify` call it with no secret and no associated data, and the RFC 9106 test calls it with the vector's, so the vector exercises the shipped mapping (R34 of the draft, R-g): vec:rfc9106/argon2id.json (1 case) in unit:password::rfc9106 (row m3.rfc9106.argon2id), mutants:password [factor-05].
- R23 `Cost::new` is `OutOfRange` for memory past 65,536 KiB or for passes or lanes of 0 or past 64; then it accepts iff at or above one OWASP Argon2id point, (47,104 KiB, 1), (19,456, 2), (12,288, 3), (9,216, 4) or (7,168, 5), and is `WeakCost` otherwise (each point accepted and its memory minus one rejected, as literals): row:password (tests/row_password.rs), mutants:password [factor-05].
- R24 `NewPassword::new` is `TooLarge` over 4,096 bytes, then `PasswordLength` under 15 Unicode scalar values for `Minimum::SingleFactor` or 8 for `Minimum::MultiFactor`; no composition rule, and every length from the minimum to 64 is accepted: row:password [factor-05].
- R25 `password_hash` is Argon2id v19 at the given cost with a 16-byte salt from `Entropy` and a 32-byte tag, as canonical PHC text; `Phc::parse(p.as_str())` reads back the same text: row:password, oracle: factor-derived/phc.json [factor-05, parse factor-07].
- R26 `Password::presented` is `TooLarge` over 4,096 bytes and `PasswordLength` when empty, and keeps every other text byte for byte; the whole password is hashed, so two that differ only in their 4,096th byte verify apart: row:password [factor-07].
- R27 `Phc::parse` is `TooLarge` over 256 bytes; `Malformed` unless PHC syntax that `argon2`'s `PasswordHash` writes back to the same text; `Unsupported` for another algorithm, a version other than 19, or a `keyid` or `data` parameter; `Malformed` unless salt 8 to 48 bytes (`phc`'s own bound), tag 16 to 64 bytes, memory 8 x lanes to R23's ceiling, passes and lanes 1 to 64; a cost below the floor parses, so older hashes verify and rehash: row:password, oracle: factor-derived/phc.json, fuzz:phc_parse [factor-07, fuzz factor-10].
- R28 `password_verify` matches iff Argon2id over the presented password with the stored parameters and salt yields the stored tag, compared by `argon2`'s `verify_password`, never by `==`; on a match `rehash` is `Rehash::Needed` with the password hashed at the `Cost` given iff the stored memory, passes or lanes is below it or the salt or tag is shorter than R25's, and `Rehash::Current` otherwise, so a stronger hash is never downgraded: row:password, oracle: factor-derived/phc.json, mutants:password [factor-07].
- R29 A verifier's `Err` does not depend on whether the presented secret matched: `password_verify`'s is `OutOfMemory`, decided by the stored cost before any tag is compared; the OTP and recovery verifiers return `Err` for no accepted input: prop:err_independent_of_secret [factor-09].

Recovery codes (NIST SP 800-63B-4 3.1.2)
- R30 `RecoveryCount::new` accepts 1 to 16, `OutOfRange` otherwise: row:recovery [factor-08].
- R31 `recovery_generate` draws `count` codes of 15 bytes (120 bits) and creates one `Recovery(d)` row per code under `Absent`, `d` the SHA-256 of the code's bytes (15 zero bytes digest to `5322fecfc92a5e3248a297a3df3eddfb9bd9049504272e4f572b87fa36d4b3bd`, as a literal); a repeated draw is `Internal`, never a merged row: row:recovery [factor-08].
- R32 `display` writes 24 Crockford base32 symbols as `XXXXXX-XXXXXX-XXXXXX-XXXXXX` (15 zero bytes are `000000-000000-000000-000000`); `parse` of the display is the same code, ignores case, `-` and spaces, reads `I` and `L` as `1` and `O` as `0`, is `TooLarge` over 64 bytes and `Malformed` unless 24 symbols remain: row:recovery, oracle: factor-derived/recovery.json, fuzz:recovery_code_parse [factor-08, fuzz factor-10].
- R33 `recovery_verify` matches iff `stored` is the row under `code.key()`; the match consumes it, so a second use is `Rejected::Wrong`: row:recovery, prop:consumed_at_most_once, mutants:recovery [factor-08, prop factor-09].

## Obligation
- O1 The base store obligation (base O1 to O15) holds on every store these effects reach; factor adds no store rule: base CONTRACT.
- O2 Two concurrent submissions of one code read one `Attempts` version, so exactly one effect applies and the other verdict is void; its re-decision counts it again: race:same_code_twice [factor-09].
- O3 Two guesses against one count both apply only in sequence; the loser re-checks against the winner's count: race:two_guesses [factor-09].
- O4 That every verdict a host reads was counted rests on base O12 (a receipt only after commit), not on a type.
- O5 The consumer lifts a verdict's effect under the one subject whose `Attempts` row made its `Permit` and whose factor row it passed: othala-core's read-set check.
- O6 Only `Throttle::reset` lowers a count, and the consumer merges it into one kind of effect, the session create that completes a login; there is no operator reset path, and a wait ends only by time or that reset (operator ruling, R-g): othala-core's interleaving invariant.
- O7 The host renders `Rejected::Replayed` exactly as `Rejected::Wrong`, so a replay reveals nothing about a past acceptance (R-g): othala-core's login UI test.
- O8 `password_hash` and `password_verify` run with no store transaction open, and in the Worker outside any Durable Object: the shells' test.
- O9 `Record::decode` is called only on a store's load path, since a decoded `Attempts` could carry any count: review, and O6's invariant.
- O10 The `Entropy` given draws from an approved random bit generator (NIST SP 800-90A), since keys, salts and codes come from it: the host's, unchecked.
- O11 The consumer reads a `Pending`'s effect only to apply it: its shape reveals a TOTP or recovery match before settle (R3); password verdicts are shape-uniform: othala-core's contract.
- O12 The host passes `Minimum::SingleFactor` unless every login with the password also requires another factor (NIST 3.1.1.2 SHALL): othala-core's login-path test.
- O13 The host stores `OtpKey::export` encrypted at rest (RFC 4226 7.5, RFC 6238 5.1), reads it only through base's confined `expose`, and stores `Phc` and `Totp`'s parameters itself: the shells' storage test.
- O14 The host's `FreeAttempts` covers the factors one login presents, since a match counts too and only a completed login resets: othala-core's configuration test.
- O15 The host confirms a candidate with `Totp::confirm`, applying its effect, before it stores the authenticator: othala-core's settings-flow test.
- O16 The host consumes a superseded recovery set's rows in the effect that installs the new set (base `Pending::join`): othala-core's settings-flow test.
- O17 Only `otp`, `password` and `recovery` call base's `expose`, the modules `gates.json` `expose` names, so `Cargo.toml` may enable `base/expose` (R-j): review checks the modules; `just canary` fails an enable that `gates.json` does not declare (base O13).

## Build
- B1 `no_std` + `alloc` on wasm32-unknown-unknown and thumbv7em-none-eabi with no features; the one feature, `std`, links std and base's `std` and changes no behaviour, and no algorithm or policy is a feature: `just wasm`, `just thumb` (`gates.json` `targets`).
- B2 MSRV 1.89 against the committed lock: `just msrv`, `just lock`.
- B3 The runtime dependencies are exactly argon2 (`alloc`, `password-hash`, `zeroize`; no `getrandom`, no `std`), base (with `expose`), hmac, sha1, sha2 and subtle (D6): `just deps` over `deps.txt`, `just deny` over `gates.json` `allow`.
- B4 The public API is the committed snapshot: `just api` over `public-api.txt`.
- B5 The ledger runs every case on disk and pins 32 cases and 32 twins, so a glob that matched nothing cannot pass: `just ledger` (`CASES` in `tests/ledger.rs`), `just twins`.
- B6 Every workspace deny-list lint is `forbid` here, so no module calls base's `host_applied` or allows a lint: `just canary`, `just lint`. The crate keeps no secret buffer of its own: `OtpKey`, `OtpCode`, `Password` and `RecoveryCode` wrap base `SecretBytes`, which base wipes (base R32) (R-j): api, review.
- B7 `src/` is mutated with a factor floor and `missed == 0`: `gates.json` `mutants`, landing with its floor [factor-10].
- B8 The fuzz targets `record_decode`, `otp_code_parse`, `phc_parse` and `recovery_code_parse` live in `factor/fuzz` with their corpora replayed [factor-04, factor-10].

## Non-claim
- N1 Copies and moves are not wiped (base N1): the `SecretBytes` `export` returns is base's, the text a host writes from `display` is the host's.
- N2 Constant time is `subtle`'s claim for codes and `password-hash`'s for the tag compare inside `verify_password`; no check measures time; a recovery row is found by digest, which reveals nothing about a 120-bit code.
- N3 No pepper or `keyid` (R27), and no bcrypt, scrypt, PBKDF2, argon2i or argon2d.
- N4 No Unicode normalization and no blocklist (NIST SHOULD and SHALL): the host's, before `Password::presented` and `NewPassword::new`.
- N5 No HOTP authenticator (the keys hold no counter row, R-g; so factor-derived/hotp.json's look-ahead and resynchronization ops are not run), otpauth URI, QR code, public code generator, drift tracking beyond `Skew::One`, T0 other than the epoch, or seven-digit code.
- N6 No permanent lock (operator ruling of 2026-11-26): NIST SP 800-63B-4 3.2.2's 100-failure disable is replaced by a wait that doubles up to `Cap`, so the guess rate is bounded at one per `Cap` and never reaches zero; at the 1-hour floor a six-digit TOTP under `Skew::One` faces at most about 8,800 guesses a year at 3 in a million each, about 2.6 per cent a year.
- N7 The throttle counts per subject across factors; passkeys are not counted here; no throttle across subjects (spraying) and no timing equalisation for a subject without the factor: the host's.
- N8 `RecoveryMatch` carries no remaining count: codes are rows of their own, and the host counts them if it lists them.

## Refinements of architecture section 2
`check` returns `Closed::Wait(until)`, never a lock (R-g). `Totp::verify` takes no `now`: the permit's time is its one clock. `password_verify` takes the host's `&Phc` and `Cost`, and `recovery_verify` the one row under `RecoveryCode::key`, not the whole set. `recovery_generate` returns its codes inside a `Pending`, so they leave only once their rows commit. `Rehash::Needed` carries the new `Phc`. `OtpKey` holds its bytes in a base `SecretBytes` and leaves as one; factor reads secret bytes through base's `expose` only in the modules O17 names (R-j).

## Module map
| Item | File | Lands | Rows and checks |
|---|---|---|---|
| factor-01 | `lib.rs`, every `src/` type, `tests/ledger.rs`, `tests/ui/`, `gates.json`, `deps.txt`, `public-api.txt` | this file, T1 to T13, R1, R2, B1 to B6 | ledger, twins, api |
| factor-02 | `src/otp.rs` | `hotp`, `OtpKey::import` | m3.rfc4226.hotp (R13, R14) |
| factor-03 | `src/throttle.rs`, `tests/row_throttle.rs` | the throttle | m3.inv.throttle-schedule, m3.inv.reset-only (R7 to R11) |
| factor-04 | `src/store.rs`, `tests/row_record.rs`, `tests/golden/`, `fuzz/` | the record codec | m3-factor-record (R5, B8) |
| factor-05 | `src/password.rs` | `argon2id`, costs, `NewPassword`, `password_hash` | m3.rfc9106.argon2id (R22 to R25) |
| factor-06 | `src/otp.rs`, `src/throttle.rs` (permit time), `tests/row_rfc6238.rs`, `tests/row_rfc6238_window.rs`, `tests/common/` | TOTP and its last step | m3-factor-rfc6238, m3-factor-rfc6238-window (R15 to R21) |
| factor-07 | `src/password.rs`, `tests/row_password.rs` (shared with factor-05) | `Password`, `Phc::parse`, verify and rehash | m3-factor-password (R23 to R28) |
| factor-08 | `src/recovery.rs`, `tests/row_recovery.rs` | recovery codes | m3-factor-recovery (R30 to R33) |
| factor-09 | `src/store.rs`, `tests/props.rs`, `tests/race.rs` | invariants | R3, R4, R6, R12, R17, R29, R33, O2, O3 |
| factor-10 | `fuzz/`, `gates.json` `mutants` | fuzz and the mutants floor | B7, B8 |
