# base contract

One claim per line, each naming the check that proves it. Tags follow the claims ledger: *Type* (the program does not compile), *Runtime* (a check returns an error), *Obligation* (the host's, proven against every `Store`), *Non-claim*.
Checks: `ui:x` is `tests/ui/fail/x.rs` with its committed `.stderr` (rustc code given) and the compiling twin `tests/ui/pass/x.rs` one line and one token away (`just twins`; `just ledger` runs with every feature on); `api` is the committed `public-api.txt` from rustdoc JSON on a pinned nightly (`just api`); `unit:m::t` is a test in `src/m.rs`; `it:f::t` is `tests/f.rs`; `mutants:m` is `just mutants` over `src/m.rs`; `conf:c` is case `c` of `testkit::store_conformance`, run here against `testkit::MemStore`; `race:t` is `tests/race.rs`.

## Type
- T1 `Secret<N>` has no `Display`: ui:secret_display (E0277), api.
- T2 `SecretBytes` has no `Display`: ui:secret_bytes_display (E0277), api.
- T3 `Secret<N>` has no `Clone`: ui:secret_clone (E0277), api.
- T4 `SecretBytes` has no `Clone`: ui:secret_bytes_clone (E0277), api.
- T5 `Secret<N>` cannot be compared with `==`: ui:secret_eq (E0277), api.
- T6 `SecretBytes` cannot be compared with `==`: ui:secret_bytes_eq (E0277), api.
- T7 `Secret<N>` has no `Serialize`, so no serde record field holds one: ui:secret_serialize (E0277; the twin is `Digest`, which serializes only under `serde`), api.
- T8 `SecretBytes` has no `Serialize`: ui:secret_bytes_serialize (E0277), api.
- T9 A secret cannot be a `StoreKey` (no `Clone`, no `Ord`); store-facing keys take `Digest`: ui:secret_key (E0277, E0369).
- T10 A verdict leaves `Pending` only through `settle`: api (no accessor, no `map`; `lift` and `join` keep it inside), `Debug` prints only the effect id (it:golden::debug_redacts), and ui:pending_verdict shows a closure cannot move it out through `map` (E0599).
- T11 `Receipt` has no public constructor; `Effect::host_applied` is the one mint: ui:receipt_forge (E0599), api.
- T12 `Receipt` is not `Clone`: ui:receipt_clone (E0277), api.
- T13 No put without a guard on its key (`create` is `Absent` plus put, `update` is `Unchanged` plus put): api (the builder's only writes are the six guarded ones); ui:unguarded_put (E0599) is the named-guess illustration.
- T14 No delete without a guard on its key (`consume`, or `delete` against a seen row): api; ui:unguarded_delete (E0599) is the named-guess illustration.

## Runtime
- R1 `b64url_encode` and `b64url_decode` (a wrapper over `base64ct`'s unpadded base64url, the D6 adoption) agree with RFC 4648 section 10 under the section 5 alphabet: it:vectors::rfc4648_section10 (total 28, 7 checked), mutants:b64url.
- R2 Symbols 62 and 63 are `-` and `_`: unit:b64url::alphabet_edges, mutants:b64url.
- R3 Padding is `Malformed`: unit:b64url::padding_is_malformed, mutants:b64url.
- R4 A symbol outside the alphabet (`+`, `/`, space, non-ASCII) is `Malformed`: unit:b64url::foreign_symbol_is_malformed, mutants:b64url.
- R5 A length of 1 mod 4 is `Malformed`: unit:b64url::lone_symbol_is_malformed, mutants:b64url.
- R6 A non-canonical tail (nonzero trailing bits) is `Malformed`, so decoding is injective: of all 64 final symbols a 2-symbol tail accepts exactly `A Q g w` and a 3-symbol tail exactly the 16 with two zero low bits: unit:b64url::noncanonical_tail_is_malformed, mutants:b64url.
- R7 Whatever decodes re-encodes to the same text: it:corpus::b64url_decode_corpus (21 committed seeds of `fuzz/fuzz_targets/b64url_decode.rs`, non-canonical tails `Zo` and `ZmC` among them), `just fuzz` in scheduled CI.
- R8 `Debug` of `Secret<N>` and `SecretBytes` prints no secret byte, and of `Pending` only its effect id: it:golden::debug_redacts against `tests/golden/debug.txt`, unit:effect::pending_debug_shows_only_the_effect_id.
- R9 `generate` draws exactly `N` bytes from `Entropy`: unit:secret::generate_draws_n_bytes, mutants:secret.
- R10 `ct_eq` is true only when every byte and the length match: unit:secret::ct_eq_compares_every_byte, mutants:secret.
- R11 `digest` is SHA-256 of the secret bytes: unit:secret::digest_is_sha256, mutants:secret.
- R12 A key named twice in one builder is `Overlap`: unit:effect::overlap_in_builder, mutants:effect.
- R13 A merge of effects sharing a key is `Overlap`: unit:effect::overlap_in_merge, mutants:effect.
- R14 A non-injective lift is `Overlap`: unit:effect::overlap_in_lift, mutants:effect.
- R15 A lift that changes a key's `scope()` is `ScopeChanged`: unit:effect::scope_changed_in_lift, mutants:effect.
- R16 `build` of an effect with no guard is `Empty`: unit:effect::empty_build, mutants:effect.
- R17 An effect whose guards plus writes exceed `MAX_EFFECT_SIZE` (128, asserted as a literal) is `TooLarge` from `build` and `merge`, and exactly 128 builds: unit:effect::size_bound; the builder latches its first fault and stops growing, and `merge` tests the bound before moving anything, so an oversize effect is never an allocation: unit:effect::oversize_builder_stops_growing, mutants:effect.
- R18 `domain` is `SpansDomains` unless every key maps to one domain: unit:effect::domain_of_keys, mutants:effect.
- R19 `settle` with another effect's receipt is `WrongReceipt`; its own receipt yields the verdict: unit:effect::settle_by_receipt, mutants:effect.
- R20 The id is 16 bytes of `Entropy`; `lift` keeps it; `merge` takes the first 16 bytes of SHA-256 of both ids in order: unit:effect::ids, mutants:effect.
- R21 `check` names every failed guard (`Missing`, `Changed`, `Present`) and passes when all hold: unit:effect::check_names_each_failure, mutants:effect.
- R22 `guards`, `puts` and `deletes` show exactly what the builder paired, consumed rows among the deletes: unit:effect::views, mutants:effect.
- R23 No builder, merge or lift sequence yields a write without a guard on its key, a key twice, or more than 128 guards plus writes: it:effect_props::construction_never_unguarded (proptest, fixed seed, 512 cases, distinct keys by construction and one repeated at times).
- R24 Against the reference store, an effect applies whole or not at all, and a `Conflict` names exactly the guards that fail: it:effect_props::all_guards_or_nothing (proptest, fixed seed, 512 cases, guards drawn mostly holding so both halves are common).
- R25 `Rows::get` reports a loaded row, an absent row, a corrupt row, and `None` for a key never loaded: unit:store::rows_slots.
- R26 `UnixTime::saturating_add` and `saturating_sub` saturate at `u64::MAX` and the epoch; `checked_duration_since` is `None` when the other instant is later: unit:time::arithmetic_saturates.
- R27 `Secret::<N>::from_b64url` takes canonical unpadded base64url of exactly `N` bytes and is `Malformed` otherwise, decoding into the secret's own buffer: unit:secret::from_b64url_takes_exactly_n, unit:b64url::exact_length, mutants:secret.
- R28 `Digest` has a text form (43-symbol unpadded base64url) that round-trips, and under `serde` serializes as that text and deserializes only from it: unit:secret::digest_text_round_trips, unit:secret::digest_serde_is_text, mutants:secret.
- R29 The vector runner counts only checked cases against its floor, and a zero floor, a total that disagrees with `SOURCES.toml` or an unlisted file fails: testkit unit:vectors (six cases).

## Obligation (every host's; `testkit::store_conformance` on the shell's exact apply path)
- O1 One transaction per apply: every guard holds or nothing is applied (puts, deletes and consumes alike), and the `Conflict` names each failed guard: conf:atomic. Each case is proven sensitive by it:conformance::each_lie_is_caught_by_its_case, sixteen stores with one lie each that must fail in the case named here, the same store without a lie passing (it:conformance::the_honest_liar_passes); atomic catches skipped writes, a conflict reported as `Error`, and puts or deletes applied despite a conflict.
- O2 A guard that fails after a write in key order leaves that write unapplied: conf:fails_after_write (a store that stops at the first failing guard).
- O3 An effect fails only on a key an earlier winner wrote, so disjoint effects and effects that only `expect` one row both apply; `Consume` checks existence only, so a decision that depends on a row's content uses `delete` against the seen row: conf:expect_shared (a store that bumps an expected row), conf:disjoint (a store that checks a table-wide version), race:pairs, race:consume_checks_existence_only, race:a_loser_fails_only_on_winners_writes.
- O4 Concurrent applies equal some serial order once each loser is re-decided against the winners' state: race:pairs, race:triples (each asserts conflicts were raced), testkit unit:race::every_order_once.
- O5 Re-applying an applied effect returns `Ok` with a receipt that settles it, and writes nothing twice: conf:reapply (a store with no applied-id record), race:same_twice, race:same_twice_catches_a_store_that_forgets_applied_ids.
- O6 The applied-id record shares the effect's transaction and is checked before any guard, and a conflicted effect's id is not recorded: conf:reapply (a store that checks the id after the guards), conf:conflict_not_applied (a store that records a conflicted id).
- O7 A store's own constraint failure is `Conflict`, never `Error`: conf:duplicate_create (a store that leaves `Absent` on a create to a unique constraint that errors).
- O8 A row past its expiry is absent to `load` and to every guard, purged or not, and an update's deadline holds: conf:expired (stores live at the deadline, whose guards ignore expiry, or whose update drops it).
- O9 A version never repeats for a key, across delete and recreate: conf:recreate (a store with per-key version counters).
- O10 An effect at the bound applies, 128 guards and 64 guarded writes alike: conf:at_bound (a store that refuses past 100 guards).
- O11 Every key a decision loaded is guarded in its effect: race:read_set (the reference store records loads; the case is a probe that must fail).
- O12 A `Receipt` is minted only after its effect committed: `host_applied` is in clippy `disallowed_methods` for every crate but `base` (`just lint`; it:lint_canary expects every `clippy.toml` path to fire, so a path that stops resolving fails), and `just confine` (`confine.sh`) fails on a `.rs` file that names `disallowed_methods` outside `testkit/src/store.rs`, `testkit/src/fixture.rs`, `tests/conformance.rs` and `tests/lint_canary.rs`, names `host_applied` outside `src/effect.rs`, the two store modules and the canary, silences a group that holds the lint (`warnings`, `clippy::style`, `clippy::all`), or on a member `Cargo.toml` that overrides or does not inherit the workspace lints; `confine.sh --self-test` plants ten evasions, multi-line attributes among them, and requires each flagged.
- O13 `expose` is read only in modules a `CONTRACT.md` names; `base` names none: `just lint` (it:lint_canary), `just confine` (names `expose` outside `src/secret.rs` and the canary). `base`'s own `src/` does not resolve the `base::` path, so its unit tests call `expose` unflagged.
- O14 After `Conflict` a decider re-decides at most `REDECIDE` (3) times; after `Error` the host re-applies the same effect with the decision's `now`, within `Retry`: consumers' contracts; unit:store::redecide_is_three, race:a_loser_redecides_up_to_three_times, race:a_loser_gives_up_after_three.

## Build
- B1 `no_std` + `alloc` for wasm32-unknown-unknown and thumbv7em-none-eabi, with `std`, `rand_core` and `serde` features off and on: `just wasm`, `just thumb`.
- B2 `RandCore` makes any `rand_core::CryptoRng` an `Entropy`: testkit `seeded` is built on it, it:vectors and every seeded test.
- B3 MSRV 1.89 (the D6 ruling): `just msrv` (`--locked`).

## Non-claim
- N1 Zeroize on drop is best effort (moves and copies are not tracked); no check can prove it.
- N2 The base64url codec is `base64ct`'s; its constant-time property is that crate's claim, not checked here.
- N3 `UnixTime::from(SystemTime)` saturates instants before the epoch to 0.
