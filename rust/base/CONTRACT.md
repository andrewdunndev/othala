# base contract

One claim per line, each naming the check that proves it. Tags follow the claims ledger: *Type* (the program does not compile), *Runtime* (a check returns an error), *Obligation* (the host's, proven against every `Store`), *Non-claim*.
Checks: `ui:x` is `tests/ui/fail/x.rs` with its committed `.stderr` (rustc code given) and the compiling twin `tests/ui/pass/x.rs` one token away (`just twins`); `api` is the committed `public-api.txt` (`just api`); `unit:m::t` is a test in `src/m.rs`; `it:f::t` is `tests/f.rs`; `mutants:m` is `just mutants` over `src/m.rs`; `conf:c` is case `c` of `testkit::store_conformance`, run here against `testkit::MemStore`; `race:t` is `tests/race.rs`.

## Type
- T1 `Secret<N>` has no `Display`: ui:secret_display (E0277), api.
- T2 `SecretBytes` has no `Display`: ui:secret_bytes_display (E0277), api.
- T3 `Secret<N>` has no `Clone`: ui:secret_clone (E0277), api.
- T4 `SecretBytes` has no `Clone`: ui:secret_bytes_clone (E0277), api.
- T5 `Secret<N>` cannot be compared with `==`: ui:secret_eq (E0277), api.
- T6 `SecretBytes` cannot be compared with `==`: ui:secret_bytes_eq (E0277), api.
- T7 `Secret<N>` has no `Serialize`, so no serde record field holds one: ui:secret_serialize (E0277), api.
- T8 `SecretBytes` has no `Serialize`: ui:secret_bytes_serialize (E0277), api.
- T9 A secret cannot be a `StoreKey` (no `Clone`, no `Ord`); store-facing keys take `Digest`: ui:secret_key (E0277, E0369).
- T10 A verdict leaves `Pending` only through `settle`: ui:pending_verdict (E0599), api.
- T11 `Receipt` has no public constructor; `Effect::host_applied` is the one mint: ui:receipt_forge (E0599), api.
- T12 `Receipt` is not `Clone`: ui:receipt_clone (E0277), api.
- T13 No put without a guard on its key (`create` is `Absent` plus put, `update` is `Unchanged` plus put): ui:unguarded_put (E0599), api.
- T14 No delete without a guard on its key (`consume`, or `delete` against a seen row): ui:unguarded_delete (E0599), api.

## Runtime
- R1 `b64url_encode` and `b64url_decode` agree with RFC 4648 section 10 under the section 5 alphabet, unpadded: it:vectors::rfc4648_section10, mutants:b64url.
- R2 Symbols 62 and 63 are `-` and `_`: unit:b64url::alphabet_edges, mutants:b64url.
- R3 Padding is `Malformed`: unit:b64url::padding_is_malformed, mutants:b64url.
- R4 A symbol outside the alphabet (`+`, `/`, space, non-ASCII) is `Malformed`: unit:b64url::foreign_symbol_is_malformed, mutants:b64url.
- R5 A length of 1 mod 4 is `Malformed`: unit:b64url::lone_symbol_is_malformed, mutants:b64url.
- R6 A non-canonical tail (nonzero trailing bits) is `Malformed`, so decoding is injective: unit:b64url::noncanonical_tail_is_malformed, mutants:b64url.
- R7 Whatever decodes re-encodes to the same text: it:corpus::b64url_decode_corpus (committed corpus of `fuzz/fuzz_targets/b64url_decode.rs`), `just fuzz` in scheduled CI.
- R8 `Debug` of `Secret<N>` and `SecretBytes` prints no secret byte: it:golden::debug_redacts against `tests/golden/debug.txt`.
- R9 `generate` draws exactly `N` bytes from `Entropy`: unit:secret::generate_draws_n_bytes, mutants:secret.
- R10 `ct_eq` is true only when every byte and the length match: unit:secret::ct_eq_compares_every_byte, mutants:secret.
- R11 `digest` is SHA-256 of the secret bytes: unit:secret::digest_is_sha256, mutants:secret.
- R12 A key named twice in one builder is `Overlap`: unit:effect::overlap_in_builder, mutants:effect.
- R13 A merge of effects sharing a key is `Overlap`: unit:effect::overlap_in_merge, mutants:effect.
- R14 A non-injective lift is `Overlap`: unit:effect::overlap_in_lift, mutants:effect.
- R15 A lift that changes a key's `scope()` is `ScopeChanged`: unit:effect::scope_changed_in_lift, mutants:effect.
- R16 `build` of an effect with no guard is `Empty`: unit:effect::empty_build, mutants:effect.
- R17 An effect whose guards plus writes exceed `MAX_EFFECT_SIZE` (128) is `TooLarge` from `build` and `merge`; exactly 128 builds: unit:effect::size_bound, mutants:effect.
- R18 `domain` is `SpansDomains` unless every key maps to one domain: unit:effect::domain_of_keys, mutants:effect.
- R19 `settle` with another effect's receipt is `WrongReceipt`; its own receipt yields the verdict: unit:effect::settle_by_receipt, mutants:effect.
- R20 The id is 16 bytes of `Entropy`; `lift` keeps it; `merge` takes the first 16 bytes of SHA-256 of both ids in order: unit:effect::ids, mutants:effect.
- R21 `check` names every failed guard (`Missing`, `Changed`, `Present`) and passes when all hold: unit:effect::check_names_each_failure, mutants:effect.
- R22 `guards`, `puts` and `deletes` show exactly what the builder paired, consumed rows among the deletes: unit:effect::views, mutants:effect.
- R23 No builder, merge or lift sequence yields a write without a guard on its key or a key twice: it:effect_props::construction_never_unguarded (proptest).
- R24 Against the reference store, an effect applies whole or not at all, and a `Conflict` names exactly the guards that fail: it:effect_props::all_guards_or_nothing (proptest).
- R25 `Rows::get` reports a loaded row, an absent row, a corrupt row, and `None` for a key never loaded: unit:store::rows_slots.

## Obligation (every host's; `testkit::store_conformance` on the shell's exact apply path)
- O1 One transaction per apply: every guard holds or nothing is applied, and the `Conflict` names each failed guard: conf:atomic.
- O2 A guard that fails after a write in key order leaves that write unapplied: conf:fails_after_write.
- O3 Two effects conflict only when one writes a row the other guards or writes; disjoint effects and effects that only `expect` one row both apply: conf:expect_shared, conf:disjoint, race:pairs.
- O4 Concurrent applies equal some serial order, and a loser re-decided against the winner's state matches it: race:pairs, race:triples.
- O5 Re-applying an applied effect returns `Ok` with a receipt that settles it, and writes nothing twice: conf:reapply, race:same_twice.
- O6 The applied-id record shares the effect's transaction and is checked before any guard: conf:reapply (a re-applied `create` would otherwise be `Present`).
- O7 A store's own constraint failure is `Conflict`, never `Error`: conf:duplicate_create.
- O8 A row past its expiry is absent to `load` and to every guard, purged or not: conf:expired.
- O9 A version never repeats for a key, across delete and recreate: conf:recreate.
- O10 An effect at `MAX_EFFECT_SIZE` applies: conf:at_bound.
- O11 Every key a decision loaded is guarded in its effect: race:read_set (the reference store records loads).
- O12 A `Receipt` is minted only after its effect committed: `host_applied` is in clippy `disallowed_methods` outside store modules (`just lint`), and `just confine` fails on any `allow` or `expect` of that lint outside `testkit/src/store.rs` and `testkit/src/fixture.rs`.
- O13 `expose` is read only in modules a `CONTRACT.md` names; for `base`, none outside `src/secret.rs`: `just lint`, `just confine`.
- O14 After `Conflict` a decider re-decides at most `REDECIDE` (3) times; after `Error` the host re-applies the same effect with the decision's `now`, within `Retry`: consumers' contracts; race:pairs re-decides within `REDECIDE`.

## Build
- B1 `no_std` + `alloc` for wasm32-unknown-unknown and thumbv7em-none-eabi, with `std`, `rand_core` and `serde` features off and on: `just wasm`, `just thumb`.
- B2 `RandCore` makes any `rand_core::CryptoRng` an `Entropy`: testkit `seeded` is built on it, it:vectors and every seeded test.
- B3 MSRV 1.85: `just msrv`.

## Non-claim
- N1 Zeroize on drop is best effort (moves and copies are not tracked); no check can prove it.
- N2 `b64url_decode` and `b64url_encode` are not constant-time.
- N3 `UnixTime::from(SystemTime)` saturates instants before the epoch to 0.
