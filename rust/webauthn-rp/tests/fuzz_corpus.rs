//! The committed fuzz corpora (CONTRACT R2, R3, R4, R6, R15, R16), replayed through each target's own property: no
//! input panics, and a seed named `<outcome>-NN` has that outcome (`ok`, or the `ErrorKind` name). A file a fuzz run
//! adds (a hash name) is replayed for panics only.
//!
//! `fuzz/seeds.tsv` names each seed's source and the rule that gives its outcome, and the manifest test re-derives
//! both: the seed's bytes from the source, its outcome from the rule, so a renamed or edited seed goes red.
//! - `oracle`: the outcome is the `webauthn-rp-derived` case's own (`ok`, or its `kind`), for a refusal `new` makes.
//! - `finish`: the case is a refusal of a finish step (its kind is not `Malformed` or `TooLarge`), which `new` reads
//!   as `ok` (R16).
//! - `rawid` (attestation_object): the harness's fixed raw id is not the attested one, `CredentialIdInvalid` (R17).
//! - `shape` (attestation_object): a `cbor.json` item that decodes but is not an attestation object, `Malformed` (R40).
//! - `golden`, `golden-cut`, `golden-extra`, `golden-version`: a `tests/golden` row, whole (`ok`), without its last
//!   byte, with an extra `00`, or with version byte 09 (`Corrupt`, R15).
//! - `hand:<Kind>`: a minimal input written for the target, its hex after the id of the CONTRACT claim it probes, with
//!   the outcome it states.
//!
//! The fixed raw id makes any other credential id `CredentialIdInvalid`, so the corpus does not prove the R51 bound
//! (ids of 1023 and 1024 bytes both read so); `row:derived` does.
use webauthn_rp::ErrorKind;

#[path = "../fuzz/property/attestation_object.rs"]
mod attestation_object;
#[path = "../fuzz/property/authenticator_data.rs"]
mod authenticator_data;
#[path = "../fuzz/property/client_data.rs"]
mod client_data;
#[path = "../fuzz/property/record.rs"]
mod record;

fn label(outcome: Result<(), ErrorKind>) -> String {
    outcome.map_or_else(|kind| format!("{kind:?}"), |()| String::from("ok"))
}

/// Replays `dir` and returns how many seeds named their outcome.
fn replay(dir: &str, check: fn(&[u8]) -> Result<(), ErrorKind>) -> usize {
    let files =
        testkit::fixture::files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(dir));
    let mut named = 0;
    for (name, data) in files {
        let outcome = testkit::fixture::replay(&format!("{dir}/{name}"), || check(&data));
        if let Some((want, _)) = name.split_once('-') {
            assert_eq!(label(outcome), want, "{dir}/{name}");
            named += 1;
        }
    }
    named
}

#[test]
fn attestation_object_corpus() {
    assert_eq!(
        replay("fuzz/corpus/attestation_object", attestation_object::check),
        52
    );
}

#[test]
fn authenticator_data_corpus() {
    assert_eq!(
        replay("fuzz/corpus/authenticator_data", authenticator_data::check),
        17
    );
}

#[test]
fn client_data_corpus() {
    assert_eq!(replay("fuzz/corpus/client_data", client_data::check), 31);
}

#[test]
fn record_corpus() {
    assert_eq!(replay("fuzz/corpus/record", record::check), 54);
}

const SEEDS: &str = include_str!("../fuzz/seeds.tsv");
const CONTRACT: &str = include_str!("../CONTRACT.md");

fn unhex(text: &str) -> Option<Vec<u8>> {
    text.trim()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

#[derive(serde::Deserialize)]
struct Expect {
    ok: bool,
    kind: Option<String>,
}

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    expect: Expect,
    attestation_object: Option<String>,
    authenticator_data: Option<String>,
    client_data_json: Option<String>,
    input: Option<String>,
}

#[derive(serde::Deserialize)]
struct Vector {
    cases: Vec<Case>,
}

/// The oracle files and golden rows by name.
fn sources() -> std::collections::BTreeMap<String, Vec<u8>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    ["../vectors/webauthn-rp-derived", "tests/golden"]
        .iter()
        .flat_map(|dir| testkit::fixture::files(&root.join(dir)))
        .collect()
}

/// The bytes a manifest line's source and rule give (none for a hand-made input) and the outcome its rule gives.
fn derive(
    target: &str,
    source: &str,
    rule: &str,
    files: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<(Option<Vec<u8>>, String), String> {
    if let Some(kind) = rule.strip_prefix("hand:") {
        let (claim, hex) = source.split_once(':').ok_or("hand source")?;
        if !CONTRACT.contains(&format!("\n- {claim} ")) {
            return Err(format!("{source}: no such claim"));
        }
        return Ok((Some(unhex(hex).ok_or("hand hex")?), kind.to_owned()));
    }
    if let Some(name) = source.strip_prefix("golden:") {
        if target != "record" {
            return Err(format!("{source}: a golden row is a record"));
        }
        let text = files.get(&format!("{name}.hex")).ok_or("no golden row")?;
        let row = unhex(&String::from_utf8_lossy(text)).ok_or("golden hex")?;
        let (bytes, outcome) = match rule {
            "golden" => (row, "ok"),
            "golden-cut" => (
                row.get(..row.len() - 1).ok_or("empty row")?.to_vec(),
                "Corrupt",
            ),
            "golden-extra" => ([row.as_slice(), &[0]].concat(), "Corrupt"),
            "golden-version" => ([&[9], row.get(1..).ok_or("empty row")?].concat(), "Corrupt"),
            _ => return Err(format!("{source}: rule {rule}")),
        };
        return Ok((Some(bytes), outcome.to_owned()));
    }
    let (file, rest) = source.split_once('#').ok_or("source")?;
    let (id, field) = rest.rsplit_once('.').ok_or("source field")?;
    let vector: Vector = serde_json::from_slice(files.get(file).ok_or("no oracle file")?)
        .map_err(|e| e.to_string())?;
    let case = vector
        .cases
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| format!("{source}: no such case"))?;
    let hex = match field {
        "attestation_object" => &case.attestation_object,
        "authenticator_data" => &case.authenticator_data,
        "client_data_json" => &case.client_data_json,
        "input" => &case.input,
        _ => return Err(format!("{source}: field {field}")),
    };
    let bytes = unhex(hex.as_deref().ok_or("no such field")?).ok_or("case hex")?;
    let kind = case.expect.kind.as_deref().unwrap_or("ok");
    let finish = !case.expect.ok && !matches!(kind, "Malformed" | "TooLarge");
    let outcome = match rule {
        "oracle" if !finish => kind,
        "finish" if finish => "ok",
        "rawid" if target == "attestation_object" && (case.expect.ok || finish) => {
            "CredentialIdInvalid"
        }
        "shape" if target == "attestation_object" && file == "cbor.json" && case.expect.ok => {
            "Malformed"
        }
        _ => return Err(format!("{source}: rule {rule} does not apply")),
    };
    Ok((Some(bytes), outcome.to_owned()))
}

#[test]
fn manifest_derives_every_seed() -> Result<(), String> {
    let files = sources();
    let mut listed = std::collections::BTreeSet::new();
    for line in SEEDS.lines() {
        let [target, seed, source, rule] = line.split('\t').collect::<Vec<_>>()[..] else {
            return Err(format!("not four columns: {line}"));
        };
        let (bytes, outcome) = derive(target, source, rule, &files)?;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus")
            .join(target);
        let corpus = testkit::fixture::files(&dir);
        let seed_bytes = &corpus
            .iter()
            .find(|(name, _)| name == seed)
            .ok_or("no such seed")?
            .1;
        if let Some(bytes) = bytes {
            assert_eq!(*seed_bytes, bytes, "{target}/{seed} bytes");
        }
        assert_eq!(
            seed.split_once('-').map(|(want, _)| want),
            Some(outcome.as_str()),
            "{target}/{seed}"
        );
        assert!(
            listed.insert((target, seed)),
            "{target}/{seed} listed twice"
        );
    }
    let mut named = 0;
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    for dir in testkit::fixture::paths(&corpus) {
        let target = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or("corpus dir")?;
        for (name, _) in testkit::fixture::files(&dir) {
            if name.contains('-') {
                named += 1;
                assert!(
                    listed.contains(&(target.as_str(), name.as_str())),
                    "{target}/{name} is not in fuzz/seeds.tsv"
                );
            }
        }
    }
    assert_eq!(named, listed.len());
    Ok(())
}

/// The empty input, which no corpus file holds (an empty file is an unread scan to `just purity`) and libFuzzer
/// always tries first.
#[test]
fn the_empty_input_is_refused_by_kind() {
    assert_eq!(attestation_object::check(&[]), Err(ErrorKind::Malformed));
    assert_eq!(authenticator_data::check(&[]), Err(ErrorKind::Malformed));
    assert_eq!(client_data::check(&[]), Err(ErrorKind::Malformed));
    assert_eq!(record::check(&[]), Err(ErrorKind::Corrupt));
}
