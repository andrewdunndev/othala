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
//! - `hand:<Kind>`: a minimal input written for the target, with the outcome it states.
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
        53
    );
}

#[test]
fn authenticator_data_corpus() {
    assert_eq!(
        replay("fuzz/corpus/authenticator_data", authenticator_data::check),
        18
    );
}

#[test]
fn client_data_corpus() {
    assert_eq!(replay("fuzz/corpus/client_data", client_data::check), 32);
}

#[test]
fn record_corpus() {
    assert_eq!(replay("fuzz/corpus/record", record::check), 55);
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    text.trim()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// The bytes a manifest line's source and rule give, and the outcome its rule gives; `None` bytes are not derived.
fn derive(target: &str, source: &str, rule: &str) -> Result<(Option<Vec<u8>>, String), String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |path: std::path::PathBuf| {
        std::fs::read_to_string(&path).map_err(|e| format!("{path:?}: {e}"))
    };
    if let Some(kind) = rule.strip_prefix("hand:") {
        return Ok((None, kind.to_owned()));
    }
    if let Some(name) = source.strip_prefix("golden:") {
        let row =
            unhex(&read(root.join(format!("tests/golden/{name}.hex")))?).ok_or("golden hex")?;
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
    let vector: serde_json::Value = serde_json::from_str(&read(
        root.join("../vectors/webauthn-rp-derived").join(file),
    )?)
    .map_err(|e| e.to_string())?;
    let case = vector
        .get("cases")
        .and_then(|c| c.as_array())
        .and_then(|cases| {
            cases
                .iter()
                .find(|c| c.get("id").and_then(|i| i.as_str()) == Some(id))
        })
        .ok_or_else(|| format!("{source}: no such case"))?;
    let bytes = unhex(
        case.get(field)
            .and_then(|f| f.as_str())
            .ok_or("no such field")?,
    )
    .ok_or("case hex")?;
    let expect = case.get("expect").ok_or("expect")?;
    let ok = expect
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .ok_or("expect.ok")?;
    let kind = expect.get("kind").and_then(|k| k.as_str()).unwrap_or("ok");
    let finish = !ok && !matches!(kind, "Malformed" | "TooLarge");
    let outcome = match rule {
        "oracle" => kind,
        "finish" if finish => "ok",
        "rawid" if target == "attestation_object" && (ok || finish) => "CredentialIdInvalid",
        "shape" if target == "attestation_object" && file == "cbor.json" && ok => "Malformed",
        _ => return Err(format!("{source}: rule {rule} does not apply")),
    };
    Ok((Some(bytes), outcome.to_owned()))
}

#[test]
fn manifest_derives_every_seed() -> Result<(), String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("fuzz/seeds.tsv")).map_err(|e| e.to_string())?;
    let mut listed = std::collections::BTreeSet::new();
    for line in text.lines() {
        let [target, seed, source, rule] = line.split('\t').collect::<Vec<_>>()[..] else {
            return Err(format!("not four columns: {line}"));
        };
        let path = root.join("fuzz/corpus").join(target).join(seed);
        let (bytes, outcome) = derive(target, source, rule)?;
        if let Some(bytes) = bytes {
            assert_eq!(
                std::fs::read(&path).map_err(|e| e.to_string())?,
                bytes,
                "{target}/{seed} bytes"
            );
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
    for target in [
        "attestation_object",
        "authenticator_data",
        "client_data",
        "record",
    ] {
        for (name, _) in testkit::fixture::files(&root.join("fuzz/corpus").join(target)) {
            if name.contains('-') {
                named += 1;
                assert!(
                    listed.contains(&(target, name.as_str())),
                    "{target}/{name} is not in fuzz/seeds.tsv"
                );
            }
        }
    }
    assert_eq!(named, listed.len());
    Ok(())
}
