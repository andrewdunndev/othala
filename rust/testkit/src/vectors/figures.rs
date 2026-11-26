//! RFC 7520 figure files (`{"figures":[...]}`): one case per numbered example, the shared preamble figures apart.
use serde::Deserialize;

use super::{Json, Outcome, SOURCES, Tally, Vector, floored, verified};

/// A numbered figure of RFC 7520.
#[derive(Clone, Debug)]
pub struct Figure {
    /// The figure number.
    pub figure: u32,
    /// The caption.
    pub caption: String,
    /// The section it sits in, such as `4.1.2`.
    pub section: String,
    /// The text as the RFC sets it.
    pub text: String,
    /// The text with whitespace removed.
    pub joined: String,
    /// The figure as JSON: the file's own parse, else `joined` from its first `{` when that parses.
    pub json: Option<Json>,
    /// Whether `json` came from `joined`; whitespace inside a string is gone there.
    pub from_joined: bool,
}

/// One numbered example (`3.1`, `4.8`, `5.13`) and its figures in order.
#[derive(Clone, Debug)]
pub struct Example {
    /// The example number.
    pub example: String,
    /// Its figures.
    pub figures: Vec<Figure>,
}

/// A figure file: the examples are its cases.
#[derive(Clone, Debug)]
pub struct Figures {
    /// Figures that belong to no one example, such as the shared plaintext.
    pub shared: Vec<Figure>,
    /// The examples in order of appearance.
    pub examples: Vec<Example>,
}

#[derive(Deserialize)]
struct RawFigure {
    figure: u32,
    caption: String,
    section: String,
    example: String,
    text: String,
    joined: String,
    json: Option<Json>,
}

#[derive(Deserialize)]
struct File {
    figures: Vec<RawFigure>,
}

/// Runs `check` over every example of an RFC 7520 figure file, with the figures shared by all of them; each call
/// reports one [`Outcome`]. Panics unless the file has the SHA-256 and the case count `SOURCES.toml` lists, every
/// figure lands in an example or the shared set, and at least `floor` (nonzero) examples were checked.
pub fn figures(
    vector: Vector,
    floor: usize,
    check: impl FnMut(&Example, &[Figure]) -> Outcome,
) -> Tally {
    figures_against(SOURCES, vector, floor, check)
}

fn figures_against(
    sources: &str,
    vector: Vector,
    floor: usize,
    mut check: impl FnMut(&Example, &[Figure]) -> Outcome,
) -> Tally {
    let path = vector.path;
    let declared = verified(sources, vector);
    let file: File = serde_json::from_str(vector.json).expect("vector file decodes");
    let total = file.figures.len();
    let mut shared = Vec::new();
    let mut examples: Vec<Example> = Vec::new();
    for raw in file.figures {
        let (json, from_joined) = match raw.json {
            Some(json) => (Some(json), false),
            None => {
                let from = raw.joined.find('{').and_then(|i| raw.joined.get(i..));
                let json = from.and_then(Json::from_text);
                let from_joined = json.is_some();
                (json, from_joined)
            }
        };
        let figure = Figure {
            figure: raw.figure,
            caption: raw.caption,
            section: raw.section,
            text: raw.text,
            joined: raw.joined,
            json,
            from_joined,
        };
        if !raw.example.contains('.') {
            shared.push(figure);
        } else if let Some(example) = examples.iter_mut().find(|e| e.example == raw.example) {
            example.figures.push(figure);
        } else {
            examples.push(Example {
                example: raw.example,
                figures: vec![figure],
            });
        }
    }
    assert_eq!(
        examples.len(),
        declared,
        "{path}: examples in file against SOURCES.toml"
    );
    let held: usize = shared.len() + examples.iter().map(|e| e.figures.len()).sum::<usize>();
    assert_eq!(held, total, "{path}: every figure lands in an example");
    let checked = examples
        .iter()
        .filter(|e| check(e, &shared) == Outcome::Checked)
        .count();
    floored(path, examples.len(), checked, floor)
}

#[cfg(test)]
mod tests {
    use super::{Example, Figure, figures_against};
    use crate::vector;
    use crate::vectors::{Outcome, Tally};

    #[derive(Default)]
    struct Seen {
        examples: usize,
        shared: usize,
        figures: usize,
        json: usize,
        joined: Vec<u32>,
    }

    fn read(file: super::Vector, floor: usize) -> (Seen, Tally) {
        let mut seen = Seen::default();
        let t = figures_against(
            super::SOURCES,
            file,
            floor,
            |e: &Example, shared: &[Figure]| {
                seen.examples += 1;
                seen.shared = shared.len();
                for f in &e.figures {
                    seen.figures += 1;
                    seen.json += usize::from(f.json.is_some());
                    if f.from_joined {
                        seen.joined.push(f.figure);
                    }
                }
                Outcome::Checked
            },
        );
        (seen, t)
    }

    #[test]
    fn jwk_has_six_examples_and_the_rsa_private_key_from_joined() {
        let (seen, t) = read(vector!("rfc7520/jwk.json"), 6);
        assert_eq!((seen.examples, seen.shared), (6, 0));
        assert_eq!((seen.figures, seen.json), (6, 6));
        assert_eq!(seen.joined, [4]);
        assert_eq!((t.total(), t.not_applicable()), (6, 0));
        let mut key = None;
        figures_against(super::SOURCES, vector!("rfc7520/jwk.json"), 6, |e, _| {
            if let Some(g) = e.figures.iter().find(|g| g.figure == 4) {
                key = g.json.as_ref().map(|j| j.parse());
            }
            Outcome::Checked
        })
        .total();
        let key: std::collections::BTreeMap<String, String> = key.unwrap_or_default();
        let names: Vec<&str> = key.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "d", "dp", "dq", "e", "kid", "kty", "n", "p", "q", "qi", "use"
            ]
        );
        assert_eq!(key.get("kty").map(String::as_str), Some("RSA"));
    }

    #[test]
    fn jws_has_eight_examples() {
        let (seen, t) = read(vector!("rfc7520/jws.json"), 8);
        assert_eq!((seen.examples, seen.shared), (8, 2));
        assert_eq!((seen.figures + seen.shared, seen.json), (65, 30));
        assert!(seen.joined.is_empty());
        assert_eq!((t.total(), t.not_applicable()), (8, 0));
    }

    #[test]
    fn jwe_has_thirteen_examples() {
        let (seen, t) = read(vector!("rfc7520/jwe.json"), 13);
        assert_eq!((seen.examples, seen.shared), (13, 1));
        assert_eq!(seen.figures + seen.shared, 150);
        assert_eq!(seen.joined, [111, 138, 151, 155, 216]);
        assert_eq!((t.total(), t.not_applicable()), (13, 0));
    }

    #[test]
    #[should_panic(expected = "rfc7520/jwk.json: 0 cases checked, floor 1")]
    fn all_not_applicable_fails() {
        figures_against(super::SOURCES, vector!("rfc7520/jwk.json"), 1, |_, _| {
            Outcome::NotApplicable
        })
        .total();
    }

    #[test]
    #[should_panic(expected = "rfc7520/jwk.json: 6 cases checked, floor 7")]
    fn floor_above_the_file_fails() {
        read(vector!("rfc7520/jwk.json"), 7).1.total();
    }
}
