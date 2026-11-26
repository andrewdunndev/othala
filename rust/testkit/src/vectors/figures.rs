//! RFC 7520 figure files (`{"figures":[...]}`): one case per numbered example, the shared preamble figures apart.
use serde::Deserialize;

use super::{Json, SOURCES, Vector, verified};

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

/// The examples of an RFC 7520 figure file. Panics unless the file has the SHA-256 and the case count `SOURCES.toml`
/// lists.
pub fn figures(vector: Vector) -> Figures {
    figures_against(SOURCES, vector)
}

fn figures_against(sources: &str, vector: Vector) -> Figures {
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
    Figures { shared, examples }
}

#[cfg(test)]
mod tests {
    use super::{Figures, figures_against};
    use crate::vector;

    fn read(f: &Figures) -> (usize, usize, usize) {
        let all = f.examples.iter().flat_map(|e| &e.figures).chain(&f.shared);
        let (mut n, mut json, mut joined) = (0, 0, 0);
        for fig in all {
            n += 1;
            json += usize::from(fig.json.is_some());
            joined += usize::from(fig.from_joined);
        }
        (n, json, joined)
    }

    fn numbers(f: &Figures) -> Vec<u32> {
        f.examples
            .iter()
            .flat_map(|e| &e.figures)
            .filter(|g| g.from_joined)
            .map(|g| g.figure)
            .collect()
    }

    #[test]
    fn jwk_has_six_examples_and_the_rsa_private_key_from_joined() {
        let f = figures_against(super::SOURCES, vector!("rfc7520/jwk.json"));
        assert_eq!(f.examples.len(), 6);
        assert!(f.shared.is_empty());
        assert_eq!(read(&f), (6, 6, 1));
        assert_eq!(numbers(&f), [4]);
        let key = f
            .examples
            .iter()
            .flat_map(|e| &e.figures)
            .find(|g| g.figure == 4)
            .and_then(|g| g.json.as_ref());
        let key: std::collections::BTreeMap<String, String> =
            key.map(|j| j.parse()).unwrap_or_default();
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
        let f = figures_against(super::SOURCES, vector!("rfc7520/jws.json"));
        assert_eq!(f.examples.len(), 8);
        assert_eq!(f.shared.len(), 2);
        assert_eq!(read(&f), (65, 30, 0));
    }

    #[test]
    fn jwe_has_thirteen_examples() {
        let f = figures_against(super::SOURCES, vector!("rfc7520/jwe.json"));
        assert_eq!(f.examples.len(), 13);
        assert_eq!(f.shared.len(), 1);
        assert_eq!(read(&f), (150, 55, 5));
        assert_eq!(numbers(&f), [111, 138, 151, 155, 216]);
    }
}
