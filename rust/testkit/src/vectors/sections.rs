//! RFC section files (`{"sections":[...]}`): one case per top-level appendix, its subsections beneath it.
use serde::Deserialize;

use super::{Json, SOURCES, Vector, verified};

/// One paragraph or figure of an RFC section.
#[derive(Clone, Debug, Deserialize)]
pub struct Block {
    /// The text as the RFC sets it.
    pub text: String,
    /// The text with whitespace removed.
    pub joined: String,
    /// The text parsed, where it is JSON.
    pub json: Option<Json>,
}

/// An RFC section.
#[derive(Clone, Debug, Deserialize)]
pub struct Section {
    /// The number, such as `A.4.1`.
    pub section: String,
    /// The heading.
    pub title: String,
    /// The section's blocks in order.
    pub blocks: Vec<Block>,
}

/// A top-level appendix with the subsections under it; this is one case of the file.
#[derive(Clone, Debug)]
pub struct Appendix {
    /// The appendix itself, such as `A.4`.
    pub section: Section,
    /// Its subsections in order, such as `A.4.1`.
    pub subsections: Vec<Section>,
}

#[derive(Deserialize)]
struct File {
    sections: Vec<Section>,
}

/// The appendices of an RFC section file. Panics unless the file has the SHA-256 and the case count `SOURCES.toml`
/// lists, and every section is an appendix or sits under one.
pub fn sections(vector: Vector) -> Vec<Appendix> {
    sections_against(SOURCES, vector)
}

fn sections_against(sources: &str, vector: Vector) -> Vec<Appendix> {
    let path = vector.path;
    let declared = verified(sources, vector);
    let file: File = serde_json::from_str(vector.json).expect("vector file decodes");
    let total = file.sections.len();
    let mut appendices: Vec<Appendix> = Vec::new();
    for section in file.sections {
        if section.section.matches('.').count() == 1 {
            appendices.push(Appendix {
                section,
                subsections: Vec::new(),
            });
        } else {
            let parent = appendices.last_mut().filter(|a| {
                section
                    .section
                    .strip_prefix(&a.section.section)
                    .is_some_and(|rest| rest.starts_with('.'))
            });
            let Some(parent) = parent else {
                panic!(
                    "{path}: section {} has no appendix before it",
                    section.section
                );
            };
            parent.subsections.push(section);
        }
    }
    assert_eq!(
        appendices.len(),
        declared,
        "{path}: appendices in file against SOURCES.toml"
    );
    let held: usize = appendices.iter().map(|a| 1 + a.subsections.len()).sum();
    assert_eq!(held, total, "{path}: every section lands in an appendix");
    appendices
}

#[cfg(test)]
mod tests {
    use super::sections_against;
    use crate::vector;
    use crate::vectors::Vector;

    const SOURCES: &str = r#"
[source."s"]
files = [
  { path = "s/ok.json", sha256 = "OK", cases = 1 },
  { path = "s/orphan.json", sha256 = "ORPHAN", cases = 1 },
]
"#;
    const OK: &str = r#"{"sections":[
      {"section":"A.1","title":"t","blocks":[]},
      {"section":"A.1.1","title":"u","blocks":[{"text":"{ }","joined":"{}","json":{}}]}]}"#;
    const ORPHAN: &str = r#"{"sections":[
      {"section":"A.1","title":"t","blocks":[]},
      {"section":"A.2.1","title":"u","blocks":[]}]}"#;

    fn sources() -> String {
        use sha2::{Digest as _, Sha256};
        let hex = |j: &str| -> String {
            Sha256::digest(j)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        SOURCES
            .replace("OK", &hex(OK))
            .replace("ORPHAN", &hex(ORPHAN))
    }

    #[test]
    fn subsections_nest_under_their_appendix() {
        let a = sections_against(&sources(), Vector::new("s/ok.json", OK));
        assert_eq!(a.len(), 1);
        let first = a
            .first()
            .map(|a| (a.section.section.as_str(), a.subsections.len()));
        assert_eq!(first, Some(("A.1", 1)));
    }

    #[test]
    #[should_panic(expected = "section A.2.1 has no appendix before it")]
    fn orphan_subsection_fails() {
        sections_against(&sources(), Vector::new("s/orphan.json", ORPHAN));
    }

    #[test]
    #[should_panic(expected = "SHA-256 of the file against SOURCES.toml")]
    fn altered_file_fails() {
        sections_against(&sources(), Vector::new("s/ok.json", ORPHAN));
    }

    // every section file in rust/vectors, with its appendices and the blocks in them
    #[test]
    fn rfc7515_appendix_a4_a7() {
        let a = sections_against(super::SOURCES, vector!("rfc7515/appendix-a4-a7.json"));
        let shape: Vec<_> = a
            .iter()
            .map(|a| (a.section.section.as_str(), a.subsections.len()))
            .collect();
        assert_eq!(shape, [("A.4", 2), ("A.5", 0), ("A.6", 4), ("A.7", 0)]);
        let blocks: usize = a
            .iter()
            .map(|a| {
                a.section.blocks.len() + a.subsections.iter().map(|s| s.blocks.len()).sum::<usize>()
            })
            .sum();
        assert_eq!(blocks, 55);
    }

    #[test]
    fn rfc8037_appendix_a() {
        let a = sections_against(super::SOURCES, vector!("rfc8037/appendix-a.json"));
        let shape: Vec<_> = a.iter().map(|a| a.section.section.as_str()).collect();
        assert_eq!(shape, ["A.1", "A.2", "A.3", "A.4", "A.5", "A.6", "A.7"]);
        assert!(a.iter().all(|a| a.subsections.is_empty()));
        let blocks: usize = a.iter().map(|a| a.section.blocks.len()).sum();
        assert_eq!(blocks, 72);
        let json = a
            .iter()
            .flat_map(|a| &a.section.blocks)
            .filter(|b| b.json.is_some())
            .count();
        assert_eq!(json, 11);
    }
}
