//! An RFC section file read whole, through testkit's checked reader.
use testkit::vectors::{Appendix, Outcome, Vector, sections};

pub(crate) fn all(vector: Vector) -> Vec<Appendix> {
    let mut file = Vec::new();
    let tally = sections(vector, 1, |appendix| {
        file.push(appendix.clone());
        Outcome::Checked
    });
    assert_eq!(tally.checked(), tally.total());
    file
}
