//! An RFC 7520 figure file read whole, through testkit's checked reader.
use testkit::vectors::{Figures, Outcome, Vector, figures};

pub(crate) fn all(vector: Vector) -> Figures {
    let mut file = Figures {
        shared: Vec::new(),
        examples: Vec::new(),
    };
    let tally = figures(vector, 1, |example, shared| {
        file.shared = shared.to_vec();
        file.examples.push(example.clone());
        Outcome::Checked
    });
    assert_eq!(tally.checked(), tally.total());
    file
}
