//! Row m3-factor-rfc6238-window: the factor-derived window, skew and replay cases through `Totp::verify`.
mod common;

use common::{Case, Outcome, attempts, run};
use factor::Rejected;
use testkit::vector;
use testkit::vectors::{Outcome as Seen, run as run_vector};

#[test]
fn window_and_replay() {
    let tally = run_vector(vector!("factor-derived/totp.json"), 1, |c: &Case| {
        let Some((outcome, mut store)) = run(c) else {
            return Seen::NotApplicable;
        };
        let accepted = matches!(outcome, Outcome::Verdict(Ok(_)));
        assert_eq!(accepted, c.expect.ok, "{}", c.id);
        // a text that is no code is refused before any permit, so nothing is counted
        let counted = matches!(outcome, Outcome::Verdict(_));
        assert_eq!(attempts(&mut store).is_some(), counted, "{}", c.id);
        match outcome {
            Outcome::Verdict(Ok(m)) => assert_eq!(Some(m.step()), c.expect.step, "{}", c.id),
            Outcome::Verdict(Err(r)) => {
                // an error kind is compared only where the oracle names one
                let named = c
                    .expect
                    .kind
                    .as_deref()
                    .filter(|k| *k == "Replayed")
                    .map(|_| Rejected::Replayed);
                assert!(named.is_none_or(|n| n == r), "{}", c.id);
            }
            Outcome::Unparsed(_) => {}
        }
        Seen::Checked
    });
    assert_eq!(tally.checked(), tally.total());
}
