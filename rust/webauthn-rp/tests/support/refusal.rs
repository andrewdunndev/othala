//! The refusal an oracle case expects: a kind always, and the step of L3 7.1 or 7.2 when the case's spec text cites one.
use core::fmt::Debug;

use serde::Deserialize;
use webauthn_rp::SpecStep;

/// The `kind` and `step` members of an `expect` that has `ok: false`.
#[derive(Deserialize)]
pub(crate) struct Refusal {
    kind: Option<String>,
    step: Option<u8>,
}

impl Refusal {
    /// `kind` and `step` are what the crate reported. The case fails unless they are exactly what the oracle states, and it fails if the oracle states no kind. `numbered` is the ceremony whose step numbers `step` counts in, or `None` for a refusal that is no step of either.
    pub(crate) fn check(
        &self,
        id: &str,
        numbered: Option<fn(u8) -> SpecStep>,
        kind: impl Debug,
        step: Option<impl Debug>,
    ) {
        self.check_seen(id, numbered, &format!("{kind:?}"), &format!("{step:?}"));
    }

    /// `check` for a refusal already rendered as the `Debug` text of its kind and of its step.
    pub(crate) fn check_seen(
        &self,
        id: &str,
        numbered: Option<fn(u8) -> SpecStep>,
        kind: &str,
        step: &str,
    ) {
        assert!(
            self.kind.is_some(),
            "{id}: a refusal states the kind it expects"
        );
        assert_eq!(Some(kind), self.kind.as_deref(), "{id}: kind");
        let want = match (numbered, self.step) {
            (_, None) => "None".to_owned(),
            (Some(number), Some(n)) => format!("Some({:?})", number(n)),
            (None, Some(n)) => format!("step {n} of neither ceremony"),
        };
        assert_eq!(step, want, "{id}: step");
    }
}
