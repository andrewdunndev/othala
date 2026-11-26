//! A JSON fragment kept as text, so no reader exposes a dynamic value.
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;

/// A JSON value from a vector file, decoded by the consumer into the type it needs.
#[derive(Clone, Debug, Deserialize)]
pub struct Json(Box<RawValue>);

impl Json {
    /// The JSON text.
    pub fn text(&self) -> &str {
        self.0.get()
    }

    /// The value as `T`; panics when it is not one.
    pub fn parse<T: DeserializeOwned>(&self) -> T {
        serde_json::from_str(self.text()).expect("vector JSON decodes as the requested type")
    }

    pub(super) fn from_text(text: &str) -> Option<Self> {
        serde_json::from_str(text).ok().map(Self)
    }
}
