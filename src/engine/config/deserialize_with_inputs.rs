use std::{
    collections::HashMap,
    sync::{LazyLock, RwLock},
};

use crate::engine::config::InterpolateInputs as _;

static RULESET_PARSING_CURRENT_INPUTS: LazyLock<RwLock<Option<HashMap<String, String>>>> =
    LazyLock::new(|| RwLock::new(None));

pub(crate) fn replace_parsing_inputs(
    inputs: HashMap<String, String>,
) -> Option<HashMap<String, String>> {
    RULESET_PARSING_CURRENT_INPUTS
        .write()
        .unwrap()
        .replace(inputs)
}

pub(crate) fn take_parsing_inputs() -> Option<HashMap<String, String>> {
    RULESET_PARSING_CURRENT_INPUTS.write().unwrap().take()
}

pub(crate) fn vec_string<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringsVisitor;

    impl<'de> serde::de::Visitor<'de> for StringsVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str(
                "a list of strings or a reference to a Ruleset input (e.g. '{Inputs.Hostnames}')",
            )
        }

        fn visit_str<E>(self, value: &str) -> Result<Vec<String>, E>
        where
            E: serde::de::Error,
        {
            let mut value = value.trim().to_string();

            let inputs_guard = RULESET_PARSING_CURRENT_INPUTS.read().unwrap();
            let inputs = inputs_guard.as_ref().ok_or_else(|| {
                E::custom("Unexpected error: Ruleset parsing current input values are unset")
            })?;

            value
                .interpolate_inputs(&inputs.into())
                .map_err(|e| E::custom(format!("Failed to render {value:?}: {e:#}")))?;

            Ok(value
                .split(',')
                .map(str::trim)
                .map(str::to_string)
                .collect())
        }

        fn visit_seq<A>(self, seq: A) -> Result<Vec<String>, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            use serde::de::Error;

            let mut seq: Vec<String> = serde::de::Deserialize::deserialize(
                serde::de::value::SeqAccessDeserializer::new(seq),
            )?;

            let inputs_guard = RULESET_PARSING_CURRENT_INPUTS.read().unwrap();
            let inputs = inputs_guard.as_ref().ok_or_else(|| {
                A::Error::custom("Unexpected error: Ruleset parsing current input values are unset")
            })?;

            for item in &mut seq {
                item.interpolate_inputs(&inputs.into())
                    .map_err(|e| A::Error::custom(format!("Failed to render {item:?}: {e:#}")))?;
            }

            Ok(seq)
        }
    }

    deserializer.deserialize_any(StringsVisitor)
}
