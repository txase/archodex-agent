mod context;
mod deserialize_regex;
mod deserialize_with_inputs;
mod event_capture;
mod resource_capture;
mod rules;

use std::collections::HashMap;

use anyhow::bail;
pub(crate) use context::*;
pub(crate) use deserialize_with_inputs::*;
pub(crate) use event_capture::*;
pub(crate) use resource_capture::*;
pub(crate) use rules::*;
use serde::Serialize;

use crate::Ruleset;

#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) contexts: Vec<Context>,
    pub(crate) rules: Vec<Rule>,
}

impl FromIterator<Ruleset> for Config {
    fn from_iter<T: IntoIterator<Item = Ruleset>>(iter: T) -> Self {
        let mut collection = Self {
            contexts: vec![],
            rules: vec![],
        };

        for ruleset in iter {
            collection.contexts.extend(ruleset.contexts.into_iter());
            collection.rules.extend(ruleset.rules.into_iter());
        }

        collection
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct InputRenderingContext<'a> {
    inputs: &'a HashMap<String, String>,
}

impl<'a> From<&'a HashMap<String, String>> for InputRenderingContext<'a> {
    fn from(inputs: &'a HashMap<String, String>) -> Self {
        Self { inputs }
    }
}

pub(crate) trait InterpolateInputs {
    fn interpolate_inputs(&mut self, inputs: &InputRenderingContext) -> anyhow::Result<()>;
}

impl InterpolateInputs for String {
    fn interpolate_inputs(&mut self, inputs: &InputRenderingContext) -> anyhow::Result<()> {
        let mut new = crate::engine::template_renderer::render_non_empty(self, inputs)?;
        std::mem::swap(self, &mut new);

        Ok(())
    }
}

impl InterpolateInputs for serde_yaml::Value {
    fn interpolate_inputs(&mut self, inputs: &InputRenderingContext) -> anyhow::Result<()> {
        match self {
            serde_yaml::Value::Mapping(map) => {
                for value in map.values_mut() {
                    value.interpolate_inputs(inputs)?;
                }
            }
            serde_yaml::Value::Sequence(seq) => {
                for value in seq {
                    value.interpolate_inputs(inputs)?;
                }
            }
            serde_yaml::Value::String(s) => s.interpolate_inputs(inputs)?,
            _ => bail!("Unsupported value type for Archodex Rule Inputs interpolation: {self:?}"),
        }

        Ok(())
    }
}

impl<I: InterpolateInputs> InterpolateInputs for HashMap<String, I> {
    fn interpolate_inputs(&mut self, inputs: &InputRenderingContext) -> anyhow::Result<()> {
        let map = std::mem::take(self);

        let mut map = map
            .into_iter()
            .map(|(mut key, mut value)| {
                key.interpolate_inputs(inputs)?;
                value.interpolate_inputs(inputs)?;

                Ok((key, value))
            })
            .collect::<anyhow::Result<_>>()?;

        std::mem::swap(self, &mut map);

        Ok(())
    }
}
