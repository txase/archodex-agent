use std::{collections::HashMap, env, error::Error, fmt, sync::Arc};

use anyhow::{Context as _, anyhow};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::engine::config::{Context, ContextConfig, Rule, RuleConfig};

#[derive(Debug)]
pub(crate) enum RulesetParsingError {
    UnsatisfiedInputs(anyhow::Error),
    ParsingError(anyhow::Error),
}

impl fmt::Display for RulesetParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RulesetParsingError::UnsatisfiedInputs(err)
            | RulesetParsingError::ParsingError(err) => write!(f, "{err}"),
        }
    }
}

impl Error for RulesetParsingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RulesetParsingError::UnsatisfiedInputs(err)
            | RulesetParsingError::ParsingError(err) => Some(err.as_ref()),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct RulesetConfig {
    _name: String,
    _description: String,
    #[serde(default)]
    _default: bool,
    #[serde(default)]
    _inputs: HashMap<String, InputConfig>,
    #[serde(default)]
    contexts: Vec<ContextConfig>,
    #[serde(default)]
    rules: Vec<RuleConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RulesetInputsOnlyConfig {
    #[serde(default)]
    inputs: HashMap<String, InputConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct InputConfig {
    _description: String,
    #[serde(default)]
    required: bool,
}

#[derive(Debug)]
pub(crate) struct Ruleset {
    pub(crate) contexts: Vec<Context>,
    pub(crate) rules: Vec<Rule>,
}

impl Ruleset {
    pub(crate) fn try_from_id_config_inputs(
        id: &str,
        config_yaml: &str,
        mut cli_arg_inputs: HashMap<String, String>,
    ) -> Result<Self, RulesetParsingError> {
        let inputs_config: RulesetInputsOnlyConfig = serde_yaml::from_str(config_yaml)
            .map_err(|e| RulesetParsingError::ParsingError(e.into()))?;

        let mut inputs = HashMap::new();

        'next_input: for (input_name, input_config) in inputs_config.inputs {
            if let Some(value) = cli_arg_inputs.remove(&input_name) {
                inputs.insert(input_name, value);
                continue 'next_input;
            }

            let env_vars_to_check = input_env_vars_to_check(id, &input_name);

            for env_var in &env_vars_to_check {
                if let Ok(value) = env::var(env_var) {
                    inputs.insert(input_name, value);
                    continue 'next_input;
                }
            }

            if input_config.required {
                return Err(RulesetParsingError::UnsatisfiedInputs(anyhow!(
                    "No value found for Ruleset Input {input_name:?}"
                )));
            }
        }

        debug!(
            ruleset_id = id,
            inputs = tracing::field::debug(&inputs),
            "Resolved inputs for Ruleset"
        );

        for input_name in cli_arg_inputs.keys() {
            warn!(
                ruleset_id = id,
                input_name, "Unused input for ruleset provided via CLI argument"
            );
        }

        crate::engine::config::replace_parsing_inputs(inputs);

        let config: RulesetConfig = serde_yaml::from_str(config_yaml)
            .map_err(|e| RulesetParsingError::ParsingError(e.into()))?;

        let inputs = crate::engine::config::take_parsing_inputs()
            .context(
                "Unexpected error: Ruleset parsing current input values are unset after parsing",
            )
            .map_err(RulesetParsingError::ParsingError)?;

        let inputs = Arc::new(inputs);

        let contexts = config
            .contexts
            .into_iter()
            .map(|context_config| {
                let context = Context::new(context_config, &inputs);
                debug!(
                    ruleset_id = id,
                    context = tracing::field::debug(&context),
                    "Parsed Ruleset context"
                );
                context
            })
            .collect::<Vec<_>>();

        let rules = config
            .rules
            .into_iter()
            .map(|rule_config| {
                let rule = Rule::try_from_config_inputs(rule_config, &inputs);
                debug!(
                    ruleset_id = id,
                    rule = tracing::field::debug(&rule),
                    "Parsed Ruleset rule"
                );
                rule
            })
            .collect::<Result<_, _>>()
            .map_err(RulesetParsingError::ParsingError)?;

        Ok(Self { contexts, rules })
    }
}

fn input_env_vars_to_check(ruleset_id: &str, input_name: &str) -> Vec<String> {
    let ruleset_id_env_var_case = ruleset_id
        .to_ascii_uppercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>();

    let input_name_env_var_case =
        input_name
            .chars()
            .enumerate()
            .fold(String::new(), |mut acc, (i, c)| {
                if i > 0 && c.is_uppercase() && !acc.ends_with('_') {
                    acc.push('_');
                }
                if c.is_alphanumeric() {
                    acc.push(c.to_ascii_uppercase());
                } else {
                    acc.push('_');
                }
                acc
            });

    vec![
        format!("ARCHODEX_RULESET_INPUT_{ruleset_id_env_var_case}_{input_name_env_var_case}"),
        input_name_env_var_case,
    ]
}
