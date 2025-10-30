use std::{collections::HashMap, sync::Arc};

use serde::Deserialize;

use crate::engine::config::deserialize_with_inputs;

use super::InterpolateInputs;

pub(crate) type Rules = Vec<Rule>;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct RuleConfig {
    #[serde(deserialize_with = "deserialize_with_inputs::vec_string")]
    hostnames: Vec<String>,
    transport_rules: Vec<TransportRuleWrapper>,
}

#[derive(Debug)]
pub(crate) struct Rule {
    pub(crate) hostnames: Vec<String>,
    pub(crate) transport_rules: Vec<TransportRule>,
    pub(crate) inputs: Arc<HashMap<String, String>>,
}

impl Rule {
    pub(crate) fn try_from_config_inputs(
        mut rule_config: RuleConfig,
        inputs: &Arc<HashMap<String, String>>,
    ) -> anyhow::Result<Self> {
        let input_rendering_context = inputs.as_ref().into();

        for hostname in &mut rule_config.hostnames {
            hostname.interpolate_inputs(&input_rendering_context)?;
        }

        Ok(Self {
            hostnames: rule_config.hostnames,
            transport_rules: rule_config
                .transport_rules
                .into_iter()
                .map(|wrapper| wrapper.0)
                .collect(),
            inputs: inputs.clone(),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct TransportRuleWrapper(
    #[serde(with = "serde_yaml::with::singleton_map")] pub TransportRule,
);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) enum TransportRule {
    Http(http::HttpTransportRule),
}

pub(crate) mod http {
    use std::collections::HashMap;

    use anyhow::Context as _;
    use regex::Regex;
    use serde::Deserialize;

    use crate::engine::config::{
        EventCapture, InputRenderingContext, InterpolateInputs, ResourceCapture,
        deserialize_with_inputs,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase", deny_unknown_fields)]
    pub(crate) struct HttpTransportRule {
        pub(crate) request: Request,
        pub(crate) response: Option<Response>,
        pub(crate) resource_captures: Vec<ResourceCapture>,
        pub(crate) event_captures: Vec<EventCapture>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase", deny_unknown_fields)]
    pub(crate) struct Request {
        #[serde(default, deserialize_with = "deserialize_with_inputs::vec_string")]
        pub(crate) methods: Vec<String>,
        #[serde(default, deserialize_with = "deserialize_with_inputs::vec_string")]
        pub(crate) routes: Vec<String>,
        #[serde(default, deserialize_with = "deserialize_with_inputs::vec_string")]
        pub(crate) ignore_routes: Vec<String>,
        #[serde(default)]
        pub(crate) headers: HashMap<String, Header>,
        #[serde(default)]
        pub(crate) body: HashMap<String, Body>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase", deny_unknown_fields)]
    pub(crate) struct Response {
        #[serde(default)]
        pub(crate) headers: HashMap<String, Header>,
        #[serde(default)]
        pub(crate) body: HashMap<String, Body>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase", deny_unknown_fields)]
    pub(crate) struct Header {
        #[serde(deserialize_with = "crate::engine::config::deserialize_regex::deserialize_regex")]
        pub(crate) regex: Regex,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase", deny_unknown_fields)]
    pub(crate) struct Body {
        pub(crate) path: String,
        pub(crate) value: Option<serde_yaml::Value>,
    }

    impl InterpolateInputs for Body {
        fn interpolate_inputs(&mut self, inputs: &InputRenderingContext) -> anyhow::Result<()> {
            self.path
                .interpolate_inputs(inputs)
                .with_context(|| "Failed to render Body Path")?;

            if let Some(value) = self.value.as_mut() {
                value
                    .interpolate_inputs(inputs)
                    .with_context(|| "Failed to render Body Value")?;
            }

            Ok(())
        }
    }
}
