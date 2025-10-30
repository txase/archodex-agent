use std::{collections::HashMap, sync::Arc};

use serde::Deserialize;

use super::{EventCapture, ResourceCapture, ResourceId};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct ContextConfig {
    conditions: HashMap<String, serde_yaml::Value>,
    resource_captures: Vec<ResourceCapture>,
    principals: Option<Vec<Principal>>,
    event_captures: Option<Vec<EventCapture>>,
}

#[derive(Debug)]
pub(crate) struct Context {
    pub(crate) conditions: HashMap<String, serde_yaml::Value>,
    pub(crate) resource_captures: Vec<ResourceCapture>,
    pub(crate) principals: Option<Vec<Principal>>,
    pub(crate) event_captures: Option<Vec<EventCapture>>,
    pub(crate) inputs: Arc<HashMap<String, String>>,
}

impl Context {
    pub(crate) fn new(config: ContextConfig, inputs: &Arc<HashMap<String, String>>) -> Self {
        Self {
            conditions: config.conditions,
            resource_captures: config.resource_captures,
            principals: config.principals,
            event_captures: config.event_captures,
            inputs: inputs.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct Principal {
    pub(crate) resource: ResourceId,
    pub(crate) event: Option<String>,
}
