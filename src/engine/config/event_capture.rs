use serde::Deserialize;

use super::{Principal, ResourceId};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct EventCapture {
    pub(crate) principals: Option<Vec<Principal>>,
    pub(crate) events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct Event {
    pub(crate) types: Vec<String>,
    pub(crate) resources: Vec<ResourceId>,
}
