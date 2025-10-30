use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct ResourceCapture {
    pub(crate) r#type: String,
    pub(crate) id: String,
    pub(crate) contains: Option<Vec<ResourceCapture>>,
}

pub(crate) type ResourceId = Vec<ResourceIdPart>;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct ResourceIdPart {
    pub(crate) r#type: String,
    pub(crate) id: String,
}
