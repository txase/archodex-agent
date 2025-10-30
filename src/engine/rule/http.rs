use std::{collections::HashMap, str::FromStr};

use anyhow::bail;
use jsonpath_rust::parser::{model::JpQuery, parse_json_path};

use crate::engine::{config, event_capture::EventCapture, resource_capture::ResourceCapture};

#[derive(Clone, Debug)]
pub(crate) struct HeaderRule {
    pub(crate) regex: regex::Regex,
}

impl TryFrom<config::http::Header> for HeaderRule {
    type Error = anyhow::Error;

    fn try_from(value: config::http::Header) -> Result<Self, Self::Error> {
        Ok(Self { regex: value.regex })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BodyRule {
    pub(crate) path: JpQuery,
    pub(crate) value: Option<serde_json::Value>,
}

impl TryFrom<config::http::Body> for BodyRule {
    type Error = anyhow::Error;

    fn try_from(value: config::http::Body) -> Result<Self, Self::Error> {
        Ok(Self {
            path: parse_json_path(&value.path)?,
            value: match value.value.map(serde_json::to_value) {
                Some(Err(err)) => bail!(err),
                Some(Ok(value)) => Some(value),
                None => None,
            },
        })
    }
}

pub(crate) type HeaderRules = HashMap<String, HeaderRule>;
pub(crate) type BodyRules = HashMap<String, BodyRule>;

#[derive(Clone, Debug)]
pub(crate) struct RequestRule {
    pub(crate) methods: Vec<::http::Method>,
    pub(crate) routes: Vec<String>,
    pub(crate) ignore_routes: Vec<String>,
    pub(crate) header_rules: HeaderRules,
    pub(crate) body_rules: BodyRules,
}

impl TryFrom<config::http::Request> for RequestRule {
    type Error = anyhow::Error;

    fn try_from(value: config::http::Request) -> Result<Self, Self::Error> {
        Ok(Self {
            methods: value
                .methods
                .into_iter()
                .map(|method| ::http::Method::from_str(&method))
                .collect::<Result<Vec<::http::Method>, ::http::method::InvalidMethod>>()?,
            routes: value.routes,
            ignore_routes: value.ignore_routes,
            header_rules: value
                .headers
                .into_iter()
                .map(|(key, value)| Ok((key, HeaderRule::try_from(value)?)))
                .collect::<Result<HeaderRules, anyhow::Error>>()?,
            body_rules: value
                .body
                .into_iter()
                .map(|(key, value)| Ok((key, BodyRule::try_from(value)?)))
                .collect::<Result<BodyRules, anyhow::Error>>()?,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseRule {
    pub(crate) header_rules: HeaderRules,
    pub(crate) body_rules: BodyRules,
}

impl TryFrom<config::http::Response> for ResponseRule {
    type Error = anyhow::Error;

    fn try_from(value: config::http::Response) -> Result<Self, Self::Error> {
        Ok(Self {
            header_rules: value
                .headers
                .into_iter()
                .map(|(key, value)| Ok((key, HeaderRule::try_from(value)?)))
                .collect::<Result<HeaderRules, anyhow::Error>>()?,
            body_rules: value
                .body
                .into_iter()
                .map(|(key, value)| Ok((key, BodyRule::try_from(value)?)))
                .collect::<Result<BodyRules, anyhow::Error>>()?,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Rule {
    pub(crate) request: RequestRule,
    pub(crate) response: Option<ResponseRule>,
    pub(crate) resource_capture_rules: Vec<ResourceCapture>,
    pub(crate) event_capture_rules: Vec<EventCapture>,
}
