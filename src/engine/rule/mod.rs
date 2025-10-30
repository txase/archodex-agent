pub(crate) mod http;

use std::{collections::HashMap, sync::Arc};

use super::{
    config::{self},
    event_capture::EventCapture,
    hostname_filter::HostnameFilter,
    resource_capture::ResourceCapture,
};

#[derive(Clone, Debug)]
pub(crate) enum TransportRule {
    Http(http::Rule),
}

impl TryFrom<config::TransportRule> for TransportRule {
    type Error = anyhow::Error;

    fn try_from(value: config::TransportRule) -> Result<Self, Self::Error> {
        match value {
            config::TransportRule::Http(http) => Ok(Self::Http(http::Rule {
                request: http.request.try_into()?,
                response: match http.response {
                    Some(response) => Some(response.try_into()?),
                    None => None,
                },
                resource_capture_rules: http
                    .resource_captures
                    .into_iter()
                    .map(ResourceCapture::try_from)
                    .collect::<anyhow::Result<Vec<_>>>()?,
                event_capture_rules: http
                    .event_captures
                    .into_iter()
                    .map(EventCapture::try_from)
                    .collect::<anyhow::Result<_>>()?,
            })),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Rule {
    pub(crate) hostnames: Vec<HostnameFilter>,
    pub(crate) transport_rules: Vec<TransportRule>,
    pub(crate) inputs: Arc<HashMap<String, String>>,
}

impl TryFrom<config::Rule> for Rule {
    type Error = anyhow::Error;

    fn try_from(value: config::Rule) -> Result<Self, Self::Error> {
        Ok(Self {
            hostnames: value
                .hostnames
                .into_iter()
                .map(HostnameFilter::try_from)
                .collect::<anyhow::Result<Vec<_>>>()?,
            transport_rules: value
                .transport_rules
                .into_iter()
                .map(TransportRule::try_from)
                .collect::<anyhow::Result<Vec<TransportRule>>>()?,
            inputs: value.inputs,
        })
    }
}
