use std::time::UNIX_EPOCH;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{ContextMethods as _, engine::resource_capture::ResourceId};

use super::{
    config,
    principal::Principal,
    template_renderer::{self, CaptureContext, RenderCapture, RenderCaptures},
    try_from_config::TryFromConfig,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct EventType {
    pub(crate) r#type: String,
    pub(crate) first_seen_at: DateTime<Utc>,
    pub(crate) last_seen_at: DateTime<Utc>,
    #[serde(skip)]
    pub(crate) retain: bool,
}

impl From<String> for EventType {
    fn from(value: String) -> Self {
        Self {
            r#type: value,
            first_seen_at: UNIX_EPOCH.into(),
            last_seen_at: UNIX_EPOCH.into(),
            retain: false,
        }
    }
}

impl From<&str> for EventType {
    fn from(value: &str) -> Self {
        value.to_string().into()
    }
}

impl RenderCaptures for EventType {
    async fn render_captures<C: Serialize>(
        &self,
        render_context: &C,
        _capture_context: Option<&CaptureContext>,
    ) -> anyhow::Result<Vec<Self>> {
        let seen_at = Utc::now();

        let event_types = template_renderer::render_non_empty(&self.r#type, render_context)?;

        let event_types =
            serde_json::from_str::<Vec<String>>(&event_types).unwrap_or_else(|_| vec![event_types]);

        Ok(event_types
            .into_iter()
            .map(|event_type| EventType {
                r#type: event_type,
                first_seen_at: seen_at,
                last_seen_at: seen_at,
                retain: false,
            })
            .collect())
    }
}

impl Ord for EventType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.r#type.cmp(&other.r#type)
    }
}

impl PartialOrd for EventType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Event {
    pub(crate) types: Vec<EventType>,
    pub(crate) resources: Vec<ResourceId>,
}

impl RenderCaptures for Event {
    async fn render_captures<C: Serialize>(
        &self,
        render_context: &C,
        capture_context: Option<&CaptureContext>,
    ) -> anyhow::Result<Vec<Self>> {
        let event_types_futs = self
            .types
            .iter()
            .map(|event_type| event_type.render_captures(render_context, capture_context));

        let event_types = futures::future::try_join_all(event_types_futs)
            .await?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let resources_futs = self.resources.iter().map(async |resource| {
            let resources = resource
                .render_captures(render_context, capture_context)
                .await?;

            if let Some(CaptureContext {
                context,
                container_id,
            }) = capture_context
            {
                anyhow::Ok(
                    context
                        .lock()
                        .await
                        .nest_resources_within_context_dns(resource, container_id, resources)
                        .await,
                )
            } else {
                anyhow::Ok(resources)
            }
        });

        let resources = futures::future::try_join_all(resources_futs)
            .await?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let mut events = Vec::with_capacity(event_types.len() * resources.len());
        for event_type in event_types {
            for resource in &resources {
                events.push(Self {
                    types: vec![event_type.clone()],
                    resources: vec![resource.clone()],
                });
            }
        }

        Ok(events)
    }
}

impl TryFrom<config::Event> for Event {
    type Error = anyhow::Error;

    fn try_from(value: config::Event) -> Result<Self, Self::Error> {
        Ok(Self {
            types: value.types.into_iter().map(EventType::from).collect(),
            resources: value
                .resources
                .into_iter()
                .map(ResourceId::try_from_config)
                .collect::<anyhow::Result<_>>()?,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EventCapture {
    pub(crate) principals: Vec<Principal>,
    pub(crate) events: Vec<Event>,
}

impl TryFrom<config::EventCapture> for EventCapture {
    type Error = anyhow::Error;

    fn try_from(value: config::EventCapture) -> Result<Self, Self::Error> {
        Ok(Self {
            principals: value
                .principals
                .unwrap_or_default()
                .into_iter()
                .map(Principal::try_from_config)
                .collect::<anyhow::Result<_>>()?,
            events: value
                .events
                .into_iter()
                .map(Event::try_from)
                .collect::<anyhow::Result<_>>()?,
        })
    }
}

impl RenderCapture for EventCapture {
    async fn render_capture<C: Serialize>(
        &self,
        render_context: &C,
        capture_context: Option<&CaptureContext>,
    ) -> anyhow::Result<Self> {
        let principals_futs = self
            .principals
            .iter()
            .map(|rule| rule.render_capture(render_context, capture_context));
        let principals = futures::future::try_join_all(principals_futs).await?;

        let events_futs = self
            .events
            .iter()
            .map(|rule| rule.render_captures(render_context, capture_context));
        let events = futures::future::try_join_all(events_futs)
            .await?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(Self { principals, events })
    }
}
