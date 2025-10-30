use anyhow::{Context as _, bail, ensure};
use colored::{ColoredString, Colorize};
use serde::Serialize;

use super::{
    config,
    report::EventLogFormat,
    resource_capture::ResourceId,
    template_renderer::{self, CaptureContext, RenderCapture, RenderCaptures},
    try_from_config::TryFromConfig,
};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct Principal {
    pub(crate) id: ResourceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) event: Option<String>,
}

impl EventLogFormat for Principal {
    fn event_log_format(&self) -> String {
        let event_format = if let Some(event) = &self.event {
            format!(" -({event})-> ").yellow()
        } else {
            ColoredString::default()
        };

        format!("{event_format}{id}", id = self.id.event_log_format())
    }
}

impl TryFromConfig<config::Principal> for Principal {
    fn try_from_config(value: config::Principal) -> anyhow::Result<Self> {
        if let Some(event) = &value.event {
            template_renderer::add_template(event)
                .context("Failed to create render template for `Event` field for principal")?;
        }

        Ok(Self {
            id: ResourceId::try_from_config(value.resource)?,
            event: value.event,
        })
    }
}

impl RenderCapture for Principal {
    async fn render_capture<C: Serialize>(
        &self,
        render_context: &C,
        capture_context: Option<&CaptureContext>,
    ) -> anyhow::Result<Self> {
        let mut ids = self
            .id
            .render_captures(render_context, capture_context)
            .await?;
        ensure!(
            ids.len() <= 1,
            "Principal ID evaluated to multiple values (IDs: {ids:?}, ID template: {:?})",
            self.id,
        );
        let Some(id) = ids.pop() else {
            bail!(
                "Principal ID evaluated to empty value (ID template: {:?})",
                self.id
            )
        };

        let event = match &self.event {
            Some(event) => {
                let event_type = template_renderer::render_non_empty(event, render_context)
                    .context("Failed to render Principal Event type")?;

                ensure!(
                    serde_json::from_str::<Vec<String>>(&event_type).is_err(),
                    "Principal Event type evaluated to multiple values (Type tempate: {event:?})"
                );

                Some(event_type)
            }
            None => None,
        };

        Ok(Principal { id, event })
    }
}

impl Ord for Principal {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.id.cmp(&other.id) {
            std::cmp::Ordering::Equal => match (&self.event, &other.event) {
                (Some(a), Some(b)) => a.cmp(b),
                (Some(_), None) => std::cmp::Ordering::Greater,
                (None, Some(_)) => std::cmp::Ordering::Less,
                (None, None) => std::cmp::Ordering::Equal,
            },
            ordering => ordering,
        }
    }
}

impl PartialOrd for Principal {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
