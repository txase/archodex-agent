mod base;
mod kubernetes;

use std::{collections::HashMap, sync::Arc};

use anyhow::{Context as _, bail, ensure};
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::{debug, instrument, trace, warn};

use crate::engine::{
    config::{self},
    event_capture::{Event, EventCapture},
    principal::Principal,
    report::Report,
    resource_capture::{ResourceCapture, ResourceId},
    template_renderer::{
        self, AGENT_CONTEXT, AgentContext, RenderCapture as _, RenderCaptures as _, render,
    },
    try_from_config::TryFromConfig,
};

use base::BaseContext;
use kubernetes::Kubernetes;

pub(crate) type Context = Arc<Mutex<Inner>>;

pub(crate) async fn new() -> Context {
    Arc::new(Mutex::new(Inner::new().await))
}

#[derive(Debug)]
pub(crate) enum Inner {
    Kubernetes(Kubernetes),
    Base(BaseContext),
}

impl Inner {
    pub(crate) async fn new() -> Inner {
        if let Some(kubernetes) = Kubernetes::new().await {
            Inner::Kubernetes(kubernetes)
        } else {
            Inner::Base(BaseContext::new())
        }
    }
}

impl PrivateContextMethods for Inner {
    fn principals_mut(&mut self) -> &mut Vec<Principal> {
        match self {
            Inner::Kubernetes(context) => context.principals_mut(),
            Inner::Base(context) => context.principals_mut(),
        }
    }

    fn report_mut(&mut self) -> &mut Report {
        match self {
            Inner::Kubernetes(context) => context.report_mut(),
            Inner::Base(context) => context.report_mut(),
        }
    }
}

impl ContextMethods for Inner {
    fn principals_without_container(&self) -> &Vec<Principal> {
        match self {
            Inner::Kubernetes(context) => context.principals_without_container(),
            Inner::Base(context) => context.principals_without_container(),
        }
    }

    async fn principals(&self, container_id: Option<&String>) -> Vec<Principal> {
        match self {
            Inner::Kubernetes(context) => context.principals(container_id).await,
            Inner::Base(context) => context.principals(container_id).await,
        }
    }

    async fn nest_resource_captures_within_context_dns(
        &self,
        rule: &ResourceCapture,
        container_id: &str,
        resource_captures: Vec<ResourceCapture>,
    ) -> Vec<ResourceCapture> {
        match self {
            Inner::Kubernetes(context) => {
                context
                    .nest_resource_captures_within_context_dns(
                        rule,
                        container_id,
                        resource_captures,
                    )
                    .await
            }
            Inner::Base(context) => {
                context
                    .nest_resource_captures_within_context_dns(
                        rule,
                        container_id,
                        resource_captures,
                    )
                    .await
            }
        }
    }

    async fn nest_resources_within_context_dns(
        &self,
        rule: &ResourceId,
        container_id: &str,
        resources: Vec<ResourceId>,
    ) -> Vec<ResourceId> {
        match self {
            Inner::Kubernetes(context) => {
                context
                    .nest_resources_within_context_dns(rule, container_id, resources)
                    .await
            }
            Inner::Base(context) => {
                context
                    .nest_resources_within_context_dns(rule, container_id, resources)
                    .await
            }
        }
    }

    async fn add_context(&mut self, value: config::Context) -> anyhow::Result<()> {
        match self {
            Inner::Kubernetes(context) => context.add_context(value).await,
            Inner::Base(context) => context.add_context(value).await,
        }
    }

    fn merge_report(&mut self, other: Report) {
        match self {
            Inner::Kubernetes(context) => context.merge_report(other),
            Inner::Base(context) => context.merge_report(other),
        }
    }

    async fn get_report(&mut self) -> Report {
        match self {
            Inner::Kubernetes(context) => context.get_report().await,
            Inner::Base(context) => context.get_report().await,
        }
    }
}

pub(super) trait PrivateContextMethods {
    fn principals_mut(&mut self) -> &mut Vec<Principal>;
    fn report_mut(&mut self) -> &mut Report;
}

#[allow(private_bounds)]
pub(crate) trait ContextMethods: std::fmt::Debug + PrivateContextMethods + Send {
    fn principals_without_container(&self) -> &Vec<Principal>;
    async fn principals(&self, container_id: Option<&String>) -> Vec<Principal>;

    async fn nest_resources_within_context_dns(
        &self,
        _rule: &ResourceId,
        _container_id: &str,
        resources: Vec<ResourceId>,
    ) -> Vec<ResourceId> {
        resources
    }

    async fn nest_resource_captures_within_context_dns(
        &self,
        _rule: &ResourceCapture,
        _container_id: &str,
        resource_captures: Vec<ResourceCapture>,
    ) -> Vec<ResourceCapture> {
        resource_captures
    }

    #[allow(clippy::too_many_lines)]
    #[instrument(level = "debug", err)]
    async fn add_context(&mut self, value: config::Context) -> anyhow::Result<()> {
        #[derive(Debug, Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct RenderContext<'a> {
            inputs: &'a HashMap<String, String>,
            agent: &'static AgentContext,
        }

        let render_context = RenderContext {
            inputs: value.inputs.as_ref(),
            agent: &AGENT_CONTEXT,
        };

        for (condition, value) in value.conditions {
            let rendered_condition = match render(&condition, &render_context) {
                Ok(rendered_condition) => rendered_condition,
                Err(err) => {
                    warn!(
                        ?condition,
                        ?err,
                        "Context failed due to failure to render condition"
                    );

                    return Ok(());
                }
            };

            let condition = serde_yaml::from_str::<serde_yaml::Value>(&rendered_condition)
                .context(format!("Failed to parse context condition as yaml ({condition:?} -> {rendered_condition:?}"))?;

            if condition == value {
                trace!(
                    ?condition,
                    ?value,
                    "Context condition passed: {condition:?} -> {rendered_condition:?} -> {condition:?} == {value:?}"
                );
            } else {
                debug!(
                    ?condition,
                    ?value,
                    "Context failed {condition:?} -> {rendered_condition:?} -> {condition:?} != {value:?}"
                );
                return Ok(());
            }
        }

        for resource in value.resource_captures {
            let rule = ResourceCapture::try_from(resource)
                .context("Failed to parse context resource capture rule")?;

            let resources = rule
                .render_captures(&render_context, None)
                .await
                .context("Failed to render context resource capture rule")?;

            self.report_mut().add_resource_captures(resources);
        }

        if self.principals_without_container().is_empty() {
            if let Some(config_principals) = &value.principals {
                for principal in config_principals {
                    let resource_id_rule = ResourceId::try_from_config(principal.resource.clone())?;

                    let mut resource_ids = resource_id_rule
                        .render_captures(&render_context, None)
                        .await
                        .context("Failed to render context principal rule")?;
                    ensure!(
                        resource_ids.len() == 1,
                        "Context principal ID evaluated to multiple values (ID template: {:?})",
                        resource_id_rule,
                    );
                    let Some(resource_id) = resource_ids.pop() else {
                        bail!(
                            "Principal ID evaluated to empty value (ID template: {:?})",
                            resource_id_rule
                        )
                    };

                    let event_type = match &principal.event {
                        Some(event) => {
                            let event_type =
                                template_renderer::render_non_empty(event, &render_context)
                                    .context("Failed to render context principal event")?;

                            ensure!(
                                serde_json::from_str::<Vec<String>>(&event_type).is_err(),
                                "Context principal Event type evaluated to multiple values (Type tempate: {event:?})"
                            );

                            Some(event_type)
                        }
                        None => None,
                    };

                    self.principals_mut().push(Principal {
                        id: resource_id,
                        event: event_type,
                    });
                }

                debug!(
                    principals_without_container = ?self.principals_without_container(),
                    "New context principals"
                );

                // If there are multiple principals, create an event to represent each principal in the chain causing the next principal in the chain
                let principals_len = self.principals_without_container().len();
                for i in 0..(principals_len - 1) {
                    let (principals, resources) =
                        self.principals_without_container().split_at(i + 1);
                    let resource = &resources.first().unwrap();

                    let event_type = resource.event.clone().context("Context principal is missing an event type. All but the first context principal must specify an event.")?;

                    let event = EventCapture {
                        principals: principals.to_vec(),
                        events: vec![Event {
                            types: vec![event_type.into()],
                            resources: vec![resource.id.clone()],
                        }],
                    }
                    .render_capture(&render_context, None)
                    .await
                    .context("Failed to render context principal chain event")?;

                    self.report_mut().add_event_capture(event);
                }
            }
        } else if value.principals.is_some() {
            warn!("Multiple principals found across contexts, only first will be used");
        }

        for event in value.event_captures.unwrap_or_default() {
            let rule = EventCapture::try_from(event)
                .context("Failed to parse context event capture rule event")?;

            let event = rule
                .render_capture(&render_context, None)
                .await
                .context("Failed to render context event capture rule")?;

            self.report_mut().add_event_capture(event);
        }

        Ok(())
    }

    fn merge_report(&mut self, other: Report) {
        self.report_mut().merge(other);
    }

    async fn get_report(&mut self) -> Report {
        std::mem::take(self.report_mut())
    }
}
