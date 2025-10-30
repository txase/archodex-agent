use std::{collections::HashMap, time::UNIX_EPOCH};

use anyhow::{Context as _, anyhow};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Serialize, ser::SerializeSeq};

use crate::{
    ContextMethods as _,
    engine::{
        config,
        template_renderer::{self, RenderCaptures},
    },
};

use super::{
    report::EventLogFormat, template_renderer::CaptureContext, try_from_config::TryFromConfig,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ResourceCapture {
    #[serde(flatten)]
    pub(crate) id: ResourceIdPart,
    pub(crate) first_seen_at: DateTime<Utc>,
    pub(crate) last_seen_at: DateTime<Utc>,
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "ResourceCapture::serialize_contains"
    )]
    pub(crate) contains: HashMap<ResourceIdPart, ResourceCapture>,
    #[serde(skip)]
    pub(crate) deletion_marker: bool,
}

impl ResourceCapture {
    pub(crate) fn new(id: ResourceIdPart) -> Self {
        let seen_at = Utc::now();

        Self {
            id,
            first_seen_at: seen_at,
            last_seen_at: seen_at,
            contains: HashMap::new(),
            deletion_marker: false,
        }
    }
}

impl TryFrom<config::ResourceCapture> for ResourceCapture {
    type Error = anyhow::Error;

    fn try_from(value: config::ResourceCapture) -> Result<Self, Self::Error> {
        template_renderer::add_template(&value.r#type).context(
            "Failed to create render template for `Type` field for resource capture rule",
        )?;

        template_renderer::add_template(&value.id)
            .context("Failed to create render template for `Id` field for resource capture rule")?;

        let contains = match value.contains {
            Some(contains) => contains
                .into_iter()
                .map(|contains| {
                    let contains = Self::try_from(contains)?;
                    Ok((contains.id.clone(), contains))
                })
                .collect::<anyhow::Result<HashMap<_, _>>>()?,
            None => HashMap::new(),
        };

        Ok(Self {
            id: ResourceIdPart {
                r#type: value.r#type,
                id: value.id,
            },
            first_seen_at: UNIX_EPOCH.into(),
            last_seen_at: UNIX_EPOCH.into(),
            contains,
            deletion_marker: false,
        })
    }
}

impl TryFrom<ResourceId> for ResourceCapture {
    type Error = anyhow::Error;

    fn try_from(mut value: ResourceId) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(anyhow!("Resource ID is empty"));
        }

        let mut capture = ResourceCapture::new(value.remove(0));
        let mut cur_capture = &mut capture;

        for part in value {
            let child = ResourceCapture::new(part.clone());
            cur_capture.merge_child_resource(child);
            cur_capture = cur_capture.contains.get_mut(&part).unwrap();
        }

        Ok(capture)
    }
}

impl ResourceCapture {
    pub(crate) fn merge_child_resource(&mut self, child: Self) -> &mut Self {
        use std::collections::hash_map::Entry::{Occupied, Vacant};

        match self.contains.entry(child.id.clone()) {
            Occupied(mut existing) => {
                existing.get_mut().merge(child);
                existing.into_mut()
            }
            Vacant(entry) => entry.insert(child),
        }
    }

    pub(crate) fn merge(&mut self, other: ResourceCapture) {
        assert_eq!(
            self.id, other.id,
            "Attempting to merge ResourceCaptures with differing Resource ID parts ({:?} vs {:?})",
            self.id, other.id
        );

        self.last_seen_at = std::cmp::max(self.last_seen_at, other.last_seen_at);

        for (other_child_id, other_child) in other.contains {
            match self.contains.get_mut(&other_child_id) {
                Some(child) => child.merge(other_child),
                None => {
                    self.contains.insert(other_child_id, other_child);
                }
            }
        }
    }

    pub(crate) fn get_child_by_id_mut(
        &mut self,
        id: &[ResourceIdPart],
    ) -> Option<&mut ResourceCapture> {
        if id.is_empty() {
            return Some(self);
        }

        let (first, rest) = id.split_at(1);
        let first = first.first()?;

        self.contains.get_mut(first)?.get_child_by_id_mut(rest)
    }

    pub(crate) fn update_last_seen_ats(&mut self, last_seen_at: DateTime<Utc>) {
        if !self.deletion_marker {
            for resource in self.contains.values_mut() {
                resource.update_last_seen_ats(last_seen_at);
            }

            self.last_seen_at = last_seen_at;
        }
    }

    pub(crate) fn clear_deleted_resources(&mut self) {
        self.contains.retain(|_, resource| {
            if resource.deletion_marker {
                false
            } else {
                resource.clear_deleted_resources();
                true
            }
        });
    }

    fn serialize_contains<S>(
        contains: &HashMap<ResourceIdPart, ResourceCapture>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(contains.len()))?;
        for resource_capture in contains.values() {
            seq.serialize_element(resource_capture)?;
        }
        seq.end()
    }

    pub(crate) fn log(&self, indents: &mut Vec<bool>, is_last: bool) {
        let lead = indents.iter().fold(String::new(), |mut acc, is_last| {
            if *is_last {
                acc += "   ";
            } else {
                acc += "│  ";
            }

            acc
        });

        let marker = if is_last { "└─" } else { "├─" };

        println!("{lead}{marker} {label} {type}", label = "Type:".bold(), type = self.id.r#type.blue());

        let lead = lead + if is_last { "  " } else { "│ " };

        println!(
            "{lead} {label} {id}",
            label = "ID:".bold(),
            id = self.id.id.cyan()
        );
        println!(
            "{lead} {label} {first_seen_at}",
            label = "First seen at:".dimmed().bold(),
            first_seen_at = self
                .first_seen_at
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
                .dimmed()
        );
        println!(
            "{lead} {label} {last_seen_at}",
            label = "Last seen at:".dimmed().bold(),
            last_seen_at = self
                .last_seen_at
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
                .dimmed()
        );

        if self.contains.is_empty() {
            println!("{lead}");
            return;
        }

        println!("{lead} │");

        indents.push(is_last);

        let mut sorted_contains = self.contains.values().collect::<Vec<_>>();
        sorted_contains.sort();
        let mut sorted_contains_iterator = sorted_contains.iter().peekable();

        while let Some(capture) = sorted_contains_iterator.next() {
            let is_last_resource = sorted_contains_iterator.peek().is_none();
            capture.log(indents, is_last_resource);
        }

        indents.pop();
    }
}

impl RenderCaptures for ResourceCapture {
    async fn render_captures<C: Serialize>(
        &self,
        render_context: &C,
        capture_context: Option<&CaptureContext>,
    ) -> anyhow::Result<Vec<Self>> {
        let contains_futs = self.contains.values().map(async |child| {
            let children = child.render_captures(render_context, None).await?;
            anyhow::Ok(
                children
                    .into_iter()
                    .map(|child| (child.id.clone(), child))
                    .collect::<Vec<_>>(),
            )
        });

        let contains = futures::future::try_join_all(contains_futs)
            .await?
            .into_iter()
            .flatten()
            .collect::<HashMap<_, _>>();

        let seen_at = Utc::now();

        let parts = self
            .id
            .render_captures(render_context, capture_context)
            .await?;

        let mut captures = Vec::with_capacity(parts.len());

        for part in parts {
            captures.push(ResourceCapture {
                id: part,
                first_seen_at: seen_at,
                last_seen_at: seen_at,
                contains: contains.clone(),
                deletion_marker: false,
            });
        }

        if let Some(CaptureContext {
            context,
            container_id,
        }) = capture_context
        {
            Ok(context
                .lock()
                .await
                .nest_resource_captures_within_context_dns(self, container_id, captures)
                .await)
        } else {
            Ok(captures)
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct ResourceIdPart {
    pub(crate) r#type: String,
    pub(crate) id: String,
}

impl From<config::ResourceIdPart> for ResourceIdPart {
    fn from(value: config::ResourceIdPart) -> Self {
        Self {
            r#type: value.r#type,
            id: value.id,
        }
    }
}

pub(crate) type ResourceId = Vec<ResourceIdPart>;

impl EventLogFormat for ResourceId {
    fn event_log_format(&self) -> String {
        self.iter()
            .map(|part| format!("{left_bracket}{type}::{id}{right_bracket}", left_bracket = "[".dimmed(), type =  part.r#type.blue(), id = part.id.cyan(), right_bracket = "]".dimmed()))
            .collect::<Vec<_>>()
            .join(&"::".dimmed())
    }
}

impl TryFromConfig<config::ResourceId> for ResourceId {
    fn try_from_config(value: config::ResourceId) -> anyhow::Result<Self> {
        value.into_iter().map(|resource_id_part| {
            template_renderer::add_template(&resource_id_part.r#type).context(
                "Failed to create render template for `Type` field for principal ID part of event capture rule",
            )?;
            template_renderer::add_template(&resource_id_part.r#id).context(
                "Failed to create render template for `Id` field for principal ID part of event capture rule",
            )?;

            Ok(ResourceIdPart::from(resource_id_part))
        }).collect()
    }
}

impl RenderCaptures for ResourceIdPart {
    async fn render_captures<C: Serialize>(
        &self,
        render_context: &C,
        _capture_context: Option<&CaptureContext>,
    ) -> anyhow::Result<Vec<Self>> {
        let types = template_renderer::render_non_empty(&self.r#type, render_context)
            .context("Failed to render ResourceEvent resource type")?;

        let types = match serde_json::from_str::<Vec<String>>(&types) {
            Ok(types) => types,
            Err(_) => vec![types],
        };

        let ids = template_renderer::render_non_empty(&self.id, render_context)
            .context("Failed to render ResourceEvent resource ID")?;

        let ids = match serde_json::from_str::<Vec<String>>(&ids) {
            Ok(ids) => ids,
            Err(_) => vec![ids],
        };

        let mut captures = Vec::with_capacity(types.len() * ids.len());

        for r#type in types {
            for id in &ids {
                captures.push(ResourceIdPart {
                    r#type: r#type.clone(),
                    id: id.clone(),
                });
            }
        }

        Ok(captures)
    }
}

async fn render_captures_for_resource_id_slice(
    resource_id: &[ResourceIdPart],
    render_context: &impl Serialize,
    capture_context: Option<&CaptureContext>,
) -> anyhow::Result<Vec<ResourceId>> {
    let [part, children @ ..] = resource_id else {
        panic!("Invalid recursion depth when rendering resource ID captures");
    };

    let part_captures = part
        .render_captures(render_context, capture_context)
        .await?;

    if children.is_empty() {
        Ok(part_captures
            .into_iter()
            .map(|part_capture| vec![part_capture])
            .collect())
    } else {
        let children_captures = Box::pin(render_captures_for_resource_id_slice(
            children,
            render_context,
            capture_context,
        ))
        .await?;

        let mut captures = Vec::new();

        for part_capture in part_captures {
            for child_capture in &children_captures {
                let capture = [
                    std::slice::from_ref(&part_capture),
                    child_capture.as_slice(),
                ]
                .concat();
                captures.push(capture);
            }
        }

        Ok(captures)
    }
}

impl RenderCaptures for ResourceId {
    async fn render_captures<C: Serialize>(
        &self,
        render_context: &C,
        capture_context: Option<&CaptureContext>,
    ) -> anyhow::Result<Vec<Self>> {
        render_captures_for_resource_id_slice(self, render_context, capture_context).await
    }
}

impl Ord for ResourceCapture {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for ResourceCapture {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ResourceIdPart {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.r#type.cmp(&other.r#type) {
            std::cmp::Ordering::Equal => self.id.cmp(&other.id),
            ordering => ordering,
        }
    }
}

impl PartialOrd for ResourceIdPart {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
