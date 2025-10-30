use std::collections::HashMap;

use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Serialize, ser::SerializeSeq};

use super::{
    event_capture::{EventCapture, EventType},
    principal::Principal,
    resource_capture::{ResourceCapture, ResourceId, ResourceIdPart},
};

pub(crate) type PrincipalChain = Vec<Principal>;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct EventSetKey {
    principals: PrincipalChain,
    resources: Vec<ResourceId>,
}

impl Ord for EventSetKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.principals.cmp(&other.principals) {
            std::cmp::Ordering::Equal => self.resources.cmp(&other.resources),
            ordering => ordering,
        }
    }
}

impl PartialOrd for EventSetKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl EventLogFormat for PrincipalChain {
    fn event_log_format(&self) -> String {
        self.iter()
            .map(EventLogFormat::event_log_format)
            .collect::<String>()
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Report {
    #[serde(serialize_with = "Report::serialize_resources")]
    resource_captures: HashMap<ResourceIdPart, ResourceCapture>,
    #[serde(serialize_with = "Report::serialize_events")]
    event_captures: HashMap<EventSetKey, Vec<EventType>>,
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}

impl Report {
    pub(crate) fn new() -> Self {
        Self {
            resource_captures: HashMap::new(),
            event_captures: HashMap::new(),
        }
    }

    pub(crate) fn add_resource_capture(&mut self, resource: ResourceCapture) {
        match self.resource_captures.get_mut(&resource.id) {
            Some(existing) => existing.merge(resource),
            None => {
                self.resource_captures.insert(resource.id.clone(), resource);
            }
        }
    }

    pub(crate) fn add_resource_captures(&mut self, resources: Vec<ResourceCapture>) {
        for resource in resources {
            self.add_resource_capture(resource);
        }
    }

    pub(crate) fn get_resource_capture_mut(
        &mut self,
        id: &ResourceId,
    ) -> Option<&mut ResourceCapture> {
        if id.is_empty() {
            return None;
        }

        let (first, rest) = id.split_at(1);
        let first = first.first()?;

        self.resource_captures
            .get_mut(first)?
            .get_child_by_id_mut(rest)
    }

    pub(crate) fn add_event_capture(&mut self, event_capture: EventCapture) {
        for event in event_capture.events {
            let key = EventSetKey {
                principals: event_capture.principals.clone(),
                resources: event.resources,
            };

            'other: for other_event_type in event.types {
                let event_types = self.event_captures.entry(key.clone()).or_default();

                for event_type in event_types.iter_mut() {
                    if event_type.r#type == other_event_type.r#type {
                        event_type.last_seen_at =
                            std::cmp::max(event_type.last_seen_at, other_event_type.last_seen_at);
                        event_type.retain = other_event_type.retain;
                        continue 'other;
                    }
                }

                event_types.push(other_event_type);
            }
        }
    }

    pub(crate) fn merge(&mut self, other: Report) {
        for (other_id_part, other_capture) in other.resource_captures {
            match self.resource_captures.get_mut(&other_id_part) {
                Some(capture) => capture.merge(other_capture),
                None => {
                    self.resource_captures.insert(other_id_part, other_capture);
                }
            }
        }

        for (other_event_set_key, other_event_types) in other.event_captures {
            match self.event_captures.get_mut(&other_event_set_key) {
                Some(event_types) => {
                    'other: for other_event_type in other_event_types {
                        for event_type in event_types.iter_mut() {
                            if event_type.r#type == other_event_type.r#type {
                                event_type.last_seen_at = std::cmp::max(
                                    event_type.last_seen_at,
                                    other_event_type.last_seen_at,
                                );
                                continue 'other;
                            }
                        }

                        event_types.push(other_event_type);
                    }
                }
                None => {
                    self.event_captures
                        .insert(other_event_set_key, other_event_types);
                }
            }
        }
    }

    pub(crate) fn update_last_seen_ats(&mut self, last_seen_at: DateTime<Utc>) {
        for resource in self.resource_captures.values_mut() {
            resource.update_last_seen_ats(last_seen_at);
        }

        for event_types in self.event_captures.values_mut() {
            for event_type in event_types {
                if event_type.retain {
                    event_type.last_seen_at = last_seen_at;
                }
            }
        }
    }

    pub(crate) fn clear_deleted_resources(&mut self) {
        self.resource_captures.retain(|_, resource| {
            if resource.deletion_marker {
                false
            } else {
                resource.clear_deleted_resources();
                true
            }
        });
    }

    pub(crate) fn clear_events(&mut self) {
        self.event_captures.retain(|_, event_types| {
            event_types.retain(|event_type| event_type.retain);
            !event_types.is_empty()
        });
    }

    fn serialize_resources<S>(
        resources: &HashMap<ResourceIdPart, ResourceCapture>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(resources.len()))?;
        for resource_capture in resources.values() {
            seq.serialize_element(resource_capture)?;
        }
        seq.end()
    }

    fn serialize_events<S>(
        events: &HashMap<EventSetKey, Vec<EventType>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct JsonEvents<'a> {
            principals: &'a Vec<Principal>,
            resources: &'a Vec<ResourceId>,
            events: &'a Vec<EventType>,
        }

        let mut seq = serializer.serialize_seq(Some(events.len()))?;
        for (key, event_types) in events {
            let events = JsonEvents {
                principals: &key.principals,
                resources: &key.resources,
                events: event_types,
            };

            seq.serialize_element(&events)?;
        }
        seq.end()
    }

    /// Extracts all resource IDs, including nested resources recursively.
    pub(crate) fn extract_resource_ids(&self) -> Vec<ResourceIdPart> {
        fn extract_recursive(capture: &ResourceCapture, ids: &mut Vec<ResourceIdPart>) {
            ids.push(capture.id.clone());
            for nested in capture.contains.values() {
                extract_recursive(nested, ids);
            }
        }

        let mut ids = Vec::new();
        for capture in self.resource_captures.values() {
            extract_recursive(capture, &mut ids);
        }
        ids
    }

    /// Counts all events across all event sets.
    pub(crate) fn count_events(&self) -> usize {
        self.event_captures.values().map(Vec::len).sum()
    }

    pub(crate) fn log(&self) {
        print!("");

        if self.resource_captures.is_empty() {
            println!("No resources captured");
        } else {
            println!("{}", "Resource captures:".bold());

            let mut sorted_resource_captures = self.resource_captures.values().collect::<Vec<_>>();
            sorted_resource_captures.sort();
            let mut sorted_resource_captures_iterator = sorted_resource_captures.iter().peekable();

            while let Some(capture) = sorted_resource_captures_iterator.next() {
                let is_last_capture = sorted_resource_captures_iterator.peek().is_none();
                capture.log(&mut vec![], is_last_capture);
            }
        }

        print!("");

        if self.event_captures.is_empty() {
            println!("No events captured\n");
            return;
        }

        println!("{}", "Event captures:".bold());

        let mut sorted_event_captures = self.event_captures.iter().collect::<Vec<_>>();
        sorted_event_captures.sort_by(|&(event_set_key_a, _), &(event_set_key_b, _)| {
            event_set_key_a.cmp(event_set_key_b)
        });

        let mut prev_principal_chain = None;
        let last_principal_chain = &sorted_event_captures.last().unwrap().0.principals;
        let mut sorted_event_captures_iterator = sorted_event_captures.iter().peekable();

        while let Some((event_set_key, event_types)) = sorted_event_captures_iterator.next() {
            let is_last_principal_chain = &event_set_key.principals == last_principal_chain;
            let is_last_event_set_for_principal_chain = sorted_event_captures_iterator
                .peek()
                .is_none_or(|(next_event_set_key, _)| {
                    next_event_set_key.principals != event_set_key.principals
                });

            if prev_principal_chain != Some(&event_set_key.principals) {
                let lead = if is_last_principal_chain {
                    "└─"
                } else {
                    "├─"
                };

                println!(
                    "{lead} {label} {principal_chain}",
                    label = "Principal chain:".bold(),
                    principal_chain = event_set_key.principals.event_log_format()
                );
                prev_principal_chain = Some(&event_set_key.principals);
            }

            let mut sorted_event_types = event_types.iter().collect::<Vec<_>>();
            sorted_event_types.sort();
            let mut sorted_event_types_iterator = sorted_event_types.iter().peekable();

            while let Some(&event_type) = sorted_event_types_iterator.next() {
                let is_last_event_type = sorted_event_types_iterator.peek().is_none();

                let lead = if is_last_principal_chain {
                    "  "
                } else {
                    "│ "
                };

                let mut resources_iterator = event_set_key.resources.iter().peekable();

                while let Some(resource) = resources_iterator.next() {
                    let is_last_event = is_last_event_set_for_principal_chain
                        && is_last_event_type
                        && resources_iterator.peek().is_none();

                    let (type_lead, details_lead) = if is_last_event {
                        (format!("{lead} └─"), format!("{lead}   "))
                    } else {
                        (format!("{lead} ├─"), format!("{lead} │ "))
                    };

                    println!(
                        "{type_lead} {label} {type}",
                        label = "Event:".bold(),
                        type = event_type.r#type.yellow(),
                    );

                    println!(
                        "{details_lead} {label} {resource}",
                        label = "Resource:".bold(),
                        resource = resource.event_log_format(),
                    );

                    println!(
                        "{details_lead} {label} {first_seen_at}",
                        label = "First seen at:".dimmed().bold(),
                        first_seen_at = event_type
                            .first_seen_at
                            .format("%Y-%m-%d %H:%M:%S UTC")
                            .to_string()
                            .dimmed()
                    );
                    println!(
                        "{details_lead} {label} {last_seen_at}",
                        label = "Last seen at:".dimmed().bold(),
                        last_seen_at = event_type
                            .last_seen_at
                            .format("%Y-%m-%d %H:%M:%S UTC")
                            .to_string()
                            .dimmed()
                    );

                    println!("{details_lead}");
                }
            }
        }

        print!("");
    }
}

pub(crate) trait EventLogFormat {
    fn event_log_format(&self) -> String;
}
