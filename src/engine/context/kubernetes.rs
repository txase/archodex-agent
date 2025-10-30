use std::{
    collections::{HashMap, HashSet, hash_map},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, bail};
use chrono::Utc;
use futures::TryStreamExt;
use k8s_openapi::{
    api::core::v1::{Namespace, Pod, Service},
    apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference},
};
use kube::{
    Api, Client, Config,
    api::{ApiResource, DynamicObject, GroupVersionKind},
};
use kube_runtime::{metadata_watcher, watcher};
use tokio::{
    sync::{Mutex, Notify, OnceCell},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tracing::{Instrument as _, debug, error_span, info, instrument, trace, warn};

use crate::engine::{
    event_capture::{Event, EventCapture, EventType},
    principal::Principal,
    report::Report,
    resource_capture::{ResourceCapture, ResourceId, ResourceIdPart},
};

use super::{ContextMethods, PrivateContextMethods};

const EXCLUDE_NAMESPACES: &[&str] = &[
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "archodex-agent",
];

pub(crate) struct Kubernetes {
    principals: Vec<Principal>,
    inner: Arc<Mutex<Inner>>,
    report: Report,
    _watcher_handle: JoinHandle<anyhow::Result<()>>,
}

type WorkloadCaptureCell = Arc<OnceCell<Option<ResourceCapture>>>;

struct Inner {
    persistent_report: Report,
    container_image_resource_ids_to_container_resource_ids:
        HashMap<ResourceId, HashSet<ResourceId>>,
    container_ids_to_container_resource_ids: HashMap<String, ResourceId>,
    container_id_waiters: HashMap<String, Arc<Notify>>,
    namespace_pod_names_to_workload_captures: HashMap<String, HashMap<String, WorkloadCaptureCell>>,
    dns_to_service_mappings: DNSToServiceMappings,
}

impl std::fmt::Debug for Kubernetes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kubernetes")
            .field("principals", &self.principals)
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

impl PrivateContextMethods for Kubernetes {
    fn principals_mut(&mut self) -> &mut Vec<Principal> {
        &mut self.principals
    }

    fn report_mut(&mut self) -> &mut Report {
        &mut self.report
    }
}

impl ContextMethods for Kubernetes {
    fn principals_without_container(&self) -> &Vec<Principal> {
        &self.principals
    }

    async fn principals(&self, container_id: Option<&String>) -> Vec<Principal> {
        let Some(container_id) = container_id else {
            return self.principals.clone();
        };

        let mut inner = self.inner.lock().await;

        let span = error_span!("Container ID", %container_id).entered();

        if let Some(container_resource_id) = inner
            .container_ids_to_container_resource_ids
            .get(container_id)
        {
            vec![Principal {
                id: container_resource_id.clone(),
                event: None,
            }]
        } else {
            // We might not have seen the container yet, so we need to wait for it
            let notify = inner
                .container_id_waiters
                .entry(container_id.clone())
                .or_default()
                .clone();
            drop(inner);

            debug!("Waiting for Container to be captured");

            let span = span.exit();

            if timeout(Duration::from_secs(15), notify.notified())
                .await
                .is_err()
            {
                let mut inner = self.inner.lock().await;

                let _span = span.entered();
                warn!("Timed out waiting for container to be captured");

                inner.container_id_waiters.remove(container_id);

                return vec![];
            }

            let inner = self.inner.lock().await;
            if let Some(container_resource_id) = inner
                .container_ids_to_container_resource_ids
                .get(container_id)
            {
                let _span = span.entered();
                debug!(
                    container = container_resource_id.last().unwrap().id,
                    "Container captured, returning resource ID"
                );
                vec![Principal {
                    id: container_resource_id.clone(),
                    event: None,
                }]
            } else {
                let _span = span.entered();
                debug!("No Container resource for Container ID");
                vec![]
            }
        }
    }

    #[instrument(
        level = "error",
        skip(self, rule, resources),
        fields(
            rule = rule.first().map_or("<Invalid>", |r| r.id.as_str()),
            resources = ?resources.iter().map(|r| r.first().map_or("<Invalid>", |r| r.id.as_str())).collect::<Vec<_>>(),
        )
    )]
    async fn nest_resources_within_context_dns(
        &self,
        rule: &ResourceId,
        container_id: &str,
        resources: Vec<ResourceId>,
    ) -> Vec<ResourceId> {
        let [rule, ..] = rule.as_slice() else {
            warn!("Resource ID rule must have at least one part");
            return resources;
        };

        if rule.id.trim() != "{TlsServerName}" {
            return resources;
        }

        // Assume all resource captures have the same rendered value
        let Some(first_resource) = resources.first() else {
            return resources;
        };

        let [first_part, ..] = first_resource.as_slice() else {
            warn!("Resource ID must have at least one part");
            return resources;
        };

        let tls_server_name = &first_part.id;

        let inner = self.inner.lock().await;

        let Some(container_resource_id) = inner
            .container_ids_to_container_resource_ids
            .get(container_id)
        else {
            return resources;
        };

        let namespace = &container_resource_id[1].id;

        let Some(service_resource_id) = inner
            .dns_to_service_mappings
            .get_service_resource_id(namespace, tls_server_name)
        else {
            debug!(
                namespace,
                tls_server_name, "No service resource ID found for namespace"
            );
            return resources;
        };

        resources
            .into_iter()
            .map(|resource| {
                let mut context_resource_id = service_resource_id.clone();
                context_resource_id.extend(resource);
                context_resource_id
            })
            .collect()
    }

    #[instrument(
        level = "error",
        skip(self, rule, resource_captures),
        fields(
            rule = rule.id.id,
            resource_captures = ?resource_captures.iter().map(|r| &r.id.id).collect::<Vec<_>>(),
        )
    )]
    async fn nest_resource_captures_within_context_dns(
        &self,
        rule: &ResourceCapture,
        container_id: &str,
        resource_captures: Vec<ResourceCapture>,
    ) -> Vec<ResourceCapture> {
        if rule.id.id.trim() != "{TlsServerName}" {
            return resource_captures;
        }

        // Assume all resource captures have the same rendered value
        let Some(first_resource) = resource_captures.first() else {
            return resource_captures;
        };

        let tls_server_name = &first_resource.id.id;

        let inner = self.inner.lock().await;

        let Some(container_resource_id) = inner
            .container_ids_to_container_resource_ids
            .get(container_id)
        else {
            return resource_captures;
        };

        let namespace = &container_resource_id[1].id;

        let Some(mut service_resource_id) = inner
            .dns_to_service_mappings
            .get_service_resource_id(namespace, tls_server_name)
        else {
            debug!(
                namespace,
                tls_server_name, "No service resource ID found for namespace"
            );
            return resource_captures;
        };

        let mut cur_resource_capture = ResourceCapture::new(service_resource_id.pop().unwrap());
        for resource_capture in resource_captures {
            cur_resource_capture.merge_child_resource(resource_capture);
        }

        while let Some(part) = service_resource_id.pop() {
            let mut capture = ResourceCapture::new(part);
            capture.merge_child_resource(cur_resource_capture);
            cur_resource_capture = capture;
        }

        vec![cur_resource_capture]
    }

    async fn get_report(&mut self) -> Report {
        let mut inner = self.inner.lock().await;

        inner.persistent_report.update_last_seen_ats(Utc::now());

        self.report.merge(inner.persistent_report.clone());

        inner.persistent_report.clear_deleted_resources();

        inner.persistent_report.clear_events();

        drop(inner);

        std::mem::take(self.report_mut())
    }
}

impl Kubernetes {
    pub(super) async fn new() -> Option<Kubernetes> {
        let Ok(node_name) = std::env::var("KUBERNETES_NODE_NAME") else {
            debug!(
                "Kubernetes context not found, KUBERNETES_NODE_NAME environment variable not set"
            );
            return None;
        };

        let config = match Config::incluster_env() {
            Ok(config) => config,
            Err(env_err) => match Config::incluster_dns() {
                Ok(config) => config,
                Err(dns_err) => {
                    debug!(?env_err, ?dns_err, "No valid Kubernetes context found");
                    return None;
                }
            },
        };

        let client = match Client::try_from(config) {
            Ok(client) => client,
            Err(err) => {
                warn!(
                    ?err,
                    "Kubernetes context found, but failed to instantiate client"
                );
                return None;
            }
        };

        let namespaces_api = Api::<Namespace>::all(client.clone());
        let mut kube_system_metadata = match namespaces_api.get_metadata("kube-system").await {
            Ok(metadata) => metadata,
            Err(err) => {
                warn!(
                    ?err,
                    "Kubernetes context found, but failed to get 'kube-system' namespace"
                );
                return None;
            }
        };

        let Some(kube_system_uid) = kube_system_metadata.metadata.uid.take() else {
            warn!("Kubernetes context found, but kube-system namespace metadata is missing uid");
            return None;
        };

        info!("Found Kubernetes context ('kube-system' namespace with uid {kube_system_uid})");

        let cluster_resource_id = vec![ResourceIdPart {
            r#type: "Kubernetes Cluster".to_owned(),
            id: kube_system_uid,
        }];

        let inner = Arc::new(Mutex::new(Inner {
            persistent_report: Report::new(),
            container_image_resource_ids_to_container_resource_ids: HashMap::new(),
            container_ids_to_container_resource_ids: HashMap::new(),
            container_id_waiters: HashMap::new(),
            namespace_pod_names_to_workload_captures: HashMap::new(),
            dns_to_service_mappings: DNSToServiceMappings::new(),
        }));

        let watcher_handle = tokio::spawn(watch_namespaces(
            client,
            inner.clone(),
            cluster_resource_id.clone(),
            node_name,
        ));

        Some(Kubernetes {
            report: Report::new(),
            principals: vec![],
            inner,
            _watcher_handle: watcher_handle,
        })
    }
}

#[instrument(level = "debug", skip(client, inner, cluster_resource_id), fields(cluster_id = %cluster_resource_id[0].id, node_name))]
async fn watch_namespaces(
    client: Client,
    inner: Arc<Mutex<Inner>>,
    cluster_resource_id: ResourceId,
    node_name: String,
) -> anyhow::Result<()> {
    let namespaces_api = Api::<Namespace>::all(client.clone());

    let join_set = Mutex::new(JoinSet::new());

    metadata_watcher(namespaces_api, watcher::Config::default())
        .err_into::<anyhow::Error>()
        .try_for_each_concurrent(None, |event| async {
            use watcher::Event::{InitApply, Apply, Delete, Init, InitDone};

            match event {
                InitApply(namespace) | Apply(namespace) => {
                    let Some(name) = namespace.metadata.name else {
                        warn!("Kubernetes Cluster reported Apply for Namespace with missing name in metadata, ignoring");
                        return Ok(());
                    };

                    if EXCLUDE_NAMESPACES.contains(&name.as_str()) {
                        return Ok(());
                    }

                    debug!(namespace = %name, "Kubernetes Cluster reported Apply event for Namespace");

                    let mut namespace_resource_id = cluster_resource_id.clone();
                    namespace_resource_id.push(ResourceIdPart {
                        r#type: "Namespace".to_string(),
                        id: name.clone(),
                    });

                    join_set.lock().await.spawn(watch_namespace_pods(client.clone(), inner.clone(), namespace_resource_id.clone(), node_name.clone()));
                    join_set.lock().await.spawn(watch_namespace_services(client.clone(), inner.clone(), namespace_resource_id));
                }
                Delete(namespace) => {
                    let Some(name) = namespace.metadata.name else {
                        warn!("Kubernetes cluster reported Delete for Namespace with missing name in metadata, ignoring");
                        return Ok(());
                    };

                    if EXCLUDE_NAMESPACES.contains(&name.as_str()) {
                        return Ok(());
                    }

                    debug!(namespace = %name, "Kubernetes Cluster reported Delete event for Namespace");

                    let inner_lock = inner.clone();
                    let mut inner = inner_lock.lock().await;

                    inner.namespace_pod_names_to_workload_captures.remove(&name);

                    let mut namespace_resource_id = cluster_resource_id.clone();
                    namespace_resource_id.push(ResourceIdPart { r#type: "Namespace".to_string(), id: name });

                    if let Some(resource) = inner.persistent_report.get_resource_capture_mut(&namespace_resource_id) {
                        resource.update_last_seen_ats(Utc::now());
                        resource.deletion_marker = true;
                    }
                },
                Init | InitDone => (),
            }

            Ok(())
        })
        .await?;

    debug!(
        "Kubernetes Cluster Namespaces watcher ended, waiting for individual Namespace watcher tasks to join"
    );

    while let Some(result) = join_set.lock().await.join_next().await {
        match result {
            Ok(result) => {
                if let Err(err) = result {
                    bail!("Task to watch Kubernetes Namespace failed: {err:#?}");
                }
            }
            Err(err) => {
                bail!(
                    "Failed to join task to watch Kubernetes Namespace after cluster shutdown: {err:#?}"
                );
            }
        }
    }

    info!("Kubernetes Cluster Namespaces watcher ended, Cluster must have shut down");

    let mut inner = inner.lock().await;
    if let Some(resource) = inner
        .persistent_report
        .get_resource_capture_mut(&cluster_resource_id)
    {
        resource.update_last_seen_ats(Utc::now());
        resource.deletion_marker = true;
    } else {
        warn!("Kubernetes Cluster resource disappeared during Kubernetes Namespaces watcher task");
    }

    Ok(())
}

#[instrument(level = "debug", skip(client, inner, namespace_resource_id), fields(namespace = %namespace_resource_id[1].id, node_name))]
async fn watch_namespace_pods(
    client: Client,
    inner: Arc<Mutex<Inner>>,
    namespace_resource_id: ResourceId,
    node_name: String,
) -> anyhow::Result<()> {
    let [cluster_id_part, namespace_id_part] = namespace_resource_id.as_slice() else {
        bail!("Namespace resource ID must have exactly two parts: cluster and namespace");
    };

    let namespace_name = &namespace_id_part.id;
    let pods_api = Api::<Pod>::namespaced(client.clone(), namespace_name);

    let namespace_pod_names_to_workload_captures_cells: Mutex<HashMap<_, HashMap<_, _>>> =
        Mutex::new(HashMap::new());

    watcher(pods_api, watcher::Config::default().fields(&format!("spec.nodeName={node_name}")))
        .err_into::<anyhow::Error>()
        .try_for_each_concurrent(None, |event| async {
            use watcher::Event::{InitApply, Apply, Delete, Init, InitDone};

            match event {
                InitApply(pod) | Apply(pod) => {
                    let Some(name) = pod.metadata.name.clone() else {
                        warn!("Kubernetes Apply event for Pod missing 'name' field");
                        return Ok(());
                    };

                    debug!(pod = name, "Kubernetes Apply event for Pod");

                    let mut inner_locked = inner.lock().await;

                    let pod_names_to_workload_captures = inner_locked.namespace_pod_names_to_workload_captures
                        .entry(namespace_name.clone())
                        .or_default();

                    let workload_capture_cell = pod_names_to_workload_captures.entry(name.clone())
                        .or_insert_with(|| Arc::new(OnceCell::new()))
                        .clone();

                    drop(inner_locked);

                    namespace_pod_names_to_workload_captures_cells.lock().await
                        .entry(namespace_name.clone())
                        .or_default()
                        .insert(name.clone(), workload_capture_cell.clone());

                    let client = client.clone();

                    if let Some(workload_capture) = workload_capture_cell
                        .get_or_init(|| capture_pod(&client, &pod, &namespace_resource_id))
                        .await {
                        let mut workload_id = namespace_resource_id.clone();
                        workload_id.push(workload_capture.id.clone());

                        let mut inner = inner.lock().await;

                        let PodCaptures { container_captures, image_captures, events } = capture_pod_containers(
                            &pod,
                            &workload_id,
                            &inner.container_ids_to_container_resource_ids
                        );

                        let _workload_span = error_span!(
                            "Workload",
                            workload_type = workload_capture.id.r#type,
                            workload_id = workload_capture.id.id,
                            pod = name
                        ).entered();

                        let mut workload_capture = workload_capture.clone();
                        for ContainerCapture { id, resource_id, capture } in container_captures {
                            workload_capture.merge_child_resource(capture);

                            let container_name = resource_id.last().unwrap().id.clone();

                            inner.container_ids_to_container_resource_ids.insert(id.clone(), resource_id);

                            // Wake up any waiters for this container ID
                            if let Some(waiters) = inner.container_id_waiters.remove(&id) {
                                debug!(container = container_name, container_id = id, "Notifying waiters for container");
                                waiters.notify_waiters();
                            }
                        }

                        let mut cluster_resource = ResourceCapture::new(cluster_id_part.clone());
                        cluster_resource
                            .merge_child_resource(ResourceCapture::new(namespace_id_part.clone()))
                            .merge_child_resource(workload_capture);

                        inner.persistent_report.add_resource_capture(cluster_resource);

                        inner.persistent_report.add_resource_captures(image_captures);

                        for event in events {
                            let container_image_resource_id = event.events[0].resources[0].clone();
                            let container_resource_id = event.principals[0].id.clone();

                            inner.container_image_resource_ids_to_container_resource_ids.entry(container_image_resource_id).or_default().insert(container_resource_id);

                            inner.persistent_report.add_event_capture(event);
                        }

                        if let Some(container_statuses) = pod.status.and_then(|status| status.container_statuses) {
                            for container_status in container_statuses {
                                if let Some(container_id) = container_status.last_state
                                    .and_then(|state| state.terminated)
                                    .and_then(|terminated| terminated.container_id) {
                                    let Some((_runtime, container_id)) = container_id.split_once("://") else {
                                        warn!(
                                            container = %container_status.name,
                                            container_id,
                                            "Received Kubernetes Apply event with terminated Container, but Container has an invalid containerID, ignoring Container"
                                        );
                                        continue;
                                    };

                                    debug!(
                                        container = %container_status.name,
                                        container_id,
                                        "Received Kubernetes Apply event with terminated Container, removing containerId from context"
                                    );

                                    inner.container_ids_to_container_resource_ids.remove(container_id);
                                }
                            }
                        }
                    }
                }
                Delete(pod) => {
                    let Some(name) = pod.metadata.name.clone() else {
                        warn!("Kubernetes Delete event for Pod missing 'name' field");
                        return Ok(());
                    };

                    debug!(pod = name, "Kubernetes Delete event for Pod");

                    if let Some(pod_names_to_workload_captures) = inner.lock().await
                        .namespace_pod_names_to_workload_captures
                        .get_mut(namespace_name) {
                        pod_names_to_workload_captures.remove(&name);
                    }

                    let mut namespace_pod_names_to_captures_cells = namespace_pod_names_to_workload_captures_cells.lock().await;

                    let pod_span = error_span!("Kubernetes Pod Delete Event", pod = name).entered();

                    let Some(pod_names_to_captures_cells) = namespace_pod_names_to_captures_cells
                        .get_mut(namespace_name) else {
                        warn!("Received Kubernetes Delete event for Pod, but there was no map of Pods to parent resource IDs for Namespace");
                        return Ok(());
                    };

                    let Some(workload_capture_cell) = pod_names_to_captures_cells.remove(&name) else {
                        warn!("Received Kubernetes Delete event for Pod, but there was no record of the Pod's parent resource ID in this Namespace");
                        return Ok(());
                    };

                    drop(namespace_pod_names_to_captures_cells);

                    let pod_span = pod_span.exit();

                    let Some(workload_capture) = workload_capture_cell.get_or_init(async || None).await else {
                        let _pod_span = pod_span.entered();
                        warn!("Received Kubernetes Delete event for unknown Pod in Namespace, ignoring");
                        return Ok(());
                    };

                    let workload_id_part = workload_capture.id.clone();

                    let mut workload_id = namespace_resource_id.clone();
                    workload_id.push(workload_id_part);

                    let mut inner = inner.lock().await;

                    let _pod_span = pod_span.entered();

                    if let Some(resource) = inner.persistent_report.get_resource_capture_mut(&workload_id) {
                        resource.update_last_seen_ats(Utc::now());
                        resource.deletion_marker = true;
                    } else {
                        warn!("Failed to find Kubernetes owner resource for Pod during deletion event");
                    }

                    let Some(status) = pod.status else {
                        warn!("Received Kubernetes Delete event for Pod without a Pod status, ignoring");
                        return Ok(());
                    };

                    let Some(container_statuses) = status.container_statuses else {
                        warn!("Received Kubernetes Delete event for Pod without container statuses, ignoring");
                        return Ok(());
                    };

                    for container_status in container_statuses {
                        let Some(container_id) = container_status.container_id else {
                            warn!(
                                container = %container_status.name,
                                "Received Kubernetes Delete event, but container in Pod status is missing containerID field, ignoring container"
                            );
                            continue;
                        };

                        let Some((_runtime, container_id)) = container_id.split_once("://") else {
                            warn!(
                                container = %container_status.name,
                                container_id,
                                "Received Kubernetes Delete event, but container in Pod status has an invalid containerID, ignoring container"
                            );
                            continue;
                        };

                        let mut container_resource_id = workload_id.clone();
                        container_resource_id.push(ResourceIdPart {
                            r#type: "Container".to_string(),
                            id: container_status.name.clone(),
                        });

                        inner.container_ids_to_container_resource_ids.remove(container_id);

                        let _container_span = error_span!(
                            "Container",
                            container = container_status.name,
                            container_id,
                            image = container_status.image
                        ).entered();

                        inner.container_ids_to_container_resource_ids.remove(container_id);

                        let Ok(container_image_id) = container_image_to_resource_id(&container_status.image) else {
                            warn!(
                                "Received Kubernetes Delete event, but container in Pod status has an invalid image, ignoring container"
                            );
                            continue;
                        };

                        match inner.container_image_resource_ids_to_container_resource_ids.entry(container_image_id.clone()) {
                            hash_map::Entry::Occupied(mut entry) => {
                                if entry.get_mut().remove(&container_resource_id) {
                                    debug!("Removed Container from Kubernetes Context");

                                    if entry.get().is_empty() {
                                        entry.remove();

                                        if let Some(resource) = inner.persistent_report.get_resource_capture_mut(&container_image_id) {
                                            debug!("Removed Container Image from Kubernetes Context");

                                            resource.update_last_seen_ats(Utc::now());
                                            resource.deletion_marker = true;
                                        } else {
                                            warn!("Failed to find Container Image resource in Kubernetes Context to remove it during deletion event");
                                        }
                                    } else {
                                        debug!("Container Image still in use, not removing from Kubernetes Context");
                                    }
                                } else {
                                    warn!("Received Kubernetes Delete event for Container, but there was no record of Container for Container Image");
                                }
                            },
                            hash_map::Entry::Vacant(_) => {
                                warn!("Received Kubernetes Delete event for Container, but there was no record of Container Image");
                            },
                        }
                    }
                },
                Init | InitDone => (),
            }

            Ok(())
        })
        .await
}

#[instrument(level = "debug", skip(client, inner, namespace_resource_id), fields(namespace = namespace_resource_id[1].id))]
async fn watch_namespace_services(
    client: Client,
    inner: Arc<Mutex<Inner>>,
    namespace_resource_id: ResourceId,
) -> anyhow::Result<()> {
    let [cluster_id_part, namespace_id_part] = namespace_resource_id.as_slice() else {
        bail!("Namespace resource ID must have exactly two parts: cluster and namespace");
    };

    let services_api = Api::<Service>::namespaced(client.clone(), &namespace_id_part.id);

    let join_set = Mutex::new(JoinSet::new());

    let service_abort_handles = Mutex::new(HashMap::new());

    watcher(services_api, watcher::Config::default())
        .err_into::<anyhow::Error>()
        .try_for_each_concurrent(None, |event| async {
            use watcher::Event::{InitApply, Apply, Delete, Init, InitDone};

            // Reap any completed watchers
            while let Some(result) = join_set.lock().await.try_join_next() {
                match result {
                    Ok(result) => {
                        if let Err(err) = result {
                            Err(err).context("Task to watch Kubernetes Namespace Service targets failed")?;
                        }
                    }
                    Err(err) => {
                        Err(err).context("Failed to join task to watch Kubernetes Namespace Service targets")?;
                    }
                }
            }

            match event {
                InitApply(service) | Apply(service) => {
                    let Some(name) = service.metadata.name.clone() else {
                        warn!("Kubernetes Apply event for Service missing 'name' field");
                        return Ok(());
                    };

                    debug!(service = name, "Kubernetes Apply event for Service");

                    let mut service_resource_id = namespace_resource_id.clone();
                    service_resource_id.push(ResourceIdPart {
                        r#type: "Service".to_string(),
                        id: name.clone(),
                    });

                    let service_resource_id_part = &service_resource_id[2];

                    let mut service_abort_handles = service_abort_handles.lock().await;
                    let hash_map::Entry::Vacant(entry) = service_abort_handles.entry(name.clone()) else {
                        bail!(
                            "Received Kubernetes Apply event for Service {name:?} in Namespace {:?}, but there was already a watcher task for this service",
                            namespace_id_part.id,
                        );
                    };

                    if let Some(selector) = service.spec.and_then(|spec| spec.selector) {
                        let label_selector = LabelSelector {
                            match_expressions: None,
                            match_labels: Some(selector),
                        };

                        let abort_handle = join_set.lock().await.spawn(watch_namespace_service_targets(
                            client.clone(),
                            inner.clone(),
                            service_resource_id.clone(),
                            label_selector,
                        ));

                        entry.insert(abort_handle);
                    } else {
                        debug!(service = name, "Kubernetes Apply event for Service without selector, not watching for targets");
                    }

                    drop(service_abort_handles);

                    let service_resource = ResourceCapture::new(service_resource_id_part.clone());

                    // Create a namespace resource and add the service as its child
                    let mut namespace_resource = ResourceCapture::new(namespace_id_part.clone());
                    namespace_resource.merge_child_resource(service_resource);

                    // Create the cluster resource and add the namespace as its child
                    let mut cluster_resource = ResourceCapture::new(cluster_id_part.clone());
                    cluster_resource.merge_child_resource(namespace_resource);

                    // Add the service to the persistent report with proper hierarchy
                    let mut inner = inner.lock().await;
                    inner.persistent_report.add_resource_capture(cluster_resource);

                    inner.dns_to_service_mappings.add_mapping(
                        namespace_id_part.id.clone(),
                        name.clone(),
                        service_resource_id,
                    );
                }
                Delete(service) => {
                    let Some(name) = &service.metadata.name else {
                        warn!("Kubernetes Delete event for Service missing 'name' field");
                        return Ok(());
                    };

                    debug!(service = name, "Kubernetes Delete event for Service");

                    // Create the service resource ID for deletion marking
                    let mut service_resource_id = namespace_resource_id.clone();
                    service_resource_id.push(ResourceIdPart {
                        r#type: "Service".to_string(),
                        id: name.to_string(),
                    });

                    let mut inner = inner.lock().await;

                    inner.dns_to_service_mappings.remove_mapping(
                        &namespace_id_part.id,
                        name,
                    );

                    // Mark the service as deleted in the persistent report
                    if let Some(resource) = inner.persistent_report.get_resource_capture_mut(&service_resource_id) {
                        resource.update_last_seen_ats(Utc::now());
                        resource.deletion_marker = true;
                    } else {
                        warn!(service = %name, "Failed to find Kubernetes Service during deletion event");
                    }

                    if let Some(abort_handle) = service_abort_handles.lock().await.remove(name) {
                        abort_handle.abort();
                    } else {
                        warn!(service = %name, "Received Kubernetes Delete event for Service, but there was no record of the watcher task");
                    }
                },
                Init | InitDone => (),
            }

            Ok(())
        })
        .await?;

    debug!(
        namespace = namespace_id_part.id,
        "Kubernetes Namespace Services watcher ended, waiting for individual watcher tasks to join"
    );

    while let Some(result) = join_set.lock().await.join_next().await {
        match result {
            Ok(result) => {
                if let Err(err) = result {
                    bail!("Task to watch Kubernetes Namespace failed: {err:#?}");
                }
            }
            Err(err) => {
                bail!(
                    "Failed to join task to watch Kubernetes Namespace after cluster shutdown: {err:#?}"
                );
            }
        }
    }

    info!("Kubernetes Cluster Namespaces watcher ended, Cluster must have shut down");

    Ok(())
}

#[instrument(level = "debug", skip(client, inner, service_resource_id), fields(cluster = service_resource_id[0].id, namespace = service_resource_id[1].id, service = service_resource_id[2].id))]
async fn watch_namespace_service_targets(
    client: Client,
    inner: Arc<Mutex<Inner>>,
    service_resource_id: ResourceId,
    label_selector: LabelSelector,
) -> anyhow::Result<()> {
    let [cluster_id_part, namespace_id_part, service_id_part] = service_resource_id.as_slice()
    else {
        bail!("Service resource ID must have exactly three parts: cluster, namespace, and service");
    };

    let namespace_resource_id = vec![cluster_id_part.clone(), namespace_id_part.clone()];
    let namespace_name = &namespace_id_part.id;

    let namespace_pod_names_to_captures_cells: Mutex<HashMap<_, HashMap<_, _>>> =
        Mutex::new(HashMap::new());

    let pods_api = Api::<Pod>::namespaced(client.clone(), &namespace_id_part.id);

    let watcher_config = watcher::Config::default()
        .labels_from(
            &label_selector
                .clone()
                .try_into()
                .with_context(|| format!("Failed to format label selector for service {service_resource_id:?} with selector {label_selector:?}"))?
        );

    watcher(pods_api, watcher_config)
        .err_into::<anyhow::Error>()
        .try_for_each_concurrent(None, |event| async {
            use watcher::Event::{InitApply, Apply, Delete};

            #[derive(Debug, PartialEq)]
            enum WatchEventType {
                Apply,
                Delete,
            }

            let (pod, event_type) = match event {
                InitApply(pod) | Apply(pod) => (pod, WatchEventType::Apply),
                Delete(pod) => (pod, WatchEventType::Delete),
                _ => return Ok(()),
            };

            let Some(name) = pod.metadata.name.clone() else {
                warn!(?event_type, service = service_id_part.id, "Kubernetes Service Target event for Pod missing 'name' field");
                return Ok(());
            };

            let workload_id_part = if event_type == WatchEventType::Apply {
                let mut inner = inner.lock().await;

                let pod_names_to_workload_captures = inner.namespace_pod_names_to_workload_captures
                    .entry(namespace_name.clone())
                    .or_default();

                let captures_cell = pod_names_to_workload_captures.entry(name.clone())
                    .or_insert_with(|| Arc::new(OnceCell::new()))
                    .clone();

                drop(inner);

                namespace_pod_names_to_captures_cells.lock().await
                    .entry(namespace_name.clone())
                    .or_default()
                    .insert(name.clone(), captures_cell.clone());

                let client = client.clone();

                let Some(workload_capture) = captures_cell
                    .get_or_init(|| capture_pod(&client, &pod, &namespace_resource_id))
                    .await else {
                        warn!(service = service_id_part.id, pod = name, "Failed to capture Pod for Apply event of Service Target");
                        return Ok(());
                    };

                workload_capture.id.clone()
            } else {
                if let Some(pod_names_to_workload_captures) = inner.lock().await
                    .namespace_pod_names_to_workload_captures.get_mut(namespace_name) {
                    pod_names_to_workload_captures.remove(&name);
                }

                let mut namespace_pod_names_to_captures_cells = namespace_pod_names_to_captures_cells.lock().await;

                let target_span = error_span!("Pod Delete Event", service = service_id_part.id, pod = name).entered();

                let Some(pod_names_to_captures_cells) = namespace_pod_names_to_captures_cells
                    .get_mut(namespace_name) else {
                    warn!("Received Kubernetes Delete event for Pod, but there was no map of Pods to parent resource IDs for Namespace");
                    return Ok(());
                };

                let Some(workload_capture_cell) = pod_names_to_captures_cells.remove(&name) else {
                    warn!("Received Kubernetes Delete event for Pod, but there was no record of the Pod's parent resource ID in this Namespace");
                    return Ok(());
                };

                drop(namespace_pod_names_to_captures_cells);

                let target_span = target_span.exit();

                let Some(workload_capture) = workload_capture_cell.get_or_init(async || None).await else {
                    let _target_span = target_span.entered();
                    warn!("Received Kubernetes Delete event for unknown Pod in Namespace, ignoring");
                    return Ok(());
                };

                workload_capture.id.clone()
            };

            let workload_span = error_span!(
                "Workload",
                workload = ?workload_id_part,
                pod = name,
            ).entered();

            let seen_at = Utc::now();

            let mut workload_id = namespace_resource_id.clone();
            workload_id.push(workload_id_part.clone());

            let target_event = EventCapture {
                principals: vec![Principal {
                    id: service_resource_id.clone(),
                    event: None,
                }],
                events: vec![Event {
                    types: vec![EventType {
                        r#type: "Targeted".to_string(),
                        first_seen_at: seen_at,
                        last_seen_at: seen_at,
                        retain: matches!(event_type, WatchEventType::Apply),
                    }],
                    resources: vec![workload_id],
                }],
            };

            debug!(%seen_at, "Recording Kubernetes Service Targeted Workload");

            let workload_span = workload_span.exit();

            let mut inner = inner.lock().await;

            let _workload_span = workload_span.entered();

            inner.persistent_report.add_event_capture(target_event);

            Ok(())
        })
        .await
}

#[instrument(level = "error", skip(client, pod), fields(namespace = namespace_resource_id.last().unwrap().id))]
async fn capture_pod(
    client: &Client,
    pod: &Pod,
    namespace_resource_id: &ResourceId,
) -> Option<ResourceCapture> {
    let Some(name) = &pod.metadata.name else {
        warn!("Kubernetes Pod missing name, ignoring");
        return None;
    };
    let name = name.to_string();

    let pod_span = error_span!("Kubernetes Pod", pod = name).entered();

    if pod.status.is_none() {
        warn!("Kubernetes Pod missing status, ignoring");
        return None;
    }

    debug!("Capturing Kubernetes Pod");

    let parent_resource = match pod.metadata.owner_references.as_deref() {
        Some([owner_reference, ..]) => {
            let owner_span = error_span!(
                "Kubernetes Pod Owner",
                owner_reference.kind = owner_reference.kind,
                owner_reference.name = owner_reference.name
            )
            .entered();

            trace!("Fetching Pod owner");

            let pod_span_async = pod_span.exit();
            let owner_span_async = owner_span.exit();

            let result = capture_parent_object(client, owner_reference, namespace_resource_id)
                .instrument(pod_span_async.clone())
                .instrument(owner_span_async.clone())
                .await;

            let _pod_span = pod_span_async.entered();
            let _owner_span = owner_span_async.entered();

            match result {
                Ok(parent_resource) => parent_resource,
                Err(err) => {
                    debug!(?err, "Failed to get parent Kubernetes resource of Pod");
                    return None;
                }
            }
        }
        _ => ResourceCapture::new(ResourceIdPart {
            r#type: "Pod".to_string(),
            id: name,
        }),
    };

    debug!(
        workload_type = parent_resource.id.r#type,
        workload_id = parent_resource.id.id,
        "Captured Pod workload resource"
    );

    Some(parent_resource)
}

struct ContainerCapture {
    id: String,
    resource_id: ResourceId,
    capture: ResourceCapture,
}

struct PodCaptures {
    container_captures: Vec<ContainerCapture>,
    image_captures: Vec<ResourceCapture>,
    events: Vec<EventCapture>,
}

#[instrument(
    level = "error",
    skip(client, owner_reference),
    fields(owner_reference.kind, owner_reference.name, namespace = namespace_resource_id.last().unwrap().id)
)]
async fn capture_parent_object(
    client: &Client,
    owner_reference: &OwnerReference,
    namespace_resource_id: &ResourceId,
) -> anyhow::Result<ResourceCapture> {
    let namespace = &namespace_resource_id.last().unwrap().id;
    let gvk = GroupVersionKind::from(owner_reference.clone());
    let api = Api::<DynamicObject>::namespaced_with(
        client.clone(),
        namespace,
        &ApiResource::from_gvk(&gvk),
    );

    let parent = api
        .get_metadata(&owner_reference.name)
        .await
        .with_context(|| {
            format!(
                "Failed to get parent of Kubernetes Object (kind: {}, name: {})",
                owner_reference.kind, owner_reference.name
            )
        })?;

    match parent.metadata.owner_references.unwrap_or_default().first() {
        Some(owner_reference) => {
            let owner_span = error_span!(
                "Kubernetes Parent Owner",
                owner_reference.kind = owner_reference.kind,
                owner_reference.name = owner_reference.name
            )
            .entered();

            trace!("Fetching owner's owner");

            let owner_span_async = owner_span.exit();
            Box::pin(capture_parent_object(
                client,
                owner_reference,
                namespace_resource_id,
            ))
            .instrument(owner_span_async)
            .await
        }
        None => Ok(ResourceCapture::new(ResourceIdPart {
            r#type: owner_reference.kind.clone(),
            id: owner_reference.name.clone(),
        })),
    }
}

fn capture_pod_containers<T>(
    pod: &Pod,
    workload_id: &ResourceId,
    seen_container_ids: &HashMap<String, T>,
) -> PodCaptures {
    let mut container_captures = vec![];
    let mut image_captures = vec![];
    let mut events = vec![];

    let seen_at = Utc::now();

    for (container_id, container_name, image) in pod
        .status
        .as_ref()
        .and_then(|status| status.container_statuses.as_ref())
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|container_status| {
            if let Some(container_id) = &container_status.container_id
                && !seen_container_ids.contains_key(container_id)
            {
                return Some((
                    container_id,
                    container_status.name.clone(),
                    container_status.image.clone(),
                ));
            }

            None
        })
    {
        let container_resource_id_part = ResourceIdPart {
            r#type: "Container".to_string(),
            id: container_name.clone(),
        };

        let Some((_runtime, container_id)) = container_id.split_once("://") else {
            warn!(
                container_id = container_id,
                "Kubernetes container in Pod status has invalid containerID, ignoring container"
            );
            continue;
        };

        let _container_span =
            error_span!("Container", container = container_name, container_id, image,).entered();

        debug!("Capturing Pod Container and Image");

        let mut container_resource_id = workload_id.clone();
        container_resource_id.push(container_resource_id_part.clone());

        container_captures.push(ContainerCapture {
            id: container_id.to_string(),
            resource_id: container_resource_id.clone(),
            capture: ResourceCapture::new(container_resource_id_part.clone()),
        });

        let Ok(container_image_id) = container_image_to_resource_id(&image) else {
            warn!("Container has an invalid image, ignoring container");
            continue;
        };

        events.push(EventCapture {
            principals: vec![Principal {
                id: container_resource_id,
                event: None,
            }],
            events: vec![Event {
                types: vec![EventType {
                    r#type: "Ran Image".to_string(),
                    first_seen_at: seen_at,
                    last_seen_at: seen_at,
                    retain: false,
                }],
                resources: vec![container_image_id.clone()],
            }],
        });

        let container_image_capture = match ResourceCapture::try_from(container_image_id.clone()) {
            Ok(capture) => capture,
            Err(err) => {
                warn!(?err, "Failed to capture container image");
                continue;
            }
        };

        image_captures.push(container_image_capture);
    }

    PodCaptures {
        container_captures,
        image_captures,
        events,
    }
}

fn container_image_to_resource_id(image: &str) -> anyhow::Result<ResourceId> {
    let Some((container_repository, container_image)) = image.split_once('/') else {
        bail!("Container image has an invalid format");
    };

    let Some((container_image, _container_tag)) = container_image.split_once(':') else {
        bail!("Container image has an invalid format");
    };

    Ok(vec![
        ResourceIdPart {
            r#type: "Container Repository".to_string(),
            id: container_repository.to_string(),
        },
        ResourceIdPart {
            r#type: "Container Image".to_string(),
            id: container_image.to_string(),
        },
    ])
}

struct DNSToServiceMappings(HashMap<String, ResourceId>);

impl DNSToServiceMappings {
    fn new() -> Self {
        Self(HashMap::new())
    }

    #[instrument(level = "error", skip(self))]
    fn add_mapping(&mut self, namespace: String, service: String, resource_id: ResourceId) {
        debug!("Adding DNS mapping for service");

        self.0
            .insert(format!("{service}.{namespace}"), resource_id.clone());
    }

    #[instrument(level = "error", skip(self))]
    fn remove_mapping(&mut self, namespace: &str, service: &str) {
        debug!("Removing DNS mapping for service");

        self.0.remove(&format!("{service}.{namespace}"));
    }

    fn get_service_resource_id(&self, namespace: &str, hostname: &str) -> Option<ResourceId> {
        let parts = hostname.split('.').collect::<Vec<_>>();

        let key = match parts.as_slice() {
            [service] => format!("{service}.{namespace}"),
            [service, namespace]
            | [service, namespace, "svc"]
            | [service, namespace, "svc", "cluster", "local"]
            | [service, namespace, "svc", "cluster", "local", ""] => {
                format!("{service}.{namespace}")
            }
            _ => return None,
        };

        self.0.get(&key).cloned()
    }
}
