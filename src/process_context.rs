use std::sync::LazyLock;

use nix::unistd::Pid;
use procfs::process::Process;
use regex::Regex;
use tracing::{debug, instrument, warn};

#[derive(Clone, Debug)]
pub(crate) struct ProcessContext {
    container_id: Option<String>,
}

// Kubernetes has two primary cgroup drivers. They generate different cgroup
// pathnames with the container ID embedded in different ways.
//
// The systemd cgroup driver generates pathnames like:
//      /kubepods.slice/kubepods-{besteffort|guaranteed|burstable}.slice/kubepods-{besteffort|guaranteed|burstable}-pod<Pod ID>.slice/{cri-containerd|crio}-<Container ID>.scope
// where the Pod ID is a UUID like "00000000_0000_0000_0000_000000000000".
//
// The cgroupfs cgroup driver generates pathnames like:
//      /kubepods/{besteffort|guaranteed|burstable}/pod<Pod ID>/<Container ID>
// where the Pod ID is a UUID like "00000000-0000-0000-0000-000000000000".
//
// This regex matches both of these formats (Pod IDs are UUIDs) with a capture
// group named "container_id" that contains the container ID.
static CGROUP_PATHNAME_CONTAINER_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:/[^/\s]+(?:\.slice)?)+/(?:[^/\s]+-)?pod[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}(?:\.slice)?/(?:[a-z-]+-)?(?P<container_id>[a-z0-9]+)(?:\.scope)?$").expect("Failed to compile container ID regex"
    )
});

impl ProcessContext {
    #[instrument(level = "error")]
    pub(crate) fn new(pid: &Pid) -> Option<Self> {
        let proc = match Process::new(pid.as_raw()) {
            Ok(proc) => proc,
            Err(procfs::ProcError::NotFound(_)) => {
                debug!(%pid, "No procfs process entry found for pid");
                return None;
            }
            Err(err) => panic!("Failed to get procfs process entry for pid {pid}: {err:#?}"),
        };

        let pathname = match proc.cgroups() {
            Ok(cgroups) => match cgroups.into_iter().next() {
                Some(cgroup) => cgroup.pathname,
                None => panic!("No cgroups found for pid {pid}"),
            },
            Err(err) => panic!("Failed to get cgroups for pid {pid}: {err:#?}"),
        };

        let Some(captures) = CGROUP_PATHNAME_CONTAINER_ID_RE.captures(&pathname) else {
            if pathname.starts_with("/kubepods") {
                warn!(
                    pathname,
                    "Kubepods CGroup pathname for process does not match Kubernetes container ID regex"
                );
            } else {
                debug!(
                    pathname,
                    "CGroup pathname does not match Kubernetes container ID regex"
                );
            }
            return Some(ProcessContext { container_id: None });
        };

        let container_id = captures
            .name("container_id")
            .unwrap_or_else(|| panic!("Failed to extract container ID from cgroup pathname regex (pathname: {pathname}"))
            .as_str()
            .to_string();

        Some(ProcessContext {
            container_id: Some(container_id),
        })
    }

    pub(crate) fn container_id(&self) -> Option<String> {
        self.container_id.clone()
    }
}
