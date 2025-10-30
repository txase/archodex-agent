use std::io;

use nix::unistd::Pid;
use procfs::{ProcError, process::Process};
use tracing::{debug, instrument, trace, warn};

#[instrument(level = "warn")]
pub(crate) fn find_file_path_from_mount_point_and_fs_path(
    pid: &Pid,
    mount_point: &str,
    fs_path: &str,
) -> Option<String> {
    trace!("find_file_path_from_mount_point_and_fs_path");

    let proc = match Process::new(pid.as_raw()) {
        Ok(proc) => proc,
        Err(procfs::ProcError::NotFound(_)) => {
            debug!("Process not found");
            return None;
        }
        Err(err) => panic!("Failed to get procfs process entry for pid {pid}: {err}"),
    };

    let mountinfo = match proc.mountinfo() {
        Ok(mountinfo) => mountinfo,
        Err(ProcError::Io(err, _)) if err.kind() == io::ErrorKind::InvalidInput => {
            debug!("Process disappeared before we could instrument it");
            return None;
        }
        Err(err) => panic!("Failed to get mountinfo for pid {pid}: {err:?}"),
    };

    if mountinfo.0.is_empty() {
        debug!("mountinfo is empty");
        return None;
    }

    let Some(mount) = mountinfo.into_iter().find(|mount| {
        mount
            .mount_point
            .to_str()
            .expect("Invalid mountinfo mount_point")
            == mount_point
    }) else {
        warn!("Could not find matching mountinfo for mount point");

        return None;
    };

    let root_path = mount.root;

    trace!(root_path, "Found root path in process mountinfo");

    assert!(
        fs_path.starts_with(&root_path),
        "File path {fs_path} does not start with mount root path {root_path}"
    );

    let path = match (&root_path[..], mount_point) {
        ("/", "/") => fs_path.to_string(),
        ("/", _) => mount_point.to_string() + fs_path,
        _ => fs_path.replacen(&root_path, mount_point, 1),
    };

    trace!(path, "Found path");

    Some(path)
}
