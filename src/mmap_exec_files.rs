pub(crate) mod mmap_exec_files_bpf {
    #![allow(clippy::pedantic)]

    #[cfg(target_arch = "aarch64")]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/skel/aarch64/mmap_exec_files.skel.rs"
    ));

    #[cfg(target_arch = "x86_64")]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/skel/x86_64/mmap_exec_files.skel.rs"
    ));
}

use std::{
    cell::RefCell,
    collections::{HashMap, hash_map::Entry},
    mem::MaybeUninit,
    time::Duration,
};

use anyhow::Context as _;
use libbpf_rs::{
    MapCore, MapFlags, RingBufferBuilder,
    skel::{OpenSkel, Skel, SkelBuilder},
};
use mmap_exec_files_bpf::{MmapExecFilesSkelBuilder, types};
use nix::{
    errno::Errno,
    sys::{
        ptrace,
        signal::Signal::{SIGSTOP, SIGTRAP},
        wait::{
            Id, WaitPidFlag,
            WaitStatus::{Exited, PtraceEvent},
            waitid,
        },
    },
    unistd::Pid,
};
use procfs::process::{MMPermissions, MMapPath, all_processes};
use tokio::{
    io::unix::AsyncFd,
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    sync::oneshot::{self, Receiver},
};
use tracing::{debug, error, error_span, trace, trace_span};

use crate::{bpf_log::bpf_log_module_get_level, mmap_exec_files_event_parser::Event};

struct PidFileReapEvent {
    pid: Pid,
    ino: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct MmapExecFileEvent {
    pub(crate) mount_point: String,
    pub(crate) fs_file_path: String,
    pub(crate) pid: Pid,
    pub(crate) ino: u64,
    pub(crate) ignore_ino: bool,
    detach_pid_sender: UnboundedSender<PidFileReapEvent>,
}

impl Drop for MmapExecFileEvent {
    fn drop(&mut self) {
        let pid_file_reap_event = PidFileReapEvent {
            pid: self.pid,
            ino: if self.ignore_ino {
                Some(self.ino)
            } else {
                None
            },
        };

        self.detach_pid_sender
            .send(pid_file_reap_event)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to send detach message for pid {pid}: {err}",
                    pid = self.pid
                )
            });
    }
}

struct PidTracedEntry {
    ptraced: bool,
    count: u8,
}

/// Create a single tight tokio async thread that listens for mmap syscalls
/// for executable file maps. When an mmap occurs, it uses `PTRACE_ATTACH` to
/// pause the process while emitting an event for the mmap'ed file. Note that
/// due to race conditions with signals, multiple mmap syscall events may be
/// received before we can pause the process.
///
/// When all events for the process have been dropped, we `PTRACE_DETACH` from the
/// process to allow it to continue.
#[allow(clippy::too_many_lines)]
pub(crate) fn mmap_exec_files() -> (UnboundedReceiver<MmapExecFileEvent>, Receiver<()>) {
    let (mmap_exec_file_event_sender, mmap_exec_file_event_receiver) = unbounded_channel();
    let (initialized_sender, initialized_receiver) = oneshot::channel();
    let mut initialized_sender = Some(initialized_sender);

    std::thread::spawn(move || -> anyhow::Result<()> {
        let span = trace_span!("mmap_exec_files");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;

        rt.block_on(async {
            let pid_counters = RefCell::new(HashMap::<Pid, PidTracedEntry>::new());
            let (detach_pid_sender, mut detach_pid_receiver) =
                unbounded_channel::<PidFileReapEvent>();

            let skel_builder = MmapExecFilesSkelBuilder::default();
            let mut open_object = MaybeUninit::uninit();
            let open_skel = skel_builder.open(&mut open_object)?;

            open_skel.maps.bss_data.log_levels[types::LogModule::LOG_MODULE_MMAP_EXEC_FILES as usize] = bpf_log_module_get_level!("mmap_exec_files");

            let mut skel = open_skel.load()?;

            skel.attach()?;

            let mut builder = RingBufferBuilder::new();

            builder.add(&skel.maps.events_ringbuf, |data: &[u8]| {
                let _enter = span.enter();

                let Event { mount_point, fs_file_path, pid, ino } = match Event::new(data) {
                    Ok(Some(event)) => event,
                    Ok(None) => return 0,
                    Err(err) => {
                        error!("Failed to parse event from mmap_exec_files ring buffer: {err}");
                        return 0;
                    },
                };

                let mut ptraced = false;

                let mut pid_counters = pid_counters.borrow_mut();
                match pid_counters.entry(pid) {
                    Entry::Vacant(entry) => {
                        if let Err(err) = ptrace::attach(pid) {
                            match err {
                                Errno::ESRCH => {
                                    debug!(%pid, "Process disappeared before we could attach to it");
                                    return 0;
                                },
                                _ => {
                                    debug!(%pid, "Failed to attach to process: {err}");
                                },
                            }
                        } else {
                            trace!(%pid, "Attached");
                            ptraced = true;
                            loop {
                                match waitid(Id::Pid(pid), WaitPidFlag::WSTOPPED | WaitPidFlag::WEXITED) {
                                    Ok(PtraceEvent(_, SIGSTOP, _)) => break,
                                    Ok(PtraceEvent(_, SIGTRAP, _)) => ptrace::cont(pid, None).unwrap_or_else(|err| panic!("Failed to suppress SIGTRAP for pid {pid}: {err}")),
                                    Ok(PtraceEvent(_, sig, _)) => ptrace::cont(pid, sig).unwrap_or_else(|err| panic!("Failed to reinject {sig:?} for pid {pid}: {err}")),
                                    Ok(Exited(_, _)) => {
                                        debug!(%pid, "Process disappeared after attaching to it");
                                        return 0;
                                    },
                                    Ok(event) => panic!("Received unknown waitstatus for pid {pid}: {event:#?}"),
                                    Err(err) => panic!("Failed to wait for attached pid {pid}: {err}"),
                                }
                            }
                            trace!(%pid, "Process now in ptrace-stop state");
                        }

                        entry.insert(PidTracedEntry { ptraced, count: 1 });
                        trace!(%pid, ptraced, "Created pid_counter entry");
                    },
                    Entry::Occupied(entry) => {
                        let ptraced_entry = entry.into_mut();
                        ptraced_entry.count += 1;
                        trace!(%pid, ptraced_entry.count, "Incremented pid_counter entry");
                    },
                }

                mmap_exec_file_event_sender.send(MmapExecFileEvent { mount_point, fs_file_path, pid, ino, ignore_ino: true, detach_pid_sender: detach_pid_sender.clone() })
                    .expect("Failed to send MmapExecFileEvent to channel");

                0
            })?;

            let ring_buffer = builder.build()?;

            let ring_buffer_async_fd = AsyncFd::new(ring_buffer.epoll_fd())?;

            debug!("Instrumenting running processes");
            let instrumenting_running_processes_span = error_span!("Instrumenting Running Processes").entered();

            let all_procs = all_processes()
                .context("Failed to list all processes to attempt to instrument them")?
                .filter_map(|proc| match proc {
                    Ok(proc) => Some(proc),
                    Err(err) => {
                        trace!(?err, "Failed to get a running process entry");
                        None
                    }
                })
                .collect::<Vec<_>>();

            for proc in all_procs {
                let maps = match proc.maps() {
                    Ok(maps) => maps,
                    Err(err) => {
                        debug!(pid = proc.pid, ?err, "Failed to get maps for running process");
                        continue;
                    }
                };

                let exe = proc.exe()
                    .unwrap_or("<unknown>".to_string().into());

                for map in &maps {
                    if !map.perms.contains(MMPermissions::EXECUTE) {
                        continue;
                    }

                    // This is likely an anonymous memory mapping created via
                    // memfd_create()
                    if map.perms.contains(MMPermissions::SHARED) {
                        continue;
                    }

                    let MMapPath::Path(path) = &map.pathname else {
                        continue;
                    };

                    let Some(path) = path.to_str() else {
                        continue;
                    };

                    let fs_file_path = path.to_string();
                    let pid = Pid::from_raw(proc.pid);

                    let mut pid_counters = pid_counters.borrow_mut();
                    match pid_counters.entry(pid) {
                        Entry::Vacant(entry) => {
                            entry.insert(PidTracedEntry { ptraced: false, count: 1 });
                            trace!(%pid, fs_file_path = path.to_string(), ino = map.inode, ptraced_entry.count = 1, ?exe, "Created pid_counter entry for running process");
                        },
                        Entry::Occupied(entry) => {
                            let ptraced_entry = entry.into_mut();
                            ptraced_entry.count += 1;
                            trace!(%pid, fs_file_path = path.to_string(), ino = map.inode, ptraced_entry.count, ?exe, "Incremented pid_counter entry for running process");
                        },
                    }

                    mmap_exec_file_event_sender
                        .send(MmapExecFileEvent {
                            // All proc map paths are absolute paths within the
                            // process's mount namespace
                            mount_point: "/".to_string(),
                            fs_file_path,
                            pid,
                            ino: map.inode,
                            ignore_ino: true,
                            detach_pid_sender: detach_pid_sender.clone(),
                        })
                        .expect("Failed to send MmapExecFileEvent for running process");
                }
            }

            instrumenting_running_processes_span.exit();
            debug!("Finished instrumenting running processes");

            // Send one dummy event with pid set to 0 to signal the agent is ready
            mmap_exec_file_event_sender
                .send(MmapExecFileEvent {
                    mount_point: String::new(),
                    fs_file_path: String::new(),
                    pid: Pid::from_raw(0),
                    ino: 0,
                    ignore_ino: false,
                    detach_pid_sender: detach_pid_sender.clone(),
                })
                .expect("Failed to send initial MmapExecFileEvent at agent startup");

            loop {
                select! {
                    guard = ring_buffer_async_fd.readable() => {
                        let mut guard = guard.expect("Error while waiting for mmap_exec_files ringbuf to be readable");
                        ring_buffer.poll(Duration::ZERO)?;
                        guard.clear_ready_matching(tokio::io::Ready::READABLE);
                    },
                    event = detach_pid_receiver.recv() => {
                        let PidFileReapEvent {pid, ino} = event.expect("detach_pid channel closed unexpectedly");

                        if pid.as_raw() == 0 {
                            // This is the initial event signifying the agent is ready
                            match initialized_sender.take() {
                                Some(sender) => sender.send(()).expect("Failed to send agent initialized signal"),
                                None => panic!("Agent initialized signal twice"),
                            }
                            continue;
                        }

                        let _span = error_span!("detach_pid", pid = pid.as_raw(), ino = ino).entered();

                        // Add bpf LRU hash map entry to mark this inode as having already been evaluated
                        if let Some(ino) = ino {
                            const TRUE_BYTES: &[u8; 1] = &[true as u8];

                            trace!("Marking inode as evaluated");
                            skel.maps.evaluated_inodes
                                .update(&ino.to_ne_bytes(), TRUE_BYTES, MapFlags::ANY)
                                .unwrap_or_else(|err| panic!("Failed to mark inode {ino} as evaluated for mmap_exec_files: {err}"));
                        }

                        let mut pid_counters = pid_counters.borrow_mut();
                        if let Entry::Occupied(mut entry) = pid_counters.entry(pid) {
                            let ptraced_entry = entry.get_mut();

                            ptraced_entry.count -= 1;

                            trace!(ptraced_entry.count, "Dropped count");

                            if ptraced_entry.count == 0 {
                                if ptraced_entry.ptraced {
                                    match ptrace::detach(pid, None) {
                                        Ok(()) => trace!("Detached from PID"),
                                        Err(Errno::ESRCH) => debug!("Process disappeared before we could detach from it"),
                                        Err(err) => panic!("Failed to detach from process {pid}: {err}")
                                    }
                                }
                                entry.remove();
                            }
                        } else {
                            panic!("PID {pid} missing from pid_counters hashmap");
                        }
                    },
                };
            }

            // We can't reach this, but we must have it so typechecking knows
            // what we're returning
            #[allow(unreachable_code)]
            anyhow::Ok(())
        })?;

        Ok(())
    });

    (mmap_exec_file_event_receiver, initialized_receiver)
}
