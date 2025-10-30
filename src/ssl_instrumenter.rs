pub(crate) mod libssl_bpf {
    #![allow(clippy::pedantic)]

    #[cfg(target_arch = "aarch64")]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/skel/aarch64/libssl.skel.rs"
    ));

    #[cfg(target_arch = "x86_64")]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/skel/x86_64/libssl.skel.rs"
    ));
}

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, hash_map::Entry},
    mem::MaybeUninit,
    sync::OnceLock,
    time::Duration,
};

use anyhow::Context;
use libbpf_rs::{
    Link, MapCore, MapFlags, RingBufferBuilder,
    skel::{OpenSkel, SkelBuilder},
};
use libssl_bpf::{LibsslSkel, LibsslSkelBuilder, types};
use nix::unistd::Pid;
use tokio::{
    io::unix::AsyncFd,
    select,
    sync::mpsc::{UnboundedReceiver, unbounded_channel},
};
use tracing::{debug, error, error_span, instrument, trace, trace_span, warn};

use crate::{
    bpf_log::bpf_log_module_get_level,
    elf::{
        GoTLSAddresses, LibSSLAddresses, RingAddresses, RustlsAddresses, SymbolAddresses,
        find_symbol_addresses,
    },
    engine::rules::Rules,
    hexdump::HexDump,
    libssl_event_parser::{
        AeadCtxInitEvent, ConnectionFreedEvent, Ctx, Event, ReadDiscardEvent, ReadEvent,
        SNIConfiguredEvent, SNISentEvent, ServerHelloFailureEvent, TlsSocketClosedEvent,
        WriteAllFinishedEvent, WriteEvent, WriteFinishedEvent,
    },
    mmap_exec_files::MmapExecFileEvent,
    mount_path::find_file_path_from_mount_point_and_fs_path,
    pid_waiter::PidWaiter,
    process_context::ProcessContext,
};

#[derive(Debug)]
pub(crate) enum LibsslEvent {
    Open(LibsslOpenEvent),
    Read(LibsslReadWriteEvent),
    Write(LibsslReadWriteEvent),
    Close(LibsslCloseEvent),
}
unsafe impl Send for LibsslEvent {}

#[derive(Debug)]
pub(crate) struct LibsslOpenEvent {
    pub(crate) pid: Pid,
    pub(crate) process_context: ProcessContext,
    pub(crate) ctx: Ctx,
    pub(crate) server_name: String,
}

#[derive(Debug)]
pub(crate) struct LibsslReadWriteEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
    pub(crate) buf: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct LibsslCloseEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn libssl_events(
    mut mmap_exec_file_event_receiver: UnboundedReceiver<MmapExecFileEvent>,
    rules: &Rules,
) -> UnboundedReceiver<LibsslEvent> {
    let (libssl_event_sender, libssl_event_receiver) = unbounded_channel();

    let server_name_filters = rules.server_name_filters();

    std::thread::spawn(move || -> anyhow::Result<()> {
        let span = trace_span!("libssl");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;

        if let Err(err) = rt.block_on(async {
            let mut no_defined_symbols = HashSet::new();
            let mut ino_to_links = HashMap::new();
            let mut rust_ino_to_links = HashMap::new();
            let per_socket_server_names = RefCell::new(HashMap::<Pid, HashMap::<Ctx, String>>::new());
            let per_connection_read_buffers = RefCell::new(HashMap::<Pid, HashMap::<Ctx, LibsslReadWriteEvent>>::new());
            let per_thread_write_buffers = RefCell::new(HashMap::<Pid, HashMap::<u64, LibsslReadWriteEvent>>::new());
            let per_process_contexts = RefCell::new(HashMap::<Pid, ProcessContext>::new());
            let pid_waiter = PidWaiter::new()?;

            let skel_builder = LibsslSkelBuilder::default();
            let mut open_object = MaybeUninit::uninit();
            let open_skel = skel_builder.open(&mut open_object)?;

            assert!((server_name_filters.len() <= open_skel.maps.rodata_data.server_name_filters.len()),
                    "Too many hostname filters generated from the rules (max filters: {}, generated filters: {})",
                    open_skel.maps.rodata_data.server_name_filters.len(), server_name_filters.len()
                );

            open_skel.maps.rodata_data.server_name_filters[..server_name_filters.len()].copy_from_slice(server_name_filters.as_slice());

            open_skel.maps.bss_data.log_levels[types::LogModule::LOG_MODULE_LIBSSL as usize] = bpf_log_module_get_level!("libssl");
            open_skel.maps.bss_data.log_levels[types::LogModule::LOG_MODULE_GOTLS as usize] = bpf_log_module_get_level!("gotls");
            open_skel.maps.bss_data.log_levels[types::LogModule::LOG_MODULE_TLS as usize] = bpf_log_module_get_level!("tls");
            open_skel.maps.bss_data.log_levels[types::LogModule::LOG_MODULE_BORINGSSL as usize] = bpf_log_module_get_level!("boringssl");
            open_skel.maps.bss_data.log_levels[types::LogModule::LOG_MODULE_RING as usize] = bpf_log_module_get_level!("ring");
            open_skel.maps.bss_data.log_levels[types::LogModule::LOG_MODULE_SERVER_NAME_FILTER as usize] = bpf_log_module_get_level!("server_name_filter");

            let mut skel = open_skel.load()?;

            let mut builder = RingBufferBuilder::new();

            builder.add(&skel.maps.events_ringbuf, |data: &[u8]| {
                let _enter = span.enter();

                let event = match Event::new(data) {
                    Ok(Some(event)) => event,
                    Ok(None) => return 0,
                    Err(err) => {
                        error!("Failed to parse event from libssl ring buffer: {err}");
                        return 0;
                    },
                };

                match event {
                    Event::SNIConfigured(SNIConfiguredEvent { pid, ctx, server_name }) => {
                        trace!(%pid, ctx = format!("{ctx:#x}"), server_name, "Adding/Updating SSL connection record: PID -> CTX -> SNI");

                        let process_context = match per_process_contexts.borrow().get(&pid) {
                            Some(process_context) => process_context.clone(),
                            None => {
                                if let Some(process_context) = ProcessContext::new(&pid) {
                                    process_context
                                } else {
                                    warn!(%pid, "Failed to get process context for PID");
                                    return 0;
                                }
                            },
                        };

                        if let Err(err) = pid_waiter.add_pid(&pid) {
                            if err.root_cause().downcast_ref::<syscalls::Errno>() == Some(&syscalls::Errno::ESRCH) {
                                debug!(%pid, "Process disappeared before we could instrument it");
                                return 0;
                            }

                            panic!("Failed to add SSL connection PID to PID Waiter: {err}");
                        }

                        per_process_contexts.borrow_mut().insert(pid, process_context.clone());
                        libssl_event_sender.send(LibsslEvent::Open(LibsslOpenEvent {
                            pid,
                            process_context,
                            ctx,
                            server_name
                        })).expect("Failed to send LibsslEvent to channel");
                    },
                    Event::SNISent(SNISentEvent { pid, ctx, server_name }) => {
                        trace!(%pid, ctx = format!("{ctx:#x}"), server_name, "Adding/Updating TLS socket record: PID -> CTX -> SNI");

                        match per_socket_server_names.borrow_mut().entry(pid) {
                            Entry::Occupied(mut entry) => {
                                entry.get_mut().insert(ctx, server_name);
                            },
                            Entry::Vacant(entry) => {
                                if let Err(err) = pid_waiter.add_pid(&pid) {
                                    if err.root_cause().downcast_ref::<syscalls::Errno>() == Some(&syscalls::Errno::ESRCH) {
                                        debug!(%pid, "Process disappeared before we could instrument it");
                                        return 0;
                                    }

                                    panic!("Failed to add SSL connection PID to PID Waiter: {err}");
                                }

                                let mut socket_map = HashMap::new();
                                socket_map.insert(ctx, server_name);
                                entry.insert(socket_map);
                            }
                        }
                    },
                    Event::ServerHelloFailure(ServerHelloFailureEvent { pid, ctx }) => {
                        trace!(%pid, ctx = format!("{ctx:#x}"), "Removing TLS socket record due to ServerHello failure: PID -> CTX");

                        if let Some(socket_map) = per_socket_server_names.borrow_mut().get_mut(&pid) {
                            socket_map.remove(&ctx);
                        }
                    },
                    Event::TlsSocketClosed(TlsSocketClosedEvent { pid, ctx }) => {
                        trace!(%pid, ctx = format!("{ctx:#x}"), "Removing TLS socket record after closure: PID -> CTX");

                        if let Some(socket_map) = per_socket_server_names.borrow_mut().get_mut(&pid) {
                            socket_map.remove(&ctx);
                        }

                        libssl_event_sender.send(LibsslEvent::Close(LibsslCloseEvent { pid, ctx })).expect("Failed to send LibsslCloseEvent to channel");
                    },
                    Event::AeadCtxInit(AeadCtxInitEvent { pid, ctx }) => {
                        trace!(%pid, ctx = format!("{ctx:#x}"), "Updating TLS socket record: PID -> CTX");

                        let server_name = match per_socket_server_names.borrow_mut().entry(pid) {
                            Entry::Occupied(entry) => {
                                if let Some(server_name) = entry.get().get(&ctx) {
                                    server_name.to_owned()
                                } else {
                                    warn!(%pid, ctx = format!("{ctx:#x}"), "No socket record found for ServerHello received event for PID");
                                    return 0;
                                }
                            },
                            Entry::Vacant(_) => {
                                warn!(%pid, "No socket records found for ServerHello received event for PID");
                                return 0;
                            }
                        };

                        debug!(%pid, ctx = format!("{ctx:#x}"), server_name, "Adding TLS connection record: PID -> CTX -> SNI");

                        let process_context = match per_process_contexts.borrow().get(&pid) {
                            Some(process_context) => process_context.clone(),
                            None => {
                                if let Some(process_context) = ProcessContext::new(&pid) {
                                    process_context
                                } else {
                                    warn!(%pid, "Failed to get process context for PID");
                                    return 0;
                                }
                            },
                        };

                        if let Err(err) = pid_waiter.add_pid(&pid) {
                            if err.root_cause().downcast_ref::<syscalls::Errno>() == Some(&syscalls::Errno::ESRCH) {
                                debug!(%pid, "Process disappeared before we could instrument it");
                                return 0;
                            }

                            panic!("Failed to add SSL connection PID to PID Waiter: {err}");
                        }

                        per_process_contexts.borrow_mut().insert(pid, process_context.clone());
                        libssl_event_sender.send(LibsslEvent::Open(LibsslOpenEvent {
                            pid,
                            process_context: process_context.clone(),
                            ctx,
                            server_name
                        })).expect("Failed to send LibsslOpenEvent to channel");
                    },
                    Event::ConnectionFreed(ConnectionFreedEvent { pid, ctx }) => {
                        trace!(%pid, ctx = format!("{ctx:#x}"), "Removing SSL connection record: PID -> CTX");

                        libssl_event_sender.send(LibsslEvent::Close(LibsslCloseEvent { pid, ctx })).expect("Failed to send LibsslCloseEvent to channel");
                    },
                    Event::Read(ReadEvent { pid, ctx, buf }) => {
                        trace!(%pid, ctx = format!("{ctx:#x}"), "Received read from PID CTX:\n{}", buf.to_hexdump());

                        match per_connection_read_buffers.borrow_mut().entry(pid).or_default().entry(ctx) {
                            Entry::Occupied(mut entry) =>  { entry.get_mut().buf.extend(buf); },
                            Entry::Vacant(entry) => { entry.insert(LibsslReadWriteEvent { pid, ctx, buf }); },
                        }
                    },
                    Event::ReadFinished(ReadEvent { pid, ctx, buf }) => {
                        trace!(%pid, ctx = format!("{ctx:#x}"), "Received read finished from PID CTX:\n{}", buf.to_hexdump());

                        let event = match per_connection_read_buffers.borrow_mut().entry(pid).or_default().remove_entry(&ctx) {
                            Some((_, mut event)) =>  {
                                event.buf.extend(buf);
                                event
                            },
                            None => LibsslReadWriteEvent { pid, ctx, buf }
                        };

                        libssl_event_sender.send(LibsslEvent::Read(event)).expect("Failed to send LibsslReadEvent to channel");
                    },
                    Event::ReadDiscard(ReadDiscardEvent { pid, ctx }) => {
                        trace!(%pid, ctx = format!("{ctx:#x}"), "Received read discard from PID CTX");

                        if let Some(per_context_read_buffers) = per_connection_read_buffers.borrow_mut().get_mut(&pid) {
                            per_context_read_buffers.remove(&ctx);
                        }
                    },
                    Event::Write(WriteEvent { pid, ctx, tid, buf }) => {
                        trace!(%pid, tid, ctx = format!("{ctx:#x}"), "Received write from PID TID CTX:\n{}", buf.to_hexdump());

                        match per_thread_write_buffers.borrow_mut().entry(pid).or_default().entry(tid) {
                            Entry::Occupied(mut entry) =>  { entry.get_mut().buf.extend(buf); },
                            Entry::Vacant(entry) => { entry.insert(LibsslReadWriteEvent { pid, ctx, buf }); },
                        }
                    },
                    Event::WriteFinished(WriteFinishedEvent { pid, tid, num_bytes_written }) => {
                        trace!(%pid, tid, num_bytes_written, "Write finished for PID TID");

                        let mut per_thread_buffers = per_thread_write_buffers.borrow_mut();

                        let Some(pid_per_thread_buffers) = per_thread_buffers.get_mut(&pid) else {
                            debug!(%pid, "No SSL connection buffers for PID while handling WriteFinishedEvent");
                            return 0;
                        };

                        let Some(mut event) = pid_per_thread_buffers.remove(&tid) else {
                            debug!(%pid, tid, "Failed to get SSL connection buffer for PID TID while handling WriteFinishedEvent");
                            return 0;
                        };

                        if num_bytes_written <= 0 {
                            return 0;
                        }

                        event.buf.truncate(num_bytes_written.try_into().unwrap());

                        libssl_event_sender.send(LibsslEvent::Write(event)).expect("Failed to send LibsslEvent to channel");
                    },
                    Event::WriteAllFinished(WriteAllFinishedEvent { pid, tid, success }) => {
                        trace!(%pid, tid, success, "Write all finished for PID TID");

                        let mut per_thread_buffers = per_thread_write_buffers.borrow_mut();

                        let Some(pid_per_thread_buffers) = per_thread_buffers.get_mut(&pid) else {
                            debug!(%pid, "No CTX connection buffers for PID while handling WriteFinishedEvent");
                            return 0;
                        };

                        let Some(event) = pid_per_thread_buffers.remove(&tid) else {
                            warn!(%pid, tid, "Failed to get SSL connection buffer for PID TID while handling WriteFinishedEvent");
                            return 0;
                        };

                        if !success {
                            return 0;
                        }

                        libssl_event_sender.send(LibsslEvent::Write(event)).expect("Failed to send LibsslEvent to channel");
                    },
                }

                0
            })?;

            let ring_buffer = builder.build()?;

            let ring_buffer_async_fd = AsyncFd::new(ring_buffer.epoll_fd())?;

            debug!(target: env!("CARGO_CRATE_NAME"), "Archodex rules loaded");

            loop {
                select! {
                    guard = ring_buffer_async_fd.readable() => {
                        let mut guard = guard.expect("Error while waiting for ssl_instrumenter ringbuf to be readable");
                        ring_buffer.poll(Duration::ZERO)?;
                        guard.clear_ready_matching(tokio::io::Ready::READABLE);
                    },
                    pids = pid_waiter.wait() => {
                        if let Err(err) = pids {
                            eprintln!("Error: {err:#?}");
                            continue;
                        }

                        for pid in pids? {
                            trace!(%pid, "Dropping all SSL connection records for PID");
                            per_socket_server_names.borrow_mut().remove(&pid);
                            per_thread_write_buffers.borrow_mut().remove(&pid);
                            per_process_contexts.borrow_mut().remove(&pid);
                            _ = skel.maps.pids_to_watch.delete(&pid.as_raw().to_ne_bytes());
                        }
                    },
                    mut event = mmap_exec_file_event_receiver.recv() => {
                        let &mut MmapExecFileEvent {
                            ref pid,
                            ref mount_point,
                            ref fs_file_path,
                            ref ino,
                            ref mut ignore_ino,
                            ..
                        } = event.as_mut().expect("mmap_exec_file_event channel closed unexpectedly");

                        let _span = error_span!("mmap_exec_file_event", pid = pid.as_raw(), ino = ino).entered();

                        let Some(path) = find_file_path_from_mount_point_and_fs_path(pid, mount_point, fs_file_path) else {
                            debug!(%pid, "Failed to instrument process before it exited");
                            continue;
                        };

                        if rust_ino_to_links.contains_key(ino) {
                            trace!(%pid, path, ino, "Adding PID for rustls executable file to pids_to_watch");
                            skel.maps.pids_to_watch.update(&pid.as_raw().to_ne_bytes(), &[1u8; 1], MapFlags::ANY).expect("Failed to add PID to pids_to_watch map");
                            *ignore_ino = false;
                        }

                        if no_defined_symbols.contains(ino) || ino_to_links.contains_key(ino) || rust_ino_to_links.contains_key(ino) {
                            trace!(%pid, path, ino, "Not analyzing executable file as it has already been instrumented");
                            continue;
                        }

                        let path = &format!("/proc/{pid}/root{path}");

                        match find_symbol_addresses(path) {
                            Some(SymbolAddresses::LibSSL(addrs)) => {
                                match instrument_libssl(path, &addrs, &mut skel) {
                                    Ok(links) => { ino_to_links.insert(*ino, links); },
                                    Err(err) => {
                                        warn!(%pid, path, ino, ?err, "Received error while instrumenting inode, ignoring future invocations");
                                        no_defined_symbols.insert(*ino);
                                    }
                                }
                            },
                            Some(SymbolAddresses::GoTLS(addrs)) => {
                                match instrument_gotls(path, &addrs, addrs.go_version.minor, &mut skel) {
                                    Ok(links) => { ino_to_links.insert(*ino, links); },
                                    Err(err) => {
                                        warn!(%pid, path, ino, ?err, "Received error while instrumenting inode, ignoring future invocations");
                                        no_defined_symbols.insert(*ino);
                                    }
                                }
                            },
                            Some(SymbolAddresses::Rustls(addrs)) => {
                                match instrument_rustls(path, &addrs, &mut skel) {
                                    Ok(links) => {
                                        rust_ino_to_links.insert(*ino, links);
                                        *ignore_ino = false;
                                        skel.maps.pids_to_watch.update(&pid.as_raw().to_ne_bytes(), &[1u8; 1], MapFlags::ANY).expect("Failed to add PID to pids_to_watch map");
                                    },
                                    Err(err) => {
                                        warn!(%pid, path, ino, ?err, "Received error while instrumenting inode, ignoring future invocations");
                                        no_defined_symbols.insert(*ino);
                                    },
                                }
                            },
                            Some(SymbolAddresses::Ring(addrs)) => {
                                match instrument_ring(path, &addrs, &mut skel) {
                                    Ok(links) => {
                                        rust_ino_to_links.insert(*ino, links);
                                        *ignore_ino = false;
                                        skel.maps.pids_to_watch.update(&pid.as_raw().to_ne_bytes(), &[1u8; 1], MapFlags::ANY).expect("Failed to add PID to pids_to_watch map");
                                    },
                                    Err(err) => {
                                        warn!(%pid, path, ino, ?err, "Received error while instrumenting inode, ignoring future invocations");
                                        no_defined_symbols.insert(*ino);
                                    },
                                }
                            }
                            None => {
                                trace!(%pid, path, ino, "No TLS symbols found in executable file");
                                no_defined_symbols.insert(*ino);
                            }
                        }
                    }
                }
            }

            // We can't reach this, but we must have it so typechecking knows
            // what we're returning
            #[allow(unreachable_code)]
            anyhow::Ok(())
        }) {
            panic!("Error in libssl_events thread: {err:#}");
        }

        unreachable!()
    });

    libssl_event_receiver
}

#[instrument(skip(addrs, skel))]
fn instrument_libssl(
    path: &str,
    addrs: &LibSSLAddresses,
    skel: &mut LibsslSkel,
) -> anyhow::Result<Vec<Link>> {
    debug!("Instrumenting executable for libssl");

    let mut links = vec![
        skel.progs
            .libssl_SSL_ctrl_entry
            .attach_uprobe(false, -1, path, addrs.ssl_ctrl)
            .context(format!(
                "Failed to attach SSL_ctrl_entry probe to {path} at address 0x{:x}",
                addrs.ssl_ctrl
            ))?,
        skel.progs
            .libssl_SSL_free_entry
            .attach_uprobe(false, -1, path, addrs.ssl_free)
            .context(format!(
                "Failed to attach SSL_free_entry probe to {path} at address 0x{:x}",
                addrs.ssl_free
            ))?,
    ];

    if let Some(addr) = addrs.ssl_read {
        links.push(
            skel.progs
                .libssl_SSL_read_entry
                .attach_uprobe(false, -1, path, addr)
                .context(format!(
                    "Failed to attach SSL_read_entry probe to {path} at address 0x{addr:x}"
                ))?,
        );

        links.push(
            skel.progs
                .libssl_SSL_read_exit
                .attach_uprobe(true, -1, path, addr)
                .context(format!(
                    "Failed to attach SSL_read_exit probe to {path} at address 0x{addr:x}"
                ))?,
        );
    }

    if let Some(addr) = addrs.ssl_read_ex {
        links.push(
            skel.progs
                .libssl_SSL_read_ex_entry
                .attach_uprobe(false, -1, path, addr)
                .context(format!(
                    "Failed to attach SSL_read_ex_entry probe to {path} at address 0x{addr:x}"
                ))?,
        );

        links.push(
            skel.progs
                .libssl_SSL_read_ex_exit
                .attach_uprobe(true, -1, path, addr)
                .context(format!(
                    "Failed to attach SSL_read_ex_exit probe to {path} at address 0x{addr:x}"
                ))?,
        );
    }

    if let Some(addr) = addrs.ssl_write {
        links.push(
            skel.progs
                .libssl_SSL_write_entry
                .attach_uprobe(false, -1, path, addr)
                .context(format!(
                    "Failed to attach SSL_write_entry probe to {path} at address 0x{addr:x}"
                ))?,
        );

        links.push(
            skel.progs
                .libssl_SSL_write_exit
                .attach_uprobe(true, -1, path, addr)
                .context(format!(
                    "Failed to attach SSL_write_exit probe to {path} at address 0x{addr:x}"
                ))?,
        );
    }

    if let Some(addr) = addrs.ssl_write_ex {
        links.push(
            skel.progs
                .libssl_SSL_write_ex_entry
                .attach_uprobe(false, -1, path, addr)
                .context(format!(
                    "Failed to attach SSL_write_ex_entry probe to {path} at address 0x{addr:x}"
                ))?,
        );

        links.push(
            skel.progs
                .libssl_SSL_write_ex_exit
                .attach_uprobe(true, -1, path, addr)
                .context(format!(
                    "Failed to attach SSL_write_ex_exit probe to {path} at address 0x{addr:x}"
                ))?,
        );
    }

    Ok(links)
}

#[instrument(skip(addrs, skel))]
fn instrument_gotls(
    path: &str,
    addrs: &GoTLSAddresses,
    go_version_minor: u16,
    skel: &mut LibsslSkel,
) -> anyhow::Result<Vec<Link>> {
    debug!("Instrumenting executable for Go runtime version 1.{go_version_minor}");

    let mut links = vec![
        skel.progs
            .go_tls_conn_handshake_context
            .attach_uprobe(false, -1, path, addrs.handshake_context.entry)
            .context(format!(
                "Failed to attach go_tls_conn_handshake_context probe to {path} at address 0x{:x}",
                addrs.handshake_context.entry
            ))?,
        skel.progs
            .go_tls_conn_close
            .attach_uprobe(false, -1, path, addrs.close.entry)
            .context(format!(
                "Failed to attach go_tls_conn_close probe to {path} at address 0x{:x}",
                addrs.close.entry
            ))?,
    ];

    // Symbols from Go version < 1.21 files are ignored in find_symbols_in_gopclntab()
    let (read_entry, read_exit, write_entry, write_exit) = if go_version_minor >= 23 {
        (
            &mut skel.progs.go_tls_conn_read_entry_1_23,
            &mut skel.progs.go_tls_conn_read_exit_1_23,
            &mut skel.progs.go_tls_conn_write_entry_1_23,
            &mut skel.progs.go_tls_conn_write_exit_1_23,
        )
    } else {
        (
            &mut skel.progs.go_tls_conn_read_entry_1_21,
            &mut skel.progs.go_tls_conn_read_exit_1_21,
            &mut skel.progs.go_tls_conn_write_entry_1_21,
            &mut skel.progs.go_tls_conn_write_exit_1_21,
        )
    };

    links.push(
        read_entry
            .attach_uprobe(false, -1, path, addrs.read.entry)
            .context(format!(
                "Failed to attach go_tls_conn_read_entry probe to {path} at address 0x{:x}",
                addrs.read.entry
            ))?,
    );

    for exit in &addrs.read.exits {
        links.push(
            read_exit
                .attach_uprobe(true, -1, path, *exit)
                .context(format!(
                    "Failed to attach go_tls_conn_read_exit probe to {path} at address 0x{exit:x}"
                ))?,
        );
    }

    links.push(
        write_entry
            .attach_uprobe(false, -1, path, addrs.write.entry)
            .context(format!(
                "Failed to attach go_tls_conn_write_entry probe to {path} at address 0x{:x}",
                addrs.write.entry
            ))?,
    );

    for exit in &addrs.write.exits {
        links.push(
            write_exit
                .attach_uprobe(true, -1, path, *exit)
                .context(format!(
                    "Failed to attach go_tls_conn_write_exit probe to {path} at address 0x{exit:x}"
                ))?,
        );
    }

    Ok(links)
}

struct OnceLinks {
    _inner: Vec<Link>,
}
unsafe impl Sync for OnceLinks {}

fn instrument_tls(skel: &mut LibsslSkel) {
    static TCP_LINKS: OnceLock<OnceLinks> = OnceLock::new();

    TCP_LINKS.get_or_init(|| {
        debug!("Encountered first rust executable, attaching to tcp_v[46]_connect(), tcp_sendmsg(), and tcp_recvmsg()");
        OnceLinks { _inner: vec![
            skel.progs.tcp_v4_connect_exit.attach().expect("Failed to attach tcp_v4_connect_exit probe"),
            skel.progs.tcp_v6_connect_exit.attach().expect("Failed to attach tcp_v6_connect_exit probe"),
            skel.progs.tcp_sendmsg_entry.attach().expect("Failed to attach tcp_sendmsg_entry probe"),
            skel.progs.tcp_sendmsg_exit.attach().expect("Failed to attach tcp_sendmsg_exit probe"),
            skel.progs.tcp_recvmsg_entry.attach().expect("Failed to attach tcp_recvmsg_entry probe"),
            skel.progs.tcp_recvmsg_exit.attach().expect("Failed to attach tcp_recvmsg_exit probe"),
            skel.progs.tcp_close_entry.attach().expect("Failed to attach tcp_close_entry probe"),
        ] }
    });
}

#[instrument(skip(addrs, skel))]
fn instrument_rustls(
    path: &str,
    addrs: &RustlsAddresses,
    skel: &mut LibsslSkel,
) -> anyhow::Result<Vec<Link>> {
    debug!("Instrumenting executable for rustls");

    instrument_tls(skel);

    Ok(vec![
        skel
            .progs
            .EVP_AEAD_CTX_init_with_direction_entry
            .attach_uprobe(false, -1, path, addrs.evp_aead_ctx_init_with_direction)
            .context(format!(
                "Failed to attach EVP_AEAD_CTX_init_with_direction_entry probe to {path} at address 0x{:x}", addrs.evp_aead_ctx_init_with_direction
            ))?,

        skel
            .progs
            .EVP_AEAD_CTX_seal_entry
            .attach_uprobe(false, -1, path, addrs.evp_aead_ctx_seal)
            .context(format!(
                "Failed to attach EVP_AEAD_CTX_seal_entry probe to {path} at address 0x{:x}", addrs.evp_aead_ctx_seal
            ))?,

        skel
            .progs
            .EVP_AEAD_CTX_open_entry
            .attach_uprobe(false, -1, path, addrs.evp_aead_ctx_open)
            .context(format!(
                "Failed to attach EVP_AEAD_CTX_open_entry probe to {path} at address 0x{:x}", addrs.evp_aead_ctx_open
            ))?,

        skel
            .progs
            .EVP_AEAD_CTX_open_exit
            .attach_uprobe(true, -1, path, addrs.evp_aead_ctx_open)
            .context(format!(
                "Failed to attach EVP_AEAD_CTX_open_exit probe to {path} at address 0x{:x}", addrs.evp_aead_ctx_open
            ))?,
    ])
}

#[instrument(skip(addrs, skel))]
fn instrument_ring(
    path: &str,
    addrs: &RingAddresses,
    skel: &mut LibsslSkel,
) -> anyhow::Result<Vec<Link>> {
    debug!("Instrumenting executable for ring");

    instrument_tls(skel);

    let mut links = vec![
        skel
            .progs
            .aes_hw_set_encrypt_key_entry
            .attach_uprobe(false, -1, path, addrs.aes_hw_set_encrypt_key)
            .context(format!(
                "Failed to attach aes_hw_set_encrypt_key_entry probe to {path} at address 0x{:x}", addrs.aes_hw_set_encrypt_key
            ))?,

        skel
            .progs
            .aes_hw_set_encrypt_key_exit
            .attach_uprobe(true, -1, path, addrs.aes_hw_set_encrypt_key)
            .context(format!(
                "Failed to attach aes_hw_set_encrypt_key_exit probe to {path} at address 0x{:x}", addrs.aes_hw_set_encrypt_key
            ))?,

        skel
            .progs
            .aes_hw_ctr32_encrypt_blocks_entry
            .attach_uprobe(false, -1, path, addrs.aes_hw_ctr32_encrypt_blocks)
            .context(format!(
                "Failed to attach aes_hw_ctr32_encrypt_blocks_entry probe to {path} at address 0x{:x}", addrs.aes_hw_ctr32_encrypt_blocks
            ))?,

        skel
            .progs
            .aes_hw_ctr32_encrypt_blocks_exit
            .attach_uprobe(true, -1, path, addrs.aes_hw_ctr32_encrypt_blocks)
            .context(format!(
                "Failed to attach aes_hw_ctr32_encrypt_blocks_exit probe to {path} at address 0x{:x}", addrs.aes_hw_ctr32_encrypt_blocks
            ))?,
    ];

    #[cfg(target_arch = "x86_64")]
    {
        links.push(
            skel.progs
                .aesni_gcm_encrypt_entry
                .attach_uprobe(false, -1, path, addrs.aesni_gcm_encrypt)
                .context(format!(
                    "Failed to attach aesni_gcm_encrypt_entry probe to {path} at address 0x{:x}",
                    addrs.aesni_gcm_encrypt
                ))?,
        );

        links.push(
            skel.progs
                .aesni_gcm_decrypt_entry
                .attach_uprobe(false, -1, path, addrs.aesni_gcm_decrypt)
                .context(format!(
                    "Failed to attach aesni_gcm_decrypt_entry probe to {path} at address 0x{:x}",
                    addrs.aesni_gcm_decrypt
                ))?,
        );

        links.push(
            skel.progs
                .aesni_gcm_decrypt_exit
                .attach_uprobe(true, -1, path, addrs.aesni_gcm_decrypt)
                .context(format!(
                    "Failed to attach aesni_gcm_decrypt_exit probe to {path} at address 0x{:x}",
                    addrs.aesni_gcm_decrypt
                ))?,
        );
    }

    #[cfg(target_arch = "aarch64")]
    {
        links.push(
            skel.progs
                .aes_gcm_enc_kernel_entry
                .attach_uprobe(false, -1, path, addrs.aes_gcm_enc_kernel)
                .context(format!(
                    "Failed to attach aes_gcm_enc_kernel_entry probe to {path} at address 0x{:x}",
                    addrs.aes_gcm_enc_kernel
                ))?,
        );

        links.push(
            skel.progs
                .aes_gcm_dec_kernel_entry
                .attach_uprobe(false, -1, path, addrs.aes_gcm_dec_kernel)
                .context(format!(
                    "Failed to attach aes_gcm_dec_kernel_entry probe to {path} at address 0x{:x}",
                    addrs.aes_gcm_dec_kernel
                ))?,
        );

        links.push(
            skel.progs
                .aes_gcm_dec_kernel_exit
                .attach_uprobe(true, -1, path, addrs.aes_gcm_dec_kernel)
                .context(format!(
                    "Failed to attach aes_gcm_dec_kernel_exit probe to {path} at address 0x{:x}",
                    addrs.aes_gcm_dec_kernel
                ))?,
        );
    }

    Ok(links)
}
