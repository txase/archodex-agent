use crate::{
    bpf_event_parser_helpers::{field_byte_slice, field_to_event_end_byte_slice},
    bpf_log::bpf_log_impls,
    hexdump::HexDump,
    mmap_exec_files::mmap_exec_files_bpf::types::{
        LogLevel, LogModule, MMAP_EXEC_FILES_EVENT_TYPE, event,
    },
};
use anyhow::{Context, bail, ensure};
use nix::unistd::Pid;
use tracing::{instrument, trace, warn};

use crate::bpf_event_parser_helpers::{field_offset, field_size};

#[derive(Debug)]
pub(crate) struct Event {
    pub(crate) mount_point: String,
    pub(crate) fs_file_path: String,
    pub(crate) pid: Pid,
    pub(crate) ino: u64,
}

impl Event {
    #[instrument(skip_all)]
    pub(crate) fn new(data: &[u8]) -> anyhow::Result<Option<Self>> {
        trace!(
            "Received event data from mmap_exec_files ring buffer:\n{}",
            data.to_hexdump()
        );

        let event_type =
            u32::from_ne_bytes(field_byte_slice!(data, event::r#type).try_into().unwrap());

        let event_type: MMAP_EXEC_FILES_EVENT_TYPE = unsafe { std::mem::transmute(event_type) };

        let pid = Pid::from_raw(i32::from_ne_bytes(
            field_byte_slice!(data, event::pid).try_into().unwrap(),
        ));

        match event_type {
            MMAP_EXEC_FILES_EVENT_TYPE::LOG_MESSAGE => {
                let module: LogModule = u32::from_ne_bytes(
                    field_byte_slice!(data, event::d::log_message::module)
                        .try_into()
                        .unwrap(),
                )
                .into();

                let level: LogLevel = u32::from_ne_bytes(
                    field_byte_slice!(data, event::d::log_message::level)
                        .try_into()
                        .unwrap(),
                )
                .into();

                let level: tracing::Level = level.into();

                let message = String::from_utf8(
                    field_to_event_end_byte_slice!(data, event::d::log_message::message).into(),
                )
                .context("Failed to parse log message from mmap exec file event")?;

                bpf_event!(level, module, message);

                return Ok(None);
            }
            MMAP_EXEC_FILES_EVENT_TYPE::MMAP_EXEC_FILE => {
                let ino = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::mmap_exec_file::ino)
                        .try_into()
                        .unwrap(),
                );

                let paths = String::from_utf8(
                    field_to_event_end_byte_slice!(data, event::d::mmap_exec_file::path).into(),
                )
                .context(
                    "Failed to parse mount point and/or file path from mmap exec file event",
                )?;

                let Ok([mount_point, fs_file_path, sentinel]): Result<[_; 3], _> = paths
                    .split('\0')
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .try_into()
                else {
                    bail!(
                        "Received invalid path payload from event ringbuf:\n{}",
                        paths.as_bytes().to_hexdump()
                    );
                };

                ensure!(
                    sentinel.is_empty(),
                    "Received invalid path payload from event ringbuf:\n{}",
                    paths.as_bytes().to_hexdump()
                );

                let event = Self {
                    mount_point,
                    fs_file_path,
                    pid,
                    ino,
                };

                trace!(?event, "Received mmap_exec_file event");

                Ok(Some(event))
            }
        }
    }
}

bpf_log_impls!();

macro_rules! bpf_event {
    ($lvl:ident, $($arg:tt)+) => {
        match $lvl {
            ::tracing::Level::TRACE => bpf_event_module!(::tracing::Level::TRACE, $($arg)+),
            ::tracing::Level::DEBUG => bpf_event_module!(::tracing::Level::DEBUG, $($arg)+),
            ::tracing::Level::INFO => bpf_event_module!(::tracing::Level::INFO, $($arg)+),
            ::tracing::Level::WARN => bpf_event_module!(::tracing::Level::WARN, $($arg)+),
            ::tracing::Level::ERROR => bpf_event_module!(::tracing::Level::ERROR, $($arg)+),
        }
    };
}

macro_rules! bpf_event_module {
    ($lvl:expr, $mod:ident, $($arg:tt)+) => {
        match $mod {
            LogModule::LOG_MODULE_MMAP_EXEC_FILES => tracing::event!(target: concat!(env!("CARGO_CRATE_NAME"), "::ebpf::mmap_exec_files"), $lvl, $($arg)+),
            LogModule::__LOG_MODULES_NUM_ENTRIES => unreachable!(),
        }
    };
}

pub(crate) use bpf_event;
pub(crate) use bpf_event_module;
