use crate::{
    bpf_log::bpf_log_impls,
    hexdump::{DebugVecU8, HexDump},
    ssl_instrumenter::libssl_bpf::types::{LogLevel, LogModule, SSL_EVENT_TYPE, event},
};
use anyhow::Context;
use nix::unistd::Pid;
use tracing::{instrument, trace, warn};

use crate::bpf_event_parser_helpers::{
    field_byte_slice, field_offset, field_size, field_to_event_end_byte_slice,
};

pub(crate) type Ctx = u64;

#[derive(Debug)]
pub(crate) enum Event {
    SNIConfigured(SNIConfiguredEvent),
    SNISent(SNISentEvent),
    ServerHelloFailure(ServerHelloFailureEvent),
    TlsSocketClosed(TlsSocketClosedEvent),
    AeadCtxInit(AeadCtxInitEvent),
    ConnectionFreed(ConnectionFreedEvent),
    Read(ReadEvent),
    ReadFinished(ReadEvent),
    ReadDiscard(ReadDiscardEvent),
    Write(WriteEvent),
    WriteFinished(WriteFinishedEvent),
    WriteAllFinished(WriteAllFinishedEvent),
}

#[derive(Debug)]
pub(crate) struct SNIConfiguredEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
    pub(crate) server_name: String,
}

#[derive(Debug)]
pub(crate) struct SNISentEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
    pub(crate) server_name: String,
}

#[derive(Debug)]
pub(crate) struct ServerHelloFailureEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
}

#[derive(Debug)]
pub(crate) struct TlsSocketClosedEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
}

#[derive(Debug)]
pub(crate) struct AeadCtxInitEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
}

#[derive(Debug)]
pub(crate) struct ConnectionFreedEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
}

pub(crate) struct ReadEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
    pub(crate) buf: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct ReadDiscardEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
}

impl std::fmt::Debug for ReadEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadEvent")
            .field("pid", &self.pid)
            .field("ctx", &self.ctx)
            .field("buf", &DebugVecU8::from(&self.buf))
            .finish()
    }
}

pub(crate) struct WriteEvent {
    pub(crate) pid: Pid,
    pub(crate) ctx: Ctx,
    pub(crate) tid: u64,
    pub(crate) buf: Vec<u8>,
}

impl std::fmt::Debug for WriteEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteEvent")
            .field("pid", &self.pid)
            .field("ctx", &self.ctx)
            .field("tid", &self.tid)
            .field("buf", &DebugVecU8::from(&self.buf))
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct WriteFinishedEvent {
    pub(crate) pid: Pid,
    pub(crate) tid: u64,
    pub(crate) num_bytes_written: i32,
}

#[derive(Debug)]
pub(crate) struct WriteAllFinishedEvent {
    pub(crate) pid: Pid,
    pub(crate) tid: u64,
    pub(crate) success: bool,
}

impl Event {
    #[instrument(skip(data))]
    pub(crate) fn new(data: &[u8]) -> anyhow::Result<Option<Self>> {
        trace!(
            "Received event data from libssl ring buffer:\n{}",
            data.to_hexdump()
        );

        let event_type =
            u32::from_ne_bytes(field_byte_slice!(data, event::r#type).try_into().unwrap());

        let event_type: SSL_EVENT_TYPE = unsafe { std::mem::transmute(event_type) };

        let pid = Pid::from_raw(i32::from_ne_bytes(
            field_byte_slice!(data, event::pid).try_into().unwrap(),
        ));

        let event = match event_type {
            SSL_EVENT_TYPE::LOG_MESSAGE => {
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
                .context("Failed to parse log message from libssl event")?;

                bpf_event!(level, module, message);

                return Ok(None);
            }
            SSL_EVENT_TYPE::SNI_CONFIGURED => {
                let ctx = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::sni_configured::ssl)
                        .try_into()
                        .unwrap(),
                );
                let server_name = String::from_utf8(
                    field_to_event_end_byte_slice!(data, event::d::sni_configured::server_name)
                        .into(),
                )
                .context("Failed to parse server_name from libssl event")?;

                Self::SNIConfigured(SNIConfiguredEvent {
                    pid,
                    ctx,
                    server_name,
                })
            }
            SSL_EVENT_TYPE::SNI_SENT => {
                let ctx = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::sni_sent::ctx)
                        .try_into()
                        .unwrap(),
                );
                let server_name = String::from_utf8(
                    field_to_event_end_byte_slice!(data, event::d::sni_sent::server_name).into(),
                )
                .context("Failed to parse server_name from libssl event")?;

                Self::SNISent(SNISentEvent {
                    pid,
                    ctx,
                    server_name,
                })
            }
            SSL_EVENT_TYPE::SERVER_HELLO_FAILURE => {
                let ctx = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::server_hello_failure::ctx)
                        .try_into()
                        .unwrap(),
                );

                Self::ServerHelloFailure(ServerHelloFailureEvent { pid, ctx })
            }
            SSL_EVENT_TYPE::TLS_SOCKET_CLOSED => {
                let ctx = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::tls_socket_closed::ctx)
                        .try_into()
                        .unwrap(),
                );

                Self::TlsSocketClosed(TlsSocketClosedEvent { pid, ctx })
            }
            SSL_EVENT_TYPE::AEAD_CTX_INIT => {
                let ctx = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::aead_ctx_init::ctx)
                        .try_into()
                        .unwrap(),
                );

                Self::AeadCtxInit(AeadCtxInitEvent { pid, ctx })
            }
            SSL_EVENT_TYPE::CONNECTION_FREED => {
                let ctx = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::connection_freed::ssl)
                        .try_into()
                        .unwrap(),
                );

                Self::ConnectionFreed(ConnectionFreedEvent { pid, ctx })
            }
            SSL_EVENT_TYPE::READ => {
                let ctx = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::read::ctx)
                        .try_into()
                        .unwrap(),
                );
                let buf = field_to_event_end_byte_slice!(data, event::d::read::buf).to_vec();

                Self::Read(ReadEvent { pid, ctx, buf })
            }
            SSL_EVENT_TYPE::READ_FINISHED => {
                let ctx = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::read::ctx)
                        .try_into()
                        .unwrap(),
                );
                let buf = field_to_event_end_byte_slice!(data, event::d::read::buf).to_vec();

                Self::ReadFinished(ReadEvent { pid, ctx, buf })
            }
            SSL_EVENT_TYPE::READ_DISCARD => {
                let ctx = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::read::ctx)
                        .try_into()
                        .unwrap(),
                );

                Self::ReadDiscard(ReadDiscardEvent { pid, ctx })
            }
            SSL_EVENT_TYPE::WRITE => {
                let ctx = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::write::ctx)
                        .try_into()
                        .unwrap(),
                );
                let tid = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::write::tid)
                        .try_into()
                        .unwrap(),
                );
                let buf = field_to_event_end_byte_slice!(data, event::d::write::buf).to_vec();

                Self::Write(WriteEvent { pid, ctx, tid, buf })
            }
            SSL_EVENT_TYPE::WRITE_FINISHED => {
                let tid = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::write_finished::tid)
                        .try_into()
                        .unwrap(),
                );
                let num_bytes_written = i32::from_ne_bytes(
                    field_byte_slice!(data, event::d::write_finished::num_bytes_written)
                        .try_into()
                        .unwrap(),
                );

                Self::WriteFinished(WriteFinishedEvent {
                    pid,
                    tid,
                    num_bytes_written,
                })
            }
            SSL_EVENT_TYPE::WRITE_ALL_FINISHED => {
                let tid = u64::from_ne_bytes(
                    field_byte_slice!(data, event::d::write_all_finished::tid)
                        .try_into()
                        .unwrap(),
                );
                let success = data[field_offset!(event::d::write_all_finished::success)] != 0;

                Self::WriteAllFinished(WriteAllFinishedEvent { pid, tid, success })
            }
        };

        trace!(?event, "Received libssl event");

        Ok(Some(event))
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
            LogModule::LOG_MODULE_LIBSSL => tracing::event!(target: concat!(env!("CARGO_CRATE_NAME"), "::ebpf::libssl"), $lvl, $($arg)+),
            LogModule::LOG_MODULE_GOTLS => tracing::event!(target: concat!(env!("CARGO_CRATE_NAME"), "::ebpf::gotls"), $lvl, $($arg)+),
            LogModule::LOG_MODULE_TLS => tracing::event!(target: concat!(env!("CARGO_CRATE_NAME"), "::ebpf::tls"), $lvl, $($arg)+),
            LogModule::LOG_MODULE_BORINGSSL => tracing::event!(target: concat!(env!("CARGO_CRATE_NAME"), "::ebpf::boringssl"), $lvl, $($arg)+),
            LogModule::LOG_MODULE_RING => tracing::event!(target: concat!(env!("CARGO_CRATE_NAME"), "::ebpf::ring"), $lvl, $($arg)+),
            LogModule::LOG_MODULE_SERVER_NAME_FILTER => tracing::event!(target: concat!(env!("CARGO_CRATE_NAME"), "::ebpf::server_name_filter"), $lvl, $($arg)+),
            LogModule::__LOG_MODULES_NUM_ENTRIES => unreachable!(),
        }
    };
}

pub(crate) use bpf_event;
pub(crate) use bpf_event_module;
