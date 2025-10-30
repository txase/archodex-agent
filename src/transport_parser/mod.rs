pub(crate) mod http;
mod http1;
mod http2;

use std::collections::{HashMap, HashSet};

use http::HttpRequestResponse;
use http2::Http2Connection;
use nix::unistd::Pid;
use tokio::{
    spawn,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tracing::{instrument, trace, warn};

use http1::Http1Connection;

use crate::{
    libssl_event_parser::Ctx,
    process_context::ProcessContext,
    ssl_instrumenter::{LibsslCloseEvent, LibsslEvent, LibsslOpenEvent, LibsslReadWriteEvent},
};

#[derive(Debug)]
pub(crate) enum TransportEvent {
    Http(HttpRequestResponse),
}

#[derive(Clone, Debug)]
pub(super) struct ConnectionContext {
    server_name: String,
    process_context: ProcessContext,
}

#[instrument(skip(libssl_event_receiver))]
pub(crate) fn transport_parser(
    mut libssl_event_receiver: UnboundedReceiver<LibsslEvent>,
) -> UnboundedReceiver<TransportEvent> {
    let (message_event_sender, message_event_receiver) = unbounded_channel();

    spawn(async move {
        let mut connection_contexts = HashMap::new();
        let mut connections = HashMap::new();
        let mut ignored_connections = HashSet::new();

        while let Some(event) = libssl_event_receiver.recv().await {
            match event {
                LibsslEvent::Open(LibsslOpenEvent {
                    pid,
                    process_context,
                    ctx,
                    server_name,
                }) => {
                    trace!(
                        container_id = process_context.container_id(),
                        %pid,
                        ctx,
                        server_name,
                        "Received LibsslEvent::Open"
                    );

                    connection_contexts.insert(
                        (pid, ctx),
                        ConnectionContext {
                            server_name,
                            process_context,
                        },
                    );
                }
                LibsslEvent::Write(LibsslReadWriteEvent { pid, ctx, mut buf }) => {
                    if ignored_connections.contains(&(pid, ctx)) {
                        continue;
                    }

                    trace!(%pid, ctx, "Received LibsslEvent::Write");

                    let connection = if let Some(connection) = connections.get_mut(&(pid, ctx)) {
                        connection
                    } else {
                        let Some(connection_context) = connection_contexts.remove(&(pid, ctx))
                        else {
                            warn!(
                                %pid,
                                ctx = format!("0x{:x}", ctx),
                                "Missing server_name entry, ignoring connection"
                            );
                            ignored_connections.insert((pid, ctx));
                            continue;
                        };

                        if let Some(connection) = Connection::new(
                            pid,
                            ctx,
                            &connection_context,
                            &message_event_sender,
                            &mut buf,
                        ) {
                            connections.insert((pid, ctx), connection);
                            connections.get_mut(&(pid, ctx)).unwrap()
                        } else {
                            warn!(
                                %pid,
                                ctx = format!("0x{:x}", ctx),
                                server_name = connection_context.server_name,
                                "Did not find HTTP client context, ignoring connection",
                            );
                            ignored_connections.insert((pid, ctx));
                            continue;
                        }
                    };

                    connection.handle_client_message(buf.as_slice());
                }
                LibsslEvent::Read(LibsslReadWriteEvent { pid, ctx, buf }) => {
                    if ignored_connections.contains(&(pid, ctx)) {
                        continue;
                    }

                    trace!(%pid, ctx, "Received LibsslEvent::Read");

                    if let Some(connection) = connections.get_mut(&(pid, ctx)) {
                        connection.handle_server_message(buf.as_slice());
                    } else {
                        warn!(
                            %pid,
                            ctx = format!("0x{:x}", ctx),
                            "Unknown connection while handling read event, ignoring"
                        );
                    }
                }
                LibsslEvent::Close(LibsslCloseEvent { pid, ctx }) => {
                    trace!(%pid, ctx, "Received LibsslEvent::Close");

                    if let Some(connection) = connections.get_mut(&(pid, ctx)) {
                        connection.handle_close();
                    } else {
                        warn!(
                            %pid,
                            ctx = format!("0x{:x}", ctx),
                            "Unknown connection while handling close event, ignoring"
                        );
                    }

                    ignored_connections.remove(&(pid, ctx));
                    connections.remove(&(pid, ctx));
                }
            }
        }
    });

    message_event_receiver
}

pub(crate) trait TransportParser: Sized {
    fn new(
        pid: Pid,
        ctx: Ctx,
        connection_context: &ConnectionContext,
        message_event_sender: &UnboundedSender<TransportEvent>,
        buf: &mut Vec<u8>,
    ) -> Option<Self>;
    fn handle_client_message(&mut self, buf: &[u8]);
    fn handle_server_message(&mut self, buf: &[u8]);
    fn handle_close(&mut self);
}

#[allow(clippy::large_enum_variant)]
enum Connection<'a> {
    Http2(Http2Connection<'a>),
    Http1(Http1Connection),
}

impl TransportParser for Connection<'_> {
    #[instrument(level = "error", skip_all, fields(pid = pid.as_raw(), ctx, connection_context))]
    fn new(
        pid: Pid,
        ctx: Ctx,
        connection_context: &ConnectionContext,
        message_event_sender: &UnboundedSender<TransportEvent>,
        buf: &mut Vec<u8>,
    ) -> Option<Self> {
        if let Some(connection) =
            Http2Connection::new(pid, ctx, connection_context, message_event_sender, buf)
        {
            return Some(Connection::Http2(connection));
        }

        if let Some(connection) =
            Http1Connection::new(pid, ctx, connection_context, message_event_sender, buf)
        {
            return Some(Connection::Http1(connection));
        }

        None
    }

    fn handle_client_message(&mut self, buf: &[u8]) {
        match self {
            Self::Http2(connection) => connection.handle_client_message(buf),
            Self::Http1(connection) => connection.handle_client_message(buf),
        }
    }

    fn handle_server_message(&mut self, buf: &[u8]) {
        match self {
            Self::Http2(connection) => connection.handle_server_message(buf),
            Self::Http1(connection) => connection.handle_server_message(buf),
        }
    }

    fn handle_close(&mut self) {
        match self {
            Self::Http2(connection) => connection.handle_close(),
            Self::Http1(connection) => connection.handle_close(),
        }
    }
}
