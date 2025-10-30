use std::{borrow::Cow, collections::HashMap};

use nix::unistd::Pid;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, instrument, trace, warn};

use crate::{hexdump::HexDump, libssl_event_parser::Ctx, transport_parser::http::DebugBody};

use super::{ConnectionContext, HttpRequestResponse, TransportEvent, TransportParser};

#[repr(u8)]
enum Http2FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    Goaway,
    WindowUpdate,
    Continuation,
}

impl TryFrom<u8> for Http2FrameType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use Http2FrameType::{
            Continuation, Data, Goaway, Headers, Ping, Priority, PushPromise, RstStream, Settings,
            WindowUpdate,
        };

        match value {
            0x00 => Ok(Data),
            0x01 => Ok(Headers),
            0x02 => Ok(Priority),
            0x03 => Ok(RstStream),
            0x04 => Ok(Settings),
            0x05 => Ok(PushPromise),
            0x06 => Ok(Ping),
            0x07 => Ok(Goaway),
            0x08 => Ok(WindowUpdate),
            0x09 => Ok(Continuation),
            val => Err(format!("Invalid HTTP/2 frame type 0x{val:x}")),
        }
    }
}

#[repr(u8)]
enum Http2Flags {
    Priority = 0x20,
    Padded = 0x08,
    EndHeaders = 0x04,
    EndStream = 0x01,
}

type StreamId = u32;

struct RequestResponseBuilders {
    request: Option<http::request::Builder>,
    request_body_buf: Vec<u8>,
    response: Option<http::response::Builder>,
    response_body_buf: Vec<u8>,
}

pub(crate) struct Http2Connection<'a> {
    pid: Pid,
    ctx: Ctx,
    connection_context: ConnectionContext,
    transport_event_sender: UnboundedSender<TransportEvent>,
    hpack_decoder: hpack::decoder::Decoder<'a>,
    client_frame_buf: Vec<u8>,
    client_headers_stream_id: StreamId,
    client_headers_buf: Vec<u8>,
    server_frame_buf: Vec<u8>,
    server_headers_stream_id: StreamId,
    server_headers_buf: Vec<u8>,
    streams: HashMap<StreamId, RequestResponseBuilders>,
}

impl TransportParser for Http2Connection<'_> {
    #[instrument(level = "error", skip_all)]
    fn new(
        pid: Pid,
        ctx: Ctx,
        connection_context: &ConnectionContext,
        transport_event_sender: &UnboundedSender<TransportEvent>,
        buf: &mut Vec<u8>,
    ) -> Option<Self> {
        const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        if buf.as_slice().starts_with(HTTP2_PREFACE) {
            buf.drain(..HTTP2_PREFACE.len());

            debug!("New HTTP/2 client context, creating connection");

            Some(Self {
                pid,
                ctx,
                connection_context: connection_context.to_owned(),
                transport_event_sender: transport_event_sender.clone(),
                hpack_decoder: hpack::decoder::Decoder::new(),
                client_frame_buf: vec![],
                client_headers_stream_id: 0,
                client_headers_buf: vec![],
                server_frame_buf: vec![],
                server_headers_stream_id: 0,
                server_headers_buf: vec![],
                streams: HashMap::new(),
            })
        } else {
            None
        }
    }

    #[instrument(level = "error", skip_all, fields(pid = self.pid.as_raw(), ctx = self.ctx, server_name = self.connection_context.server_name))]
    fn handle_client_message(&mut self, buf: &[u8]) {
        trace!("Received HTTP/2 client buffer:\n{}", buf.to_hexdump());

        self.client_frame_buf.extend_from_slice(buf);

        loop {
            if self.client_frame_buf.len() < 9usize {
                return;
            }

            let payload_len = ((self.client_frame_buf[0] as usize) << 16)
                | ((self.client_frame_buf[1] as usize) << 8)
                | self.client_frame_buf[2] as usize;

            if self.client_frame_buf.len() < 9 + payload_len {
                return;
            }

            trace!(
                "Handling HTTP/2 client frame:\n{}",
                self.client_frame_buf[..9 + payload_len].to_hexdump()
            );

            match self.client_frame_buf[3].try_into() {
                Ok(Http2FrameType::Headers) => {
                    let flags = self.client_frame_buf[4];
                    self.client_headers_stream_id =
                        u32::from_be_bytes(self.client_frame_buf[5..9].try_into().unwrap());

                    let mut headers_block = &self.client_frame_buf[9..9 + payload_len];

                    if flags & (Http2Flags::Padded as u8) != 0 {
                        let pad_length = self.client_frame_buf[9] as usize;
                        headers_block = &headers_block[1..payload_len - pad_length];
                    }

                    if flags & (Http2Flags::Priority as u8) != 0 {
                        headers_block = &headers_block[5..];
                    }

                    self.client_headers_buf.extend_from_slice(headers_block);

                    if flags & (Http2Flags::EndHeaders as u8) != 0 {
                        match self.hpack_decoder.decode(&self.client_headers_buf) {
                            Ok(headers) => self.handle_client_headers(headers),
                            Err(err) => warn!(
                                stream = self.client_headers_stream_id,
                                ?err,
                                "Received invalid HTTP/2 request headers / trailers for stream"
                            ),
                        }

                        self.client_headers_buf.clear();
                    }

                    if flags & (Http2Flags::EndStream as u8) != 0 {
                        trace!(
                            stream = self.client_headers_stream_id,
                            "Received entire request",
                        );
                    }
                }
                Ok(Http2FrameType::Continuation) => 'continuation: {
                    let flags = self.client_frame_buf[4];
                    let stream_id =
                        u32::from_be_bytes(self.client_frame_buf[5..9].try_into().unwrap());

                    if stream_id != self.client_headers_stream_id {
                        warn!(
                            continuation_stream = stream_id,
                            previous_stream = self.client_headers_stream_id,
                            "Stream ID in HTTP/2 CONTINUATION frame does not match previous stream ID, ignoring frame"
                        );
                        break 'continuation;
                    }

                    let headers_block = &self.client_frame_buf[9..9 + payload_len];

                    self.client_headers_buf.extend_from_slice(headers_block);

                    if flags & (Http2Flags::EndHeaders as u8) != 0 {
                        match self.hpack_decoder.decode(&self.client_headers_buf) {
                            Ok(headers) => self.handle_client_headers(headers),
                            Err(err) => warn!(
                                stream = stream_id,
                                ?err,
                                "Received invalid HTTP/2 request headers / trailers for stream"
                            ),
                        }

                        self.client_headers_buf.clear();
                    }
                }
                Ok(Http2FrameType::Data) => 'data: {
                    let flags = self.client_frame_buf[4];
                    let stream_id =
                        u32::from_be_bytes(self.client_frame_buf[5..9].try_into().unwrap());

                    let Some(request_response) = self.streams.get_mut(&stream_id) else {
                        warn!(
                            stream = stream_id,
                            "Missing stream when receiving DATA HTTP/2 frame, ignoring"
                        );
                        break 'data;
                    };

                    let mut data = &self.client_frame_buf[9..9 + payload_len];

                    if flags & (Http2Flags::Padded as u8) != 0 {
                        let padding_len = data[0] as usize;
                        data = &data[1..payload_len - padding_len];
                    }

                    if flags & (Http2Flags::EndStream as u8) != 0 {
                        trace!(stream = stream_id, "Received entire request");
                    }

                    request_response.request_body_buf.extend_from_slice(data);
                }
                Ok(_) => (),
                Err(err) => warn!(
                    ?err,
                    "Invalid HTTP/2 frame type while handling client request"
                ),
            }

            self.client_frame_buf.drain(..9 + payload_len);
        }
    }

    #[instrument(level = "error", skip_all, fields(pid = self.pid.as_raw(), ctx = self.ctx, server_name = self.connection_context.server_name))]
    fn handle_server_message(&mut self, buf: &[u8]) {
        trace!("Received HTTP/2 server buffer:\n{}", buf.to_hexdump());

        self.server_frame_buf.extend_from_slice(buf);

        loop {
            if self.server_frame_buf.len() < 9usize {
                return;
            }

            let payload_len = ((self.server_frame_buf[0] as usize) << 16)
                | ((self.server_frame_buf[1] as usize) << 8)
                | self.server_frame_buf[2] as usize;

            if self.server_frame_buf.len() < 9 + payload_len {
                return;
            }

            trace!(
                "Handling HTTP/2 server frame type {:x}:\n{}",
                self.server_frame_buf[3],
                self.server_frame_buf[..9 + payload_len].to_hexdump()
            );

            match self.server_frame_buf[3].try_into() {
                Ok(Http2FrameType::Headers) => {
                    let flags = self.server_frame_buf[4];
                    self.server_headers_stream_id =
                        u32::from_be_bytes(self.server_frame_buf[5..9].try_into().unwrap());

                    let mut headers_block = &self.server_frame_buf[9..9 + payload_len];

                    if flags & (Http2Flags::Padded as u8) != 0 {
                        let pad_length = self.server_frame_buf[9] as usize;
                        headers_block = &headers_block[1..payload_len - pad_length];
                    }

                    if flags & (Http2Flags::Priority as u8) != 0 {
                        headers_block = &headers_block[5..];
                    }

                    self.server_headers_buf.extend_from_slice(headers_block);

                    if flags & (Http2Flags::EndHeaders as u8) != 0 {
                        match self.hpack_decoder.decode(&self.server_headers_buf) {
                            Ok(headers) => self.handle_server_headers(headers),
                            Err(err) => warn!(
                                stream = self.server_headers_stream_id,
                                ?err,
                                "Received invalid HTTP/2 request headers / trailers for stream",
                            ),
                        }

                        self.server_headers_buf.clear();
                    }

                    if flags & (Http2Flags::EndStream as u8) != 0 {
                        self.emit_request_response(self.server_headers_stream_id);
                    }
                }
                Ok(Http2FrameType::Continuation) => 'continuation: {
                    let flags = self.server_frame_buf[4];
                    let stream_id =
                        u32::from_be_bytes(self.server_frame_buf[5..9].try_into().unwrap());

                    if stream_id != self.server_headers_stream_id {
                        warn!(
                            continuation_stream = stream_id,
                            previous_stream = self.server_headers_stream_id,
                            "Invalid stream ID in HTTP/2 CONTINUATION frame, previous headers stream ID was different, ignoring frame"
                        );
                        break 'continuation;
                    }

                    let headers_block = &self.server_frame_buf[9..9 + payload_len];

                    self.server_headers_buf.extend_from_slice(headers_block);

                    if flags & (Http2Flags::EndHeaders as u8) != 0 {
                        match self.hpack_decoder.decode(&self.server_headers_buf) {
                            Ok(headers) => self.handle_server_headers(headers),
                            Err(err) => warn!(
                                stream = stream_id,
                                ?err,
                                "Received invalid HTTP/2 request headers / trailers for stream"
                            ),
                        }

                        self.server_headers_buf.clear();
                    }
                }
                Ok(Http2FrameType::Data) => 'data: {
                    let flags = self.server_frame_buf[4];
                    let stream_id =
                        u32::from_be_bytes(self.server_frame_buf[5..9].try_into().unwrap());

                    let Some(request_response) = self.streams.get_mut(&stream_id) else {
                        warn!(
                            stream = stream_id,
                            "Missing stream when receiving DATA HTTP/2 frame, ignoring"
                        );
                        break 'data;
                    };

                    let mut data = &self.server_frame_buf[9..9 + payload_len];

                    if flags & (Http2Flags::Padded as u8) != 0 {
                        let padding_len = data[0] as usize;
                        data = &data[1..payload_len - padding_len];
                    }

                    request_response.response_body_buf.extend_from_slice(data);

                    if flags & (Http2Flags::EndStream as u8) != 0 {
                        self.emit_request_response(stream_id);
                    }
                }
                Ok(_) => (),
                Err(err) => {
                    warn!(
                        ?err,
                        "Invalid HTTP/2 frame type while handling server response"
                    );
                }
            }

            self.server_frame_buf.drain(..9 + payload_len);
        }
    }

    fn handle_close(&mut self) {
        trace!(
            pid = self.pid.as_raw(),
            ctx = self.ctx,
            "Handling HTTP/2 connection close"
        );

        for stream_id in self.streams.keys().copied().collect::<Vec<_>>() {
            trace!(
                pid = self.pid.as_raw(),
                ctx = self.ctx,
                stream_id,
                "Emitting request/response for stream"
            );
            self.emit_request_response(stream_id);
        }
    }
}

impl Http2Connection<'_> {
    #[instrument(level = "error", skip_all, fields(stream = self.server_headers_stream_id))]
    fn handle_client_headers(&mut self, headers: Vec<(Vec<u8>, Vec<u8>)>) {
        if self
            .streams
            .get_mut(&self.client_headers_stream_id)
            .is_some()
        {
            debug!(
                headers = ?headers_utf8(&headers),
                "Received HTTP/2 request trailers, ignoring"
            );
        } else {
            debug!(
                headers = ?headers_utf8(&headers),
                "Received HTTP/2 request headers",
            );

            let mut method = None;
            let mut authority = vec![];
            let mut path = None;
            let headers: Vec<_> = headers
                .into_iter()
                .filter_map(|(name, value)| match name.as_slice() {
                    b":method" => {
                        method = Some(value);
                        None
                    }
                    b":scheme" => None,
                    b":authority" => {
                        authority.clone_from(&value);
                        Some((b"Host".to_vec(), value))
                    }
                    b":path" => {
                        path = Some(value);
                        None
                    }
                    _ => Some((name, value)),
                })
                .collect();

            let Some(path) = path else {
                warn!("HTTP/2 request headers missing :path field, ignoring request");
                return;
            };

            let Some(method) = method else {
                warn!("HTTP/2 request headers missing :method field, ignoring request");
                return;
            };

            let headers = convert_headers(headers);

            let mut request = http::request::Builder::new()
                .version(http::Version::HTTP_2)
                .method(method.as_slice())
                .uri(path.as_slice());

            request.headers_mut().unwrap().extend(headers);

            let builders = RequestResponseBuilders {
                request: Some(request),
                request_body_buf: vec![],
                response: None,
                response_body_buf: vec![],
            };

            self.streams.insert(self.client_headers_stream_id, builders);
        }
    }

    #[instrument(level = "error", skip_all, fields(stream = self.server_headers_stream_id))]
    fn handle_server_headers(&mut self, headers: Vec<(Vec<u8>, Vec<u8>)>) {
        let Some(builders) = self.streams.get_mut(&self.server_headers_stream_id) else {
            error!(
                "Received HTTP/2 response headers for non-existent stream {}, ignoring headers",
                self.server_headers_stream_id
            );
            return;
        };

        let mut status = None;
        let headers: Vec<_> = headers
            .into_iter()
            .filter_map(|(name, value)| match name.as_slice() {
                b":status" => {
                    status = Some(value);
                    None
                }
                _ => Some((name, value)),
            })
            .collect();

        let Some(status) = status else {
            warn!("HTTP/2 response headers missing :status field, ignoring request");
            return;
        };

        let headers = convert_headers(headers);

        if builders.response.is_some() {
            debug!(
                stream = self.server_headers_stream_id,
                ?headers,
                "Received HTTP/2 response trailers, ignoring"
            );
            return;
        }

        debug!(
            stream = self.server_headers_stream_id,
            ?headers,
            "Received HTTP/2 response headers"
        );

        let mut response = http::response::Builder::new()
            .version(http::Version::HTTP_2)
            .status(status.as_slice());

        response.headers_mut().unwrap().extend(headers);

        builders.response = Some(response);
    }

    #[instrument(level = "error", skip(self))]
    fn emit_request_response(&mut self, stream_id: StreamId) {
        let mut builders = self.streams.remove(&stream_id).unwrap_or_else(|| {
            panic!("Failed to find HTTP/2 request/response to emit for stream {stream_id}")
        });

        debug!("Received full HTTP/2 request and response");

        let request_response = HttpRequestResponse {
            tls_server_name: self.connection_context.server_name.clone(),
            container_id: self.connection_context.process_context.container_id(),
            version: http::Version::HTTP_2,
            request: builders
                .request
                .take()
                .unwrap()
                .body(DebugBody(std::mem::take(&mut builders.request_body_buf)))
                .unwrap(),
            response: builders
                .response
                .take()
                .unwrap()
                .body(DebugBody(std::mem::take(&mut builders.response_body_buf)))
                .unwrap(),
        };

        self.transport_event_sender
            .send(TransportEvent::Http(request_response))
            .expect("Failed to send TransportEvent::Http from Http2Connection");
    }
}

fn convert_headers(headers: Vec<(Vec<u8>, Vec<u8>)>) -> http::HeaderMap {
    use http::header::{HeaderName, HeaderValue};

    let mut header_map = http::HeaderMap::new();

    for (name, value) in headers {
        match (
            HeaderName::from_bytes(&name),
            HeaderValue::from_bytes(&value),
        ) {
            (Ok(name), Ok(value)) => {
                header_map.insert(name, value);
            }
            (Ok(_), Err(_)) => warn!(
                header = std::string::String::from_utf8_lossy(&name).into_owned(),
                "Header name has invalid value, ignoring"
            ),
            (Err(_), _) => warn!(
                header = std::string::String::from_utf8_lossy(&name).into_owned(),
                "Header name is invalid, ignoring"
            ),
        }
    }

    header_map
}

fn headers_utf8(headers: &[(Vec<u8>, Vec<u8>)]) -> Vec<(Cow<'_, str>, Cow<'_, str>)> {
    headers
        .iter()
        .map(|(key, value)| (String::from_utf8_lossy(key), String::from_utf8_lossy(value)))
        .collect()
}
