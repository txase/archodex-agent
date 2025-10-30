use std::str::FromStr;

use httparse::Header;
use nix::unistd::Pid;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, instrument, trace, warn};

use crate::{hexdump::HexDump, libssl_event_parser::Ctx};

use super::{
    ConnectionContext, HttpRequestResponse, TransportEvent, TransportParser, http::DebugBody,
};

enum ContentLength {
    Bytes(usize),
    Chunked(Option<usize>),
}

pub(crate) struct Http1Connection {
    pid: Pid,
    ctx: Ctx,
    connection_context: ConnectionContext,
    transport_event_sender: UnboundedSender<TransportEvent>,
    client_buf: Vec<u8>,
    request_content_length: Option<usize>,
    request: Option<http::request::Builder>,
    request_complete: bool,
    server_buf: Vec<u8>,
    server_chunks: Vec<Vec<u8>>,
    response_content_length: Option<ContentLength>,
    response: Option<http::response::Builder>,
}

impl TransportParser for Http1Connection {
    #[instrument(level = "error", skip_all)]
    fn new(
        pid: Pid,
        ctx: Ctx,
        connection_context: &ConnectionContext,
        transport_event_sender: &UnboundedSender<TransportEvent>,
        buf: &mut Vec<u8>,
    ) -> Option<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(buf) {
            Ok(status) => {
                trace!("Received HTTP/1 client buffer:\n{}", buf.to_hexdump());

                debug!("New HTTP/1 client context, creating connection");

                let request = if let httparse::Status::Complete(body_offset) = status {
                    let mut request = match req.version.unwrap() {
                        0 => http::request::Builder::new().version(http::Version::HTTP_10),
                        1 => http::request::Builder::new(), // default
                        ver => {
                            warn!("Unknown HTTP/1 request minor version {ver}, leaving default as HTTP/1.1");
                            http::request::Builder::new()
                        }
                    }
                    .method(req.method.unwrap())
                    .uri(req.path.unwrap());

                    convert_headers(&headers, request.headers_mut().unwrap());

                    buf.drain(..body_offset);

                    Some(request)
                } else {
                    trace!("Partial HTTP/1 client context received");
                    None
                };

                Some(Self {
                    pid,
                    ctx,
                    connection_context: connection_context.to_owned(),
                    transport_event_sender: transport_event_sender.clone(),
                    client_buf: vec![],
                    request_content_length: None,
                    request,
                    request_complete: false,
                    server_buf: vec![],
                    server_chunks: vec![],
                    response_content_length: None,
                    response: None,
                })
            }
            _ => None,
        }
    }

    #[instrument(level = "error", skip_all, fields(pid = self.pid.as_raw(), ctx = self.ctx, server_name = self.connection_context.server_name))]
    fn handle_client_message(&mut self, buf: &[u8]) {
        trace!("Received HTTP/1 client buffer:\n{}", buf.to_hexdump());

        if self.request_complete {
            error!("Received additional client data for completed request, ignoring");
            return;
        }

        self.client_buf.extend_from_slice(buf);

        if self.request.is_none() {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(&self.client_buf) {
                Ok(httparse::Status::Complete(body_offset)) => {
                    let mut request = match req.version.unwrap() {
                        0 => http::request::Builder::new().version(http::Version::HTTP_10),
                        1 => http::request::Builder::new(), // default
                        ver => {
                            warn!("Unknown HTTP/1 request minor version {ver}, leaving default as HTTP/1.1");
                            http::request::Builder::new()
                        }
                    }
                    .method(req.method.unwrap())
                    .uri(req.path.unwrap());

                    convert_headers(&headers, request.headers_mut().unwrap());

                    self.request = Some(request);

                    self.client_buf.drain(..body_offset);
                }
                Ok(httparse::Status::Partial) => return,
                Err(err) => {
                    warn!(?err, "Error while parsing request, ignoring");
                    return;
                }
            }
        }

        let request_content_length = if let Some(request_content_length) =
            self.request_content_length
        {
            request_content_length
        } else {
            let request_content_length = if let Some(value) = self
                .request
                .as_ref()
                .unwrap()
                .headers_ref()
                .unwrap()
                .get(http::header::CONTENT_LENGTH)
            {
                if let Ok(value_str) = value.to_str() {
                    if let Ok(length) = value_str.parse::<usize>() {
                        length
                    } else {
                        warn!(
                            value = ?value_str,
                            "Invalid Content-Length value in client request, ignoring"
                        );
                        return;
                    }
                } else {
                    warn!(
                        value = std::string::String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        "Invalid Content-Length value in client request, ignoring"
                    );
                    return;
                }
            } else {
                0
            };

            self.request_content_length = Some(request_content_length);
            request_content_length
        };

        if self.client_buf.len() >= request_content_length {
            self.client_buf.drain(request_content_length..);
            trace!("Received entire request");
            self.request_complete = true;
        }
    }

    #[instrument(level = "error", skip_all, fields(pid = self.pid.as_raw(), ctx = self.ctx, server_name = self.connection_context.server_name))]
    fn handle_server_message(&mut self, buf: &[u8]) {
        trace!("Received HTTP/1 server buffer:\n{}", buf.to_hexdump());

        if self.request.is_none() {
            warn!(
                "Received server message without having received request headers first, ignoring message"
            );
            return;
        }

        let orig_server_buf_len = self.server_buf.len();
        self.server_buf.extend_from_slice(buf);

        if self.response.is_none() {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut res = httparse::Response::new(&mut headers);
            match res.parse(&self.server_buf) {
                Ok(httparse::Status::Complete(body_offset)) => {
                    let mut response = match res.version.unwrap() {
                        0 => http::response::Builder::new().version(http::Version::HTTP_10),
                        1 => http::response::Builder::new(), // default
                        ver => {
                            warn!("Unknown HTTP/1 response minor version {ver}, leaving default as HTTP/1.1");
                            http::response::Builder::new()
                        }
                    }
                    .status(res.code.unwrap());

                    convert_headers(&headers, response.headers_mut().unwrap());

                    self.response = Some(response);

                    self.server_buf.drain(..body_offset);
                }
                Ok(httparse::Status::Partial) => return,
                Err(err) => {
                    warn!(?err, "Error while parsing response headers, ignoring");
                    self.server_buf.truncate(orig_server_buf_len);
                    return;
                }
            }
        }

        loop {
            // We know request and response must exist based on checks above and
            // returns after calls to reset() below
            let request = self.request.as_mut().unwrap();
            let response = self.response.as_mut().unwrap();

            self.response_content_length = match self.response_content_length {
                None => {
                    let response_content_length = if let Some(&http::Method::HEAD) =
                        request.method_ref()
                    {
                        ContentLength::Bytes(0)
                    } else if let Some(value) = response
                        .headers_ref()
                        .unwrap()
                        .get(http::header::CONTENT_LENGTH)
                    {
                        if let Ok(value_str) = value.to_str() {
                            if let Ok(length) = value_str.parse::<usize>() {
                                ContentLength::Bytes(length)
                            } else {
                                warn!(
                                    value = ?value_str,
                                    "Invalid Content-Length value in server response, ignoring"
                                );
                                return;
                            }
                        } else {
                            warn!(
                                value = std::string::String::from_utf8_lossy(value.as_bytes())
                                    .into_owned(),
                                "Invalid Content-Length value in server response, ignoring"
                            );
                            return;
                        }
                    } else if let Some(value) = response
                        .headers_ref()
                        .unwrap()
                        .get(http::header::TRANSFER_ENCODING)
                    {
                        match value.to_str() {
                            Ok(value_str) if value_str.contains("chunked") => {
                                ContentLength::Chunked(None)
                            }
                            Ok(_) => ContentLength::Bytes(0),
                            Err(_) => {
                                warn!(
                                    value = std::string::String::from_utf8_lossy(value.as_bytes())
                                        .into_owned(),
                                    "Invalid Transfer-Encoding value in server response, ignoring"
                                );
                                return;
                            }
                        }
                    } else {
                        ContentLength::Bytes(0)
                    };

                    Some(response_content_length)
                }
                Some(ContentLength::Bytes(response_content_length)) => {
                    if self.server_buf.len() >= response_content_length {
                        self.server_buf.drain(response_content_length..);

                        debug!("Received full HTTP/1 request and response");

                        let request_response = HttpRequestResponse {
                            tls_server_name: self.connection_context.server_name.clone(),
                            container_id: self.connection_context.process_context.container_id(),
                            version: request.version_ref().unwrap().to_owned(),
                            request: std::mem::take(request)
                                .body(DebugBody(std::mem::take(&mut self.client_buf)))
                                .unwrap(),
                            response: std::mem::take(response)
                                .body(DebugBody(std::mem::take(&mut self.server_buf)))
                                .unwrap(),
                        };

                        self.transport_event_sender
                            .send(TransportEvent::Http(request_response))
                            .expect("Failed to send TransportEvent::Http from Http1Connection");

                        self.reset();
                    } else {
                        trace!(
                            "Incomplete response (received {} / {} bytes), will wait for more data",
                            self.server_buf.len(),
                            response_content_length
                        );
                    }

                    return;
                }
                Some(ContentLength::Chunked(None)) => {
                    // We're looking for the beginning of a chunk, which starts with
                    // the length of the chunk (in ascii hex) followed by "\r\n"
                    let Some(content_length_end) =
                        self.server_buf.iter().position(|byte| *byte == b'\r')
                    else {
                        trace!(
                            "Incomplete chunked header '{:?}', will wait for more data",
                            self.server_buf
                        );
                        return;
                    };

                    // We need to be able to take everything through the "\r\n", so
                    // if we don't have the "\n" yet, then wait
                    if self.server_buf.len() == content_length_end + 1 {
                        trace!(
                            "Incomplete chunked header '{:?}', will wait for more data",
                            self.server_buf
                        );
                        return;
                    }

                    if self.server_buf[content_length_end + 1] != b'\n' {
                        warn!(
                            value = ?self.server_buf[..=content_length_end],
                            "Invalid chunked encoding header, ignoring connection"
                        );
                        return;
                    }

                    let length = if let Ok(length_str) =
                        std::str::from_utf8(&self.server_buf[..content_length_end])
                    {
                        if let Ok(length) = usize::from_str_radix(length_str, 16) {
                            length
                        } else {
                            warn!(
                                value = length_str,
                                "Invalid chunked encoding length, ignoring connection"
                            );
                            return;
                        }
                    } else {
                        warn!(
                            value = std::string::String::from_utf8_lossy(
                                &self.server_buf[..content_length_end]
                            )
                            .into_owned(),
                            "Invalid chunked encoding header, ignoring connection"
                        );
                        return;
                    };

                    self.server_buf.drain(..content_length_end + 2);

                    if length == 0 {
                        self.server_buf.clear();

                        debug!("Received full HTTP/1 request and chunked response");

                        let request_response = HttpRequestResponse {
                            tls_server_name: self.connection_context.server_name.clone(),
                            container_id: self.connection_context.process_context.container_id(),
                            version: request.version_ref().unwrap().to_owned(),
                            request: std::mem::take(request)
                                .body(DebugBody(std::mem::take(&mut self.client_buf)))
                                .unwrap(),
                            response: std::mem::take(response)
                                .body(DebugBody(self.server_chunks.concat()))
                                .unwrap(),
                        };

                        self.transport_event_sender
                            .send(TransportEvent::Http(request_response))
                            .expect("Failed to send TransportEvent::Http from Http1Connection");

                        self.reset();

                        return;
                    } else if self.received_full_chunk(length) {
                        Some(ContentLength::Chunked(None))
                    } else {
                        return;
                    }
                }
                Some(ContentLength::Chunked(Some(length))) => {
                    if self.received_full_chunk(length) {
                        Some(ContentLength::Chunked(None))
                    } else {
                        return;
                    }
                }
            }
        }
    }

    fn handle_close(&mut self) {}
}

impl Http1Connection {
    fn reset(&mut self) {
        self.client_buf.clear();
        self.request_content_length = None;
        self.request = None;
        self.request_complete = false;
        self.server_buf.clear();
        self.server_chunks.clear();
        self.response_content_length = None;
        self.response = None;
    }

    fn received_full_chunk(&mut self, length: usize) -> bool {
        if self.server_buf.len() >= length + 2 {
            let chunked_trailer = &self.server_buf[length..length + 2];
            if chunked_trailer != b"\r\n" {
                warn!(value = ?chunked_trailer,
                    "Invalid chunked encoding trailer, ignoring connection");
                return false;
            }

            trace!("Received HTTP/1 response full chunk");

            self.server_chunks
                .push(self.server_buf.drain(..length).collect());

            self.server_buf.drain(..2);

            true
        } else {
            false
        }
    }
}

fn convert_headers(
    headers: &[Header<'_>],
    http_headers: &mut http::HeaderMap<http::header::HeaderValue>,
) {
    use http::header::{HeaderName, HeaderValue};

    for header in headers {
        if header.name.is_empty() {
            continue;
        }

        match (
            HeaderName::from_str(header.name),
            HeaderValue::from_bytes(header.value),
        ) {
            (Ok(name), Ok(value)) => {
                http_headers.insert(name, value);
            }
            (Ok(_), Err(_)) => {
                warn!(
                    name = header.name,
                    "Header name has invalid value, ignoring"
                );
            }
            (Err(_), _) => {
                warn!(header = header.name, "Header name is invalid, ignoring");
            }
        }
    }
}
