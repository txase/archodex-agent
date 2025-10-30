use crate::hexdump::HexDump;

#[derive(Debug, Default)]
pub(crate) struct HttpRequestResponse {
    pub(crate) tls_server_name: String,
    pub(crate) container_id: Option<String>,
    pub(crate) version: http::Version,
    pub(crate) request: http::Request<DebugBody>,
    pub(crate) response: http::Response<DebugBody>,
}

#[derive(Default)]
pub(crate) struct DebugBody(pub(crate) Vec<u8>);

impl std::fmt::Debug for DebugBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\n{}", self.0.to_hexdump())
    }
}

impl From<Vec<u8>> for DebugBody {
    fn from(value: Vec<u8>) -> Self {
        DebugBody(value)
    }
}
