use std::sync::OnceLock;

use anyhow::{Context as _, anyhow, bail, ensure};
use base64::prelude::*;
use http::HeaderValue;
use prost::Message as _;
use tracing::warn;
use url::Url;

use crate::proto;

struct ReportApiKey {
    endpoint: Url,
    account_salt: [u8; 16],
    header_value: HeaderValue,
}

impl ReportApiKey {
    fn parse(value: &str, service_endpoint: Option<&String>) -> anyhow::Result<Self> {
        const ERROR_MESSAGE: &str = "Invalid report API key";

        let mut header_value = HeaderValue::from_str(value)
            .context("Unexpected error: Failed to convert report API key to header value")?;
        header_value.set_sensitive(true);

        let Some(key_id) = value.strip_prefix("archodex_report_api_key_") else {
            bail!(ERROR_MESSAGE);
        };

        let key_id_value = key_id.splitn(2, '_').collect::<Vec<_>>();

        let [key_id, value] = key_id_value[..] else {
            bail!(ERROR_MESSAGE);
        };

        let key_id = key_id.parse::<u32>().map_err(|_| anyhow!(ERROR_MESSAGE))?;

        ensure!((100_000..999_9999).contains(&key_id), ERROR_MESSAGE);

        let decoded_value = BASE64_STANDARD
            .decode(value)
            .map_err(|_| anyhow!(ERROR_MESSAGE))?;

        ensure!(!decoded_value.is_empty(), ERROR_MESSAGE);

        let decoded_value = proto::ReportApiKey::decode(decoded_value.as_slice())
            .map_err(|_| anyhow!(ERROR_MESSAGE))?;

        if decoded_value.report_api_key_version != 1 {
            bail!(ERROR_MESSAGE);
        }

        let endpoint = match (&decoded_value.endpoint, service_endpoint) {
            (Some(endpoint), None) | (None, Some(endpoint)) => endpoint,
            (Some(_), Some(endpoint)) => {
                warn!(
                    "Service endpoint provided for Report API Key for a managed archodex.com account, using provided service endpoint {endpoint}"
                );
                endpoint
            }
            (None, None) => {
                bail!(
                    "The Archodex Service Endpoint must be provided (e.g. --service-endpoint) when using a Report API Key for a self-hosted Archodex account"
                );
            }
        };

        Ok(Self {
            endpoint: Url::parse(endpoint).map_err(|_| anyhow!(ERROR_MESSAGE))?,
            account_salt: decoded_value
                .account_salt
                .try_into()
                .map_err(|_| anyhow!(ERROR_MESSAGE))?,
            header_value,
        })
    }
}

static API_KEY: OnceLock<ReportApiKey> = OnceLock::new();

pub(crate) fn set(api_key: &str, service_endpoint: Option<&String>) -> anyhow::Result<()> {
    let api_key = ReportApiKey::parse(api_key, service_endpoint)?;

    API_KEY
        .set(api_key)
        .map_err(|_| anyhow!("Unexpected error: Report API key attempted to be set twice"))
}

pub(crate) fn endpoint() -> Option<&'static Url> {
    API_KEY.get().map(|key| &key.endpoint)
}

pub(crate) fn account_salt() -> Option<&'static [u8; 16]> {
    API_KEY.get().map(|key| &key.account_salt)
}

pub(crate) fn header_value() -> Option<&'static HeaderValue> {
    API_KEY.get().map(|key| &key.header_value)
}
