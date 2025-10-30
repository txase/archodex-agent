use std::time::Duration;

use anyhow::{anyhow, bail};
use http::{HeaderValue, header::AUTHORIZATION};
use reqwest::Url;
use tokio::time::timeout;
use tracing::{debug, error_span, trace_span};

use crate::{REPORT_TX_TIMEOUT, engine::report::Report};

pub(crate) async fn send_report(
    report: Report,
    endpoint: &Url,
    report_api_key_header_value: &HeaderValue,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();

    let mut url = endpoint.clone();
    url.set_path("/report");

    let _send_report_span = error_span!("Send Report", %url).entered();
    let _report_key_span = trace_span!(
        "Archodex Report API Key",
        value = report_api_key_header_value.to_str().unwrap()
    )
    .entered();
    debug!("Sending report to Archodex service");

    let response = match timeout(
        REPORT_TX_TIMEOUT,
        client
            .post(url.clone())
            .header(AUTHORIZATION, report_api_key_header_value)
            .json(&report)
            .send(),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => {
            return Err(anyhow!(err).context(format!(
                "Failed to send report to Archodex service at {url}"
            )));
        }
        Err(_) => {
            bail!("Sending report to Archodex endpoint {url} timed out ({REPORT_TX_TIMEOUT:?})");
        }
    };

    let status = response.status();

    if !status.is_success() {
        match timeout(Duration::from_secs(5), response.text()).await {
            Ok(Ok(text)) => {
                bail!("Failed to send report to Archodex service at {url}: {status}: {text}")
            }
            Ok(Err(err)) => bail!(
                "Failed to send report to Archodex service at {url}: {status} <Error while receiving response body>: {err:#?}"
            ),
            Err(_) => bail!(
                "Failed to send report to Archodex service at {url}: {status} <Timed out while receiving response body>"
            ),
        }
    }

    Ok(())
}
