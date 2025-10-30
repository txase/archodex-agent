use std::collections::{HashMap, HashSet};

use anyhow::{Context as _, bail};
use clap::Args;
use octocrab::models::repos::secret_scanning_alert::{
    SecretScanningAlert, SecretsScanningAlertLocation,
};
use tracing::{Span, debug, info, instrument, trace, warn};

use crate::{
    Report, account_salted_hasher,
    engine::{
        event_capture::{Event, EventCapture},
        principal::Principal,
        resource_capture::{ResourceCapture, ResourceIdPart},
    },
    global_opts::GlobalOpts,
    report_api_key, send_report,
};

use super::{SecretsCommands, SecretsSubcommands::GitHub};

#[derive(Args, Debug)]
pub(crate) struct GitHubCommand {
    #[clap(flatten)]
    global_opts: GlobalOpts,

    /// GitHub Organization
    ///
    /// The GitHub Organization to fetch secret scanning alerts from.
    #[arg(short = 'o', long, env = "ARCHODEX_SECRETS_GITHUB_ORG")]
    github_org: String,

    /// GitHub Token
    ///
    /// This token is used to fetch secret scanning alerts for the GitHub Organization.
    #[arg(
        short = 't',
        long,
        env = "ARCHODEX_SECRETS_GITHUB_TOKEN",
        hide_env_values = true
    )]
    github_token: String,
}

#[instrument(level = "debug", fields(report_api_key, github_token))]
#[instrument(
    level = "trace",
    fields(github_org, secret_values_hash_salt, log_report)
)]
pub(crate) async fn handle_github_command(
    SecretsCommands {
        subcommand:
            GitHub(GitHubCommand {
                global_opts:
                    GlobalOpts {
                        report_api_key,
                        service_endpoint,
                        log_report,
                        secret_values_hash_salt,
                    },
                github_org,
                github_token,
            }),
    }: SecretsCommands,
) -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap_or_else(|_| panic!("Failed to install AWS LC PKI provider"));

    if let Some(key) = &report_api_key {
        report_api_key::set(key, service_endpoint.as_ref())?;
    } else {
        info!(
            "No report API key provided via --report-api-key argument or ARCHODEX_REPORT_API_KEY environment variable, will not send reports to Archodex service"
        );

        if service_endpoint.is_some() {
            warn!(
                "--service-endpoint or ARCHODEX_SERVICE_ENDPOINT environment variable was set, but no report API key was provided"
            );
        }
    }

    account_salted_hasher::init(secret_values_hash_salt.as_ref())?;

    // Setup GitHub client with the provided token
    let octocrab = octocrab::OctocrabBuilder::new()
        .user_access_token(github_token)
        .build()
        .context("Failed to create GitHub client")?;

    let params = GitHubApiListSecretScanningAlertsParams {
        per_page: Some(100),
        ..Default::default()
    };

    debug!("Fetching GitHub Secret Scanning Alerts");

    let alerts: octocrab::Page<SecretScanningAlert> = octocrab
        .get(
            format!("/orgs/{github_org}/secret-scanning/alerts"),
            Some(&params),
        )
        .await
        .context("Failed to fetch secret scanning alerts")?;

    let mut report = Report::new();

    // Process each alert
    for alert in alerts {
        process_alert(&octocrab, &mut report, alert).await?;
    }

    log_and_send_report(report, log_report).await?;

    Ok(())
}

#[instrument(level = "error", skip(octocrab, report, alert), fields(owner, repo, number = alert.number, secret_value))]
#[instrument(level = "trace", skip_all, fields(secret = alert.secret))]
async fn process_alert(
    octocrab: &octocrab::Octocrab,
    report: &mut Report,
    alert: SecretScanningAlert,
) -> anyhow::Result<()> {
    // Get repository name from alert url
    let Some(path_segments) = alert
        .url
        .path_segments()
        .map(std::iter::Iterator::collect::<Vec<_>>)
    else {
        bail!(
            "Failed to parse GitHub Secret Scanning Alert URL: {}",
            alert.url
        );
    };

    let [_repos, owner, repo, ..] = path_segments.as_slice() else {
        bail!(
            "Failed to parse repository name from GitHub Secret Scanning Alert URL: {}",
            alert.url
        );
    };

    let secret_value =
        account_salted_hasher::hash(alert.secret.as_bytes()).context("Failed to hash secret")?;

    Span::current().record("owner", owner);
    Span::current().record("repo", repo);
    Span::current().record("secret_value", format!("{secret_value:064x}"));

    trace!("Processing alert");

    let repo_handler = octocrab.repos(*owner, *repo);
    let alert_handler = repo_handler.secrets_scanning();

    let locations: octocrab::Page<SecretsScanningAlertLocation> = alert_handler
        .get_alert_locations(alert.number.try_into().unwrap())
        .await?;

    let mut repo_locations: HashMap<_, HashSet<_>> = HashMap::new();

    for location in locations {
        // Secrets can be found in many places, e.g. GH Issues. Skip everything
        // except for code locations.
        let SecretsScanningAlertLocation::Commit { path, .. } = location else {
            continue;
        };

        // Fetch file content from default branch
        match repo_handler.get_content().path(&path).send().await {
            Ok(mut content) => {
                let content = content.take_items()[0].decoded_content().with_context(|| {
                    format!(
                        "Failed to decode GitHub contents for file {path:?} of repo {owner}/{repo}",
                    )
                })?;

                // Check if file content contains the secret
                if content.contains(&alert.secret) {
                    debug!(file = path, "Secret still exists in file");
                } else {
                    debug!(file = path, "Secret no longer exists in file");
                    continue;
                }
            }
            Err(e) => {
                debug!(
                    path,
                    "Path for GitHub Secret Scanning Alert not found: {e:#?}",
                );

                continue;
            }
        }

        repo_locations.entry(*repo).or_default().insert(path);
    }

    if repo_locations.is_empty() {
        debug!("Secret not found in any repositories");
        return Ok(());
    }

    trace!(?repo_locations, "Secret found in repositories");

    let secret_value_resource_id = vec![ResourceIdPart {
        r#type: "Secret Value".to_string(),
        id: format!("{secret_value:064x}"),
    }];

    let secret_value_capture = ResourceCapture::try_from(secret_value_resource_id.clone())?;
    report.add_resource_capture(secret_value_capture);

    for (repo, paths) in repo_locations {
        let blob_resource_id = vec![
            ResourceIdPart {
                r#type: "GitHub Service".to_string(),
                id: "https://github.com".to_string(),
            },
            ResourceIdPart {
                r#type: "Organization".to_string(),
                id: (*owner).to_string(),
            },
            ResourceIdPart {
                r#type: "Git Repository".to_string(),
                id: repo.to_string(),
            },
            ResourceIdPart {
                r#type: "Blob".to_string(),
                id: paths.iter().cloned().collect::<Vec<_>>().join(","),
            },
        ];

        let blob_capture = ResourceCapture::try_from(blob_resource_id.clone())?;
        report.add_resource_capture(blob_capture);

        let event = EventCapture {
            principals: vec![Principal {
                id: blob_resource_id,
                event: None,
            }],
            events: vec![Event {
                types: vec!["Hardcoded".into()],
                resources: vec![secret_value_resource_id.clone()],
            }],
        };
        report.add_event_capture(event);
    }

    Ok(())
}

async fn log_and_send_report(report: Report, log_report: bool) -> anyhow::Result<()> {
    debug!(
        "Sending report: {}",
        serde_json::to_string_pretty(&report).expect("Failed to convert report to JSON")
    );

    if log_report {
        report.log();
    }

    if let (Some(endpoint), Some(header_value)) =
        (report_api_key::endpoint(), report_api_key::header_value())
    {
        send_report(report, endpoint, header_value).await?;
        info!("Archodex report sent successfully");
    }

    Ok(())
}

/// Parameters for GitHub API request
///
/// See [GitHub API documentation](https://docs.github.com/en/rest/secret-scanning/secret-scanning#list-secret-scanning-alerts-for-an-organization)
#[derive(Default, serde::Serialize)]
struct GitHubApiListSecretScanningAlertsParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    per_page: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolution: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validity: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_publicly_leaked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_multi_repo: Option<bool>,
}
