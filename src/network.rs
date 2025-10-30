use std::{
    collections::{HashMap, HashSet},
    env,
    fmt::Write as _,
    fs,
    io::{self, Read as _, Write as _},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    str::FromStr as _,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::{Context as _, bail, ensure};
use clap::{Args, Subcommand};
use include_dir::include_dir;
use tokio::{
    select,
    signal::{
        self,
        unix::{SignalKind, signal},
    },
    time::{Instant, sleep_until},
};
use tracing::{debug, info, instrument, warn};
use url::Url;

use crate::{
    Config, Context, ContextMethods as _, Report, Rules, Ruleset, account_salted_hasher,
    engine::context,
    global_opts::GlobalOpts,
    libssl_events,
    license_enforcement::{
        EVENT_LIMIT_CTA, LimitState, LimitType, OperatingMode, RESOURCE_LIMIT_CTA,
    },
    mmap_exec_files, report_api_key,
    ruleset::RulesetParsingError,
    send_report, transport_parser,
};

const FIRST_REPORT_PERIOD: Duration = Duration::from_secs(20);
const REPORT_PERIOD: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Subcommand)]
enum NetworkCommands {
    /// Check status of the running Network agent
    #[command(hide(true))]
    Status,
}

#[derive(Args, Debug)]
pub(crate) struct NetworkCommand {
    #[command(subcommand)]
    subcommand: Option<NetworkCommands>,

    #[clap(flatten)]
    global_opts: GlobalOpts,

    /// Comma-separated list of Archodex built-in non-default rulesets to enable
    #[arg(
        short,
        long,
        env = "ARCHODEX_ENABLE_RULESETS",
        value_parser=EnableRulesetsParser,
        value_name = "RULESET_ID[,RULESET_ID...]",
        default_value_t,
    )]
    enable_rulesets: EnableRulesets,

    /// Comma-separated list of Archodex built-in default rulesets to disable
    #[arg(
        short,
        long,
        env = "ARCHODEX_DISABLE_RULESETS",
        value_parser=DisableRulesetsParser,
        value_name = "RULESET_ID[,RULESET_ID...]",
        default_value_t,
    )]
    disable_rulesets: DisableRulesets,

    /// Use additional Archodex rulesets from paths or URLs
    ///
    /// The IDs of the rulesets default to the stems of the ruleset filenames.
    /// For example, if an additional ruleset is
    /// `https://example.com/my_ruleset.yaml`, its ruleset ID will be
    /// `my_ruleset`.
    #[arg(
        short,
        long,
        env = "ARCHODEX_ADDITIONAL_RULESETS",
        value_delimiter = ',',
        value_name = "[RULESET_ID=]PATH_OR_URL[,[RULESET_ID=]PATH_OR_URL...]"
    )]
    additional_rulesets: Vec<String>,

    /// Provide a value for an Archodex ruleset input
    ///
    /// (e.g. `--ruleset-input <ruleset_id>:<input_name>=<value>`)
    ///
    /// [env: `ARCHODEX_RULESET_INPUT_<RULESET_ID>_<INPUT_NAME>=`]
    #[arg(short, long, value_name = "RULESET_ID:INPUT_NAME=VALUE")]
    ruleset_input: Vec<String>,
}

static BUILTIN_RULESETS_DEFAULT_ENABLED: include_dir::Dir<'_> =
    include_dir!("$CARGO_MANIFEST_DIR/archodex-rulesets/enabled");
static BUILTIN_RULESETS_DEFAULT_DISABLED: include_dir::Dir<'_> =
    include_dir!("$CARGO_MANIFEST_DIR/archodex-rulesets/disabled");

#[derive(Clone, Debug, Default)]
struct EnableRulesets(Vec<String>);

impl std::fmt::Display for EnableRulesets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join(","))
    }
}

impl std::iter::IntoIterator for EnableRulesets {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Clone)]
struct EnableRulesetsParser;

impl clap::builder::TypedValueParser for EnableRulesetsParser {
    type Value = EnableRulesets;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        if value.is_empty() {
            return Ok(EnableRulesets::default());
        }

        let values = value.to_str().unwrap().split(',').collect::<Vec<_>>();

        let (values, invalid_values): (Vec<_>, Vec<_>) = values.into_iter().partition(|&value| {
            BUILTIN_RULESETS_DEFAULT_DISABLED
                .files()
                .any(|file| file.path().file_stem().unwrap().to_str().unwrap() == value)
        });

        if !invalid_values.is_empty() {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!(
                    "Invalid default-disabled ruleset IDs provided to enable (via --enable-rulesets or ARCHODEX_ENABLE_RULESETS): {}\n",
                    invalid_values.join(", ")
                ),
            ));
        }

        Ok(EnableRulesets(
            values
                .into_iter()
                .map(std::string::ToString::to_string)
                .collect(),
        ))
    }

    fn possible_values(
        &self,
    ) -> Option<Box<dyn Iterator<Item = clap::builder::PossibleValue> + '_>> {
        Some(Box::new(BUILTIN_RULESETS_DEFAULT_DISABLED.files().map(
            |file| {
                clap::builder::PossibleValue::new(
                    file.path().file_stem().unwrap().to_str().unwrap(),
                )
            },
        )))
    }
}

#[derive(Clone, Debug, Default)]
struct DisableRulesets(Vec<String>);

impl std::fmt::Display for DisableRulesets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join(","))
    }
}

impl std::iter::IntoIterator for DisableRulesets {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Clone)]
struct DisableRulesetsParser;

impl clap::builder::TypedValueParser for DisableRulesetsParser {
    type Value = DisableRulesets;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        if value.is_empty() {
            return Ok(DisableRulesets::default());
        }

        let values = value.to_str().unwrap().split(',').collect::<Vec<_>>();

        let (values, invalid_values): (Vec<_>, Vec<_>) = values.into_iter().partition(|&value| {
            BUILTIN_RULESETS_DEFAULT_ENABLED
                .files()
                .any(|file| file.path().file_stem().unwrap().to_str().unwrap() == value)
        });

        if !invalid_values.is_empty() {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!(
                    "Invalid default-disabled ruleset IDs provided to disable (via --disable-rulesets or ARCHODEX_DISABLE_RULESETS): {}\n",
                    invalid_values.join(", ")
                ),
            ));
        }

        Ok(DisableRulesets(
            values
                .into_iter()
                .map(std::string::ToString::to_string)
                .collect(),
        ))
    }

    fn possible_values(
        &self,
    ) -> Option<Box<dyn Iterator<Item = clap::builder::PossibleValue> + '_>> {
        Some(Box::new(BUILTIN_RULESETS_DEFAULT_ENABLED.files().map(
            |file| {
                clap::builder::PossibleValue::new(
                    file.path().file_stem().unwrap().to_str().unwrap(),
                )
            },
        )))
    }
}

pub(crate) async fn handle_network_command(command: NetworkCommand) -> anyhow::Result<()> {
    match &command.subcommand {
        Some(NetworkCommands::Status) => handle_status_command(),
        None => return run_ebpf_agent(command).await,
    }

    Ok(())
}

fn handle_status_command() {
    match check_status() {
        Ok(status) => {
            println!("{status}");
            if status != Status::Ready {
                std::process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("Failed to check agent status: {err}");
            std::process::exit(1);
        }
    }
}

#[derive(Debug, PartialEq)]
enum Status {
    NotRunning,
    Started,
    Ready,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRunning => write!(f, "Not Running"),
            Self::Started => write!(f, "Started"),
            Self::Ready => write!(f, "Ready"),
        }
    }
}

impl std::str::FromStr for Status {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Not Running" => Ok(Self::NotRunning),
            "Started" => Ok(Self::Started),
            "Ready" => Ok(Self::Ready),
            s => bail!("Invalid status string '{s}'"),
        }
    }
}

#[instrument]
fn check_status() -> anyhow::Result<Status> {
    let Ok(path) = env::var("ARCHODEX_AGENT_STATUS_PATH") else {
        bail!("ARCHODEX_AGENT_STATUS_PATH environment variable is not set");
    };

    let mut stream = match UnixStream::connect(&path) {
        Ok(stream) => stream,
        Err(err) => {
            debug!(
                ?err,
                path, "Received error when attempting to connect to unix stream"
            );

            if err.kind() != io::ErrorKind::NotFound {
                bail!(err);
            }

            return Ok(Status::NotRunning);
        }
    };

    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .context("Failed to set status check read timeout")?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("Failed to read agent status")?;

    Status::from_str(&response)
}

async fn run_ebpf_agent(ebpf_command: NetworkCommand) -> anyhow::Result<()> {
    let NetworkCommand {
        global_opts:
            GlobalOpts {
                report_api_key,
                service_endpoint,
                log_report,
                secret_values_hash_salt,
            },
        enable_rulesets,
        disable_rulesets,
        additional_rulesets,
        ruleset_input,
        ..
    } = ebpf_command;

    // Setup crypto and API key
    setup_agent_environment(
        report_api_key.as_ref(),
        service_endpoint.as_ref(),
        secret_values_hash_salt.as_ref(),
    )?;

    // Setup status tracking
    let status = Arc::new(Mutex::new(Status::Started));
    run_status_listener(Arc::clone(&status));

    // Parse rulesets and initialize systems
    let (context, rules) = parse_archodex_rulesets(
        enable_rulesets,
        disable_rulesets,
        additional_rulesets,
        ruleset_input,
    )
    .await?;

    // Initialize eBPF subsystems
    let report_receiver = initialize_ebpf_subsystems(&rules, &context).await?;

    // Mark as ready
    *status.lock().unwrap() = Status::Ready;
    info!("Archodex agent is ready");
    debug!(?context, "Context");

    // Initialize license enforcement based on license key
    let rate_limiter = if report_api_key::header_value().is_none() {
        debug!("Rate limiting enabled: operating in Standalone mode (no license key detected)");
        LimitState::for_mode(OperatingMode::Standalone)
    } else {
        // TODO: Extend License enforcement to based both on details
        //       in the license and backend updates
        debug!("Rate limiting enabled: license key detected, using team plan limits");
        LimitState::for_mode(OperatingMode::Team)
    };

    // Run the main event loop
    run_event_loop(report_receiver, context, log_report, rate_limiter).await?;

    Ok(())
}

#[instrument(skip(status))]
fn run_status_listener(status: Arc<Mutex<Status>>) {
    let Ok(path) = env::var("ARCHODEX_AGENT_STATUS_PATH") else {
        return;
    };

    if let Err(err) = fs::remove_file(&path)
        && err.kind() != io::ErrorKind::NotFound
    {
        panic!("Failed to remove status socket at path {path}: {err}");
    }

    let listener = UnixListener::bind(&path)
        .unwrap_or_else(|err| panic!("Failed to create status socket at path {path}: {err}"));

    fs::set_permissions(&path, PermissionsExt::from_mode(0o666)).unwrap_or_else(|err| {
        panic!("Failed to make status socket at path {path} readable: {err}")
    });

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let status_string = (*(status.lock().unwrap())).to_string();
                    if let Err(err) = stream.write_all(status_string.as_bytes()) {
                        warn!(?err, "Failed to send status to connection");
                    }
                }
                Err(err) => {
                    warn!(?err, "Failed to accept incoming status connection");
                }
            }
        }
    });
}

fn setup_libbpf_logging() {
    libbpf_rs::set_print(Some((
        libbpf_rs::PrintLevel::Debug,
        |bpf_level, message| match bpf_level {
            libbpf_rs::PrintLevel::Debug => tracing::debug!(message),
            libbpf_rs::PrintLevel::Info => tracing::info!(message),
            libbpf_rs::PrintLevel::Warn => tracing::warn!(message),
        },
    )));
}

fn setup_agent_environment(
    report_api_key: Option<&String>,
    service_endpoint: Option<&String>,
    secret_values_hash_salt: Option<&String>,
) -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap_or_else(|_| panic!("Failed to install AWS LC PKI provider"));

    if let Some(key) = report_api_key {
        report_api_key::set(key, service_endpoint)?;
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

    account_salted_hasher::init(secret_values_hash_salt)?;
    Ok(())
}

async fn initialize_ebpf_subsystems(
    rules: &Rules,
    context: &Context,
) -> anyhow::Result<tokio::sync::mpsc::UnboundedReceiver<Report>> {
    setup_libbpf_logging();

    let (mmap_exec_file_event_receiver, initialized_receiver) = mmap_exec_files();
    let libssl_event_receiver = libssl_events(mmap_exec_file_event_receiver, rules);
    let transport_event_receiver = transport_parser(libssl_event_receiver);
    let report_receiver = rules.message_parser(transport_event_receiver, context.clone());

    // Wait for initialization to complete
    initialized_receiver
        .await
        .expect("Failed to receive agent initialized event");

    Ok(report_receiver)
}

async fn run_event_loop(
    mut report_receiver: tokio::sync::mpsc::UnboundedReceiver<Report>,
    context: Context,
    log_report: bool,
    mut rate_limiter: LimitState,
) -> anyhow::Result<()> {
    // Setup signal handlers
    let mut sigusr1 =
        signal(SignalKind::user_defined1()).expect("Failed to install SIGUSR1 handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");

    let mut deadline = Instant::now() + FIRST_REPORT_PERIOD;

    loop {
        select! {
            new_report = report_receiver.recv() => {
                process_new_report(&context, new_report).await?;
            },
            continue_after_sending_report = report_trigger(&mut sigusr1, &mut sigterm, deadline) => {
                send_and_process_report(&context, log_report, &mut rate_limiter).await?;
                if !continue_after_sending_report {
                    break;
                }
                deadline = Instant::now() + REPORT_PERIOD;
            },
        }
    }

    Ok(())
}

async fn report_trigger(
    sigusr1: &mut tokio::signal::unix::Signal,
    sigterm: &mut tokio::signal::unix::Signal,
    deadline: Instant,
) -> bool {
    select! {
        () = sleep_until(deadline) => true,
        _ = sigusr1.recv() => {
            info!("Received SIGUSR1, sending report");
            true
        },
        _ = signal::ctrl_c() => {
            info!("Received SIGINT, sending report and exiting");
            false
        },
        _ = sigterm.recv() => {
            info!("Received SIGTERM, sending report and exiting");
            false
        },
    }
}

async fn process_new_report(context: &Context, new_report: Option<Report>) -> anyhow::Result<()> {
    let Some(new_report) = new_report else {
        unreachable!("Report channel closed unexpectedly");
    };

    debug!(
        "Received new report: {}",
        serde_json::to_string_pretty(&new_report)?
    );

    context.lock().await.merge_report(new_report);
    Ok(())
}

async fn send_and_process_report(
    context: &Context,
    log_report: bool,
    rate_limiter: &mut LimitState,
) -> anyhow::Result<()> {
    let report = context.lock().await.get_report().await;

    debug!(
        "Sending report: {}",
        serde_json::to_string_pretty(&report).expect("Failed to convert report to JSON")
    );

    // Apply license enforcement limits
    let result = rate_limiter.check_limits(&report).await;

    // Finish if rate limits reached
    if !result.allow_report {
        info!("Rate limit reached: {:?}", result.limits_reached);
        return Ok(());
    }

    if log_report {
        report.log();
    }

    // Display usage information
    let usage = rate_limiter.usage_info().await;
    info!(
        "────────────────────────────────────────────────────────────────────────────────────────────"
    );
    info!("{}", usage);
    info!(
        "────────────────────────────────────────────────────────────────────────────────────────────"
    );

    // Show CTAs if a limit was just breached
    for limit in &result.new_limits {
        match limit {
            LimitType::Resource => {
                eprintln!("{RESOURCE_LIMIT_CTA}");
            }
            LimitType::Event => {
                eprintln!("{EVENT_LIMIT_CTA}");
            }
        }
    }

    if let (Some(endpoint), Some(header_value)) =
        (report_api_key::endpoint(), report_api_key::header_value())
    {
        send_report(report, endpoint, header_value).await?;
        info!("Archodex report sent successfully");
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn parse_archodex_rulesets(
    enable_rulesets: EnableRulesets,
    disable_rulesets: DisableRulesets,
    additional_rulesets: Vec<String>,
    ruleset_inputs: Vec<String>,
) -> anyhow::Result<(Context, Rules)> {
    let mut ruleset_inputs = ruleset_inputs
      .into_iter()
      .try_fold(HashMap::new(), |mut acc: HashMap<_, HashMap<_, String>>, input| {
          let (ruleset_id, input_name_value) = input.split_once(':').with_context(|| {
              format!(
                  "Failed to parse ruleset ID from ruleset input argument {input:?}, expected format <ruleset_id>:<input_name>=<value>"
              )
          })?;

          let (input_name, value) = input_name_value.split_once('=').with_context(|| {
              format!(
                  "Failed to parse input name and value from ruleset input argument {input:?}, expected format <ruleset_id>:<input_name>=<value>"
              )
          })?;

          acc.entry(ruleset_id.to_owned())
              .or_default()
              .insert(input_name.to_owned(), value.to_owned());

          anyhow::Ok(acc)
      })?;

    let mut enable_rulesets: HashSet<String> = HashSet::from_iter(enable_rulesets);
    let mut disable_rulesets: HashSet<String> = HashSet::from_iter(disable_rulesets);

    let mut enabled_builtin_rulesets = HashMap::new();

    for file in BUILTIN_RULESETS_DEFAULT_ENABLED.files() {
        let ruleset_id = file.path().file_stem().unwrap().to_str().unwrap();

        if disable_rulesets.remove(ruleset_id) {
            info!(
                "Built-in Archodex ruleset {ruleset_id} disabled by command-line --disable-rulesets argument or ARCHODEX_DISABLE_RULESETS env var"
            );

            continue;
        }

        let contents = file.contents_utf8().with_context(|| {
            format!(
                "Built-in Archodex ruleset {ruleset_id} is enabled but could not be parsed as UTF-8"
            )
        })?;

        enabled_builtin_rulesets.insert(ruleset_id.to_owned(), contents.to_owned());
    }

    for ruleset_id in disable_rulesets {
        warn!(
            ruleset_id,
            "Built-in Archodex ruleset disabled by command-line --disable-rulesets argument or ARCHODEX_DISABLE_RULESETS env var, but ruleset is not built-in"
        );
    }

    for file in BUILTIN_RULESETS_DEFAULT_DISABLED.files() {
        let ruleset_id = file
            .path()
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        if enable_rulesets.remove(&ruleset_id) {
            info!(
                "Built-in Archodex ruleset {ruleset_id} enabled by command-line --enable-rulesets argument or ARCHODEX_ENABLE_RULESETS env var"
            );

            let contents = file.contents_utf8().with_context(|| {
                format!(
                    "Built-in Archodex ruleset {ruleset_id} is enabled but could not be parsed as UTF-8"
                )
            })?;

            enabled_builtin_rulesets.insert(ruleset_id, contents.to_owned());
        }
    }

    for ruleset_id in enable_rulesets {
        warn!(
            ruleset_id,
            "Built-in Archodex ruleset enabled by command-line --enable-rulesets argument or ARCHODEX_ENABLE_RULESETS env var, but ruleset is not built-in"
        );
    }

    let mut path_rulesets = HashMap::new();

    for ruleset in additional_rulesets {
        let (ruleset_id, ruleset) = ruleset.split_once('=').map_or_else(
            || (None, ruleset.as_str()),
            |(id, ruleset)| (Some(id.to_string()), ruleset),
        );

        if let Ok(url) = Url::parse(ruleset) {
            let ruleset_id = ruleset_id
              .or_else(|| {
                  url.path_segments()
                      .and_then(|mut segments| segments.next_back())
                      .and_then(|segment| segment.split_once('.'))
                      .map(|(id, _)| id.to_string())
              })
              .with_context(|| format!("Failed to parse ruleset ID from URL {ruleset:?}\n  Check the URL or provide a ruleset ID: `<ruleset_id>={ruleset}`"))?;

            ensure!(
                !ruleset_id.is_empty(),
                "Failed to parse ruleset ID from URL {ruleset:?}\n  Check the URL or provide a ruleset ID: `<ruleset_id>={ruleset}`"
            );

            let response = reqwest::get(url)
                .await
                .with_context(|| {
                    format!("Failed to fetch additional Archodex ruleset {ruleset:?}")
                })?
                .error_for_status()
                .with_context(|| {
                    format!("Failed to fetch additional Archodex ruleset {ruleset:?}")
                })?
                .text()
                .await
                .with_context(|| {
                    format!("Failed to fetch additional Archodex ruleset {ruleset:?}")
                })?;

            path_rulesets.insert(ruleset_id, response);
        } else {
            let ruleset_path = Path::new(&ruleset);

            ensure!(
                ruleset_path.exists(),
                "Additional Archodex ruleset path {ruleset:?} does not exist"
            );

            ensure!(
                ruleset_path.is_file(),
                "Additional Archodex ruleset path {ruleset:?} is not a file"
            );

            let ruleset_id = ruleset_id.unwrap_or_else(|| {
                ruleset_path
                    .file_stem()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            });

            let contents = fs::read_to_string(ruleset_path).with_context(|| {
                format!("Failed to read additional Archodex ruleset from path {ruleset:?}")
            })?;

            path_rulesets.insert(ruleset_id, contents);
        }
    }

    let mut enabled_rulesets_log = "Enabled rulesets:".to_string();
    for ruleset_id in enabled_builtin_rulesets.keys() {
        write!(&mut enabled_rulesets_log, "\n  {ruleset_id} (built-in)").unwrap();
    }
    for ruleset_id in path_rulesets.keys() {
        write!(&mut enabled_rulesets_log, "\n  {ruleset_id}").unwrap();
    }

    info!("{enabled_rulesets_log}");

    let rulesets = enabled_builtin_rulesets
        .into_iter()
        .chain(path_rulesets.into_iter())
        .filter_map(|(ruleset_id, contents)| {
            let cli_arg_inputs = ruleset_inputs.remove(&ruleset_id).unwrap_or_default();

            match Ruleset::try_from_id_config_inputs(&ruleset_id, &contents, cli_arg_inputs) {
                Ok(ruleset) => {
                    debug!(ruleset_id, "Parsed and validated Archodex ruleset");
                    Some(Ok(ruleset))
                }
                Err(RulesetParsingError::UnsatisfiedInputs(err)) => {
                    info!("Disabling Archodex ruleset {ruleset_id}: {err}");
                    None
                }
                Err(RulesetParsingError::ParsingError(err)) => Some(
                    Err(err).context(format!("Failed to parse Archodex ruleset {ruleset_id:?}")),
                ),
            }
        })
        .collect::<anyhow::Result<Config>>()?;

    if rulesets.rules.is_empty() {
        bail!("No Archodex rulesets with rules are enabled");
    }

    for ruleset_id in ruleset_inputs.keys() {
        warn!(
            ruleset_id,
            "Ruleset input values provided for ruleset, but ruleset was not enabled"
        );
    }

    let context = context::new().await;
    let mut context_unlocked = context.lock().await;

    for config_context in rulesets.contexts {
        context_unlocked.add_context(config_context).await?;
    }

    drop(context_unlocked);

    let rules = Rules::new(rulesets.rules).context("Failed to parse Archodex rules")?;

    Ok((context, rules))
}
