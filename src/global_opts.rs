use clap::{ArgAction, Args, value_parser};

#[derive(Debug, Args)]
pub(crate) struct GlobalOpts {
    /// Archodex Report API Key
    ///
    /// If the Report API Key is not provided, the agent will run in
    /// logging-only mode and will not send reports to the Archodex service.
    #[arg(
        short = 'k',
        long,
        env = "ARCHODEX_REPORT_API_KEY",
        hide_env_values = true
    )]
    pub(crate) report_api_key: Option<String>,

    /// Archodex Service Endpoint
    ///
    /// The Service Endpoint to send reports to must be specified when Archodex
    /// is self-hosted (e.g. `https://service.archodex:5732`).
    #[arg(short, long, env = "ARCHODEX_SERVICE_ENDPOINT")]
    pub(crate) service_endpoint: Option<String>,

    /// Log report to stdout
    #[arg(short, long, env = "ARCHODEX_LOG_REPORT", value_parser = value_parser!(bool), action = ArgAction::Set, default_value_t = true)]
    pub(crate) log_report: bool,

    /// Provide Salt for Secret Value Hashes
    ///
    /// Secret Values are never logged or transmitted. Instead, they are
    /// cryptographically hashed (SHA-256) with a random salt. Each Archodex
    /// service account has a unique salt. The salt value is embedded in the
    /// Archodex Report API Key. If you do not provide an Archodex Report API
    /// Key, you may provide a salt value to use instead. This is useful for
    /// testing and debugging purposes. If neither are provided, a random salt
    /// is generated at startup, which means Secret Value hashes for the same
    /// values will be different between invocations of the agent. This is a
    /// security risk mitigation to ensure that common secret values cannot be
    /// determined from Secret Value hashes.
    ///
    /// The value must be a hex string with a length of 16 bytes (32 characters)
    #[arg(long, env = "ARCHODEX_SECRET_VALUES_HASH_SALT")]
    pub(crate) secret_values_hash_salt: Option<String>,
}
