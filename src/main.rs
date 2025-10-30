mod account_salted_hasher;
mod bpf_event_parser_helpers;
mod bpf_log;
mod elf;
mod engine;
mod global_opts;
mod gopclntab;
mod hexdump;
mod libssl_event_parser;
pub(crate) mod license_enforcement;
mod mmap_exec_files;
mod mmap_exec_files_event_parser;
mod mount_path;
mod network;
mod pid_waiter;
mod process_context;
mod report_api_key;
mod ruleset;
mod secrets;
mod send_report;
mod ssl_instrumenter;
mod transport_parser;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/archodex.report_api_key.rs"));
}

use std::{env, time::Duration};

use clap::{Parser, command};
use engine::{
    config::Config,
    context::{Context, ContextMethods},
    report::Report,
    rules::Rules,
};
use mmap_exec_files::mmap_exec_files;
use network::{NetworkCommand, handle_network_command};
use regex::Regex;
use ruleset::Ruleset;
use secrets::{SecretsCommands, handle_secrets_command};
use send_report::send_report;
use ssl_instrumenter::libssl_events;
use transport_parser::transport_parser;

pub(crate) const REPORT_TX_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, clap::Args)]
struct MarkdownHelpCommand;

#[derive(Debug, clap::Subcommand)]
enum Commands {
    /// Network agent commands
    Network(NetworkCommand),

    /// Secrets scanner agent commands
    Secrets(SecretsCommands),

    #[command(hide = true)]
    MarkdownHelp(MarkdownHelpCommand),
}

fn setup_logging() {
    use std::io::IsTerminal;
    use tracing_subscriber::{
        filter::{EnvFilter, LevelFilter},
        fmt,
    };

    let color = std::io::stdout().is_terminal()
        && (match env::var("COLORTERM") {
            Ok(value) => value == "truecolor" || value == "24bit",
            _ => false,
        } || match env::var("TERM") {
            Ok(value) => value == "direct" || value == "truecolor",
            _ => false,
        });

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    let fmt = fmt().with_env_filter(env_filter);

    if color {
        fmt.event_format(fmt::format().pretty())
            .with_file(false)
            .with_line_number(false)
            .with_ansi(color)
            .init();
    } else {
        fmt.with_file(false)
            .with_line_number(false)
            .with_ansi(false)
            .init();
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Cli::parse();

    setup_logging();

    match opts.command {
        Commands::Network(ebpf_command) => {
            handle_network_command(ebpf_command).await?;
        }
        Commands::Secrets(secrets_command) => {
            Box::pin(handle_secrets_command(secrets_command)).await?;
        }
        Commands::MarkdownHelp(_) => {
            let options = clap_markdown::MarkdownOptions::new().show_footer(false);

            let markdown = clap_markdown::help_markdown_custom::<Cli>(&options).replace("↴", "");

            // Demote the top two levels of headers by one level each
            let subheader_demotion_re = Regex::new(r"(?m)^## ")?;
            let header_demotion_re = Regex::new(r"(?m)^# ")?;

            let markdown = subheader_demotion_re.replace_all(&markdown, "### ");
            let markdown = header_demotion_re.replace_all(&markdown, "## ");

            println!("{markdown}");
        }
    }

    Ok(())
}
