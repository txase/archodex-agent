mod github;

use clap::{Args, Subcommand};
use github::{GitHubCommand, handle_github_command};

#[derive(Args, Debug)]
pub(crate) struct SecretsCommands {
    #[command(subcommand)]
    subcommand: SecretsSubcommands,
}

#[derive(Debug, Subcommand)]
enum SecretsSubcommands {
    /// Report Secret Values from GitHub Secret Scanning
    #[command(name = "github")]
    GitHub(GitHubCommand),
}

pub(crate) async fn handle_secrets_command(command: SecretsCommands) -> anyhow::Result<()> {
    match &command.subcommand {
        SecretsSubcommands::GitHub(_) => Box::pin(handle_github_command(command)).await,
    }
}
