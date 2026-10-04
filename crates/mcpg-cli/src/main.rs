#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use mcpg_domain::verdict::ExitCode;

mod cmd;

#[derive(Parser)]
#[command(name = "mcp-gate")]
#[command(version = "0.1.0")]
#[command(about = "Linux CI regression tester and capability policy gate for MCP servers")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a server in a capsule and evaluate it against its policy
    Run {
        /// Config file to run
        #[arg(short = 'c', long = "config", default_value = "./mcp-gate.yaml")]
        config: PathBuf,
        /// Seed for reproducible execution (64 hex characters)
        #[arg(long = "seed")]
        seed: Option<mcpg_domain::seed::Seed>,
    },
    /// Check a config file against the schema and resolve all paths
    Validate {
        /// Config file to validate
        #[arg(short = 'c', long = "config", default_value = "./mcp-gate.yaml")]
        config: PathBuf,
    },
    /// Print host isolation capabilities as JSON
    Probe,
    /// Print version, commit, build target and supported MCP protocol versions
    Version,
}

fn run_command(cmd: Commands) -> ExitCode {
    match cmd {
        Commands::Run { config, seed } => cmd::run::execute(&config, seed),
        Commands::Validate { config } => cmd::validate::execute(&config),
        Commands::Probe => cmd::probe::execute(),
        Commands::Version => {
            println!("mcp-gate 0.1.0");
            println!("Supported MCP protocol versions: 2025-06-18, 2024-11-05");
            ExitCode::Pass
        }
    }
}

fn handle_cli_error(err: clap::Error) -> ! {
    if err.use_stderr() {
        eprintln!("{err}");
        std::process::exit(ExitCode::Usage as i32);
    } else {
        print!("{err}");
        std::process::exit(ExitCode::Pass as i32);
    }
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(err) => handle_cli_error(err),
    };
    let code = run_command(cli.command);
    std::process::exit(code as i32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_version() {
        let cli = Cli::try_parse_from(["mcp-gate", "version"]).expect("parse version command");
        let code = run_command(cli.command);
        assert_eq!(code, ExitCode::Pass);
    }

    #[test]
    fn validates_valid_and_invalid_configs_in_unit() {
        let valid_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/configs/valid/annotated.yaml");
        let code_valid = run_command(Commands::Validate { config: valid_path });
        assert_eq!(code_valid, ExitCode::Pass);

        let invalid_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/configs/invalid/unknown_key.yaml");
        let code_invalid = run_command(Commands::Validate {
            config: invalid_path,
        });
        assert_eq!(code_invalid, ExitCode::Usage);

        let missing_path = Path::new("non_existent_config.yaml");
        let code_missing = run_command(Commands::Validate {
            config: missing_path.to_path_buf(),
        });
        assert_eq!(code_missing, ExitCode::Usage);
    }
}
