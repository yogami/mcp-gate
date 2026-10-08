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

#[derive(clap::Args)]
struct RunArgs {
    /// Config file to run
    #[arg(short = 'c', long = "config", default_value = "./mcp-gate.yaml")]
    config: PathBuf,
    /// Where reports go
    #[arg(long = "out-dir", default_value = "./mcp-gate-results")]
    out_dir: PathBuf,
    /// SARIF output path, '-' disables
    #[arg(long = "sarif")]
    sarif: Option<String>,
    /// JUnit output path, '-' disables
    #[arg(long = "junit")]
    junit: Option<String>,
    /// NDJSON evidence output path
    #[arg(long = "evidence")]
    evidence: Option<String>,
    /// Operational mode: enforce or observe
    #[arg(long = "mode", default_value = "enforce")]
    mode: String,
    /// Comma-separated list of required features
    #[arg(long = "require")]
    require: Option<String>,
    /// Lowest SARIF level that makes the verdict FAIL
    #[arg(long = "fail-on")]
    fail_on: Option<String>,
    /// Seed for reproducible execution (64 hex characters)
    #[arg(long = "seed")]
    seed: Option<mcpg_domain::seed::Seed>,
    /// Override total run timeout in seconds
    #[arg(long = "timeout")]
    timeout: Option<u64>,
    /// Keep the run directory for debugging
    #[arg(long = "keep-capsule")]
    keep_capsule: bool,
    /// Write raw canary values into evidence
    #[arg(long = "evidence-include-values")]
    evidence_include_values: bool,
    /// Do not emit GitHub workflow commands
    #[arg(long = "no-annotations")]
    no_annotations: bool,
    /// Suppress summary console output
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
    /// Increase logging verbosity
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate an empty mcp-gate.yaml configuration file in the current directory
    Init,
    /// Run a server in a capsule and evaluate it against its policy
    Run(Box<RunArgs>),
    /// Check a config file against the schema and resolve all paths
    Validate {
        /// Config file to validate
        #[arg(short = 'c', long = "config", default_value = "./mcp-gate.yaml")]
        config: PathBuf,
    },
    /// Print host isolation capabilities as JSON
    Probe,
    /// Print documentation for a rule ID (e.g. mcp-gate explain MCPG005)
    Explain {
        /// Rule ID to explain (e.g. MCPG001, MCPG005)
        rule: String,
    },
    /// Print version, commit, build target and supported MCP protocol versions
    Version,
}

fn parse_mode(s: &str) -> Result<mcpg_domain::mode::Mode, ExitCode> {
    match s.to_lowercase().as_str() {
        "enforce" => Ok(mcpg_domain::mode::Mode::Enforce),
        "observe" => Ok(mcpg_domain::mode::Mode::Observe),
        _ => {
            eprintln!("Error: invalid mode '{s}', expected 'enforce' or 'observe'");
            Err(ExitCode::Usage)
        }
    }
}

fn parse_feature_item(
    item: &str,
    out: &mut Vec<mcpg_domain::host::Feature>,
) -> Result<(), ExitCode> {
    let trimmed = item.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    match trimmed.parse::<mcpg_domain::host::Feature>() {
        Ok(f) => {
            out.push(f);
            Ok(())
        }
        Err(e) => {
            eprintln!("Error: {e}");
            Err(ExitCode::Usage)
        }
    }
}

fn parse_require(raw_opt: Option<&str>) -> Result<Vec<mcpg_domain::host::Feature>, ExitCode> {
    let mut features = Vec::new();
    let Some(raw) = raw_opt else {
        return Ok(features);
    };
    for part in raw.split(',') {
        parse_feature_item(part, &mut features)?;
    }
    Ok(features)
}

fn parse_fail_on(
    raw_opt: Option<&str>,
) -> Result<Option<mcpg_domain::config::model::FailOnLevel>, ExitCode> {
    let Some(raw) = raw_opt else {
        return Ok(None);
    };
    match raw.to_ascii_lowercase().as_str() {
        "error" => Ok(Some(mcpg_domain::config::model::FailOnLevel::Error)),
        "warning" => Ok(Some(mcpg_domain::config::model::FailOnLevel::Warning)),
        "note" => Ok(Some(mcpg_domain::config::model::FailOnLevel::Note)),
        _ => {
            eprintln!(
                "Error: invalid fail-on level '{raw}', expected 'error', 'warning', or 'note'"
            );
            Err(ExitCode::Usage)
        }
    }
}

fn build_run_options(args: RunArgs) -> Result<mcpg_app::orchestrator::RunOptions, ExitCode> {
    let requested_mode = parse_mode(&args.mode)?;
    let require = parse_require(args.require.as_deref())?;
    let fail_on = parse_fail_on(args.fail_on.as_deref())?;

    if args.evidence_include_values && std::env::var("CI").is_ok() {
        eprintln!("Error: --evidence-include-values is forbidden in CI environments (exit 64)");
        return Err(ExitCode::Usage);
    }

    let verbosity = if args.quiet {
        mcpg_app::orchestrator::Verbosity::Quiet
    } else if args.verbose {
        mcpg_app::orchestrator::Verbosity::Verbose
    } else {
        mcpg_app::orchestrator::Verbosity::Normal
    };

    Ok(mcpg_app::orchestrator::RunOptions {
        config_path: args.config,
        out_dir: args.out_dir,
        sarif_path: args.sarif,
        junit_path: args.junit,
        evidence_path: args.evidence,
        requested_mode,
        require,
        fail_on,
        seed: args.seed,
        timeout: args.timeout,
        keep_capsule: args.keep_capsule,
        evidence_include_values: args.evidence_include_values,
        no_annotations: args.no_annotations,
        quiet: args.quiet,
        verbose: args.verbose,
        verbosity,
    })
}

fn run_command(cmd: Commands) -> ExitCode {
    match cmd {
        Commands::Init => cmd::init::execute(),
        Commands::Run(boxed_args) => {
            let opts = match build_run_options(*boxed_args) {
                Ok(o) => o,
                Err(code) => return code,
            };
            cmd::run::execute(&opts)
        }
        Commands::Validate { config } => cmd::validate::execute(&config),
        Commands::Probe => cmd::probe::execute(),
        Commands::Explain { rule } => cmd::explain::execute(&rule),
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

    #[cfg(target_os = "linux")]
    if !matches!(cli.command, Commands::Probe) {
        if let Err(err) = mcpg_linux::self_harden::harden_self() {
            eprintln!("Warning: failed to harden runner process: {err}");
        }
    }

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
