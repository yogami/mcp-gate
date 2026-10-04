#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

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
    /// Print version, commit, build target and supported MCP protocol versions
    Version,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Version => {
            println!("mcp-gate 0.1.0");
            println!("Supported MCP protocol versions: 2025-06-18, 2024-11-05");
        }
    }
}
