//! IKEWolf -- IKE/IPsec security scanner for authorized penetration testing.
//!
//! Sends crafted IKE packets to UDP 500/4500, collects and parses responses,
//! fingerprints implementations, enumerates accepted transforms, and extracts
//! crackable Aggressive Mode PSK hashes (hashcat 5300/5400/38100).

#![forbid(unsafe_code)]

mod cli;
mod engine;
mod output;

use clap::Parser;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    let globals = cli.global_opts();

    // Initialize tracing.
    let filter = if globals.quiet {
        "error".to_owned()
    } else {
        match globals.verbose {
            0 => "warn".to_owned(),
            1 => "info".to_owned(),
            2 => "debug".to_owned(),
            _ => "trace".to_owned(),
        }
    };

    tracing_subscriber::fmt().with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&filter))).with_target(false).with_writer(std::io::stderr).init();

    // Apply --no-color.
    output::apply_no_color(globals.no_color);

    // Build tokio runtime and dispatch.
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    match cli.command {
        cli::Command::Completions(ref args) => {
            cli::completions(args);
            Ok(())
        },
        cli::Command::Scan(args) => rt.block_on(cli::scan::run(args, &globals)),
        cli::Command::EnumGroups(args) => rt.block_on(cli::enum_groups::run(args, &globals)),
    }
}
