//! CLI argument parsing and subcommand dispatch.
//!
//! Convention: `Cli` struct with `GlobalOpts` extraction,
//! `Command` enum with `Subcommand` derive, `H_*` heading constants.

use clap::{Parser, Subcommand};

pub(crate) mod enum_groups;
pub(crate) mod scan;
pub(crate) mod target;

// --- Help section headings (group related flags in --help output) ------------

pub(crate) const H_TARGET: &str = "Target Selection";
pub(crate) const H_TIMING: &str = "Timing & Rate Limiting";
pub(crate) const H_OUTPUT: &str = "Output";
pub(crate) const H_IKE: &str = "IKE Protocol";

/// IKEWolf -- IKE/IPsec security scanner for authorized penetration testing.
///
/// Sends crafted IKE packets to discover VPN endpoints, enumerate accepted
/// transforms, fingerprint implementations, and extract crackable Aggressive
/// Mode PSK hashes (hashcat 5300/5400/38100).
///
/// For authorized security testing only.
#[derive(Debug, Parser)]
#[command(
    name = "ikewolf",
    version,
    about,
    long_about = None,
    help_template = "{about-with-newline}\n{usage-heading} {usage}\n\n{options}\n{after-help}",
    after_help = COMMANDS_HELP,
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,

    /// Increase verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub(crate) verbose: u8,

    /// Suppress all output except errors
    #[arg(short, long, global = true)]
    pub(crate) quiet: bool,

    /// Disable colored output (also honoured via NO_COLOR env var)
    #[arg(long, global = true, help_heading = H_OUTPUT)]
    pub(crate) no_color: bool,
}

/// Categorised command listing.
const COMMANDS_HELP: &str = concat!(
    "Commands:\n",
    "  Scanning:\n",
    "    scan          Scan targets for IKE/IPsec VPN endpoints\n",
    "    enum-groups   Enumerate valid VPN group names via Aggressive Mode\n",
    "  Utilities:\n",
    "    completions   Generate shell completions\n",
    "\n",
    "Run `ikewolf <COMMAND> --help` for per-command options.\n",
    "\n",
    "Examples:\n",
    "  ikewolf scan 192.168.1.1                       # single target\n",
    "  ikewolf scan 10.0.0.0/24 --psk --id vpngroup   # subnet PSK extraction\n",
    "  ikewolf scan -f targets.txt --json              # file input, JSON output\n",
    "  ikewolf enum-groups 10.0.0.1 -w groups.txt     # group name enumeration\n",
);

/// Global options extracted from `Cli` before the subcommand match moves it.
#[derive(Debug, Clone)]
pub(crate) struct GlobalOpts {
    pub(crate) verbose: u8,
    pub(crate) quiet: bool,
    pub(crate) no_color: bool,
}

impl Cli {
    #[must_use]
    pub(crate) fn global_opts(&self) -> GlobalOpts {
        GlobalOpts { verbose: self.verbose, quiet: self.quiet, no_color: self.no_color }
    }
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Scan targets for IKE/IPsec VPN endpoints
    Scan(scan::ScanArgs),

    /// Enumerate valid VPN group names via Aggressive Mode
    EnumGroups(enum_groups::EnumGroupsArgs),

    /// Generate shell completions
    Completions(CompletionsArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub(crate) shell: clap_complete::Shell,
}

pub(crate) fn completions(args: &CompletionsArgs) {
    let mut cmd = <Cli as clap::CommandFactory>::command();
    clap_complete::generate(args.shell, &mut cmd, "ikewolf", &mut std::io::stdout());
}
