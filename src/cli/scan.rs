//! `ikewolf scan` subcommand -- the primary scanning interface.

use std::fmt::Write as _;
use std::time::Instant;

use clap::Args;

use crate::cli::target;
use crate::cli::{GlobalOpts, H_IKE, H_OUTPUT, H_TARGET, H_TIMING};
use crate::engine::scanner::{ScanConfig, ScanOutput, Scanner};
use crate::output;

const SCAN_EXAMPLES: &str = "\
Examples:
  ikewolf scan 10.0.0.0/24
  ikewolf scan 10.0.0.1 --psk --id vpngroup
  ikewolf scan -f hosts.txt --json
  ikewolf scan 10.0.0.1 -p 4500 --ikev2
  ikewolf scan 10.0.0.1 --aggressive --id-type fqdn --id host.example.com";

/// Identity payload type for Aggressive Mode probes.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub(crate) enum IdType {
    /// Opaque key identifier (type 11). Default for VPN group names.
    #[default]
    KeyId,
    /// Fully Qualified Domain Name (type 2).
    Fqdn,
    /// User FQDN / email address (type 3).
    UserFqdn,
    /// IPv4 address (type 1).
    Ipv4,
}

impl IdType {
    #[must_use]
    pub(crate) fn to_protocol(self) -> ike_protocol::ikev1::model::Ikev1IdType {
        match self {
            Self::KeyId => ike_protocol::ikev1::model::Ikev1IdType::KeyId,
            Self::Fqdn => ike_protocol::ikev1::model::Ikev1IdType::Fqdn,
            Self::UserFqdn => ike_protocol::ikev1::model::Ikev1IdType::UserFqdn,
            Self::Ipv4 => ike_protocol::ikev1::model::Ikev1IdType::Ipv4Addr,
        }
    }
}

/// Scan targets for IKE/IPsec VPN endpoints.
///
/// Sends IKEv1 Main Mode, IKEv1 Aggressive Mode, and/or IKEv2 SA_INIT
/// probes. Reports accepted transforms, vendor fingerprints, and security
/// findings.
#[derive(Debug, Args)]
#[command(after_long_help = SCAN_EXAMPLES)]
pub(crate) struct ScanArgs {
    /// Targets: IPs, CIDRs. Omit if using -f.
    #[arg(required_unless_present = "targets_file", help_heading = H_TARGET)]
    pub(crate) targets: Vec<String>,

    /// Read targets from FILE (one per line, # comments, blank lines skipped)
    #[arg(short = 'f', long = "file", value_name = "FILE", help_heading = H_TARGET)]
    pub(crate) targets_file: Option<String>,

    /// UDP destination port
    #[arg(short, long, default_value_t = 500, value_name = "PORT", help_heading = H_TARGET)]
    pub(crate) port: u16,

    /// Source UDP port (random if unset)
    #[arg(long, value_name = "PORT", help_heading = H_TARGET)]
    pub(crate) source_port: Option<u16>,

    /// Per-probe timeout in milliseconds
    #[arg(short = 't', long, default_value_t = 500, value_name = "MS", help_heading = H_TIMING)]
    pub(crate) timeout: u64,

    /// Number of retransmissions per probe
    #[arg(long, default_value_t = 3, value_name = "N", help_heading = H_TIMING)]
    pub(crate) retries: u32,

    /// Timeout multiplier after each retry (exponential backoff)
    #[arg(long, default_value_t = 1.5, value_name = "MULT", help_heading = H_TIMING)]
    pub(crate) backoff: f64,

    /// Maximum outstanding probes
    #[arg(short = 'c', long, default_value_t = 256, value_name = "N", help_heading = H_TIMING)]
    pub(crate) concurrency: usize,

    /// Rate limit in packets per second (0 = unlimited)
    #[arg(long, default_value_t = 0, value_name = "PPS", help_heading = H_TIMING)]
    pub(crate) rate: u32,

    /// Wait time (ms) after last send for straggler responses
    #[arg(long, default_value_t = 3000, value_name = "MS", help_heading = H_TIMING)]
    pub(crate) end_wait: u64,

    /// Also send Aggressive Mode probes
    #[arg(long, help_heading = H_IKE)]
    pub(crate) aggressive: bool,

    /// Extract PSK hashes (implies --aggressive)
    #[arg(long, help_heading = H_IKE)]
    pub(crate) psk: bool,

    /// Identity / group name for Aggressive Mode
    #[arg(long, default_value = "vpn", value_name = "NAME", help_heading = H_IKE)]
    pub(crate) id: String,

    /// ID payload type for Aggressive Mode
    #[arg(long, default_value = "key-id", value_name = "TYPE", help_heading = H_IKE)]
    pub(crate) id_type: IdType,

    /// Scan IKEv1 only
    #[arg(long, help_heading = H_IKE)]
    pub(crate) ikev1: bool,

    /// Scan IKEv2 only
    #[arg(long, help_heading = H_IKE)]
    pub(crate) ikev2: bool,

    /// Write JSON results to FILE
    #[arg(long, value_name = "FILE", help_heading = H_OUTPUT)]
    pub(crate) json: Option<String>,

    /// Write text results to FILE (in addition to stdout)
    #[arg(short = 'o', long = "output", value_name = "FILE", help_heading = H_OUTPUT)]
    pub(crate) output_file: Option<String>,

    /// Write hashcat lines to FILE (format: ip:hash)
    #[arg(long, value_name = "FILE", help_heading = H_OUTPUT)]
    pub(crate) hashes: Option<String>,

    /// Show response timing for implementation fingerprinting
    #[arg(long, help_heading = H_OUTPUT)]
    pub(crate) show_backoff: bool,

    /// Quick mode: only probe DH group 14 for aggressive mode (default: walks all DH groups)
    #[arg(long, help_heading = H_IKE)]
    pub(crate) quick: bool,
}

impl ScanArgs {
    #[must_use]
    pub(crate) fn send_ikev1(&self) -> bool {
        !self.ikev2 || self.ikev1
    }

    #[must_use]
    pub(crate) fn send_ikev2(&self) -> bool {
        !self.ikev1 || self.ikev2
    }

    #[must_use]
    pub(crate) fn send_aggressive(&self) -> bool {
        self.aggressive || self.psk
    }

    /// Merge positional targets and file-based targets into one list.
    pub(crate) fn all_target_specs(&self) -> anyhow::Result<Vec<String>> {
        let mut specs = self.targets.clone();
        if let Some(ref path) = self.targets_file {
            let content = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read target file {path}: {e}"))?;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                specs.push(trimmed.to_owned());
            }
        }
        Ok(specs)
    }
}

/// Run the scan subcommand.
pub(crate) async fn run(args: ScanArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let start = Instant::now();

    let specs = args.all_target_specs()?;
    let targets = target::parse_targets(&specs, args.port)?;
    if !globals.quiet {
        output::status_info(&format!("Scanning {} target(s) on UDP/{}", targets.len(), args.port));
    }

    let config = ScanConfig {
        timeout_ms: args.timeout,
        retries: args.retries,
        backoff_factor: args.backoff,
        concurrency: args.concurrency,
        rate_pps: args.rate,
        end_wait_ms: args.end_wait,
        send_ikev1: args.send_ikev1(),
        send_ikev2: args.send_ikev2(),
        send_aggressive: args.send_aggressive(),
        extract_psk: args.psk,
        identity: args.id.clone(),
        id_type: args.id_type.to_protocol(),
        source_port: args.source_port,
        show_backoff: args.show_backoff,
        quick: args.quick,
    };

    let scanner = Scanner::new(config);
    let result = scanner.scan(&targets, globals.quiet).await?;

    write_results(&result, &args, globals, start);

    Ok(())
}

fn format_text_results(result: &ScanOutput, args: &ScanArgs, start: Instant) -> String {
    let mut out = String::new();
    let elapsed = start.elapsed();
    let responded = result.hosts.iter().filter(|h| h.responded).count();

    let _ = writeln!(out, "Scan complete: {responded}/{} responded in {:.2}s", result.hosts.len(), elapsed.as_secs_f64());

    for host in &result.hosts {
        if !host.responded {
            continue;
        }
        let _ = writeln!(out, "\n{}", host.target);

        if let Some(ref v1) = host.ikev1_result {
            let _ = writeln!(out, "  IKEv1: {}", if v1.transforms.is_empty() { "no proposal chosen" } else { "responded" });
            if let Some(ref id) = v1.server_id {
                let _ = writeln!(out, "    Server ID: {id}");
            }
            for t in &v1.transforms {
                let _ = writeln!(out, "    Transform: {t}");
            }
            for vid in &v1.vendor_ids {
                let _ = writeln!(out, "    Vendor ID: {vid}");
            }
            for n in &v1.notifications {
                let _ = writeln!(out, "    Notify: {n}");
            }
            if v1.cert_request_count > 0 {
                let _ = writeln!(out, "    Certificate Requests: {}", v1.cert_request_count);
            }
            if v1.nat_detected {
                let _ = writeln!(out, "    NAT-T: detected");
            }
        }

        if let Some(ref v2) = host.ikev2_result {
            let _ = writeln!(out, "  IKEv2: {}", if v2.proposals.is_empty() { "no proposal chosen" } else { "responded" });
            if let Some(ref dh) = v2.dh_group {
                let _ = writeln!(out, "    DH Group: {dh}");
            }
            for p in &v2.proposals {
                let _ = writeln!(out, "    Proposal {}:", p.number);
                for t in &p.transforms {
                    let _ = writeln!(out, "      {t}");
                }
            }
            for vid in &v2.vendor_ids {
                let _ = writeln!(out, "    Vendor ID: {vid}");
            }
            for n in &v2.notifications {
                let _ = writeln!(out, "    Notify: {n}");
            }
            if v2.cert_request_count > 0 {
                let _ = writeln!(out, "    Certificate Requests: {}", v2.cert_request_count);
            }
        }

        for psk in &host.psk_hashes {
            let _ = writeln!(out, "  PSK Hash ({}):", psk.hash_type);
            let _ = writeln!(out, "    hashcat: {}", psk.hashcat_line);
            if let Some(ref warn) = psk.warning {
                let _ = writeln!(out, "    WARNING: {warn}");
            }
        }

        if args.show_backoff
            && let Some(ms) = host.response_time_ms
        {
            let _ = writeln!(out, "  Response time: {ms}ms");
        }
    }

    if result.interrupted {
        let _ = writeln!(out, "Scan interrupted (partial results)");
    }
    out
}

fn write_results(result: &ScanOutput, args: &ScanArgs, globals: &GlobalOpts, start: Instant) {
    if !globals.quiet {
        let text = format_text_results(result, args, start);
        output::status_ok(text.lines().next().unwrap_or("Scan complete"));
        for line in text.lines().skip(1) {
            println!("{line}");
        }

        if let Some(ref path) = args.output_file {
            if let Err(e) = std::fs::write(path, &text) {
                output::status_warn(&format!("cannot write {path}: {e}"));
            } else {
                output::status_ok(&format!("Text results written to {path}"));
            }
        }
    }

    if let Some(ref path) = args.json {
        let filtered = ScanOutput { hosts: result.hosts.iter().filter(|h| h.responded).cloned().collect(), interrupted: result.interrupted };
        match serde_json::to_string_pretty(&filtered) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    output::status_warn(&format!("cannot write {path}: {e}"));
                } else if !globals.quiet {
                    output::status_ok(&format!("JSON results written to {path}"));
                }
            },
            Err(e) => output::status_warn(&format!("JSON serialization failed: {e}")),
        }
    }

    if let Some(ref path) = args.hashes {
        let mut lines = String::new();
        for host in &result.hosts {
            for psk in &host.psk_hashes {
                let _ = writeln!(lines, "{}:{}", host.target.addr, psk.hashcat_line);
            }
        }
        if let Err(e) = std::fs::write(path, &lines) {
            output::status_warn(&format!("cannot write {path}: {e}"));
        } else if !globals.quiet {
            let count = lines.lines().count();
            output::status_ok(&format!("{count} hash(es) written to {path}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_args() -> ScanArgs {
        ScanArgs {
            targets: Vec::new(),
            targets_file: None,
            port: 500,
            source_port: None,
            timeout: 500,
            retries: 3,
            backoff: 1.5,
            concurrency: 256,
            rate: 0,
            end_wait: 3000,
            aggressive: false,
            psk: false,
            id: "vpn".to_owned(),
            id_type: IdType::KeyId,
            ikev1: false,
            ikev2: false,
            json: None,
            output_file: None,
            hashes: None,
            show_backoff: false,
            quick: false,
        }
    }

    #[test]
    fn version_selection_default_sends_both() {
        let args = default_args();
        assert!(args.send_ikev1());
        assert!(args.send_ikev2());
    }

    #[test]
    fn version_selection_ikev1_only() {
        let args = ScanArgs { ikev1: true, ..default_args() };
        assert!(args.send_ikev1());
        assert!(!args.send_ikev2());
    }

    #[test]
    fn version_selection_ikev2_only() {
        let args = ScanArgs { ikev2: true, ..default_args() };
        assert!(!args.send_ikev1());
        assert!(args.send_ikev2());
    }

    #[test]
    fn version_selection_both_explicit() {
        let args = ScanArgs { ikev1: true, ikev2: true, ..default_args() };
        assert!(args.send_ikev1());
        assert!(args.send_ikev2());
    }

    #[test]
    fn psk_implies_aggressive() {
        let args = ScanArgs { psk: true, ..default_args() };
        assert!(args.send_aggressive());
    }

    #[test]
    fn aggressive_without_psk() {
        let args = ScanArgs { aggressive: true, ..default_args() };
        assert!(args.send_aggressive());
    }

    #[test]
    fn no_aggressive_by_default() {
        let args = default_args();
        assert!(!args.send_aggressive());
    }

    #[test]
    fn id_type_to_protocol_mapping() {
        assert_eq!(u8::from(IdType::KeyId.to_protocol()), 11);
        assert_eq!(u8::from(IdType::Fqdn.to_protocol()), 2);
        assert_eq!(u8::from(IdType::UserFqdn.to_protocol()), 3);
        assert_eq!(u8::from(IdType::Ipv4.to_protocol()), 1);
    }

    #[test]
    fn target_file_parsing() {
        let dir = std::env::temp_dir().join("ikewolf-test-targets");
        drop(std::fs::create_dir_all(&dir));
        let file = dir.join("targets.txt");
        std::fs::write(&file, "# comment\n10.0.0.1\n\n10.0.0.2\n# another comment\n10.0.0.3\n").unwrap();

        let args = ScanArgs { targets: vec!["192.168.1.1".to_owned()], targets_file: Some(file.to_str().unwrap().to_owned()), ..default_args() };

        let specs = args.all_target_specs().unwrap();
        assert_eq!(specs.len(), 4);
        assert_eq!(specs[0], "192.168.1.1");
        assert_eq!(specs[1], "10.0.0.1");
        assert_eq!(specs[2], "10.0.0.2");
        assert_eq!(specs[3], "10.0.0.3");

        drop(std::fs::remove_dir_all(dir));
    }

    #[test]
    fn target_file_missing_returns_error() {
        let args = ScanArgs { targets_file: Some("/nonexistent/path/targets.txt".to_owned()), ..default_args() };
        assert!(args.all_target_specs().is_err());
    }
}
