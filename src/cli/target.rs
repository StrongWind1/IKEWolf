//! Target parsing: IP addresses, CIDR ranges, files, and stdin.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, bail};

/// A resolved scan target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub(crate) struct Target {
    /// Target IP address.
    pub(crate) addr: IpAddr,
    /// Target UDP port (default 500).
    pub(crate) port: u16,
}

impl Target {
    /// Create a new target.
    #[must_use]
    pub(crate) fn new(addr: IpAddr, port: u16) -> Self {
        Self { addr, port }
    }

    /// Socket address for UDP send.
    #[must_use]
    pub(crate) fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr, self.port)
    }
}

impl core::fmt::Display for Target {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

/// Parse a list of target specifications into resolved `Target`s.
///
/// Each spec can be:
/// - An IP address: `192.168.1.1`
/// - An IP:port: `192.168.1.1:4500`
/// - A CIDR range: `192.168.1.0/24`
/// - A CIDR:port: `192.168.1.0/24:500`
///
/// Deduplicates by (IP, port).
pub(crate) fn parse_targets(specs: &[String], default_port: u16) -> anyhow::Result<Vec<Target>> {
    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for spec in specs {
        let parsed = parse_one_spec(spec, default_port).with_context(|| format!("invalid target: {spec}"))?;
        for target in parsed {
            if seen.insert((target.addr, target.port)) {
                targets.push(target);
            }
        }
    }

    if targets.is_empty() {
        bail!("no targets specified");
    }

    Ok(targets)
}

/// Parse a single target specification.
fn parse_one_spec(spec: &str, default_port: u16) -> anyhow::Result<Vec<Target>> {
    // Try CIDR first (contains '/').
    if let Some(slash_pos) = spec.find('/') {
        return parse_cidr(spec, slash_pos, default_port);
    }

    // Try IP:port or bare IP.
    let (ip_str, port) = split_host_port(spec, default_port);
    let addr: IpAddr = ip_str.parse().with_context(|| format!("invalid IP: {ip_str}"))?;
    Ok(vec![Target::new(addr, port)])
}

/// Parse a CIDR specification like `192.168.1.0/24` or `192.168.1.0/24:500`.
fn parse_cidr(spec: &str, slash_pos: usize, default_port: u16) -> anyhow::Result<Vec<Target>> {
    // Check for trailing :port after the CIDR.
    let (cidr_str, port) = if let Some(colon_pos) = spec.rfind(':') {
        if colon_pos > slash_pos {
            let port: u16 = spec.get(colon_pos + 1..).unwrap_or_default().parse().with_context(|| format!("invalid port in: {spec}"))?;
            (spec.get(..colon_pos).unwrap_or_default(), port)
        } else {
            (spec, default_port)
        }
    } else {
        (spec, default_port)
    };

    let network: ipnet::IpNet = cidr_str.parse().with_context(|| format!("invalid CIDR: {cidr_str}"))?;

    let mut targets = Vec::new();
    for addr in network.hosts() {
        targets.push(Target::new(addr, port));
    }

    Ok(targets)
}

/// Split `host:port` or return the default port.
fn split_host_port(spec: &str, default_port: u16) -> (&str, u16) {
    // IPv6 addresses are bracketed: [::1]:500
    if let Some(bracket_end) = spec.starts_with('[').then(|| spec.find(']')).flatten() {
        let ip = spec.get(1..bracket_end).unwrap_or_default();
        let port = spec.get(bracket_end + 2..).and_then(|s| s.parse().ok()).unwrap_or(default_port);
        return (ip, port);
    }

    // IPv4: last colon splits host:port, but only if there's exactly one colon.
    if let Some(colon_pos) = spec.rfind(':').filter(|_| spec.matches(':').count() == 1) {
        let ip = spec.get(..colon_pos).unwrap_or_default();
        let port = spec.get(colon_pos + 1..).and_then(|s| s.parse().ok()).unwrap_or(default_port);
        return (ip, port);
    }

    (spec, default_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_ip() {
        let targets = parse_targets(&["192.168.1.1".to_owned()], 500).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].addr, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(targets[0].port, 500);
    }

    #[test]
    fn parse_ip_with_port() {
        let targets = parse_targets(&["10.0.0.1:4500".to_owned()], 500).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].port, 4500);
    }

    #[test]
    fn parse_cidr_24() {
        let targets = parse_targets(&["10.0.0.0/30".to_owned()], 500).unwrap();
        // /30 = 4 addresses, 2 usable hosts (network + broadcast excluded by .hosts()).
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn dedup_targets() {
        let targets = parse_targets(&["192.168.1.1".to_owned(), "192.168.1.1".to_owned()], 500).unwrap();
        assert_eq!(targets.len(), 1);
    }

    #[test]
    fn empty_targets_error() {
        assert!(parse_targets(&[], 500).is_err());
    }

    #[test]
    fn target_display() {
        let t = Target::new("10.0.0.1".parse().unwrap(), 500);
        assert_eq!(t.to_string(), "10.0.0.1:500");
    }

    #[test]
    fn parse_ipv6_bare() {
        let targets = parse_targets(&["::1".to_owned()], 500).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(targets[0].addr.is_ipv6());
        assert_eq!(targets[0].port, 500);
    }

    #[test]
    fn parse_ipv6_bracketed_with_port() {
        let targets = parse_targets(&["[::1]:4500".to_owned()], 500).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(targets[0].addr.is_ipv6());
        assert_eq!(targets[0].port, 4500);
    }

    #[test]
    fn parse_ipv6_bracketed_no_port() {
        let targets = parse_targets(&["[fe80::1]".to_owned()], 500).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(targets[0].addr.is_ipv6());
        assert_eq!(targets[0].port, 500);
    }
}
