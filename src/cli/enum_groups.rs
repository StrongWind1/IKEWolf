//! `ikewolf enum-groups` subcommand -- VPN group name enumeration.
//!
//! Sends IKEv1 Aggressive Mode probes with each group name from a wordlist.
//! A valid group name elicits SA + KE + HASH_R; an invalid one gets silence
//! or a notification. RFC 2409 section 7.

use std::net::IpAddr;
use std::time::Duration;

use clap::Args;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use ike_protocol::ikev1::hash::PskCrackData;
use ike_protocol::ikev1::message::{self as v1msg, Ikev1Response};
use ike_protocol::ikev1::model::DhGroup;
use ike_protocol::ikev1::sa::Ikev1Transform;

use crate::cli::scan::IdType;
use crate::cli::{GlobalOpts, H_IKE, H_TARGET, H_TIMING};
use crate::output;

use super::H_OUTPUT;

const ENUM_GROUPS_EXAMPLES: &str = "\
Examples:
  ikewolf enum-groups 10.0.0.1 -w groupnames.txt
  ikewolf enum-groups 10.0.0.1 -w wordlist.txt --delay 200
  ikewolf enum-groups 10.0.0.1 -w wordlist.txt --id-type fqdn --psk";

/// Enumerate valid VPN group names via Aggressive Mode response differences.
///
/// Sends IKEv1 Aggressive Mode probes with each group name from a wordlist.
/// Valid names produce a full SA + KE + HASH_R response; invalid names get
/// silence or a notification.
#[derive(Debug, Args)]
#[command(after_long_help = ENUM_GROUPS_EXAMPLES)]
pub(crate) struct EnumGroupsArgs {
    /// Target IP address
    #[arg(help_heading = H_TARGET)]
    pub(crate) target: String,

    /// Wordlist file (one group name per line)
    #[arg(short = 'w', long, value_name = "FILE", help_heading = H_TARGET)]
    pub(crate) wordlist: String,

    /// UDP destination port
    #[arg(short, long, default_value_t = 500, value_name = "PORT", help_heading = H_TARGET)]
    pub(crate) port: u16,

    /// Per-probe timeout in milliseconds
    #[arg(short = 't', long, default_value_t = 500, value_name = "MS", help_heading = H_TIMING)]
    pub(crate) timeout: u64,

    /// Delay between probes in milliseconds
    #[arg(long, default_value_t = 100, value_name = "MS", help_heading = H_TIMING)]
    pub(crate) delay: u64,

    /// ID payload type
    #[arg(long, default_value = "key-id", value_name = "TYPE", help_heading = H_IKE)]
    pub(crate) id_type: IdType,

    /// Also extract PSK hashes for valid groups
    #[arg(long, help_heading = H_OUTPUT)]
    pub(crate) psk: bool,
}

/// Run the enum-groups subcommand.
pub(crate) async fn run(args: EnumGroupsArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let addr: IpAddr = args.target.parse().map_err(|_| anyhow::anyhow!("invalid target IP: {}", args.target))?;
    let content = std::fs::read_to_string(&args.wordlist).map_err(|e| anyhow::anyhow!("cannot read wordlist {}: {e}", args.wordlist))?;
    let names: Vec<&str> = content.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();

    if names.is_empty() {
        anyhow::bail!("wordlist is empty");
    }

    if !globals.quiet {
        output::status_info(&format!("Enumerating {} group name(s) against {}:{}", names.len(), addr, args.port));
    }

    let socket = UdpSocket::bind(if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await?;
    let dest = std::net::SocketAddr::new(addr, args.port);
    let probe_timeout = Duration::from_millis(args.timeout);
    let delay = Duration::from_millis(args.delay);
    let id_type = args.id_type.to_protocol();
    let transforms = default_aggressive_transforms();

    let mut valid_count = 0u32;
    let mut recv_buf = vec![0u8; 65535];

    for name in &names {
        let mut rng = rand::rng();
        let cookie: u64 = rand::RngExt::random::<u64>(&mut rng) | 1;
        let dh_group = transforms.first().map_or(DhGroup::Modp2048, |t| t.dh_group);
        let ke_len = dh_group.ke_len().unwrap_or(256);
        let mut ke_data = vec![0u8; ke_len];
        rand::RngExt::fill(&mut rng, ke_data.as_mut_slice());
        let mut nonce_data = vec![0u8; 20];
        rand::RngExt::fill(&mut rng, nonce_data.as_mut_slice());

        let packet = v1msg::build_aggressive_msg1(cookie, &transforms, &ke_data, &nonce_data, id_type, name.as_bytes(), &[]);

        if let Err(e) = socket.send_to(&packet, dest).await {
            tracing::debug!(name, error = %e, "send failed");
            continue;
        }

        let resp = match timeout(probe_timeout, socket.recv_from(&mut recv_buf)).await {
            Ok(Ok((len, _))) => Ikev1Response::parse(recv_buf.get(..len).unwrap_or_default()),
            _ => None,
        };

        if let Some(ref r) = resp {
            if r.hash_r.is_some() {
                valid_count += 1;
                output::status_ok(&format!("VALID: {name}"));

                if args.psk {
                    let sa_body = ike_protocol::ikev1::sa::build_sa_body(&transforms);
                    if let Some(crack) = build_crack_data(r, cookie, &sa_body, &ke_data, &nonce_data) {
                        println!("    hashcat: {}", crack.to_hashcat());
                    }
                }
            } else {
                tracing::debug!(name, "response without HASH_R (invalid group or notification)");
            }
        }

        tokio::time::sleep(delay).await;
    }

    if !globals.quiet {
        output::status_info(&format!("Done: {valid_count} valid group(s) found out of {}", names.len()));
    }

    Ok(())
}

fn build_crack_data(resp: &Ikev1Response, cookie: u64, sa_body: &[u8], ke_data: &[u8], nonce_data: &[u8]) -> Option<PskCrackData> {
    let hash_r = resp.hash_r.as_ref()?;
    let resp_ke = resp.ke_data.as_ref()?;
    let resp_nonce = resp.nonce.as_ref()?;
    let id_body = resp.id_body.as_ref()?;

    Some(PskCrackData { g_xr: resp_ke.clone(), g_xi: ke_data.to_vec(), cky_r: resp.header.responder_spi.to_be_bytes(), cky_i: cookie.to_be_bytes(), sai_b: sa_body.to_vec(), idir_b: id_body.clone(), ni_b: nonce_data.to_vec(), nr_b: resp_nonce.clone(), hash_r: hash_r.clone() })
}

fn default_aggressive_transforms() -> Vec<Ikev1Transform> {
    use ike_protocol::ikev1::model::{Ikev1AuthMethod, Ikev1EncryptionAlg, Ikev1HashAlg};
    let psk = Ikev1AuthMethod::PreSharedKey;
    let g14 = DhGroup::Modp2048;
    let lt = Some(28800);
    vec![
        Ikev1Transform { encryption: Ikev1EncryptionAlg::AesCbc, key_length: Some(256), hash: Ikev1HashAlg::Sha256, auth_method: psk, dh_group: g14, lifetime_secs: lt },
        Ikev1Transform { encryption: Ikev1EncryptionAlg::AesCbc, key_length: Some(256), hash: Ikev1HashAlg::Sha1, auth_method: psk, dh_group: g14, lifetime_secs: lt },
        Ikev1Transform { encryption: Ikev1EncryptionAlg::TripleDesCbc, key_length: None, hash: Ikev1HashAlg::Sha1, auth_method: psk, dh_group: g14, lifetime_secs: lt },
        Ikev1Transform { encryption: Ikev1EncryptionAlg::TripleDesCbc, key_length: None, hash: Ikev1HashAlg::Md5, auth_method: psk, dh_group: g14, lifetime_secs: lt },
    ]
}
