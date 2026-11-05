//! Async UDP scanner core.
//!
//! Single-socket event loop: sends IKE probes to many targets, matches
//! responses by initiator cookie, handles retransmission with exponential
//! backoff, and enforces concurrency + rate limits.
//!
//! Retry logic:
//! - IKEv2 COOKIE challenge: resend SA_INIT with cookie prepended (RFC 7296 section 2.6)
//! - IKEv2 INVALID_KE_PAYLOAD: retry with the suggested DH group
//! - IKEv1 NO_PROPOSAL_CHOSEN: probe individual transforms to enumerate accepted algorithms
//! - IKEv1 BAD_PROPOSAL_SYNTAX: retry with a compact transform set (6 common suites)

use std::collections::HashMap;
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressStyle};
use rand::RngExt;
use serde::Serialize;
use tokio::net::UdpSocket;

use ike_protocol::attribute::{DataAttribute, v1_class};
use ike_protocol::header::IkeHeader;
use ike_protocol::ikev1::hash::PskCrackData;
use ike_protocol::ikev1::message::{self as v1msg, Ikev1Response};
use ike_protocol::ikev1::model::{DhGroup, Ikev1AuthMethod, Ikev1EncryptionAlg, Ikev1HashAlg, Ikev1IdType};
use ike_protocol::ikev2::model::Ikev2NotifyType;
use ike_protocol::notify_codes::Ikev1NotifyType;
use ike_protocol::vendor;

use ike_protocol::ikev1::sa::Ikev1Transform;
use ike_protocol::ikev2::message::{self as v2msg, Ikev2SaInitResponse};
use ike_protocol::ikev2::model::{Ikev2EncryptionAlg, Ikev2IntegrityAlg, Ikev2PrfAlg};
use ike_protocol::ikev2::sa::{Ikev2Proposal, Ikev2Transform};

use crate::cli::target::Target;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Scanner configuration.
#[derive(Debug, Clone)]
pub(crate) struct ScanConfig {
    pub(crate) timeout_ms: u64,
    pub(crate) retries: u32,
    pub(crate) backoff_factor: f64,
    pub(crate) concurrency: usize,
    pub(crate) rate_pps: u32,
    pub(crate) end_wait_ms: u64,
    pub(crate) send_ikev1: bool,
    pub(crate) send_ikev2: bool,
    pub(crate) send_aggressive: bool,
    pub(crate) extract_psk: bool,
    pub(crate) identity: String,
    pub(crate) id_type: Ikev1IdType,
    pub(crate) source_port: Option<u16>,
    pub(crate) show_backoff: bool,
    pub(crate) quick: bool,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// Output of a scan run (contains only hosts that responded).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScanOutput {
    pub(crate) hosts: Vec<HostResult>,
    pub(crate) total_targets: usize,
    pub(crate) interrupted: bool,
}

/// Result for a single host.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct HostResult {
    pub(crate) target: Target,
    pub(crate) responded: bool,
    pub(crate) ikev1_result: Option<Ikev1HostResult>,
    pub(crate) ikev2_result: Option<Ikev2HostResult>,
    pub(crate) psk_hashes: Vec<PskHashResult>,
    pub(crate) response_time_ms: Option<u64>,
}

/// IKEv1 result for a host.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Ikev1HostResult {
    pub(crate) transforms: Vec<String>,
    pub(crate) vendor_ids: Vec<String>,
    pub(crate) notifications: Vec<String>,
    pub(crate) server_id: Option<String>,
    pub(crate) cert_request_count: usize,
    pub(crate) nat_detected: bool,
}

/// IKEv2 result for a host.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Ikev2HostResult {
    pub(crate) proposals: Vec<Ikev2ProposalSummary>,
    pub(crate) vendor_ids: Vec<String>,
    pub(crate) notifications: Vec<String>,
    pub(crate) cookie_challenge: bool,
    pub(crate) suggested_dh_group: Option<u16>,
    pub(crate) dh_group: Option<String>,
    pub(crate) cert_request_count: usize,
}

/// IKEv2 proposal for output.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Ikev2ProposalSummary {
    pub(crate) number: u8,
    pub(crate) transforms: Vec<String>,
}

/// Extracted PSK hash.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PskHashResult {
    pub(crate) hash_type: String,
    pub(crate) hashcat_mode: Option<u32>,
    pub(crate) hashcat_line: String,
    pub(crate) warning: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal probe state
// ---------------------------------------------------------------------------

struct ProbeState {
    target_idx: usize,
    probe_type: ProbeKind,
    cookie: u64,
    first_sent: Instant,
    last_sent: Instant,
    current_timeout: Duration,
    retries_left: u32,
    retry_count: u8,
    packet: Vec<u8>,
    sa_body: Vec<u8>,
    ke_data: Vec<u8>,
    nonce_data: Vec<u8>,
    harvest: Option<HarvestState>,
    send_after: Option<Instant>,
}

const HARVEST_DELAY: Duration = Duration::from_millis(300);

struct HarvestState {
    encryption: Ikev1EncryptionAlg,
    key_length: Option<u16>,
    dh_group: DhGroup,
    hash_idx: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeKind {
    Ikev1MainMode,
    Ikev1AggressiveDh(DhGroup),
    Ikev2SaInit,
}

struct ProbeQueue {
    num_targets: usize,
    kinds: Vec<ProbeKind>,
}

impl ProbeQueue {
    fn len(&self) -> usize {
        self.num_targets * self.kinds.len()
    }

    fn get(&self, cursor: usize) -> Option<(usize, ProbeKind)> {
        if cursor >= self.len() {
            return None;
        }
        let target_idx = cursor / self.kinds.len();
        let kind_idx = cursor % self.kinds.len();
        self.kinds.get(kind_idx).map(|&kind| (target_idx, kind))
    }
}

/// Max protocol-level retries (COOKIE + INVALID_KE, or v1 transform enumeration).
const MAX_PROTO_RETRIES: u8 = 2;

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

pub(crate) struct Scanner {
    config: ScanConfig,
}

impl Scanner {
    #[must_use]
    pub(crate) fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    pub(crate) async fn scan(&self, targets: &[Target], quiet: bool) -> anyhow::Result<ScanOutput> {
        tracing::info!(targets = targets.len(), timeout_ms = self.config.timeout_ms, retries = self.config.retries, concurrency = self.config.concurrency, rate_pps = self.config.rate_pps, "starting scan");

        let socket = self.bind_socket(targets).await?;
        let mut host_results: HashMap<usize, HostResult> = HashMap::new();
        let probe_queue = self.build_probe_queue(targets);
        let pb = create_progress_bar(probe_queue.len(), quiet);

        let loop_result = self.run_event_loop(&socket, targets, &mut host_results, &probe_queue, &pb).await;

        pb.finish_and_clear();

        let responded = host_results.len();
        tracing::info!(responded, total = targets.len(), interrupted = loop_result, "scan complete");

        let hosts: Vec<HostResult> = host_results.into_values().collect();
        Ok(ScanOutput { hosts, total_targets: targets.len(), interrupted: loop_result })
    }

    async fn bind_socket(&self, targets: &[Target]) -> anyhow::Result<UdpSocket> {
        let port = self.config.source_port.unwrap_or(0);
        let has_ipv6 = targets.iter().any(|t| t.addr.is_ipv6());
        let bind_addr = if has_ipv6 { format!("[::]:{port}") } else { format!("0.0.0.0:{port}") };
        Ok(UdpSocket::bind(&bind_addr).await?)
    }

    fn build_probe_queue(&self, targets: &[Target]) -> ProbeQueue {
        let mut kinds = Vec::new();
        if self.config.extract_psk && self.config.send_aggressive {
            kinds.push(ProbeKind::Ikev1AggressiveDh(DhGroup::Modp2048));
        }
        if self.config.send_ikev1 {
            kinds.push(ProbeKind::Ikev1MainMode);
        }
        if self.config.send_ikev2 {
            kinds.push(ProbeKind::Ikev2SaInit);
        }
        if !self.config.extract_psk && self.config.send_aggressive {
            kinds.push(ProbeKind::Ikev1AggressiveDh(DhGroup::Modp2048));
        }
        ProbeQueue { num_targets: targets.len(), kinds }
    }

    /// Returns `true` if interrupted by SIGINT.
    async fn run_event_loop(&self, socket: &UdpSocket, targets: &[Target], host_results: &mut HashMap<usize, HostResult>, probe_queue: &ProbeQueue, pb: &ProgressBar) -> bool {
        let mut outstanding: HashMap<u64, ProbeState> = HashMap::new();
        let mut retry_queue: Vec<ProbeState> = Vec::new();
        let mut queue_cursor = 0usize;
        let mut responded_count = 0u64;
        let mut hash_count = 0u64;
        let min_interval = rate_interval(self.config.rate_pps);
        let mut last_send = Instant::now().checked_sub(min_interval).unwrap_or_else(Instant::now);
        let mut recv_buf = vec![0u8; 65535];
        let scan_start = Instant::now();
        let end_wait = Duration::from_millis(self.config.end_wait_ms);

        loop {
            let all_sent = queue_cursor >= probe_queue.len() && retry_queue.is_empty();
            if all_sent && outstanding.is_empty() {
                return false;
            }
            if is_end_wait_expired(all_sent, &outstanding, end_wait) {
                return false;
            }

            let next_timeout = compute_next_timeout(all_sent, &outstanding, self.config.concurrency);

            tokio::select! {
                result = socket.recv_from(&mut recv_buf) => {
                    if let Ok((len, _addr)) = result {
                        let retry = self.handle_recv(
                            recv_buf.get(..len).unwrap_or_default(),
                            targets, &mut outstanding, host_results,
                            &mut responded_count, &mut hash_count, pb,
                        );
                        if let Some(retry_probe) = retry {
                            retry_queue.push(retry_probe);
                        }
                    }
                }

                () = tokio::time::sleep(next_timeout) => {
                    let now = Instant::now();
                    self.retransmit_expired(socket, targets, &mut outstanding, pb, now).await;
                    self.send_probes(
                        socket, targets, probe_queue, &mut queue_cursor,
                        &mut outstanding, &mut retry_queue, &mut last_send, min_interval, now, pb,
                    ).await;
                }

                Ok(()) = tokio::signal::ctrl_c() => {
                    return true;
                }
            }

            if scan_start.elapsed() > Duration::from_hours(1) {
                return false;
            }
        }
    }

    fn handle_recv(&self, data: &[u8], targets: &[Target], outstanding: &mut HashMap<u64, ProbeState>, host_results: &mut HashMap<usize, HostResult>, responded_count: &mut u64, hash_count: &mut u64, pb: &ProgressBar) -> Option<ProbeState> {
        let hdr = IkeHeader::parse(data)?;
        let probe = outstanding.remove(&hdr.initiator_spi)?;
        let prev_hashes = host_results.get(&probe.target_idx).map_or(0, |h| h.psk_hashes.len());

        let retry = self.process_response(&probe, data, targets, host_results);

        let new_hashes = host_results.get(&probe.target_idx).map_or(0, |h| h.psk_hashes.len());
        if new_hashes > prev_hashes {
            *hash_count += u64::try_from(new_hashes - prev_hashes).unwrap_or(1);
        }

        *responded_count += 1;
        pb.inc(1);
        if self.config.extract_psk {
            pb.set_message(format!("{} responded, {} hashes", *responded_count, *hash_count));
        } else {
            pb.set_message(format!("{} responded", *responded_count));
        }
        retry
    }

    async fn retransmit_expired(&self, socket: &UdpSocket, targets: &[Target], outstanding: &mut HashMap<u64, ProbeState>, pb: &ProgressBar, now: Instant) {
        let expired: Vec<u64> = outstanding.iter().filter(|(_, p)| p.last_sent.elapsed() >= p.current_timeout).map(|(c, _)| *c).collect();

        for cookie in expired {
            let Some(mut probe) = outstanding.remove(&cookie) else {
                continue;
            };
            if probe.retries_left > 0 {
                probe.retries_left -= 1;
                probe.current_timeout = Duration::from_secs_f64(probe.current_timeout.as_secs_f64() * self.config.backoff_factor);
                probe.last_sent = now;
                if let Some(target) = targets.get(probe.target_idx)
                    && let Err(e) = socket.send_to(&probe.packet, target.socket_addr()).await
                {
                    tracing::debug!(target = %target, error = %e, "retransmit failed");
                }
                drop(outstanding.insert(cookie, probe));
            } else {
                pb.inc(1);
            }
        }
    }

    async fn send_probes(&self, socket: &UdpSocket, targets: &[Target], probe_queue: &ProbeQueue, queue_cursor: &mut usize, outstanding: &mut HashMap<u64, ProbeState>, retry_queue: &mut Vec<ProbeState>, last_send: &mut Instant, min_interval: Duration, now: Instant, pb: &ProgressBar) {
        while outstanding.len() < self.config.concurrency && now.duration_since(*last_send) >= min_interval {
            let probe = if let Some(p) = retry_queue.pop() {
                if p.send_after.is_some_and(|t| Instant::now() < t) {
                    retry_queue.insert(0, p);
                    break;
                }
                p
            } else if let Some((target_idx, probe_kind)) = probe_queue.get(*queue_cursor) {
                *queue_cursor += 1;
                self.build_probe(target_idx, probe_kind)
            } else {
                break;
            };

            if let Some(target) = targets.get(probe.target_idx) {
                match socket.send_to(&probe.packet, target.socket_addr()).await {
                    Ok(_) => {
                        drop(outstanding.insert(probe.cookie, probe));
                    },
                    Err(e) => {
                        tracing::debug!(target = %target, error = %e, "send failed, skipping probe");
                        pb.inc(1);
                    },
                }
            }
            *last_send = Instant::now();
        }
    }

    fn build_probe(&self, target_idx: usize, kind: ProbeKind) -> ProbeState {
        let mut rng = rand::rng();
        let cookie: u64 = rng.random::<u64>() | 1;
        let initial_timeout = Duration::from_millis(self.config.timeout_ms);
        let now = Instant::now();

        match kind {
            ProbeKind::Ikev1MainMode => {
                let transforms = default_ikev1_transforms();
                let packet = v1msg::build_main_mode_msg1_with_vids(cookie, &transforms, vendor::DEFAULT_V1_VIDS);
                ProbeState { target_idx, probe_type: kind, cookie, first_sent: now, last_sent: now, current_timeout: initial_timeout, retries_left: self.config.retries, retry_count: 0, packet, sa_body: Vec::new(), ke_data: Vec::new(), nonce_data: Vec::new(), harvest: None, send_after: None }
            },
            ProbeKind::Ikev1AggressiveDh(dh_group) => {
                let transforms = ikev1_transforms_for_groups(&[dh_group]);
                let sa_body = ike_protocol::ikev1::sa::build_sa_body(&transforms);
                let ke_len = dh_group.ke_len().unwrap_or(256);
                let mut ke_data = vec![0u8; ke_len];
                rng.fill(ke_data.as_mut_slice());
                let mut nonce_data = vec![0u8; 20];
                rng.fill(nonce_data.as_mut_slice());

                let id_data = encode_id_data(self.config.id_type, &self.config.identity);
                let packet = v1msg::build_aggressive_msg1(cookie, &transforms, &ke_data, &nonce_data, self.config.id_type, &id_data, vendor::DEFAULT_V1_VIDS);

                ProbeState { target_idx, probe_type: kind, cookie, first_sent: now, last_sent: now, current_timeout: initial_timeout, retries_left: self.config.retries, retry_count: 0, packet, sa_body, ke_data, nonce_data, harvest: None, send_after: None }
            },
            ProbeKind::Ikev2SaInit => {
                let proposals = default_ikev2_proposals();
                let dh_group: u16 = DhGroup::Modp2048.into();
                let mut ke_data = vec![0u8; 256];
                rng.fill(ke_data.as_mut_slice());
                let mut nonce_data = vec![0u8; 32];
                rng.fill(nonce_data.as_mut_slice());

                let packet = v2msg::build_sa_init_request(cookie, &proposals, dh_group, &ke_data, &nonce_data, None);

                ProbeState { target_idx, probe_type: kind, cookie, first_sent: now, last_sent: now, current_timeout: initial_timeout, retries_left: self.config.retries, retry_count: 0, packet, sa_body: Vec::new(), ke_data, nonce_data, harvest: None, send_after: None }
            },
        }
    }

    fn process_response(&self, probe: &ProbeState, data: &[u8], targets: &[Target], results: &mut HashMap<usize, HostResult>) -> Option<ProbeState> {
        let target = targets.get(probe.target_idx)?;
        let result = results.entry(probe.target_idx).or_insert_with(|| HostResult { target: target.clone(), responded: false, ikev1_result: None, ikev2_result: None, psk_hashes: Vec::new(), response_time_ms: None });

        let retry = match probe.probe_type {
            ProbeKind::Ikev1MainMode => self.process_v1_main(probe, data, result),
            ProbeKind::Ikev1AggressiveDh(_) => self.process_v1_aggressive(probe, data, result),
            ProbeKind::Ikev2SaInit => self.process_v2_init(probe, data, result),
        };

        if result.ikev1_result.is_some() || result.ikev2_result.is_some() {
            result.responded = true;
            if self.config.show_backoff && result.response_time_ms.is_none() {
                let elapsed_ms = u64::try_from(probe.first_sent.elapsed().as_millis()).unwrap_or(u64::MAX);
                result.response_time_ms = Some(elapsed_ms);
            }
        }

        retry
    }

    fn process_v1_main(&self, probe: &ProbeState, data: &[u8], result: &mut HostResult) -> Option<ProbeState> {
        let resp = Ikev1Response::parse(data)?;

        if resp.is_no_proposal_chosen() && probe.retry_count == 0 {
            tracing::debug!(target_idx = probe.target_idx, "v1 NO_PROPOSAL_CHOSEN, starting transform enumeration");
            result.ikev1_result = Some(Ikev1HostResult { transforms: Vec::new(), vendor_ids: Vec::new(), notifications: resp.notifications.iter().map(|(t, d)| format_v1_notify(*t, d)).collect(), server_id: None, cert_request_count: resp.cert_requests.len(), nat_detected: !resp.nat_d.is_empty() });
            return self.build_single_transform_probe(probe.target_idx, 0);
        }

        if resp.is_bad_proposal_syntax() && probe.retry_count < MAX_PROTO_RETRIES {
            tracing::debug!(target_idx = probe.target_idx, "v1 BAD_PROPOSAL_SYNTAX, retrying with compact transforms");
            result.ikev1_result = Some(Ikev1HostResult { transforms: Vec::new(), vendor_ids: Vec::new(), notifications: resp.notifications.iter().map(|(t, d)| format_v1_notify(*t, d)).collect(), server_id: None, cert_request_count: resp.cert_requests.len(), nat_detected: !resp.nat_d.is_empty() });
            return Some(self.build_compact_v1_probe(probe));
        }

        let hr = ikev1_host_result(&resp);
        if let Some(ref existing) = result.ikev1_result {
            let mut merged = existing.clone();
            for t in &hr.transforms {
                if !merged.transforms.contains(t) {
                    merged.transforms.push(t.clone());
                }
            }
            result.ikev1_result = Some(merged);
        } else {
            result.ikev1_result = Some(hr);
        }

        // Continue enumeration: either continuing an in-progress walk, or
        // starting one after the initial success to discover all accepted transforms.
        if probe.retry_count > 0 {
            let next_idx = usize::from(probe.retry_count);
            return self.build_single_transform_probe(probe.target_idx, next_idx);
        }
        self.build_single_transform_probe(probe.target_idx, 0)
    }

    fn process_v1_aggressive(&self, probe: &ProbeState, data: &[u8], result: &mut HostResult) -> Option<ProbeState> {
        let resp = Ikev1Response::parse(data)?;

        if resp.is_no_proposal_chosen() {
            if probe.harvest.is_some() {
                return self.next_harvest_probe(probe);
            }
            return self.next_aggressive_dh_probe(probe);
        }

        let agg_result = ikev1_host_result(&resp);
        if let Some(ref mut existing) = result.ikev1_result {
            if existing.server_id.is_none() {
                existing.server_id = agg_result.server_id;
            }
            if agg_result.nat_detected {
                existing.nat_detected = true;
            }
            for vid in &agg_result.vendor_ids {
                if !existing.vendor_ids.contains(vid) {
                    existing.vendor_ids.push(vid.clone());
                }
            }
        } else {
            result.ikev1_result = Some(agg_result);
        }

        if self.config.extract_psk {
            if probe.harvest.is_some() {
                if let Some(hash_result) = extract_psk_hash(probe, &resp) {
                    result.psk_hashes.push(hash_result);
                }
                return self.next_harvest_probe(probe);
            }
            if let Some(accepted) = resp.transforms.first() {
                return self.start_harvest(probe, accepted);
            }
        }
        None
    }

    fn next_aggressive_dh_probe(&self, probe: &ProbeState) -> Option<ProbeState> {
        let ProbeKind::Ikev1AggressiveDh(current_group) = probe.probe_type else {
            return None;
        };
        let all_groups: Vec<DhGroup> = if self.config.quick { vec![DhGroup::Modp2048] } else { aggressive_dh_walk_order() };
        let current_pos = all_groups.iter().position(|&g| g == current_group)?;
        let next_group = *all_groups.get(current_pos + 1)?;
        let ke_len = next_group.ke_len()?;

        tracing::debug!(target_idx = probe.target_idx, current = ?current_group, next = ?next_group, "aggressive NO_PROPOSAL, trying next DH group");

        let mut rng = rand::rng();
        let cookie: u64 = rng.random::<u64>() | 1;
        let transforms = ikev1_transforms_for_groups(&[next_group]);
        let sa_body = ike_protocol::ikev1::sa::build_sa_body(&transforms);
        let mut ke_data = vec![0u8; ke_len];
        rng.fill(ke_data.as_mut_slice());
        let mut nonce_data = vec![0u8; 20];
        rng.fill(nonce_data.as_mut_slice());
        let id_data = encode_id_data(self.config.id_type, &self.config.identity);
        let packet = v1msg::build_aggressive_msg1(cookie, &transforms, &ke_data, &nonce_data, self.config.id_type, &id_data, vendor::DEFAULT_V1_VIDS);
        let now = Instant::now();

        Some(ProbeState {
            target_idx: probe.target_idx,
            probe_type: ProbeKind::Ikev1AggressiveDh(next_group),
            cookie,
            first_sent: probe.first_sent,
            last_sent: now,
            current_timeout: Duration::from_millis(self.config.timeout_ms),
            retries_left: self.config.retries,
            retry_count: probe.retry_count + 1,
            packet,
            sa_body,
            ke_data,
            nonce_data,
            harvest: None,
            send_after: None,
        })
    }

    fn process_v2_init(&self, probe: &ProbeState, data: &[u8], result: &mut HostResult) -> Option<ProbeState> {
        let resp = Ikev2SaInitResponse::parse(data)?;

        // COOKIE retry: RFC 7296 section 2.6.
        if let Some(cookie_data) = resp.cookie()
            && probe.retry_count < MAX_PROTO_RETRIES
        {
            tracing::debug!(target_idx = probe.target_idx, "IKEv2 COOKIE challenge, retrying");
            let proposals = default_ikev2_proposals();
            let dh_group: u16 = DhGroup::Modp2048.into();
            let packet = v2msg::build_sa_init_request_with_cookie(probe.cookie, cookie_data, &proposals, dh_group, &probe.ke_data, &probe.nonce_data);
            let now = Instant::now();
            return Some(ProbeState {
                target_idx: probe.target_idx,
                probe_type: ProbeKind::Ikev2SaInit,
                cookie: probe.cookie,
                first_sent: probe.first_sent,
                last_sent: now,
                current_timeout: Duration::from_millis(self.config.timeout_ms),
                retries_left: self.config.retries,
                retry_count: probe.retry_count + 1,
                packet,
                sa_body: Vec::new(),
                ke_data: probe.ke_data.clone(),
                nonce_data: probe.nonce_data.clone(),
                harvest: None,
                send_after: None,
            });
        }

        // INVALID_KE retry: use the suggested DH group.
        if let Some(suggested_group) = resp.invalid_ke_suggested_group()
            && probe.retry_count < MAX_PROTO_RETRIES
        {
            let group = DhGroup::from(suggested_group);
            let ke_len = group.ke_len().unwrap_or(256);
            tracing::debug!(target_idx = probe.target_idx, group = suggested_group, ke_len, "IKEv2 INVALID_KE, retrying with suggested group");

            let mut rng = rand::rng();
            let new_cookie: u64 = rng.random::<u64>() | 1;
            let mut ke_data = vec![0u8; ke_len];
            rng.fill(ke_data.as_mut_slice());
            let mut nonce_data = vec![0u8; 32];
            rng.fill(nonce_data.as_mut_slice());

            let proposals = default_ikev2_proposals();
            let packet = v2msg::build_sa_init_request(new_cookie, &proposals, suggested_group, &ke_data, &nonce_data, None);
            let now = Instant::now();

            return Some(ProbeState {
                target_idx: probe.target_idx,
                probe_type: ProbeKind::Ikev2SaInit,
                cookie: new_cookie,
                first_sent: probe.first_sent,
                last_sent: now,
                current_timeout: Duration::from_millis(self.config.timeout_ms),
                retries_left: self.config.retries,
                retry_count: probe.retry_count + 1,
                packet,
                sa_body: Vec::new(),
                ke_data,
                nonce_data,
                harvest: None,
                send_after: None,
            });
        }

        result.ikev2_result = Some(Ikev2HostResult {
            proposals: resp.proposals.iter().map(|p| Ikev2ProposalSummary { number: p.number, transforms: p.transforms.iter().map(ToString::to_string).collect() }).collect(),
            vendor_ids: resp.vendor_ids.iter().map(|v| bytes_to_display(v)).collect(),
            notifications: resp.notifications.iter().map(|(t, d)| format_v2_notify(*t, d)).collect(),
            cookie_challenge: resp.cookie().is_some(),
            suggested_dh_group: resp.invalid_ke_suggested_group(),
            dh_group: resp.ke_dh_group.map(|g| DhGroup::from(g).to_string()),
            cert_request_count: resp.cert_requests.len(),
        });

        None
    }

    /// Build a probe for a single IKEv1 transform at the given index in the
    /// full enumeration set. Used for iterative transform enumeration after
    /// NO_PROPOSAL_CHOSEN — covers every algorithm combination in the registry.
    fn build_single_transform_probe(&self, target_idx: usize, transform_idx: usize) -> Option<ProbeState> {
        let all_transforms = all_ikev1_transforms();
        let transform = all_transforms.get(transform_idx)?;

        let mut rng = rand::rng();
        let cookie: u64 = rng.random::<u64>() | 1;
        let packet = v1msg::build_main_mode_msg1(cookie, &[*transform]);
        let now = Instant::now();
        let retry_count = u8::try_from(transform_idx + 1).unwrap_or(u8::MAX);

        Some(ProbeState {
            target_idx,
            probe_type: ProbeKind::Ikev1MainMode,
            cookie,
            first_sent: now,
            last_sent: now,
            current_timeout: Duration::from_millis(self.config.timeout_ms),
            retries_left: self.config.retries,
            retry_count,
            packet,
            sa_body: Vec::new(),
            ke_data: Vec::new(),
            nonce_data: Vec::new(),
            harvest: None,
            send_after: None,
        })
    }

    fn build_compact_v1_probe(&self, prev: &ProbeState) -> ProbeState {
        let mut rng = rand::rng();
        let cookie: u64 = rng.random::<u64>() | 1;
        let transforms = compact_ikev1_transforms();
        let packet = v1msg::build_main_mode_msg1_with_vids(cookie, &transforms, vendor::DEFAULT_V1_VIDS);
        let now = Instant::now();

        ProbeState {
            target_idx: prev.target_idx,
            probe_type: ProbeKind::Ikev1MainMode,
            cookie,
            first_sent: prev.first_sent,
            last_sent: now,
            current_timeout: Duration::from_millis(self.config.timeout_ms),
            retries_left: self.config.retries,
            retry_count: prev.retry_count + 1,
            packet,
            sa_body: Vec::new(),
            ke_data: Vec::new(),
            nonce_data: Vec::new(),
            harvest: None,
            send_after: None,
        }
    }

    fn start_harvest(&self, probe: &ProbeState, accepted: &Ikev1Transform) -> Option<ProbeState> {
        let harvest = HarvestState { encryption: accepted.encryption, key_length: accepted.key_length, dh_group: accepted.dh_group, hash_idx: 0 };
        self.build_harvest_probe(probe.target_idx, probe.first_sent, &harvest)
    }

    fn next_harvest_probe(&self, probe: &ProbeState) -> Option<ProbeState> {
        let prev = probe.harvest.as_ref()?;
        let harvest = HarvestState { encryption: prev.encryption, key_length: prev.key_length, dh_group: prev.dh_group, hash_idx: prev.hash_idx + 1 };
        self.build_harvest_probe(probe.target_idx, probe.first_sent, &harvest)
    }

    fn build_harvest_probe(&self, target_idx: usize, first_sent: Instant, harvest: &HarvestState) -> Option<ProbeState> {
        let all_hashes = Ikev1HashAlg::all();
        let hash_alg = *all_hashes.get(harvest.hash_idx)?;
        let ke_len = harvest.dh_group.ke_len()?;

        let transform = Ikev1Transform { encryption: harvest.encryption, key_length: harvest.key_length, hash: hash_alg, auth_method: Ikev1AuthMethod::PreSharedKey, dh_group: harvest.dh_group, lifetime_secs: Some(28800) };

        let mut rng = rand::rng();
        let cookie: u64 = rng.random::<u64>() | 1;
        let sa_body = ike_protocol::ikev1::sa::build_sa_body(&[transform]);
        let mut ke_data = vec![0u8; ke_len];
        rng.fill(ke_data.as_mut_slice());
        let mut nonce_data = vec![0u8; 20];
        rng.fill(nonce_data.as_mut_slice());
        let id_data = encode_id_data(self.config.id_type, &self.config.identity);
        let packet = v1msg::build_aggressive_msg1(cookie, &[transform], &ke_data, &nonce_data, self.config.id_type, &id_data, vendor::DEFAULT_V1_VIDS);
        let now = Instant::now();

        Some(ProbeState {
            target_idx,
            probe_type: ProbeKind::Ikev1AggressiveDh(harvest.dh_group),
            cookie,
            first_sent,
            last_sent: now,
            current_timeout: Duration::from_millis(self.config.timeout_ms),
            retries_left: self.config.retries,
            retry_count: 0,
            packet,
            sa_body,
            ke_data,
            nonce_data,
            harvest: Some(HarvestState { encryption: harvest.encryption, key_length: harvest.key_length, dh_group: harvest.dh_group, hash_idx: harvest.hash_idx }),
            send_after: Some(Instant::now() + HARVEST_DELAY),
        })
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn create_progress_bar(total: usize, quiet: bool) -> ProgressBar {
    if quiet {
        return ProgressBar::hidden();
    }
    let total = u64::try_from(total).unwrap_or(u64::MAX);
    let pb = ProgressBar::new(total);
    let style = ProgressStyle::default_bar().template("[*] Scanning  {bar:40.cyan/blue}  {pos}/{len}  ({msg})  [{elapsed_precise} / ~{eta_precise}]").unwrap_or_else(|_| ProgressStyle::default_bar());
    pb.set_style(style);
    pb.set_message("0 responded");
    pb
}

fn rate_interval(rate_pps: u32) -> Duration {
    if rate_pps > 0 { Duration::from_secs_f64(1.0 / f64::from(rate_pps)) } else { Duration::ZERO }
}

fn is_end_wait_expired(all_sent: bool, outstanding: &HashMap<u64, ProbeState>, end_wait: Duration) -> bool {
    if !all_sent || outstanding.is_empty() {
        return false;
    }
    let Some(oldest_deadline) = outstanding.values().map(|p| p.last_sent + p.current_timeout).min() else {
        return true;
    };
    Instant::now() > oldest_deadline + end_wait
}

fn compute_next_timeout(all_sent: bool, outstanding: &HashMap<u64, ProbeState>, concurrency: usize) -> Duration {
    if !all_sent && outstanding.len() < concurrency {
        return Duration::from_millis(1);
    }
    outstanding.values().map(|p| p.current_timeout.saturating_sub(p.last_sent.elapsed())).min().unwrap_or(Duration::from_millis(100)).max(Duration::from_millis(1))
}

fn ikev1_host_result(resp: &Ikev1Response) -> Ikev1HostResult {
    Ikev1HostResult {
        transforms: resp.transforms.iter().map(ToString::to_string).collect(),
        vendor_ids: resp.vendor_ids.iter().map(|v| bytes_to_display(v)).collect(),
        notifications: resp.notifications.iter().map(|(t, d)| format_v1_notify(*t, d)).collect(),
        server_id: resp.decoded_id().map(|id| id.to_string()),
        cert_request_count: resp.cert_requests.len(),
        nat_detected: !resp.nat_d.is_empty(),
    }
}

fn format_v1_notify(notify_type: u16, data: &[u8]) -> String {
    let name = Ikev1NotifyType::from(notify_type);
    if data.is_empty() {
        return format!("{name}");
    }
    match notify_type {
        14 => format_v1_notify_attributes(name, data),
        _ => format!("{name} data={}", bytes_to_display(data)),
    }
}

fn format_v2_notify(notify_type: u16, data: &[u8]) -> String {
    let name = Ikev2NotifyType::from(notify_type);
    if data.is_empty() {
        return format!("{name}");
    }
    match notify_type {
        17 | 16388 | 16389 | 16390 => format!("{name}"),
        16431 => format_v2_signature_hash_algorithms(data),
        _ => format!("{name} data={}", bytes_to_display(data)),
    }
}

fn format_v1_notify_attributes(name: Ikev1NotifyType, data: &[u8]) -> String {
    let attrs = DataAttribute::parse_all(data);
    if attrs.is_empty() {
        return format!("{name} data={}", bytes_to_display(data));
    }
    let mut parts = Vec::new();
    for attr in &attrs {
        let label = match attr.attr_type() {
            v1_class::ENCRYPTION => "Enc",
            v1_class::HASH => "Hash",
            v1_class::AUTH_METHOD => "Auth",
            v1_class::GROUP_DESC => "DH",
            v1_class::LIFE_TYPE => "LifeType",
            v1_class::LIFE_DURATION => "LifeDuration",
            v1_class::KEY_LENGTH => "KeyLen",
            other => {
                parts.push(format!("attr{other}={}", attr.as_short().unwrap_or(0)));
                continue;
            },
        };
        if let Some(val) = attr.as_short() {
            let decoded = match attr.attr_type() {
                v1_class::ENCRYPTION => Ikev1EncryptionAlg::from(val).to_string(),
                v1_class::HASH => Ikev1HashAlg::from(val).to_string(),
                v1_class::AUTH_METHOD => Ikev1AuthMethod::from(val).to_string(),
                v1_class::GROUP_DESC => DhGroup::from(val).to_string(),
                v1_class::LIFE_TYPE => match val {
                    1 => "seconds".to_owned(),
                    2 => "kilobytes".to_owned(),
                    _ => val.to_string(),
                },
                _ => val.to_string(),
            };
            parts.push(format!("{label}={decoded}"));
        } else {
            parts.push(format!("{label}=<long>"));
        }
    }
    format!("{name} ({})", parts.join(", "))
}

fn format_v2_signature_hash_algorithms(data: &[u8]) -> String {
    let algos: Vec<&str> = data
        .chunks_exact(2)
        .filter_map(|c| {
            let pair: &[u8; 2] = c.try_into().ok()?;
            Some(match u16::from_be_bytes(*pair) {
                1 => "SHA-1",
                2 => "SHA-256",
                3 => "SHA-384",
                4 => "SHA-512",
                5 => "Identity",
                _ => "?",
            })
        })
        .collect();
    format!("SignatureHashAlgorithms: {}", algos.join(", "))
}

/// DH groups in aggressive mode walk order: most common first, then all others.
/// Computed from the registry — every group with a known KE length is included.
/// Encode the identity string as the correct binary format for the ID type.
/// ID_IPV4_ADDR requires 4 bytes of binary IP, not ASCII.
fn encode_id_data(id_type: Ikev1IdType, identity: &str) -> Vec<u8> {
    match id_type {
        Ikev1IdType::Ipv4Addr => {
            if let Ok(addr) = identity.parse::<std::net::Ipv4Addr>() {
                return addr.octets().to_vec();
            }
            identity.as_bytes().to_vec()
        },
        Ikev1IdType::Ipv6Addr => {
            if let Ok(addr) = identity.parse::<std::net::Ipv6Addr>() {
                return addr.octets().to_vec();
            }
            identity.as_bytes().to_vec()
        },
        _ => identity.as_bytes().to_vec(),
    }
}

fn aggressive_dh_walk_order() -> Vec<DhGroup> {
    let priority = [DhGroup::Modp2048, DhGroup::Modp1024, DhGroup::Ecp256, DhGroup::Modp1536, DhGroup::Modp4096, DhGroup::Ecp384, DhGroup::Curve25519];
    let mut result: Vec<DhGroup> = priority.to_vec();
    for &g in DhGroup::all() {
        if g.ke_len().is_some() && !result.contains(&g) {
            result.push(g);
        }
    }
    result
}

fn extract_psk_hash(probe: &ProbeState, resp: &Ikev1Response) -> Option<PskHashResult> {
    let hash_r = resp.hash_r.as_ref()?;
    let ke_data = resp.ke_data.as_ref()?;
    let nonce = resp.nonce.as_ref()?;
    let id_body = resp.id_body.as_ref()?;

    let crack = PskCrackData {
        g_xr: ke_data.clone(),
        g_xi: probe.ke_data.clone(),
        cky_r: resp.header.responder_spi.to_be_bytes(),
        cky_i: resp.header.initiator_spi.to_be_bytes(),
        sai_b: probe.sa_body.clone(),
        idir_b: id_body.clone(),
        ni_b: probe.nonce_data.clone(),
        nr_b: nonce.clone(),
        hash_r: hash_r.clone(),
    };

    let msg_len = crack.g_xr.len() + crack.g_xi.len() + crack.cky_r.len() + crack.cky_i.len() + crack.sai_b.len() + crack.idir_b.len();
    let warning = match crack.hash_type() {
        ike_protocol::ikev1::hash::PskHashType::Md5 | ike_protocol::ikev1::hash::PskHashType::Sha1 if msg_len >= 512 => Some(format!("hashcat modes 5300/5400 reject msg_buf >= 512 bytes (this hash has {msg_len}); use a DH group <= 1024-bit, or crack with mode 38100 if SHA-256")),
        _ => None,
    };

    Some(PskHashResult { hash_type: crack.hash_type().to_string(), hashcat_mode: crack.hash_type().hashcat_mode(), hashcat_line: crack.to_hashcat(), warning })
}

// ---------------------------------------------------------------------------
// Default transform sets
// ---------------------------------------------------------------------------

/// Generate IKEv1 transforms from the IANA registries — no hand-picked lists.
/// Every known encryption (x every key length) x every known hash x the given DH groups.
fn ikev1_transforms_for_groups(groups: &[DhGroup]) -> Vec<Ikev1Transform> {
    let psk = Ikev1AuthMethod::PreSharedKey;
    let lt = Some(28800);
    let mut transforms = Vec::new();
    for &enc in Ikev1EncryptionAlg::all() {
        for &kl in enc.key_lengths() {
            for &hash in Ikev1HashAlg::all() {
                for &group in groups {
                    transforms.push(Ikev1Transform { encryption: enc, key_length: kl, hash, auth_method: psk, dh_group: group, lifetime_secs: lt });
                }
            }
        }
    }
    transforms
}

fn default_ikev1_transforms() -> Vec<Ikev1Transform> {
    ikev1_transforms_for_groups(&[DhGroup::Modp2048, DhGroup::Modp1024])
}

fn compact_ikev1_transforms() -> Vec<Ikev1Transform> {
    let psk = Ikev1AuthMethod::PreSharedKey;
    let lt = Some(28800);
    vec![
        Ikev1Transform { encryption: Ikev1EncryptionAlg::AesCbc, key_length: Some(256), hash: Ikev1HashAlg::Sha256, auth_method: psk, dh_group: DhGroup::Modp2048, lifetime_secs: lt },
        Ikev1Transform { encryption: Ikev1EncryptionAlg::AesCbc, key_length: Some(256), hash: Ikev1HashAlg::Sha1, auth_method: psk, dh_group: DhGroup::Modp2048, lifetime_secs: lt },
        Ikev1Transform { encryption: Ikev1EncryptionAlg::AesCbc, key_length: Some(128), hash: Ikev1HashAlg::Sha256, auth_method: psk, dh_group: DhGroup::Modp2048, lifetime_secs: lt },
        Ikev1Transform { encryption: Ikev1EncryptionAlg::AesCbc, key_length: Some(128), hash: Ikev1HashAlg::Sha1, auth_method: psk, dh_group: DhGroup::Modp2048, lifetime_secs: lt },
        Ikev1Transform { encryption: Ikev1EncryptionAlg::TripleDesCbc, key_length: None, hash: Ikev1HashAlg::Sha1, auth_method: psk, dh_group: DhGroup::Modp2048, lifetime_secs: lt },
        Ikev1Transform { encryption: Ikev1EncryptionAlg::TripleDesCbc, key_length: None, hash: Ikev1HashAlg::Sha1, auth_method: psk, dh_group: DhGroup::Modp1024, lifetime_secs: lt },
    ]
}

/// Generate IKEv2 proposals from the IANA registries — no hand-picked lists.
/// Split into AEAD (INTEG=NONE) and non-AEAD (real INTEG) proposals.
fn default_ikev2_proposals() -> Vec<Ikev2Proposal> {
    // DH groups: every group with a known KE length.
    let dh_groups: Vec<DhGroup> = DhGroup::all().iter().copied().filter(|g| g.ke_len().is_some()).collect();

    // PRF: every known algorithm.
    let prfs: Vec<Ikev2Transform> = Ikev2PrfAlg::all().iter().map(|&alg| Ikev2Transform::prf(alg)).collect();
    let dh_transforms: Vec<Ikev2Transform> = dh_groups.iter().map(|&g| Ikev2Transform::dh(g)).collect();

    // Proposal 1: AEAD ciphers (INTEG = NONE).
    let mut aead = Vec::new();
    for &alg in Ikev2EncryptionAlg::all() {
        if alg.is_aead() {
            for &kl in alg.key_lengths() {
                aead.push(Ikev2Transform::encr(alg, kl));
            }
        }
    }
    aead.extend_from_slice(&prfs);
    aead.push(Ikev2Transform::integ(Ikev2IntegrityAlg::None));
    aead.extend_from_slice(&dh_transforms);

    // Proposal 2: Non-AEAD ciphers (requires real INTEG).
    let mut non_aead = Vec::new();
    for &alg in Ikev2EncryptionAlg::all() {
        if !alg.is_aead() {
            for &kl in alg.key_lengths() {
                non_aead.push(Ikev2Transform::encr(alg, kl));
            }
        }
    }
    non_aead.extend_from_slice(&prfs);
    for &alg in Ikev2IntegrityAlg::all() {
        if alg != Ikev2IntegrityAlg::None {
            non_aead.push(Ikev2Transform::integ(alg));
        }
    }
    non_aead.extend_from_slice(&dh_transforms);

    vec![Ikev2Proposal::ike(1, aead), Ikev2Proposal::ike(2, non_aead)]
}

/// IKEv1 transforms for enumeration after NO_PROPOSAL_CHOSEN.
/// Computed from registries — tests one variable at a time against two bases.
fn all_ikev1_transforms() -> Vec<Ikev1Transform> {
    let mut transforms = Vec::new();
    let lt = Some(28800);
    let psk = Ikev1AuthMethod::PreSharedKey;
    let dh_groups_with_ke: Vec<DhGroup> = DhGroup::all().iter().copied().filter(|g| g.ke_len().is_some()).collect();

    // Pass 1: modern base (AES-256/SHA-256/PSK/DH14) — vary one variable at a time.
    let b1_enc = Ikev1EncryptionAlg::AesCbc;
    let b1_kl = Some(256);
    let b1_hash = Ikev1HashAlg::Sha256;
    let b1_group = DhGroup::Modp2048;

    for &enc in Ikev1EncryptionAlg::all() {
        for &kl in enc.key_lengths() {
            transforms.push(Ikev1Transform { encryption: enc, key_length: kl, hash: b1_hash, auth_method: psk, dh_group: b1_group, lifetime_secs: lt });
        }
    }
    for &hash in Ikev1HashAlg::all() {
        if hash != b1_hash {
            transforms.push(Ikev1Transform { encryption: b1_enc, key_length: b1_kl, hash, auth_method: psk, dh_group: b1_group, lifetime_secs: lt });
        }
    }
    for &group in &dh_groups_with_ke {
        if group != b1_group {
            transforms.push(Ikev1Transform { encryption: b1_enc, key_length: b1_kl, hash: b1_hash, auth_method: psk, dh_group: group, lifetime_secs: lt });
        }
    }
    for &auth in Ikev1AuthMethod::all() {
        if auth != psk {
            transforms.push(Ikev1Transform { encryption: b1_enc, key_length: b1_kl, hash: b1_hash, auth_method: auth, dh_group: b1_group, lifetime_secs: lt });
        }
    }

    // Pass 2: legacy base (3DES/SHA-1/PSK/DH2) — vary enc and hash.
    let b2_enc = Ikev1EncryptionAlg::TripleDesCbc;
    let b2_hash = Ikev1HashAlg::Sha1;
    let b2_group = DhGroup::Modp1024;

    for &enc in Ikev1EncryptionAlg::all() {
        for &kl in enc.key_lengths() {
            if enc != b2_enc || kl.is_some() {
                transforms.push(Ikev1Transform { encryption: enc, key_length: kl, hash: b2_hash, auth_method: psk, dh_group: b2_group, lifetime_secs: lt });
            }
        }
    }
    for &hash in Ikev1HashAlg::all() {
        if hash != b2_hash {
            transforms.push(Ikev1Transform { encryption: b2_enc, key_length: None, hash, auth_method: psk, dh_group: b2_group, lifetime_secs: lt });
        }
    }

    transforms
}

// ---------------------------------------------------------------------------
// Hex / ASCII encoding
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn bytes_to_display(bytes: &[u8]) -> String {
    if !bytes.is_empty() && bytes.iter().all(|&b| matches!(b, 0x20..=0x7E)) { String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| hex_encode(bytes)) } else { hex_encode(bytes) }
}
