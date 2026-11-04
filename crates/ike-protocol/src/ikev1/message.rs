//! IKEv1 complete message builders for Main Mode and Aggressive Mode.
//!
//! These produce ready-to-send UDP datagrams. The scanner calls `build_*`
//! with the desired parameters and gets back a byte buffer.

use crate::header::{ExchangeType, HEADER_LEN, IkeHeader, IkeVersion};
use crate::ikev1::model::Ikev1IdType;
use crate::ikev1::sa::{self, Ikev1Transform};
use crate::payload::{self, v1_types};

/// Build a complete IKEv1 Main Mode message 1 (Identity Protection).
///
/// Contains: ISAKMP Header + SA payload [+ VID(s)].
/// This is the first message in a Phase 1 Main Mode exchange.
/// RFC 2409 section 5.
///
/// The responder replies with the chosen transform, or a NO-PROPOSAL-CHOSEN
/// notification.
#[must_use]
pub fn build_main_mode_msg1(initiator_spi: u64, transforms: &[Ikev1Transform]) -> Vec<u8> {
    build_main_mode_msg1_with_vids(initiator_spi, transforms, &[])
}

/// Build Main Mode message 1 with optional Vendor ID payloads.
/// Sending DPD, NAT-T, and XAUTH VIDs causes many servers to reveal
/// additional VIDs and negotiate capabilities they would otherwise hide.
#[must_use]
pub fn build_main_mode_msg1_with_vids(initiator_spi: u64, transforms: &[Ikev1Transform], vendor_ids: &[&[u8]]) -> Vec<u8> {
    let sa_body = sa::build_sa_body(transforms);

    let mut payloads: Vec<(u8, Vec<u8>)> = vec![(v1_types::SA, sa_body)];
    for vid in vendor_ids {
        payloads.push((v1_types::VENDOR_ID, vid.to_vec()));
    }

    let payload_refs: Vec<(u8, &[u8])> = payloads.iter().map(|(t, b)| (*t, b.as_slice())).collect();
    let (first_payload_type, chained_bytes) = payload::build_payload_chain(&payload_refs);

    let total_len = u32::try_from(HEADER_LEN + chained_bytes.len()).unwrap_or(u32::MAX);
    let header = IkeHeader { initiator_spi, responder_spi: 0, next_payload: first_payload_type, version: IkeVersion::V1, exchange_type: ExchangeType::IdentityProtection, flags: 0, message_id: 0, length: total_len };

    let mut packet = Vec::with_capacity(HEADER_LEN + chained_bytes.len());
    packet.extend_from_slice(&header.to_bytes());
    packet.extend_from_slice(&chained_bytes);
    packet
}

/// Build a complete IKEv1 Aggressive Mode message 1.
///
/// Contains: ISAKMP Header + SA + KE + Nonce + ID [+ VID(s)].
/// This is the message that triggers the server to respond with HASH_R
/// (the crackable PSK hash). RFC 2409 section 7.1.
///
/// # Parameters
///
/// - `initiator_spi`: 8-byte random cookie.
/// - `transforms`: SA proposal (typically a single transform for Aggressive Mode).
/// - `ke_data`: DH public value (random bytes, length must match the DH group).
/// - `nonce`: Random nonce (8-256 bytes, typically 20). RFC 2409 section 5.
/// - `id_type`: Identity payload type (usually `KeyId` for group name).
/// - `id_data`: Identity data (e.g., the VPN group name as bytes).
/// - `vendor_ids`: Optional vendor ID payloads to include (raw bytes per VID).
#[must_use]
pub fn build_aggressive_msg1(initiator_spi: u64, transforms: &[Ikev1Transform], ke_data: &[u8], nonce: &[u8], id_type: Ikev1IdType, id_data: &[u8], vendor_ids: &[&[u8]]) -> Vec<u8> {
    // Build payload bodies (without generic headers -- build_payload_chain adds them).
    let sa_body = sa::build_sa_body(transforms);

    // KE body is just the raw DH public value. RFC 2408 section 3.7.
    let ke_body = ke_data;

    // Nonce body is just the raw nonce. RFC 2408 section 3.13.
    let nonce_body = nonce;

    // ID body: ID type (1) + Protocol ID (1) + Port (2) + ID data (variable).
    // RFC 2408 section 3.8 + RFC 2407 section 4.6.2.1.
    let mut id_body = Vec::with_capacity(4 + id_data.len());
    id_body.push(u8::from(id_type)); // ID Type
    id_body.push(0); // Protocol ID (0 = unused)
    id_body.extend_from_slice(&0u16.to_be_bytes()); // Port (0 = unused)
    id_body.extend_from_slice(id_data);

    // Collect all payloads in order: SA, KE, Nonce, ID, [VID(s)].
    let mut payloads: Vec<(u8, Vec<u8>)> = vec![(v1_types::SA, sa_body), (v1_types::KE, ke_body.to_vec()), (v1_types::NONCE, nonce_body.to_vec()), (v1_types::ID, id_body)];

    for vid in vendor_ids {
        payloads.push((v1_types::VENDOR_ID, vid.to_vec()));
    }

    // Build the chained payload bytes.
    let payload_refs: Vec<(u8, &[u8])> = payloads.iter().map(|(t, b)| (*t, b.as_slice())).collect();
    let (first_payload_type, chained_bytes) = payload::build_payload_chain(&payload_refs);

    let total_len = u32::try_from(HEADER_LEN + chained_bytes.len()).unwrap_or(u32::MAX);
    let header = IkeHeader {
        initiator_spi,
        responder_spi: 0,
        next_payload: first_payload_type,
        version: IkeVersion::V1,
        exchange_type: ExchangeType::Aggressive, // RFC 2409 section 7.
        flags: 0,
        message_id: 0,
        length: total_len,
    };

    let mut packet = Vec::with_capacity(HEADER_LEN + chained_bytes.len());
    packet.extend_from_slice(&header.to_bytes());
    packet.extend_from_slice(&chained_bytes);
    packet
}

/// Parsed response from an IKEv1 Main Mode message 2 or Aggressive Mode message 2.
/// Contains the fields extracted from the server's response.
#[derive(Debug, Clone)]
pub struct Ikev1Response {
    /// Parsed ISAKMP header.
    pub header: IkeHeader,
    /// SA payload: the chosen transform(s). Empty if this is a notification.
    pub transforms: Vec<Ikev1Transform>,
    /// KE payload data (DH public value). Present in Aggressive Mode response.
    pub ke_data: Option<Vec<u8>>,
    /// Nonce payload data. Present in Aggressive Mode response.
    pub nonce: Option<Vec<u8>>,
    /// ID payload body (type + protocol + port + data). Present in Aggressive Mode.
    pub id_body: Option<Vec<u8>>,
    /// HASH payload data (HASH_R for PSK cracking). Present in Aggressive Mode.
    pub hash_r: Option<Vec<u8>>,
    /// Vendor ID payloads (raw bytes, one per VID).
    pub vendor_ids: Vec<Vec<u8>>,
    /// Notification payloads: (notify_type, data).
    pub notifications: Vec<(u16, Vec<u8>)>,
    /// Certificate Request payloads.
    pub cert_requests: Vec<Vec<u8>>,
    /// NAT-D payloads (RFC 3947).
    pub nat_d: Vec<Vec<u8>>,
}

impl Ikev1Response {
    /// Parse an IKEv1 response from raw UDP datagram bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = IkeHeader::parse(data)?;
        let msg_len = usize::try_from(header.length).ok()?;
        if msg_len > data.len() {
            return None;
        }

        let payload_area = data.get(HEADER_LEN..msg_len)?;
        let payloads = payload::iter_payloads(payload_area, header.next_payload);

        let mut response = Self { header, transforms: Vec::new(), ke_data: None, nonce: None, id_body: None, hash_r: None, vendor_ids: Vec::new(), notifications: Vec::new(), cert_requests: Vec::new(), nat_d: Vec::new() };

        for (ptype, body) in payloads {
            match ptype {
                v1_types::SA => {
                    response.transforms = sa::parse_sa_body(&body);
                },
                v1_types::KE => {
                    response.ke_data = Some(body);
                },
                v1_types::NONCE => {
                    response.nonce = Some(body);
                },
                v1_types::ID => {
                    response.id_body = Some(body);
                },
                v1_types::HASH => {
                    response.hash_r = Some(body);
                },
                v1_types::VENDOR_ID => {
                    response.vendor_ids.push(body);
                },
                v1_types::NOTIFICATION => {
                    // Notification body: DOI(4) + Protocol-ID(1) + SPI Size(1) + Notify Type(2) + [SPI] + [Data]
                    // RFC 2408 section 3.14.
                    if let Some(hdr_bytes) = body.get(..8).and_then(|s| <&[u8; 8]>::try_from(s).ok()) {
                        let notify_type = u16::from_be_bytes([hdr_bytes[6], hdr_bytes[7]]);
                        let spi_size = usize::from(hdr_bytes[5]);
                        let notify_data = body.get(8 + spi_size..).unwrap_or_default().to_vec();
                        response.notifications.push((notify_type, notify_data));
                    }
                },
                v1_types::CERT_REQ => {
                    response.cert_requests.push(body);
                },
                v1_types::NAT_D | v1_types::NAT_D_RFC => {
                    response.nat_d.push(body);
                },
                _ => {},
            }
        }

        Some(response)
    }

    /// Whether this response is a notification (no SA, has notification payloads).
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.transforms.is_empty() && !self.notifications.is_empty()
    }

    /// Get the NO-PROPOSAL-CHOSEN notification, if present.
    #[must_use]
    pub fn is_no_proposal_chosen(&self) -> bool {
        self.notifications.iter().any(|(t, _)| *t == 14)
    }

    /// Get the BAD-PROPOSAL-SYNTAX notification, if present.
    #[must_use]
    pub fn is_bad_proposal_syntax(&self) -> bool {
        self.notifications.iter().any(|(t, _)| *t == 15)
    }

    /// Decode the responder's ID payload into a human-readable form.
    /// The ID body layout is: ID-Type(1) + Protocol-ID(1) + Port(2) + ID-Data(variable).
    /// RFC 2408 section 3.8 + RFC 2407 section 4.6.2.1.
    #[must_use]
    pub fn decoded_id(&self) -> Option<DecodedId> {
        DecodedId::parse(self.id_body.as_deref()?)
    }
}

/// Decoded IKEv1 Identity payload. RFC 2408 section 3.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedId {
    /// ID type from the first byte. RFC 2407 section 4.6.2.1.
    pub id_type: Ikev1IdType,
    /// Human-readable representation of the identity.
    pub value: String,
}

impl DecodedId {
    /// Parse from the raw ID payload body (type + protocol + port + data).
    #[must_use]
    pub fn parse(body: &[u8]) -> Option<Self> {
        if body.len() < 4 {
            return None;
        }
        let id_type = Ikev1IdType::from(*body.first()?);
        let id_data = body.get(4..)?;

        let value = match id_type {
            Ikev1IdType::Ipv4Addr if id_data.len() >= 4 => {
                let octets: &[u8; 4] = id_data.get(..4)?.try_into().ok()?;
                format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
            },
            Ikev1IdType::Ipv6Addr if id_data.len() >= 16 => {
                let octets: &[u8; 16] = id_data.get(..16)?.try_into().ok()?;
                let addr = std::net::Ipv6Addr::from(*octets);
                addr.to_string()
            },
            Ikev1IdType::Fqdn | Ikev1IdType::UserFqdn | Ikev1IdType::KeyId => String::from_utf8_lossy(id_data).into_owned(),
            _ => {
                if !id_data.is_empty() && id_data.iter().all(|&b| matches!(b, 0x20..=0x7E)) {
                    String::from_utf8_lossy(id_data).into_owned()
                } else {
                    let mut hex = String::with_capacity(id_data.len() * 2);
                    for &b in id_data {
                        use core::fmt::Write;
                        let _ = write!(hex, "{b:02x}");
                    }
                    hex
                }
            },
        };

        Some(Self { id_type, value })
    }
}

impl core::fmt::Display for DecodedId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({})", self.value, self.id_type)
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unreadable_literal, reason = "hex SPI test values")]
    use super::*;
    use crate::ikev1::model::*;

    fn default_transforms() -> Vec<Ikev1Transform> {
        vec![
            Ikev1Transform { encryption: Ikev1EncryptionAlg::AesCbc, key_length: Some(256), hash: Ikev1HashAlg::Sha256, auth_method: Ikev1AuthMethod::PreSharedKey, dh_group: DhGroup::Modp2048, lifetime_secs: Some(28800) },
            Ikev1Transform { encryption: Ikev1EncryptionAlg::AesCbc, key_length: Some(128), hash: Ikev1HashAlg::Sha1, auth_method: Ikev1AuthMethod::PreSharedKey, dh_group: DhGroup::Modp1024, lifetime_secs: Some(28800) },
        ]
    }

    #[test]
    fn main_mode_msg1_header() {
        let spi = 0xDEADBEEFCAFEBABE;
        let packet = build_main_mode_msg1(spi, &default_transforms());

        let hdr = IkeHeader::parse(&packet).expect("parse header");
        assert_eq!(hdr.initiator_spi, spi);
        assert_eq!(hdr.responder_spi, 0);
        assert_eq!(hdr.version, IkeVersion::V1);
        assert_eq!(hdr.exchange_type, ExchangeType::IdentityProtection);
        assert_eq!(hdr.next_payload, v1_types::SA);
        assert_eq!(hdr.message_id, 0);
        assert_eq!(hdr.length as usize, packet.len());
    }

    #[test]
    fn aggressive_msg1_has_all_payloads() {
        let spi = 0x0102030405060708;
        let ke = vec![0xAA; 256]; // 2048-bit DH group = 256 bytes
        let nonce = vec![0xBB; 20];
        let group_name = b"vpngroup";

        let packet = build_aggressive_msg1(
            spi,
            &default_transforms()[..1], // single transform for aggressive
            &ke,
            &nonce,
            Ikev1IdType::KeyId,
            group_name,
            &[],
        );

        let hdr = IkeHeader::parse(&packet).expect("parse header");
        assert_eq!(hdr.exchange_type, ExchangeType::Aggressive);
        assert_eq!(hdr.next_payload, v1_types::SA);
        assert_eq!(hdr.length as usize, packet.len());

        // Parse the payloads to verify they're all present.
        let payload_area = &packet[HEADER_LEN..];
        let payloads = payload::iter_payloads(payload_area, hdr.next_payload);

        let types: Vec<u8> = payloads.iter().map(|(t, _)| *t).collect();
        assert!(types.contains(&v1_types::SA), "missing SA");
        assert!(types.contains(&v1_types::KE), "missing KE");
        assert!(types.contains(&v1_types::NONCE), "missing Nonce");
        assert!(types.contains(&v1_types::ID), "missing ID");
    }

    #[test]
    fn aggressive_msg1_with_vendor_ids() {
        let spi = 0x0102030405060708;
        let ke = vec![0xAA; 128];
        let nonce = vec![0xBB; 20];
        let vid1 = b"\xde\xad\xbe\xef";
        let vid2 = b"\xca\xfe\xba\xbe";

        let packet = build_aggressive_msg1(spi, &default_transforms()[..1], &ke, &nonce, Ikev1IdType::UserFqdn, b"test@example.com", &[&vid1[..], &vid2[..]]);

        let hdr = IkeHeader::parse(&packet).expect("parse header");
        let payload_area = &packet[HEADER_LEN..];
        let payloads = payload::iter_payloads(payload_area, hdr.next_payload);

        let vid_count = payloads.iter().filter(|(t, _)| *t == v1_types::VENDOR_ID).count();
        assert_eq!(vid_count, 2, "expected 2 VID payloads");
    }

    #[test]
    fn parse_main_mode_response_from_built_packet() {
        // Build a packet and parse it as if it were a response.
        // This tests the parser against our own builder output.
        let spi = 0xDEADBEEFCAFEBABE;
        let transforms = default_transforms();
        let packet = build_main_mode_msg1(spi, &transforms);

        let response = Ikev1Response::parse(&packet).expect("parse response");
        assert_eq!(response.header.initiator_spi, spi);
        assert_eq!(response.transforms.len(), 2);
        assert_eq!(response.transforms[0].encryption, Ikev1EncryptionAlg::AesCbc);
    }
}
