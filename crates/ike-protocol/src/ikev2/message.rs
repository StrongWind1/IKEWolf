//! IKEv2 IKE_SA_INIT message builder and response parser.
//!
//! IKE_SA_INIT is the first exchange in IKEv2 (RFC 7296 section 1.2).
//! It is unauthenticated and unencrypted -- the scanner can send it
//! and parse the response without any key material.

use crate::header::{ExchangeType, HEADER_LEN, IkeHeader, IkeVersion};
use crate::ikev2::model::Ikev2NotifyType;
use crate::ikev2::sa::{self, Ikev2Proposal};
use crate::payload::{self, v2_types};

/// Build a complete IKEv2 IKE_SA_INIT request packet.
///
/// Contains: IKE Header + SA + KE + Nonce [+ NAT-D notifications].
/// RFC 7296 section 1.2.
///
/// # Parameters
///
/// - `initiator_spi`: 8-byte random SPI.
/// - `proposals`: SA proposals (typically one with multiple transform alternatives).
/// - `ke_dh_group`: DH group number for the KE payload header. RFC 7296 section 3.4.
/// - `ke_data`: DH public value (random bytes, length must match group).
/// - `nonce`: Random nonce (16-256 bytes). RFC 7296 section 3.9.
/// - `nat_detection`: Optional NAT-D notify payloads (source IP hash, dest IP hash).
#[must_use]
pub fn build_sa_init_request(initiator_spi: u64, proposals: &[Ikev2Proposal], ke_dh_group: u16, ke_data: &[u8], nonce: &[u8], nat_detection: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let sa_body = sa::build_sa_body(proposals);

    // KE payload body: DH Group (2 bytes) + Reserved (2 bytes) + KE data.
    // RFC 7296 section 3.4.
    let mut ke_body = Vec::with_capacity(4 + ke_data.len());
    ke_body.extend_from_slice(&ke_dh_group.to_be_bytes());
    ke_body.extend_from_slice(&[0, 0]); // Reserved. RFC 7296 section 3.4.
    ke_body.extend_from_slice(ke_data);

    let mut payloads: Vec<(u8, Vec<u8>)> = vec![(v2_types::SA, sa_body), (v2_types::KE, ke_body), (v2_types::NONCE, nonce.to_vec())];

    // NAT-D notifications. RFC 7296 section 2.23.
    if let Some((src_hash, dst_hash)) = nat_detection {
        payloads.push((v2_types::NOTIFY, build_nat_d_notify(Ikev2NotifyType::NatDetectionSourceIp, src_hash)));
        payloads.push((v2_types::NOTIFY, build_nat_d_notify(Ikev2NotifyType::NatDetectionDestinationIp, dst_hash)));
    }

    let payload_refs: Vec<(u8, &[u8])> = payloads.iter().map(|(t, b)| (*t, b.as_slice())).collect();
    let (first_type, chained) = payload::build_payload_chain(&payload_refs);

    let Ok(total_len) = u32::try_from(HEADER_LEN + chained.len()) else {
        return Vec::new();
    };

    let header = IkeHeader {
        initiator_spi,
        responder_spi: 0,
        next_payload: first_type,
        version: IkeVersion::V2,
        exchange_type: ExchangeType::IkeSaInit,
        flags: 0x08, // Initiator flag. RFC 7296 section 3.1.
        message_id: 0,
        length: total_len,
    };

    let mut packet = Vec::with_capacity(total_len as usize);
    packet.extend_from_slice(&header.to_bytes());
    packet.extend_from_slice(&chained);
    packet
}

/// Build an IKEv2 IKE_SA_INIT request with a COOKIE notification prepended.
///
/// RFC 7296 section 2.6: when the responder sends N(COOKIE), the initiator
/// retries IKE_SA_INIT with the cookie as the first payload, followed by the
/// original SA + KE + Nonce payloads.
#[must_use]
pub fn build_sa_init_request_with_cookie(initiator_spi: u64, cookie: &[u8], proposals: &[Ikev2Proposal], ke_dh_group: u16, ke_data: &[u8], nonce: &[u8]) -> Vec<u8> {
    let sa_body = sa::build_sa_body(proposals);

    let mut ke_body = Vec::with_capacity(4 + ke_data.len());
    ke_body.extend_from_slice(&ke_dh_group.to_be_bytes());
    ke_body.extend_from_slice(&[0, 0]);
    ke_body.extend_from_slice(ke_data);

    let cookie_notify = build_notify_body(Ikev2NotifyType::Cookie, cookie);

    let payloads: Vec<(u8, Vec<u8>)> = vec![(v2_types::NOTIFY, cookie_notify), (v2_types::SA, sa_body), (v2_types::KE, ke_body), (v2_types::NONCE, nonce.to_vec())];

    let payload_refs: Vec<(u8, &[u8])> = payloads.iter().map(|(t, b)| (*t, b.as_slice())).collect();
    let (first_type, chained) = payload::build_payload_chain(&payload_refs);

    let Ok(total_len) = u32::try_from(HEADER_LEN + chained.len()) else {
        return Vec::new();
    };

    let header = IkeHeader { initiator_spi, responder_spi: 0, next_payload: first_type, version: IkeVersion::V2, exchange_type: ExchangeType::IkeSaInit, flags: 0x08, message_id: 0, length: total_len };

    let mut packet = Vec::with_capacity(total_len as usize);
    packet.extend_from_slice(&header.to_bytes());
    packet.extend_from_slice(&chained);
    packet
}

/// Build a generic notify payload body (Protocol ID=0, SPI Size=0).
fn build_notify_body(notify_type: Ikev2NotifyType, data: &[u8]) -> Vec<u8> {
    let nt: u16 = notify_type.into();
    let mut body = Vec::with_capacity(4 + data.len());
    body.push(0); // Protocol ID = 0. RFC 7296 section 3.10.
    body.push(0); // SPI Size = 0.
    body.extend_from_slice(&nt.to_be_bytes());
    body.extend_from_slice(data);
    body
}

/// Build a NAT-D notify payload body. Delegates to [`build_notify_body`].
fn build_nat_d_notify(notify_type: Ikev2NotifyType, hash: &[u8]) -> Vec<u8> {
    build_notify_body(notify_type, hash)
}

/// Parsed IKEv2 IKE_SA_INIT response.
#[derive(Debug, Clone)]
pub struct Ikev2SaInitResponse {
    /// Parsed IKE header.
    pub header: IkeHeader,
    /// SA payload: the chosen proposal. Empty if this is a notification-only response.
    pub proposals: Vec<Ikev2Proposal>,
    /// KE payload: DH group (2 bytes) + public value.
    pub ke_dh_group: Option<u16>,
    /// KE payload: DH public value bytes.
    pub ke_data: Option<Vec<u8>>,
    /// Nonce payload data (responder nonce).
    pub nonce: Option<Vec<u8>>,
    /// Vendor ID payloads.
    pub vendor_ids: Vec<Vec<u8>>,
    /// Notification payloads: (notify_type_u16, data).
    pub notifications: Vec<(u16, Vec<u8>)>,
    /// Certificate Request payloads.
    pub cert_requests: Vec<Vec<u8>>,
}

impl Ikev2SaInitResponse {
    /// Parse from raw UDP datagram bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = IkeHeader::parse(data)?;
        let total = usize::try_from(header.length).ok()?;
        if total > data.len() {
            return None;
        }

        let payload_area = data.get(HEADER_LEN..total)?;
        let payloads = payload::iter_payloads(payload_area, header.next_payload);

        let mut response = Self { header, proposals: Vec::new(), ke_dh_group: None, ke_data: None, nonce: None, vendor_ids: Vec::new(), notifications: Vec::new(), cert_requests: Vec::new() };

        for (ptype, body) in payloads {
            match ptype {
                v2_types::SA => {
                    response.proposals = sa::parse_sa_body(&body);
                },
                // KE body: DH Group (2) + Reserved (2) + KE data. RFC 7296 section 3.4.
                v2_types::KE if body.len() >= 4 => {
                    let hdr: &[u8; 4] = body.get(..4).and_then(|s| s.try_into().ok()).unwrap_or(&[0; 4]);
                    response.ke_dh_group = Some(u16::from_be_bytes([hdr[0], hdr[1]]));
                    response.ke_data = Some(body.get(4..).unwrap_or_default().to_vec());
                },
                v2_types::NONCE => {
                    response.nonce = Some(body);
                },
                v2_types::VENDOR_ID => {
                    response.vendor_ids.push(body);
                },
                // Notify body: Protocol ID (1) + SPI Size (1) + Notify Type (2) + [SPI] + [Data].
                // RFC 7296 section 3.10.
                v2_types::NOTIFY if body.len() >= 4 => {
                    let hdr: &[u8; 4] = body.get(..4).and_then(|s| s.try_into().ok()).unwrap_or(&[0; 4]);
                    let spi_size = usize::from(hdr[1]);
                    let notify_type = u16::from_be_bytes([hdr[2], hdr[3]]);
                    let notify_data = body.get(4 + spi_size..).unwrap_or_default().to_vec();
                    response.notifications.push((notify_type, notify_data));
                },
                v2_types::CERT_REQ => {
                    response.cert_requests.push(body);
                },
                _ => {},
            }
        }

        Some(response)
    }

    /// Check for NO_PROPOSAL_CHOSEN notification.
    #[must_use]
    pub fn is_no_proposal_chosen(&self) -> bool {
        let code: u16 = Ikev2NotifyType::NoProposalChosen.into();
        self.notifications.iter().any(|(t, _)| *t == code)
    }

    /// Check for INVALID_KE_PAYLOAD notification. Returns the suggested DH group if present.
    #[must_use]
    pub fn invalid_ke_suggested_group(&self) -> Option<u16> {
        let code: u16 = Ikev2NotifyType::InvalidKePayload.into();
        self.notifications.iter().find_map(|(t, data)| {
            if *t == code {
                let bytes: &[u8; 2] = data.get(..2)?.try_into().ok()?;
                Some(u16::from_be_bytes(*bytes))
            } else {
                None
            }
        })
    }

    /// Check for COOKIE notification. Returns the cookie data if present.
    #[must_use]
    pub fn cookie(&self) -> Option<&[u8]> {
        let code: u16 = Ikev2NotifyType::Cookie.into();
        self.notifications.iter().find_map(|(t, data)| if *t == code && !data.is_empty() { Some(data.as_slice()) } else { None })
    }

    /// Whether IKEv2 fragmentation is supported (notify type 16430). RFC 7383.
    #[must_use]
    pub fn supports_fragmentation(&self) -> bool {
        let code: u16 = Ikev2NotifyType::Ikev2FragmentationSupported.into();
        self.notifications.iter().any(|(t, _)| *t == code)
    }

    /// Whether this is a notification-only response (no SA).
    #[must_use]
    pub fn is_notification_only(&self) -> bool {
        self.proposals.is_empty() && !self.notifications.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev1::model::DhGroup;
    use crate::ikev2::model::*;
    use crate::ikev2::sa::Ikev2Transform;

    fn sample_proposals() -> Vec<Ikev2Proposal> {
        vec![Ikev2Proposal::ike(
            1,
            vec![
                Ikev2Transform::encr(Ikev2EncryptionAlg::AesGcm16, Some(256)),
                Ikev2Transform::encr(Ikev2EncryptionAlg::AesCbc, Some(128)),
                Ikev2Transform::prf(Ikev2PrfAlg::HmacSha256),
                Ikev2Transform::integ(Ikev2IntegrityAlg::None),
                Ikev2Transform::integ(Ikev2IntegrityAlg::HmacSha256_128),
                Ikev2Transform::dh(DhGroup::Modp2048),
            ],
        )]
    }

    #[test]
    fn sa_init_request_header() {
        let spi = 0xDEAD_BEEF_CAFE_BABE;
        let ke = vec![0xAA; 256]; // group 14 = 2048-bit = 256 bytes
        let nonce = vec![0xBB; 32];

        let packet = build_sa_init_request(spi, &sample_proposals(), 14, &ke, &nonce, None);

        let hdr = IkeHeader::parse(&packet).expect("parse header");
        assert_eq!(hdr.initiator_spi, spi);
        assert_eq!(hdr.responder_spi, 0);
        assert_eq!(hdr.version, IkeVersion::V2);
        assert_eq!(hdr.exchange_type, ExchangeType::IkeSaInit);
        assert_eq!(hdr.flags, 0x08); // Initiator flag
        assert_eq!(hdr.message_id, 0);
        assert_eq!(hdr.length as usize, packet.len());
    }

    #[test]
    fn sa_init_has_sa_ke_nonce() {
        let packet = build_sa_init_request(0x0102_0304_0506_0708, &sample_proposals(), 14, &[0xAA; 256], &[0xBB; 32], None);

        let hdr = IkeHeader::parse(&packet).expect("parse header");
        let payload_area = &packet[HEADER_LEN..];
        let payloads = payload::iter_payloads(payload_area, hdr.next_payload);

        let types: Vec<u8> = payloads.iter().map(|(t, _)| *t).collect();
        assert!(types.contains(&v2_types::SA), "missing SA");
        assert!(types.contains(&v2_types::KE), "missing KE");
        assert!(types.contains(&v2_types::NONCE), "missing Nonce");
    }

    #[test]
    fn sa_init_with_nat_detection() {
        let src_hash = [0x11; 20]; // SHA-1 hash is 20 bytes
        let dst_hash = [0x22; 20];

        let packet = build_sa_init_request(0x0102_0304_0506_0708, &sample_proposals(), 14, &[0xAA; 256], &[0xBB; 32], Some((&src_hash, &dst_hash)));

        let hdr = IkeHeader::parse(&packet).expect("parse header");
        let payload_area = &packet[HEADER_LEN..];
        let payloads = payload::iter_payloads(payload_area, hdr.next_payload);

        let notify_count = payloads.iter().filter(|(t, _)| *t == v2_types::NOTIFY).count();
        assert_eq!(notify_count, 2, "expected 2 NAT-D notifies");
    }

    #[test]
    fn parse_own_sa_init_as_response() {
        let packet = build_sa_init_request(0xDEAD_BEEF_CAFE_BABE, &sample_proposals(), 14, &[0xAA; 256], &[0xBB; 32], None);

        let response = Ikev2SaInitResponse::parse(&packet).expect("parse response");
        assert_eq!(response.proposals.len(), 1);
        assert_eq!(response.proposals[0].transforms.len(), 6);
        assert_eq!(response.ke_dh_group, Some(14));
        assert!(response.ke_data.is_some());
        assert!(response.nonce.is_some());
        assert!(!response.is_no_proposal_chosen());
        assert!(response.cookie().is_none());
        assert!(response.invalid_ke_suggested_group().is_none());
    }

    #[test]
    fn sa_init_with_cookie_has_notify_first() {
        let cookie_data = vec![0xCC; 32];
        let packet = build_sa_init_request_with_cookie(0xDEAD_BEEF_CAFE_BABE, &cookie_data, &sample_proposals(), 14, &[0xAA; 256], &[0xBB; 32]);

        let hdr = IkeHeader::parse(&packet).expect("parse header");
        assert_eq!(hdr.next_payload, v2_types::NOTIFY, "first payload must be NOTIFY (cookie)");

        let payload_area = &packet[HEADER_LEN..];
        let payloads = payload::iter_payloads(payload_area, hdr.next_payload);
        assert_eq!(payloads.len(), 4, "NOTIFY + SA + KE + Nonce");
        assert_eq!(payloads[0].0, v2_types::NOTIFY);
        assert_eq!(payloads[1].0, v2_types::SA);
        assert_eq!(payloads[2].0, v2_types::KE);
        assert_eq!(payloads[3].0, v2_types::NONCE);
    }
}
