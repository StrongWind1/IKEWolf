//! IKEv2 SA payload construction and parsing.
//!
//! IKEv2 SA encoding differs from IKEv1: proposals contain typed transforms
//! (ENCR, PRF, INTEG, DH), each with an optional key-length attribute.
//! Same-type transforms within a proposal are OR (choice), different types
//! are AND (combination). RFC 7296 section 3.3.

use crate::attribute::{DataAttribute, v2_attr};
use crate::ikev1::model::DhGroup;
use crate::ikev2::model::{Ikev2EncryptionAlg, Ikev2IntegrityAlg, Ikev2PrfAlg, Ikev2TransformType};
use crate::payload::{PAYLOAD_HEADER_LEN, PayloadHeader};

/// A single IKEv2 transform: type + ID + optional key length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2Transform {
    /// Transform type (ENCR, PRF, INTEG, DH, ESN).
    pub transform_type: Ikev2TransformType,
    /// Transform ID (algorithm-specific). Interpretation depends on `transform_type`.
    pub transform_id: u16,
    /// Key length in bits (optional, for variable-length ciphers).
    pub key_length: Option<u16>,
}

impl Ikev2Transform {
    /// Create an encryption transform.
    #[must_use]
    pub fn encr(alg: Ikev2EncryptionAlg, key_length: Option<u16>) -> Self {
        Self { transform_type: Ikev2TransformType::Encryption, transform_id: alg.into(), key_length }
    }

    /// Create a PRF transform.
    #[must_use]
    pub fn prf(alg: Ikev2PrfAlg) -> Self {
        Self { transform_type: Ikev2TransformType::Prf, transform_id: alg.into(), key_length: None }
    }

    /// Create an integrity transform.
    #[must_use]
    pub fn integ(alg: Ikev2IntegrityAlg) -> Self {
        Self { transform_type: Ikev2TransformType::Integrity, transform_id: alg.into(), key_length: None }
    }

    /// Create a DH group transform.
    #[must_use]
    pub fn dh(group: DhGroup) -> Self {
        Self { transform_type: Ikev2TransformType::DhGroup, transform_id: group.into(), key_length: None }
    }

    /// Serialize the transform substructure body (after the 4-byte generic header).
    /// Layout: Last(1) + Reserved(1) + Length(2) + Type(1) + Reserved(1) + ID(2) + [Attrs].
    /// RFC 7296 section 3.3.2.
    fn body_bytes(self) -> Vec<u8> {
        let mut body = Vec::with_capacity(4);
        body.push(u8::from(self.transform_type));
        body.push(0); // Reserved. RFC 7296 section 3.3.2.
        body.extend_from_slice(&self.transform_id.to_be_bytes());
        if let Some(kl) = self.key_length {
            body.extend_from_slice(&DataAttribute::short(v2_attr::KEY_LENGTH, kl).to_bytes());
        }
        body
    }

    /// Parse from the body bytes of a transform substructure (after the generic header).
    #[must_use]
    fn from_body_bytes(body: &[u8]) -> Option<Self> {
        let hdr: &[u8; 4] = body.get(..4)?.try_into().ok()?;
        let transform_type = Ikev2TransformType::from(hdr[0]);
        let transform_id = u16::from_be_bytes([hdr[2], hdr[3]]);

        let mut key_length = None;
        if let Some(attr_area) = body.get(4..) {
            let attrs = DataAttribute::parse_all(attr_area);
            for attr in &attrs {
                if attr.attr_type() == v2_attr::KEY_LENGTH {
                    key_length = attr.as_short();
                }
            }
        }

        Some(Self { transform_type, transform_id, key_length })
    }
}

/// An IKEv2 proposal: a set of transforms that together define a crypto suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2Proposal {
    /// Proposal number (1-based).
    pub number: u8,
    /// Protocol ID: 1=IKE, 2=AH, 3=ESP. RFC 7296 section 3.3.1.
    pub protocol_id: u8,
    /// SPI (empty for initial IKE SA).
    pub spi: Vec<u8>,
    /// Transforms in this proposal.
    pub transforms: Vec<Ikev2Transform>,
}

impl core::fmt::Display for Ikev2Transform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.transform_type {
            Ikev2TransformType::Encryption => {
                let alg = Ikev2EncryptionAlg::from(self.transform_id);
                write!(f, "ENCR:{alg}")?;
            },
            Ikev2TransformType::Prf => {
                let alg = Ikev2PrfAlg::from(self.transform_id);
                write!(f, "PRF:{alg}")?;
            },
            Ikev2TransformType::Integrity => {
                let alg = Ikev2IntegrityAlg::from(self.transform_id);
                write!(f, "INTEG:{alg}")?;
            },
            Ikev2TransformType::DhGroup => {
                let group = DhGroup::from(self.transform_id);
                write!(f, "DH:{group}")?;
            },
            _ => write!(f, "{}:{}", self.transform_type, self.transform_id)?,
        }
        if let Some(kl) = self.key_length {
            write!(f, "-{kl}")?;
        }
        Ok(())
    }
}

impl Ikev2Proposal {
    /// Create an IKE SA proposal with the given transforms.
    #[must_use]
    pub fn ike(number: u8, transforms: Vec<Ikev2Transform>) -> Self {
        Self {
            number,
            protocol_id: 1, // IKE. RFC 7296 section 3.3.1.
            spi: Vec::new(),
            transforms,
        }
    }
}

/// Build the SA payload body (after the generic payload header) for IKEv2.
/// Contains one or more proposals, each containing transforms.
/// RFC 7296 section 3.3.
#[must_use]
pub fn build_sa_body(proposals: &[Ikev2Proposal]) -> Vec<u8> {
    let mut out = Vec::new();

    for (i, proposal) in proposals.iter().enumerate() {
        let is_last = i + 1 >= proposals.len();

        // Build transform substructures.
        let mut transform_bytes = Vec::new();
        for (ti, transform) in proposal.transforms.iter().enumerate() {
            let t_is_last = ti + 1 >= proposal.transforms.len();
            let t_body = transform.body_bytes();
            let t_total = PAYLOAD_HEADER_LEN + t_body.len();
            let Ok(t_len) = u16::try_from(t_total) else {
                continue;
            };

            // Transform substructure header. RFC 7296 section 3.3.2.
            let t_hdr = PayloadHeader {
                // Last Substruc: 0 = last, 3 = more. RFC 7296 section 3.3.2.
                next_payload: if t_is_last { 0 } else { 3 },
                flags: 0,
                length: t_len,
            };
            transform_bytes.extend_from_slice(&t_hdr.to_bytes());
            transform_bytes.extend_from_slice(&t_body);
        }

        // Proposal substructure body: Proposal# + ProtocolID + SPISize + NumTransforms + [SPI] + Transforms.
        let spi_size = proposal.spi.len();
        let mut prop_body = Vec::with_capacity(4 + spi_size + transform_bytes.len());
        prop_body.push(proposal.number);
        prop_body.push(proposal.protocol_id);
        let Ok(spi_len_u8) = u8::try_from(spi_size) else {
            continue;
        };
        prop_body.push(spi_len_u8);
        let Ok(num_transforms) = u8::try_from(proposal.transforms.len()) else {
            continue;
        };
        prop_body.push(num_transforms);
        prop_body.extend_from_slice(&proposal.spi);
        prop_body.extend_from_slice(&transform_bytes);

        let prop_total = PAYLOAD_HEADER_LEN + prop_body.len();
        let Ok(prop_len) = u16::try_from(prop_total) else {
            continue;
        };

        // Proposal substructure header. RFC 7296 section 3.3.1.
        let prop_hdr = PayloadHeader {
            // Last Substruc: 0 = last, 2 = more. RFC 7296 section 3.3.1.
            next_payload: if is_last { 0 } else { 2 },
            flags: 0,
            length: prop_len,
        };
        out.extend_from_slice(&prop_hdr.to_bytes());
        out.extend_from_slice(&prop_body);
    }

    out
}

/// Parse an IKEv2 SA payload body into proposals.
#[must_use]
pub fn parse_sa_body(mut body: &[u8]) -> Vec<Ikev2Proposal> {
    let mut proposals = Vec::new();

    while body.len() >= PAYLOAD_HEADER_LEN {
        let Some(prop_hdr) = PayloadHeader::parse(body) else {
            break;
        };
        let prop_total = usize::from(prop_hdr.length);
        if prop_total < PAYLOAD_HEADER_LEN + 4 || prop_total > body.len() {
            break;
        }

        let prop_body = body.get(PAYLOAD_HEADER_LEN..prop_total).unwrap_or_default();
        let prop_hdr_bytes: &[u8; 4] = match prop_body.get(..4).and_then(|s| s.try_into().ok()) {
            Some(h) => h,
            None => break,
        };

        let number = prop_hdr_bytes[0];
        let protocol_id = prop_hdr_bytes[1];
        let spi_size = usize::from(prop_hdr_bytes[2]);

        let spi_end = 4 + spi_size;
        if prop_body.len() < spi_end {
            break;
        }
        let spi = prop_body.get(4..spi_end).unwrap_or_default().to_vec();
        let transform_area = prop_body.get(spi_end..).unwrap_or_default();

        let transforms = parse_transforms(transform_area);

        proposals.push(Ikev2Proposal { number, protocol_id, spi, transforms });

        if prop_hdr.next_payload == 0 {
            break;
        }
        body = body.get(prop_total..).unwrap_or_default();
    }

    proposals
}

/// Parse transform substructures from the transform area of a proposal.
fn parse_transforms(mut data: &[u8]) -> Vec<Ikev2Transform> {
    let mut transforms = Vec::new();

    while data.len() >= PAYLOAD_HEADER_LEN {
        let Some(t_hdr) = PayloadHeader::parse(data) else {
            break;
        };
        let t_total = usize::from(t_hdr.length);
        if t_total < PAYLOAD_HEADER_LEN + 4 || t_total > data.len() {
            break;
        }

        let t_body = data.get(PAYLOAD_HEADER_LEN..t_total).unwrap_or_default();
        if let Some(transform) = Ikev2Transform::from_body_bytes(t_body) {
            transforms.push(transform);
        }

        if t_hdr.next_payload == 0 {
            break;
        }
        data = data.get(t_total..).unwrap_or_default();
    }

    transforms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::model::*;

    fn sample_proposal() -> Ikev2Proposal {
        Ikev2Proposal::ike(
            1,
            vec![
                Ikev2Transform::encr(Ikev2EncryptionAlg::AesGcm16, Some(256)),
                Ikev2Transform::encr(Ikev2EncryptionAlg::AesCbc, Some(128)),
                Ikev2Transform::prf(Ikev2PrfAlg::HmacSha256),
                Ikev2Transform::prf(Ikev2PrfAlg::HmacSha1),
                Ikev2Transform::integ(Ikev2IntegrityAlg::None),
                Ikev2Transform::integ(Ikev2IntegrityAlg::HmacSha256_128),
                Ikev2Transform::dh(DhGroup::Modp2048),
                Ikev2Transform::dh(DhGroup::Ecp256),
            ],
        )
    }

    #[test]
    fn sa_body_round_trip() {
        let proposals = vec![sample_proposal()];
        let sa_body = build_sa_body(&proposals);
        let parsed = parse_sa_body(&sa_body);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].number, 1);
        assert_eq!(parsed[0].protocol_id, 1); // IKE
        assert!(parsed[0].spi.is_empty());
        assert_eq!(parsed[0].transforms.len(), 8);

        // Verify first transform: AES-GCM-256.
        assert_eq!(parsed[0].transforms[0].transform_type, Ikev2TransformType::Encryption);
        assert_eq!(Ikev2EncryptionAlg::from(parsed[0].transforms[0].transform_id), Ikev2EncryptionAlg::AesGcm16);
        assert_eq!(parsed[0].transforms[0].key_length, Some(256));

        // Verify DH group transform.
        assert_eq!(parsed[0].transforms[6].transform_type, Ikev2TransformType::DhGroup);
        assert_eq!(DhGroup::from(parsed[0].transforms[6].transform_id), DhGroup::Modp2048);
    }

    #[test]
    fn multiple_proposals() {
        let proposals = vec![
            Ikev2Proposal::ike(1, vec![Ikev2Transform::encr(Ikev2EncryptionAlg::AesGcm16, Some(256)), Ikev2Transform::prf(Ikev2PrfAlg::HmacSha256), Ikev2Transform::integ(Ikev2IntegrityAlg::None), Ikev2Transform::dh(DhGroup::Modp2048)]),
            Ikev2Proposal::ike(2, vec![Ikev2Transform::encr(Ikev2EncryptionAlg::AesCbc, Some(128)), Ikev2Transform::prf(Ikev2PrfAlg::HmacSha1), Ikev2Transform::integ(Ikev2IntegrityAlg::HmacSha1_96), Ikev2Transform::dh(DhGroup::Modp1024)]),
        ];

        let sa_body = build_sa_body(&proposals);
        let parsed = parse_sa_body(&sa_body);

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].number, 1);
        assert_eq!(parsed[0].transforms.len(), 4);
        assert_eq!(parsed[1].number, 2);
        assert_eq!(parsed[1].transforms.len(), 4);
    }

    #[test]
    fn empty_proposals() {
        let sa_body = build_sa_body(&[]);
        assert!(sa_body.is_empty());
        assert!(parse_sa_body(&sa_body).is_empty());
    }
}
