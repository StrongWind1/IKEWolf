//! IKEv1 SA, Proposal, and Transform payload construction and parsing.
//!
//! An IKEv1 Phase 1 SA payload contains:
//!   SA header (DOI + Situation) → one Proposal → N Transforms
//!
//! Each Transform carries attributes (encryption, hash, auth, DH group,
//! lifetime, key length) encoded as data attributes (TV/TLV).
//!
//! Wire layout per RFC 2408 section 3.4-3.6 and RFC 2407 (IPsec DOI).

use crate::attribute::{DataAttribute, v1_class};
use crate::ikev1::model::{DhGroup, Ikev1AuthMethod, Ikev1EncryptionAlg, Ikev1HashAlg, Ikev1ProtocolId, LifeType};
use crate::payload::{PAYLOAD_HEADER_LEN, PayloadHeader, v1_types};

/// IPsec DOI value. RFC 2407 section 1. Always 1 for IPsec.
const IPSEC_DOI: u32 = 1;

/// Situation: SIT_IDENTITY_ONLY. RFC 2407 section 4.2. Almost always 0x01.
const SIT_IDENTITY_ONLY: u32 = 1;

/// Transform-ID for IKE Phase 1: KEY_IKE = 1. RFC 2409 Appendix A.
const TRANSFORM_ID_KEY_IKE: u8 = 1;

/// A single IKEv1 Phase 1 transform offer -- one combination of
/// encryption + hash + auth + DH group + optional key length + lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev1Transform {
    /// Encryption algorithm. RFC 2409 Appendix A, attribute class 1.
    pub encryption: Ikev1EncryptionAlg,
    /// Key length in bits (for variable-length ciphers like AES). `None` for fixed-length.
    pub key_length: Option<u16>,
    /// Hash algorithm. RFC 2409 Appendix A, attribute class 2.
    pub hash: Ikev1HashAlg,
    /// Authentication method. RFC 2409 Appendix A, attribute class 3.
    pub auth_method: Ikev1AuthMethod,
    /// DH group. RFC 2409 Appendix A, attribute class 4.
    pub dh_group: DhGroup,
    /// SA lifetime in seconds. `None` omits the attribute.
    pub lifetime_secs: Option<u32>,
}

impl Ikev1Transform {
    /// Serialize to the body of a Transform payload (after the 4-byte generic
    /// header and the 4-byte transform-specific header). Returns the attribute bytes.
    #[must_use]
    pub fn to_attribute_bytes(self) -> Vec<u8> {
        let mut attrs: Vec<DataAttribute> =
            vec![DataAttribute::short(v1_class::ENCRYPTION, self.encryption.into()), DataAttribute::short(v1_class::HASH, self.hash.into()), DataAttribute::short(v1_class::AUTH_METHOD, self.auth_method.into()), DataAttribute::short(v1_class::GROUP_DESC, self.dh_group.into())];

        if let Some(key_len) = self.key_length {
            attrs.push(DataAttribute::short(v1_class::KEY_LENGTH, key_len));
        }

        if let Some(secs) = self.lifetime_secs {
            attrs.push(DataAttribute::short(v1_class::LIFE_TYPE, LifeType::Seconds.into()));
            let secs_bytes = secs.to_be_bytes().to_vec();
            attrs.push(DataAttribute::long(v1_class::LIFE_DURATION, secs_bytes));
        }

        DataAttribute::serialize_all(&attrs)
    }

    /// Parse from the attribute bytes of a Transform payload body (after the
    /// 4-byte transform-specific header). Best-effort: missing attributes
    /// produce default/zero values.
    #[must_use]
    pub fn from_attributes(attrs: &[DataAttribute]) -> Self {
        let mut encryption = Ikev1EncryptionAlg::Other(0);
        let mut key_length = None;
        let mut hash = Ikev1HashAlg::Other(0);
        let mut auth_method = Ikev1AuthMethod::Other(0);
        let mut dh_group = DhGroup::Other(0);
        let mut lifetime_secs = None;

        for attr in attrs {
            match attr.attr_type() {
                v1_class::ENCRYPTION => {
                    if let Some(v) = attr.as_short() {
                        encryption = Ikev1EncryptionAlg::from(v);
                    }
                },
                v1_class::KEY_LENGTH => {
                    if let Some(v) = attr.as_short() {
                        key_length = Some(v);
                    }
                },
                v1_class::HASH => {
                    if let Some(v) = attr.as_short() {
                        hash = Ikev1HashAlg::from(v);
                    }
                },
                v1_class::AUTH_METHOD => {
                    if let Some(v) = attr.as_short() {
                        auth_method = Ikev1AuthMethod::from(v);
                    }
                },
                v1_class::GROUP_DESC => {
                    if let Some(v) = attr.as_short() {
                        dh_group = DhGroup::from(v);
                    }
                },
                v1_class::LIFE_DURATION => {
                    if let DataAttribute::Long { value, .. } = attr {
                        lifetime_secs = parse_lifetime_secs(value);
                    }
                },
                _ => {}, // ignore unknown attributes
            }
        }

        Self { encryption, key_length, hash, auth_method, dh_group, lifetime_secs }
    }
}

/// Parse a big-endian lifetime value (2 or 4 bytes) as seconds.
fn parse_lifetime_secs(bytes: &[u8]) -> Option<u32> {
    if let Ok(b) = <&[u8; 4]>::try_from(bytes) {
        return Some(u32::from_be_bytes(*b));
    }
    let b: &[u8; 2] = bytes.try_into().ok()?;
    Some(u32::from(u16::from_be_bytes(*b)))
}

/// Build a complete IKEv1 Phase 1 SA payload body (everything after the
/// generic payload header).
///
/// Layout: DOI (4) + Situation (4) + Proposal payload + Transform payloads.
/// The generic payload header is NOT included -- the caller adds it.
#[must_use]
pub fn build_sa_body(transforms: &[Ikev1Transform]) -> Vec<u8> {
    let transform_payloads = build_transform_payloads(transforms);
    let num_transforms = u8::try_from(transforms.len()).unwrap_or(u8::MAX);
    let proposal_body = build_proposal_body(num_transforms, &transform_payloads);

    let proposal_total_len = u16::try_from(PAYLOAD_HEADER_LEN + proposal_body.len()).unwrap_or(u16::MAX);
    let proposal_hdr = PayloadHeader {
        next_payload: 0, // last proposal
        flags: 0,
        length: proposal_total_len,
    };

    let mut body = Vec::new();
    // DOI. RFC 2407 section 1.
    body.extend_from_slice(&IPSEC_DOI.to_be_bytes());
    // Situation. RFC 2407 section 4.2.
    body.extend_from_slice(&SIT_IDENTITY_ONLY.to_be_bytes());
    // Proposal payload (header + body).
    body.extend_from_slice(&proposal_hdr.to_bytes());
    body.extend_from_slice(&proposal_body);

    body
}

/// Build the Proposal payload body: proposal header + transform payloads.
fn build_proposal_body(num_transforms: u8, transform_payloads_bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + transform_payloads_bytes.len());
    // Proposal # (1). RFC 2408 section 3.5.
    body.push(1);
    // Protocol-ID: ISAKMP (1) for Phase 1. RFC 2407 section 4.4.1.
    body.push(u8::from(Ikev1ProtocolId::Isakmp));
    // SPI Size: 0 for Phase 1 (ISAKMP SA has no SPI in the proposal).
    body.push(0);
    // Number of Transforms.
    body.push(num_transforms);
    // No SPI bytes (SPI size = 0).
    // Transform payloads follow.
    body.extend_from_slice(transform_payloads_bytes);
    body
}

/// Build all Transform payloads concatenated, with correct next-payload chaining.
fn build_transform_payloads(transforms: &[Ikev1Transform]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, transform) in transforms.iter().enumerate() {
        let attr_bytes = transform.to_attribute_bytes();
        let is_last = i + 1 >= transforms.len();

        // Transform-specific header (4 bytes): Transform#, Transform-ID, Reserved(2).
        // RFC 2408 section 3.6.
        let transform_num = u8::try_from(i + 1).unwrap_or(u8::MAX);
        let transform_specific: [u8; 4] = [
            transform_num, // Transform # (1-based). RFC 2408 section 3.6.
            TRANSFORM_ID_KEY_IKE,
            0, // Reserved
            0, // Reserved
        ];

        let body_len = transform_specific.len() + attr_bytes.len();
        let total_len = u16::try_from(PAYLOAD_HEADER_LEN + body_len).unwrap_or(u16::MAX);

        let hdr = PayloadHeader {
            // Next payload: 3 (Transform) if more follow, 0 if last. RFC 2408 section 3.6.
            next_payload: if is_last { 0 } else { v1_types::TRANSFORM },
            flags: 0,
            length: total_len,
        };

        out.extend_from_slice(&hdr.to_bytes());
        out.extend_from_slice(&transform_specific);
        out.extend_from_slice(&attr_bytes);
    }
    out
}

/// Parse an IKEv1 SA payload body (after the generic payload header).
/// Returns the list of transforms the server chose/offered.
///
/// Tolerant of malformed data: returns what was successfully parsed.
#[must_use]
pub fn parse_sa_body(body: &[u8]) -> Vec<Ikev1Transform> {
    // DOI (4 bytes) + Situation (4 bytes) = 8 bytes before proposals.
    if body.len() < 8 {
        return Vec::new();
    }
    let proposal_data = body.get(8..).unwrap_or_default();
    parse_proposal_transforms(proposal_data)
}

/// Parse transforms from the proposal payload area (after DOI+Situation).
fn parse_proposal_transforms(mut data: &[u8]) -> Vec<Ikev1Transform> {
    let mut transforms = Vec::new();

    while data.len() >= PAYLOAD_HEADER_LEN {
        let Some(prop_hdr) = PayloadHeader::parse(data) else {
            break;
        };
        let prop_total = usize::from(prop_hdr.length);
        if prop_total < PAYLOAD_HEADER_LEN + 4 || prop_total > data.len() {
            break;
        }
        let prop_body = data.get(PAYLOAD_HEADER_LEN..prop_total).unwrap_or_default();
        if prop_body.len() < 4 {
            break;
        }
        let spi_size = usize::from(*prop_body.get(2).unwrap_or(&0));
        let transform_area = prop_body.get(4 + spi_size..).unwrap_or_default();

        let mut tdata = transform_area;
        while tdata.len() >= PAYLOAD_HEADER_LEN {
            let Some(t_hdr) = PayloadHeader::parse(tdata) else {
                break;
            };
            let t_total = usize::from(t_hdr.length);
            if t_total < PAYLOAD_HEADER_LEN + 4 || t_total > tdata.len() {
                break;
            }
            let attr_area = tdata.get(PAYLOAD_HEADER_LEN + 4..t_total).unwrap_or_default();
            let attrs = DataAttribute::parse_all(attr_area);
            transforms.push(Ikev1Transform::from_attributes(&attrs));

            tdata = tdata.get(t_total..).unwrap_or_default();
        }

        // Move to next proposal (or stop if this was the last).
        if prop_hdr.next_payload == 0 {
            break;
        }
        data = data.get(prop_total..).unwrap_or_default();
    }

    transforms
}

impl core::fmt::Display for Ikev1Transform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.encryption)?;
        if let Some(kl) = self.key_length {
            write!(f, "-{kl}")?;
        }
        write!(f, " / {} / {} / {}", self.hash, self.auth_method, self.dh_group)?;
        if let Some(lt) = self.lifetime_secs {
            write!(f, " ({lt}s)")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_transform() -> Ikev1Transform {
        Ikev1Transform { encryption: Ikev1EncryptionAlg::AesCbc, key_length: Some(256), hash: Ikev1HashAlg::Sha256, auth_method: Ikev1AuthMethod::PreSharedKey, dh_group: DhGroup::Modp2048, lifetime_secs: Some(28800) }
    }

    #[test]
    fn transform_attribute_round_trip() {
        let t = sample_transform();
        let attr_bytes = t.to_attribute_bytes();
        let attrs = DataAttribute::parse_all(&attr_bytes);
        let parsed = Ikev1Transform::from_attributes(&attrs);
        assert_eq!(t, parsed);
    }

    #[test]
    fn sa_body_build_and_parse() {
        let transforms = vec![
            Ikev1Transform { encryption: Ikev1EncryptionAlg::AesCbc, key_length: Some(256), hash: Ikev1HashAlg::Sha256, auth_method: Ikev1AuthMethod::PreSharedKey, dh_group: DhGroup::Modp2048, lifetime_secs: Some(28800) },
            Ikev1Transform { encryption: Ikev1EncryptionAlg::TripleDesCbc, key_length: None, hash: Ikev1HashAlg::Sha1, auth_method: Ikev1AuthMethod::PreSharedKey, dh_group: DhGroup::Modp1024, lifetime_secs: Some(28800) },
        ];

        let sa_body = build_sa_body(&transforms);

        // Verify DOI and Situation.
        assert_eq!(&sa_body[0..4], &IPSEC_DOI.to_be_bytes());
        assert_eq!(&sa_body[4..8], &SIT_IDENTITY_ONLY.to_be_bytes());

        // Parse back and verify.
        let parsed = parse_sa_body(&sa_body);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], transforms[0]);
        assert_eq!(parsed[1], transforms[1]);
    }

    #[test]
    fn single_transform_round_trip() {
        let transforms = vec![sample_transform()];
        let sa_body = build_sa_body(&transforms);
        let parsed = parse_sa_body(&sa_body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], transforms[0]);
    }

    #[test]
    fn empty_transforms() {
        let sa_body = build_sa_body(&[]);
        let parsed = parse_sa_body(&sa_body);
        assert!(parsed.is_empty());
    }

    #[test]
    fn transform_display() {
        let t = sample_transform();
        let s = t.to_string();
        assert!(s.contains("AesCbc"), "should contain cipher: {s}");
        assert!(s.contains("256"), "should contain key length: {s}");
        assert!(s.contains("Sha256"), "should contain hash: {s}");
        assert!(s.contains("28800"), "should contain lifetime: {s}");
    }

    #[test]
    fn parse_truncated_sa_body() {
        // Less than DOI + Situation = 8 bytes.
        assert!(parse_sa_body(&[0; 7]).is_empty());
        // DOI + Situation but no proposals.
        assert!(parse_sa_body(&[0; 8]).is_empty());
    }
}
