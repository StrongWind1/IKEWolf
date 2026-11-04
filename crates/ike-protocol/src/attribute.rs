//! IKE data attribute encoding -- shared by IKEv1 and IKEv2 transform payloads.
//!
//! RFC 2408 section 3.3 (IKEv1) / RFC 7296 section 3.3.5 (IKEv2). The top bit
//! of the type field selects between two encodings:
//!
//! **Type/Value (TV, AF=1)** -- 4 bytes, for attributes that fit in a `u16`:
//! ```text
//! |1| Attribute Type (15 bits) | Value (u16) |
//! ```
//!
//! **Type/Length/Value (TLV, AF=0)** -- 4+N bytes, for variable-length:
//! ```text
//! |0| Attribute Type (15 bits) | Length (u16) | Value (N bytes) |
//! ```

/// Parsed data attribute.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DataAttribute {
    /// Basic (TV) attribute: type + 2-byte value. AF bit = 1.
    Short {
        /// Attribute type (15-bit, AF bit stripped).
        attr_type: u16,
        /// Inline 2-byte value.
        value: u16,
    },
    /// Variable-length (TLV) attribute: type + length + value. AF bit = 0.
    Long {
        /// Attribute type (15-bit, AF bit stripped).
        attr_type: u16,
        /// Variable-length value.
        value: Vec<u8>,
    },
}

impl DataAttribute {
    /// Convenience: create a short (TV) attribute.
    #[must_use]
    pub fn short(attr_type: u16, value: u16) -> Self {
        Self::Short { attr_type, value }
    }

    /// Convenience: create a long (TLV) attribute.
    #[must_use]
    pub fn long(attr_type: u16, value: Vec<u8>) -> Self {
        Self::Long { attr_type, value }
    }

    /// The attribute type (15-bit, AF bit stripped).
    #[must_use]
    pub fn attr_type(&self) -> u16 {
        match self {
            Self::Short { attr_type, .. } | Self::Long { attr_type, .. } => *attr_type,
        }
    }

    /// Get the value as a `u16` if this is a short (TV) attribute.
    #[must_use]
    pub fn as_short(&self) -> Option<u16> {
        match self {
            Self::Short { value, .. } => Some(*value),
            Self::Long { .. } => None,
        }
    }

    /// Total serialized length in bytes (including the 4-byte header).
    #[must_use]
    pub fn wire_len(&self) -> usize {
        match self {
            Self::Short { .. } => 4,
            Self::Long { value, .. } => 4 + value.len(),
        }
    }

    /// Serialize to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_len());
        match self {
            Self::Short { attr_type, value } => {
                let type_with_af = attr_type | 0x8000;
                buf.extend_from_slice(&type_with_af.to_be_bytes());
                buf.extend_from_slice(&value.to_be_bytes());
            },
            Self::Long { attr_type, value } => {
                buf.extend_from_slice(&attr_type.to_be_bytes());
                // Value length is capped at u16::MAX by construction; IKE attributes
                // never exceed a few hundred bytes (DH primes are the largest at 1024).
                let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(value);
            },
        }
        buf
    }

    /// Parse one data attribute from a buffer. Returns the attribute and the
    /// number of bytes consumed, or `None` if the buffer is too short.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        let b: &[u8; 4] = buf.get(..4)?.try_into().ok()?;
        let type_field = u16::from_be_bytes([b[0], b[1]]);
        let af = type_field & 0x8000 != 0;
        let attr_type = type_field & 0x7FFF;

        if af {
            let value = u16::from_be_bytes([b[2], b[3]]);
            Some((Self::Short { attr_type, value }, 4))
        } else {
            let length = usize::from(u16::from_be_bytes([b[2], b[3]]));
            let total = 4 + length;
            let value_slice = buf.get(4..total)?;
            Some((Self::Long { attr_type, value: value_slice.to_vec() }, total))
        }
    }

    /// Parse all data attributes from a buffer (e.g., the body of a
    /// Transform payload after the fixed fields).
    #[must_use]
    pub fn parse_all(mut buf: &[u8]) -> Vec<Self> {
        let mut attrs = Vec::new();
        while !buf.is_empty() {
            let Some((attr, consumed)) = Self::parse(buf) else {
                break;
            };
            attrs.push(attr);
            buf = buf.get(consumed..).unwrap_or_default();
        }
        attrs
    }

    /// Serialize a list of attributes to bytes.
    #[must_use]
    pub fn serialize_all(attrs: &[Self]) -> Vec<u8> {
        let total: usize = attrs.iter().map(Self::wire_len).sum();
        let mut buf = Vec::with_capacity(total);
        for attr in attrs {
            buf.extend_from_slice(&attr.to_bytes());
        }
        buf
    }
}

/// IKEv1 Phase 1 attribute classes. RFC 2409 Appendix A.
pub mod v1_class {
    /// Encryption Algorithm. RFC 2409 Appendix A.
    pub const ENCRYPTION: u16 = 1;
    /// Hash Algorithm. RFC 2409 Appendix A.
    pub const HASH: u16 = 2;
    /// Authentication Method. RFC 2409 Appendix A.
    pub const AUTH_METHOD: u16 = 3;
    /// Group Description (DH group). RFC 2409 Appendix A.
    pub const GROUP_DESC: u16 = 4;
    /// Group Type. RFC 2409 Appendix A.
    pub const GROUP_TYPE: u16 = 5;
    /// Group Prime/Irreducible Polynomial. RFC 2409 Appendix A.
    pub const GROUP_PRIME: u16 = 6;
    /// Group Generator One. RFC 2409 Appendix A.
    pub const GROUP_GENERATOR_ONE: u16 = 7;
    /// Group Generator Two. RFC 2409 Appendix A.
    pub const GROUP_GENERATOR_TWO: u16 = 8;
    /// Group Curve A. RFC 2409 Appendix A.
    pub const GROUP_CURVE_A: u16 = 9;
    /// Group Curve B. RFC 2409 Appendix A.
    pub const GROUP_CURVE_B: u16 = 10;
    /// Life Type. RFC 2409 Appendix A.
    pub const LIFE_TYPE: u16 = 11;
    /// Life Duration. RFC 2409 Appendix A.
    pub const LIFE_DURATION: u16 = 12;
    /// PRF. RFC 2409 Appendix A.
    pub const PRF: u16 = 13;
    /// Key Length (in bits). RFC 2409 Appendix A.
    pub const KEY_LENGTH: u16 = 14;
    /// Field Size. RFC 2409 Appendix A.
    pub const FIELD_SIZE: u16 = 15;
    /// Group Order. RFC 2409 Appendix A.
    pub const GROUP_ORDER: u16 = 16;
}

/// IKEv2 transform attribute types. RFC 7296 section 3.3.5.
pub mod v2_attr {
    /// Key Length (in bits). The only transform attribute RFC 7296 defines.
    pub const KEY_LENGTH: u16 = 14;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_attribute_round_trip() {
        let attr = DataAttribute::short(v1_class::ENCRYPTION, 7);
        let bytes = attr.to_bytes();
        assert_eq!(bytes, [0x80, 0x01, 0x00, 0x07]);

        let (parsed, consumed) = DataAttribute::parse(&bytes).expect("parse");
        assert_eq!(consumed, 4);
        assert_eq!(parsed, attr);
    }

    #[test]
    fn long_attribute_round_trip() {
        let attr = DataAttribute::long(v1_class::LIFE_DURATION, vec![0x00, 0x00, 0x70, 0x80]);
        let bytes = attr.to_bytes();
        assert_eq!(bytes, [0x00, 0x0C, 0x00, 0x04, 0x00, 0x00, 0x70, 0x80]);

        let (parsed, consumed) = DataAttribute::parse(&bytes).expect("parse");
        assert_eq!(consumed, 8);
        assert_eq!(parsed, attr);
    }

    #[test]
    fn parse_all_mixed() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&DataAttribute::short(v1_class::ENCRYPTION, 7).to_bytes());
        buf.extend_from_slice(&DataAttribute::short(v1_class::KEY_LENGTH, 256).to_bytes());
        buf.extend_from_slice(&DataAttribute::short(v1_class::LIFE_TYPE, 1).to_bytes());
        buf.extend_from_slice(&DataAttribute::long(v1_class::LIFE_DURATION, vec![0x00, 0x00, 0x70, 0x80]).to_bytes());

        let attrs = DataAttribute::parse_all(&buf);
        assert_eq!(attrs.len(), 4);
        assert_eq!(attrs[0].as_short(), Some(7));
        assert_eq!(attrs[1].as_short(), Some(256));
        assert_eq!(attrs[2].as_short(), Some(1));
        assert_eq!(attrs[3].attr_type(), v1_class::LIFE_DURATION);
    }

    #[test]
    fn serialize_all_matches_manual() {
        let attrs = vec![DataAttribute::short(v1_class::ENCRYPTION, 7), DataAttribute::short(v1_class::HASH, 2)];
        let serialized = DataAttribute::serialize_all(&attrs);
        assert_eq!(serialized.len(), 8);
        assert_eq!(&serialized[0..4], &[0x80, 0x01, 0x00, 0x07]);
        assert_eq!(&serialized[4..8], &[0x80, 0x02, 0x00, 0x02]);
    }

    #[test]
    fn empty_buffer_parse() {
        assert!(DataAttribute::parse(&[]).is_none());
        assert!(DataAttribute::parse_all(&[]).is_empty());
    }
}
