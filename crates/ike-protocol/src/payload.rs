//! Generic payload header -- 4 bytes, prefixes every IKE payload.
//!
//! RFC 2408 section 3.2 (IKEv1) / RFC 7296 section 3.2 (IKEv2). The two
//! versions interpret the reserved/flags byte differently, but the layout
//! is identical:
//!
//! ```text
//! Offset  Size  Field
//! 0       1     Next Payload (0 = last in chain)
//! 1       1     Flags (IKEv2: bit 7 = Critical) / Reserved (IKEv1: must be 0)
//! 2       2     Payload Length (includes this 4-byte header, big-endian)
//! ```

/// Fixed size of the generic payload header.
pub const PAYLOAD_HEADER_LEN: usize = 4;

/// Parsed generic payload header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadHeader {
    /// Type of the next payload in the chain. 0 means this is the last.
    pub next_payload: u8,
    /// Flags byte. IKEv2: bit 7 = Critical (responder MUST reject if
    /// unrecognised). IKEv1: reserved, must be zero.
    pub flags: u8,
    /// Total length of this payload including this 4-byte header.
    pub length: u16,
}

impl PayloadHeader {
    /// Parse from a buffer. Returns `None` if shorter than 4 bytes.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b: &[u8; PAYLOAD_HEADER_LEN] = buf.get(..PAYLOAD_HEADER_LEN)?.try_into().ok()?;
        Some(Self { next_payload: b[0], flags: b[1], length: u16::from_be_bytes([b[2], b[3]]) })
    }

    /// Serialize to 4 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; PAYLOAD_HEADER_LEN] {
        let [l0, l1] = self.length.to_be_bytes();
        [self.next_payload, self.flags, l0, l1]
    }

    /// The body length (payload length minus the 4-byte header).
    #[must_use]
    pub fn body_len(self) -> usize {
        usize::from(self.length.saturating_sub(4))
    }

    /// Whether the IKEv2 Critical bit (bit 7) is set. RFC 7296 section 3.2.
    #[must_use]
    pub fn is_critical(self) -> bool {
        self.flags & 0x80 != 0
    }
}

/// IKEv1 payload types. RFC 2408 section 3.1.
pub mod v1_types {
    /// No Next Payload (end of chain).
    pub const NONE: u8 = 0;
    /// Security Association. RFC 2408 section 3.4.
    pub const SA: u8 = 1;
    /// Proposal. RFC 2408 section 3.5.
    pub const PROPOSAL: u8 = 2;
    /// Transform. RFC 2408 section 3.6.
    pub const TRANSFORM: u8 = 3;
    /// Key Exchange. RFC 2408 section 3.7.
    pub const KE: u8 = 4;
    /// Identification. RFC 2408 section 3.8.
    pub const ID: u8 = 5;
    /// Certificate. RFC 2408 section 3.9.
    pub const CERT: u8 = 6;
    /// Certificate Request. RFC 2408 section 3.10.
    pub const CERT_REQ: u8 = 7;
    /// Hash. RFC 2408 section 3.11. Carries HASH_R in Aggressive Mode.
    pub const HASH: u8 = 8;
    /// Signature. RFC 2408 section 3.12.
    pub const SIG: u8 = 9;
    /// Nonce. RFC 2408 section 3.13.
    pub const NONCE: u8 = 10;
    /// Notification. RFC 2408 section 3.14.
    pub const NOTIFICATION: u8 = 11;
    /// Delete. RFC 2408 section 3.15.
    pub const DELETE: u8 = 12;
    /// Vendor ID. RFC 2408 section 3.16.
    pub const VENDOR_ID: u8 = 13;
    /// SA KEK Payload. RFC 3547 / RFC 6407 (GDOI).
    pub const SA_KEK: u8 = 15;
    /// SA TEK Payload. RFC 3547 / RFC 6407 (GDOI).
    pub const SA_TEK: u8 = 16;
    /// Key Download. RFC 3547 (GDOI).
    pub const KEY_DOWNLOAD: u8 = 17;
    /// Sequence Number. RFC 3547 (GDOI).
    pub const SEQUENCE_NUMBER: u8 = 18;
    /// Proof of Possession. RFC 3547 (GDOI).
    pub const PROOF_OF_POSSESSION: u8 = 19;
    /// NAT-Discovery (RFC 3947). Final RFC value.
    pub const NAT_D_RFC: u8 = 20;
    /// NAT-Original Address (RFC 3947). Final RFC value.
    pub const NAT_OA_RFC: u8 = 21;
    /// Group Associated Policy. RFC 6407 (GDOI).
    pub const GAP: u8 = 22;
    /// NAT-Discovery. Draft value, widely deployed. RFC 3947 section 3.2.
    pub const NAT_D: u8 = 130;
    /// NAT-Original Address. Draft value, widely deployed. RFC 3947 section 3.3.
    pub const NAT_OA: u8 = 131;
}

/// IKEv2 payload types. RFC 7296 section 3.2.
pub mod v2_types {
    /// No Next Payload.
    pub const NONE: u8 = 0;
    /// Security Association. RFC 7296 section 3.3.
    pub const SA: u8 = 33;
    /// Key Exchange. RFC 7296 section 3.4.
    pub const KE: u8 = 34;
    /// Identification - Initiator. RFC 7296 section 3.5.
    pub const ID_I: u8 = 35;
    /// Identification - Responder. RFC 7296 section 3.5.
    pub const ID_R: u8 = 36;
    /// Certificate. RFC 7296 section 3.6.
    pub const CERT: u8 = 37;
    /// Certificate Request. RFC 7296 section 3.7.
    pub const CERT_REQ: u8 = 38;
    /// Authentication. RFC 7296 section 3.8.
    pub const AUTH: u8 = 39;
    /// Nonce. RFC 7296 section 3.9.
    pub const NONCE: u8 = 40;
    /// Notify. RFC 7296 section 3.10.
    pub const NOTIFY: u8 = 41;
    /// Delete. RFC 7296 section 3.11.
    pub const DELETE: u8 = 42;
    /// Vendor ID. RFC 7296 section 3.12.
    pub const VENDOR_ID: u8 = 43;
    /// Traffic Selector - Initiator. RFC 7296 section 3.13.
    pub const TS_I: u8 = 44;
    /// Traffic Selector - Responder. RFC 7296 section 3.13.
    pub const TS_R: u8 = 45;
    /// Encrypted and Authenticated (SK). RFC 7296 section 3.14.
    pub const ENCRYPTED: u8 = 46;
    /// Configuration. RFC 7296 section 3.15.
    pub const CONFIGURATION: u8 = 47;
    /// EAP. RFC 7296 section 3.16.
    pub const EAP: u8 = 48;
    /// Generic Secure Password Method. RFC 6467.
    pub const GSPM: u8 = 49;
    /// Group Identification. RFC 9838.
    pub const ID_G: u8 = 50;
    /// Group Security Association. RFC 9838.
    pub const GSA: u8 = 51;
    /// Key Download (IKEv2 GDOI). RFC 9838.
    pub const KD: u8 = 52;
    /// Encrypted and Authenticated Fragment. RFC 7383.
    pub const SKF: u8 = 53;
    /// Puzzle Solution. RFC 8019.
    pub const PS: u8 = 54;
}

/// Walk the payload chain in a parsed IKE message body (after the 28-byte
/// header). Yields `(payload_type, body_slice)` for each payload.
///
/// Stops at next_payload == 0 (last) or when the buffer is exhausted.
/// Malformed payloads (length < 4, length exceeding remaining buffer) cause
/// early termination -- the caller gets what was successfully parsed.
#[must_use]
pub fn iter_payloads(mut buf: &[u8], first_payload_type: u8) -> Vec<(u8, Vec<u8>)> {
    let mut result = Vec::new();
    let mut current_type = first_payload_type;

    while current_type != 0 && buf.len() >= PAYLOAD_HEADER_LEN {
        let Some(hdr) = PayloadHeader::parse(buf) else {
            break;
        };
        let total_len = usize::from(hdr.length);
        if total_len < PAYLOAD_HEADER_LEN || total_len > buf.len() {
            break;
        }
        let body = buf.get(PAYLOAD_HEADER_LEN..total_len).unwrap_or_default();
        result.push((current_type, body.to_vec()));
        current_type = hdr.next_payload;
        buf = buf.get(total_len..).unwrap_or_default();
    }

    result
}

/// Build a payload chain: given a list of `(payload_type, body_bytes)`,
/// serialize them with correct next-payload chaining and length fields.
///
/// Returns the concatenated payload bytes and the `next_payload` value for
/// the ISAKMP header (the type of the first payload).
#[must_use]
pub fn build_payload_chain(payloads: &[(u8, &[u8])]) -> (u8, Vec<u8>) {
    let Some(first) = payloads.first() else {
        return (0, Vec::new());
    };

    let first_type = first.0;
    let mut out = Vec::new();

    for (i, (_, body)) in payloads.iter().enumerate() {
        let next = payloads.get(i + 1).map_or(0, |(t, _)| *t);
        let total_len = u16::try_from(PAYLOAD_HEADER_LEN + body.len()).unwrap_or(u16::MAX);
        let hdr = PayloadHeader { next_payload: next, flags: 0, length: total_len };
        out.extend_from_slice(&hdr.to_bytes());
        out.extend_from_slice(body);
    }

    (first_type, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_header_round_trip() {
        let hdr = PayloadHeader { next_payload: 4, flags: 0, length: 132 };
        let bytes = hdr.to_bytes();
        let parsed = PayloadHeader::parse(&bytes).expect("parse should succeed");
        assert_eq!(hdr, parsed);
    }

    #[test]
    fn body_len_calculation() {
        let hdr = PayloadHeader { next_payload: 0, flags: 0, length: 24 };
        assert_eq!(hdr.body_len(), 20);
    }

    #[test]
    fn critical_bit() {
        let hdr = PayloadHeader { next_payload: 0, flags: 0x80, length: 4 };
        assert!(hdr.is_critical());

        let hdr2 = PayloadHeader { next_payload: 0, flags: 0x00, length: 4 };
        assert!(!hdr2.is_critical());
    }

    #[test]
    fn chain_build_and_iter() {
        let payloads: Vec<(u8, &[u8])> = vec![(v1_types::SA, &[0xDE, 0xAD]), (v1_types::KE, &[0xBE, 0xEF, 0xCA, 0xFE]), (v1_types::NONCE, &[0x01, 0x02, 0x03])];
        let (first_type, chain) = build_payload_chain(&payloads);
        assert_eq!(first_type, v1_types::SA);

        let parsed = iter_payloads(&chain, first_type);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].0, v1_types::SA);
        assert_eq!(parsed[0].1, vec![0xDE, 0xAD]);
        assert_eq!(parsed[1].0, v1_types::KE);
        assert_eq!(parsed[1].1, vec![0xBE, 0xEF, 0xCA, 0xFE]);
        assert_eq!(parsed[2].0, v1_types::NONCE);
        assert_eq!(parsed[2].1, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn empty_chain() {
        let (first_type, chain) = build_payload_chain(&[]);
        assert_eq!(first_type, 0);
        assert!(chain.is_empty());
    }
}
