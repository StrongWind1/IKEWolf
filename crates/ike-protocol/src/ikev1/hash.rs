//! IKEv1 Aggressive Mode PSK hash extraction and cracking format output.
//!
//! When a server responds to an Aggressive Mode probe, its HASH_R payload
//! contains a keyed HMAC that can be cracked offline to recover the
//! pre-shared key. RFC 2409 section 5:
//!
//! ```text
//! SKEYID    = prf(PSK, Ni_b || Nr_b)
//! HASH_R    = prf(SKEYID, g^xr || g^xi || CKY-R || CKY-I || SAi_b || IDir_b)
//! ```
//!
//! Everything except the PSK is known from the exchange. This module collects
//! those fields and formats them for hashcat (modes 5300/5400/38100) and
//! ike-scan's `psk-crack` tool.

use crate::ikev1::model::Ikev1HashAlg;

/// Hash type detected from HASH_R length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PskHashType {
    /// HMAC-MD5 (16-byte HASH_R). hashcat mode 5300.
    Md5,
    /// HMAC-SHA1 (20-byte HASH_R). hashcat mode 5400.
    Sha1,
    /// HMAC-Tiger (24-byte HASH_R). No hashcat mode.
    Tiger,
    /// HMAC-SHA-256 (32-byte HASH_R). hashcat mode 38100.
    Sha256,
    /// HMAC-SHA-384 (48-byte HASH_R). No hashcat mode.
    Sha384,
    /// HMAC-SHA-512 (64-byte HASH_R). No hashcat mode.
    Sha512,
    /// Unknown hash length.
    Unknown(usize),
}

impl PskHashType {
    /// Detect from the HASH_R payload length. RFC 2409 section 5.
    #[must_use]
    pub fn from_hash_len(len: usize) -> Self {
        match len {
            16 => Self::Md5,
            20 => Self::Sha1,
            24 => Self::Tiger,
            32 => Self::Sha256,
            48 => Self::Sha384,
            64 => Self::Sha512,
            _ => Self::Unknown(len),
        }
    }

    /// The hashcat mode number, if one exists.
    #[must_use]
    pub fn hashcat_mode(self) -> Option<u32> {
        match self {
            Self::Md5 => Some(5300),
            Self::Sha1 => Some(5400),
            Self::Sha256 => Some(38100),
            Self::Tiger | Self::Sha384 | Self::Sha512 | Self::Unknown(_) => None,
        }
    }

    /// Try to match from the negotiated IKEv1 hash algorithm.
    #[must_use]
    pub fn from_ikev1_hash(alg: Ikev1HashAlg) -> Self {
        match alg {
            Ikev1HashAlg::Md5 => Self::Md5,
            Ikev1HashAlg::Sha1 => Self::Sha1,
            Ikev1HashAlg::Tiger => Self::Tiger,
            Ikev1HashAlg::Sha256 => Self::Sha256,
            Ikev1HashAlg::Sha384 => Self::Sha384,
            Ikev1HashAlg::Sha512 => Self::Sha512,
            Ikev1HashAlg::Other(_) => Self::Unknown(0),
        }
    }
}

impl core::fmt::Display for PskHashType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Md5 => write!(f, "HMAC-MD5"),
            Self::Sha1 => write!(f, "HMAC-SHA1"),
            Self::Tiger => write!(f, "HMAC-Tiger"),
            Self::Sha256 => write!(f, "HMAC-SHA256"),
            Self::Sha384 => write!(f, "HMAC-SHA384"),
            Self::Sha512 => write!(f, "HMAC-SHA512"),
            Self::Unknown(len) => write!(f, "Unknown({len}B)"),
        }
    }
}

/// Collected PSK cracking material from an Aggressive Mode exchange.
///
/// All 9 fields needed to verify a candidate PSK offline:
/// - From the initiator (message 1): `g_xi`, `cky_i`, `sai_b`, `ni_b`
/// - From the responder (message 2): `g_xr`, `cky_r`, `idir_b`, `nr_b`, `hash_r`
#[derive(Debug, Clone)]
pub struct PskCrackData {
    /// Responder's DH public value (from KE payload in message 2).
    pub g_xr: Vec<u8>,
    /// Initiator's DH public value (from KE payload in message 1, our data).
    pub g_xi: Vec<u8>,
    /// Responder cookie (from ISAKMP header bytes 8-15 of message 2).
    pub cky_r: [u8; 8],
    /// Initiator cookie (from ISAKMP header bytes 0-7, our cookie).
    pub cky_i: [u8; 8],
    /// SA payload body from message 1 (our SA, without the generic header).
    pub sai_b: Vec<u8>,
    /// Responder ID payload body from message 2 (without the generic header).
    pub idir_b: Vec<u8>,
    /// Initiator nonce body from message 1 (our nonce).
    pub ni_b: Vec<u8>,
    /// Responder nonce body from message 2.
    pub nr_b: Vec<u8>,
    /// HASH_R from message 2 (the value we're cracking against).
    pub hash_r: Vec<u8>,
}

impl PskCrackData {
    /// Detect the hash type from the HASH_R length.
    #[must_use]
    pub fn hash_type(&self) -> PskHashType {
        PskHashType::from_hash_len(self.hash_r.len())
    }

    /// Format for hashcat modes 5300 (MD5) / 5400 (SHA1) / 38100 (SHA256).
    ///
    /// Nine colon-separated hex fields, matching hashcat's IKE-PSK parser:
    /// `g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r`
    ///
    /// This is the same format ike-scan's `--pskcrack` produces and the same
    /// format the `psk-crack` tool consumes.
    #[must_use]
    pub fn to_hashcat(&self) -> String {
        [hex_encode(&self.g_xr), hex_encode(&self.g_xi), hex_encode(&self.cky_r), hex_encode(&self.cky_i), hex_encode(&self.sai_b), hex_encode(&self.idir_b), hex_encode(&self.ni_b), hex_encode(&self.nr_b), hex_encode(&self.hash_r)].join(":")
    }

    /// Alias for [`to_hashcat`](Self::to_hashcat) -- the format is identical.
    /// Kept for clarity when the caller specifically targets ike-scan's `psk-crack`.
    #[must_use]
    pub fn to_psk_crack(&self) -> String {
        self.to_hashcat()
    }
}

/// Lowercase hex encoding (no allocator-free hex crate needed in the protocol crate).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_crack_data(hash_len: usize) -> PskCrackData {
        PskCrackData { g_xr: vec![0x01; 128], g_xi: vec![0x02; 128], cky_r: [0xAA; 8], cky_i: [0xBB; 8], sai_b: vec![0xCC; 40], idir_b: vec![0xDD; 8], ni_b: vec![0xEE; 20], nr_b: vec![0xFF; 20], hash_r: vec![0x11; hash_len] }
    }

    #[test]
    fn hash_type_detection() {
        assert_eq!(PskHashType::from_hash_len(16), PskHashType::Md5);
        assert_eq!(PskHashType::from_hash_len(20), PskHashType::Sha1);
        assert_eq!(PskHashType::from_hash_len(32), PskHashType::Sha256);
        assert_eq!(PskHashType::from_hash_len(48), PskHashType::Sha384);
        assert_eq!(PskHashType::from_hash_len(64), PskHashType::Sha512);
        assert!(matches!(PskHashType::from_hash_len(7), PskHashType::Unknown(7)));
    }

    #[test]
    fn hashcat_modes() {
        assert_eq!(PskHashType::Md5.hashcat_mode(), Some(5300));
        assert_eq!(PskHashType::Sha1.hashcat_mode(), Some(5400));
        assert_eq!(PskHashType::Sha256.hashcat_mode(), Some(38100));
        assert_eq!(PskHashType::Sha384.hashcat_mode(), None);
    }

    #[test]
    fn hashcat_format_nine_fields() {
        let data = sample_crack_data(20);
        let hashcat = data.to_hashcat();
        let parts: Vec<&str> = hashcat.split(':').collect();
        assert_eq!(parts.len(), 9, "hashcat format must have 9 colon-separated fields");
        assert_eq!(parts[0].len(), 256, "g_xr (128 bytes) = 256 hex chars");
        assert_eq!(parts[1].len(), 256, "g_xi (128 bytes) = 256 hex chars");
        assert_eq!(parts[2].len(), 16, "cky_r (8 bytes) = 16 hex chars");
        assert_eq!(parts[3].len(), 16, "cky_i (8 bytes) = 16 hex chars");
        assert_eq!(parts[8].len(), 40, "SHA1 hash_r = 40 hex chars");
    }

    #[test]
    fn hashcat_format_md5_hash_length() {
        let data = sample_crack_data(16);
        assert_eq!(data.hash_type(), PskHashType::Md5);
        let line = data.to_hashcat();
        let parts: Vec<&str> = line.split(':').collect();
        assert_eq!(parts.len(), 9);
        assert_eq!(parts[8].len(), 32, "MD5 hash_r = 32 hex chars");
    }

    #[test]
    fn hashcat_format_sha256_hash_length() {
        let data = sample_crack_data(32);
        assert_eq!(data.hash_type(), PskHashType::Sha256);
        let line = data.to_hashcat();
        let parts: Vec<&str> = line.split(':').collect();
        assert_eq!(parts.len(), 9);
        assert_eq!(parts[8].len(), 64, "SHA256 hash_r = 64 hex chars");
    }

    #[test]
    fn psk_crack_equals_hashcat() {
        let data = sample_crack_data(20);
        assert_eq!(data.to_psk_crack(), data.to_hashcat());
    }

    #[test]
    fn hex_encode_correctness() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00, 0xFF]), "00ff");
    }

    #[test]
    fn hash_type_display() {
        assert_eq!(PskHashType::Md5.to_string(), "HMAC-MD5");
        assert_eq!(PskHashType::Sha256.to_string(), "HMAC-SHA256");
        assert_eq!(PskHashType::Unknown(7).to_string(), "Unknown(7B)");
    }
}
