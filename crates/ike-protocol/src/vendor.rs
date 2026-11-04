//! Vendor ID payload matching and fingerprint database.
//!
//! Vendor ID payloads (RFC 2408 section 3.16) carry MD5 hashes of
//! vendor-specific strings. Multiple VID payloads can appear in a single
//! IKE message. Matching them against a database identifies the
//! implementation.
//!
//! There is no IANA registry for VID values — each implementation defines
//! its own. The constants below are the well-known VIDs that IKEWolf sends
//! in outgoing probes to elicit maximum information from servers.

/// Dead Peer Detection (DPD). RFC 3706.
/// MD5("FRAGMENTATION") is NOT this — DPD has its own fixed hash.
/// Value from ike-scan `ike-vendor-ids` and RFC 3706 section 1.
pub const VID_DPD: &[u8] = &[0xAF, 0xCA, 0xD7, 0x13, 0x68, 0xA1, 0xF1, 0xC9, 0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57, 0x01, 0x00];

/// NAT-Traversal (RFC 3947). Final RFC version.
/// MD5("RFC 3947")
pub const VID_NAT_T_RFC: &[u8] = &[0x4A, 0x13, 0x1C, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5C, 0x57, 0x28, 0xF2, 0x0E, 0x95, 0x45, 0x2F];

/// NAT-Traversal draft-ietf-ipsec-nat-t-ike-02. Widely deployed (Cisco, Windows).
/// MD5("draft-ietf-ipsec-nat-t-ike-02\n")
pub const VID_NAT_T_02: &[u8] = &[0xCD, 0x60, 0x46, 0x43, 0x35, 0xDF, 0x21, 0xF8, 0x7C, 0xFD, 0xB2, 0xFC, 0x68, 0xB6, 0xA8, 0x68];

/// NAT-Traversal draft-ietf-ipsec-nat-t-ike-03.
/// MD5("draft-ietf-ipsec-nat-t-ike-03\n")
pub const VID_NAT_T_03: &[u8] = &[0x7D, 0x94, 0x19, 0xA6, 0x53, 0x10, 0xCA, 0x6F, 0x2C, 0x17, 0x9D, 0x92, 0x15, 0x52, 0x9D, 0x56];

/// XAUTH. Cisco/IETF extended authentication.
/// MD5("draft-ietf-ipsra-isakmp-xauth-06.txt")
pub const VID_XAUTH: &[u8] = &[0x09, 0x00, 0x26, 0x89, 0xDF, 0xD6, 0xB7, 0x12, 0x80, 0xA2, 0x24, 0xDE, 0xC3, 0x3B, 0x81, 0xE5];

/// IKE Fragmentation. draft-ietf-ipsec-ike-frag / Cisco proprietary.
/// MD5("FRAGMENTATION") + 0x80000000 (20 bytes total).
/// Cisco, Check Point, and Fortinet enable fragmentation features when they
/// see this VID. strongSwan sends it with the 0x80000000 capability flags.
pub const VID_FRAGMENTATION: &[u8] = &[0x40, 0x48, 0xB7, 0xD5, 0x6E, 0xBC, 0xE8, 0x85, 0x25, 0xE7, 0xDE, 0x7F, 0x00, 0xD6, 0xC2, 0xD3, 0x80, 0x00, 0x00, 0x00];

/// Cisco Unity. MD5("CISCO-UNITY").
/// Cisco ASA/PIX responds with additional VIDs and configuration attributes
/// when it sees this VID. Very common in enterprise VPN deployments.
pub const VID_CISCO_UNITY: &[u8] = &[0x12, 0xF5, 0xF2, 0x8C, 0x45, 0x71, 0x68, 0xA9, 0x70, 0x2D, 0x9F, 0xE2, 0x74, 0xCC, 0x01, 0x00];

/// IKEv2 fragmentation supported. RFC 7383.
/// Sent as N(IKEV2_FRAGMENTATION_SUPPORTED) notify type 16430, not a VID.
/// Included here for reference only — sent via notify payloads, not VID payloads.
pub const IKEV2_FRAG_NOTIFY_TYPE: u16 = 16430;

/// The set of VIDs to include in IKEv1 outgoing probes.
/// Sending these causes many servers to reveal additional VIDs and
/// negotiate capabilities they would otherwise hide.
pub const DEFAULT_V1_VIDS: &[&[u8]] = &[VID_DPD, VID_NAT_T_RFC, VID_NAT_T_02, VID_XAUTH, VID_FRAGMENTATION, VID_CISCO_UNITY];
