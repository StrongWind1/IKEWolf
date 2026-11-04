//! IKEv1 numeric registries per RFC 2407 (DOI), RFC 2408 (ISAKMP), and
//! RFC 2409 (IKE).
//!
//! IKEv2 shares no payload numbering, exchange numbering, or transform
//! encoding with these, so its own registries live in
//! [`crate::ikev2::model`].

use crate::registry;

// --- Encryption Algorithm (attribute class 1, RFC 2409 Appendix A) ----------

registry! {
    /// IKEv1 encryption algorithms. RFC 2409 Appendix A, attribute class 1.
    Ikev1EncryptionAlg: u16 {
        /// DES-CBC. RFC 2405. 56-bit effective key. Broken, deprecated.
        DesCbc = 1,
        /// IDEA-CBC. 128-bit key. Rare.
        IdeaCbc = 2,
        /// Blowfish-CBC. Variable key. Uncommon.
        BlowfishCbc = 3,
        /// RC5-R16-B64-CBC. Variable key. Rare.
        Rc5Cbc = 4,
        /// 3DES-CBC. RFC 2451. 168-bit effective key. Deprecated.
        TripleDesCbc = 5,
        /// CAST-CBC. 128-bit key. Uncommon.
        CastCbc = 6,
        /// AES-CBC. RFC 3602. Requires Key Length attribute (128/192/256).
        AesCbc = 7,
        /// Camellia-CBC. Requires Key Length attribute. Rare.
        CamelliaCbc = 8,
    }
}

impl Ikev1EncryptionAlg {
    /// Key lengths to offer for this cipher. Variable-length ciphers return
    /// multiple options. Fixed-length ciphers return `&[None]`.
    #[must_use]
    pub fn key_lengths(self) -> &'static [Option<u16>] {
        match self {
            Self::AesCbc | Self::CamelliaCbc => &[Some(256), Some(192), Some(128)],
            Self::BlowfishCbc => &[Some(256), Some(128)],
            Self::CastCbc | Self::IdeaCbc | Self::Rc5Cbc => &[Some(128)],
            Self::DesCbc | Self::TripleDesCbc | Self::Other(_) => &[None],
        }
    }
}

// --- Hash Algorithm (attribute class 2, RFC 2409 Appendix A) ----------------

registry! {
    /// IKEv1 hash algorithms. RFC 2409 Appendix A, attribute class 2.
    Ikev1HashAlg: u16 {
        /// MD5. 128-bit output. Deprecated.
        Md5 = 1,
        /// SHA-1. 160-bit output. Being deprecated.
        Sha1 = 2,
        /// Tiger. 192-bit output. Rare.
        Tiger = 3,
        /// SHA2-256. 256-bit output.
        Sha256 = 4,
        /// SHA2-384. 384-bit output.
        Sha384 = 5,
        /// SHA2-512. 512-bit output.
        Sha512 = 6,
    }
}

impl Ikev1HashAlg {
    /// Output length in bytes for this hash algorithm.
    #[must_use]
    pub fn output_len(self) -> Option<usize> {
        match self {
            Self::Md5 => Some(16),
            Self::Sha1 => Some(20),
            Self::Tiger => Some(24),
            Self::Sha256 => Some(32),
            Self::Sha384 => Some(48),
            Self::Sha512 => Some(64),
            Self::Other(_) => None,
        }
    }
}

// --- Authentication Method (attribute class 3, RFC 2409 Appendix A) ---------

registry! {
    /// IKEv1 authentication methods. RFC 2409 Appendix A, attribute class 3.
    Ikev1AuthMethod: u16 {
        /// Pre-Shared Key. Crackable in Aggressive Mode.
        PreSharedKey = 1,
        /// DSS Signatures. Rare.
        DssSignatures = 2,
        /// RSA Signatures. Certificate-based. RFC 2409 section 5.1.
        RsaSignatures = 3,
        /// Encryption with RSA. Rare.
        RsaEncryption = 4,
        /// Revised Encryption with RSA. Rare.
        RevisedRsaEncryption = 5,
        /// ECDSA with SHA-256 on P-256. RFC 4754.
        EcdsaSha256P256 = 9,
        /// ECDSA with SHA-384 on P-384. RFC 4754.
        EcdsaSha384P384 = 10,
        /// ECDSA with SHA-512 on P-521. RFC 4754.
        EcdsaSha512P521 = 11,
        /// XAUTH Initiator Pre-Shared Key. Cisco XAUTH extension.
        XauthInitPsk = 65001,
        /// XAUTH Responder Pre-Shared Key.
        XauthRespPsk = 65002,
        /// XAUTH Initiator DSS.
        XauthInitDss = 65003,
        /// XAUTH Responder DSS.
        XauthRespDss = 65004,
        /// XAUTH Initiator RSA.
        XauthInitRsa = 65005,
        /// XAUTH Responder RSA.
        XauthRespRsa = 65006,
        /// XAUTH Initiator RSA Encryption.
        XauthInitRsaEnc = 65007,
        /// XAUTH Responder RSA Encryption.
        XauthRespRsaEnc = 65008,
        /// XAUTH Initiator Revised RSA Encryption.
        XauthInitRsaRevEnc = 65009,
        /// XAUTH Responder Revised RSA Encryption.
        XauthRespRsaRevEnc = 65010,
        /// Hybrid Initiator RSA. Cisco Hybrid (server cert + XAUTH).
        HybridInitRsa = 65098,
        /// Hybrid Responder RSA.
        HybridRespRsa = 65099,
        /// Hybrid Initiator DSS.
        HybridInitDss = 65100,
        /// Hybrid Responder DSS.
        HybridRespDss = 65101,
    }
}

impl Ikev1AuthMethod {
    /// Whether this is a PSK-based method (crackable in Aggressive Mode).
    #[must_use]
    pub fn is_psk(self) -> bool {
        matches!(self, Self::PreSharedKey | Self::XauthInitPsk | Self::XauthRespPsk)
    }

    /// Whether this is an XAUTH method.
    #[must_use]
    pub fn is_xauth(self) -> bool {
        let v: u16 = self.into();
        (65001..=65010).contains(&v)
    }

    /// Whether this is a Hybrid method.
    #[must_use]
    pub fn is_hybrid(self) -> bool {
        let v: u16 = self.into();
        (65098..=65101).contains(&v)
    }
}

// --- DH Group Description (attribute class 4, RFC 2409 Appendix A) ----------

registry! {
    /// Diffie-Hellman groups. RFC 2409 Appendix A, RFC 3526, RFC 5903, RFC 5114, RFC 8031.
    DhGroup: u16 {
        /// MODP-768. Broken (Logjam-class). RFC 2409 section 6.1.
        Modp768 = 1,
        /// MODP-1024. Weak (state-level breakable). RFC 2409 section 6.2.
        Modp1024 = 2,
        /// EC2N-155. Withdrawn.
        Ec2n155 = 3,
        /// EC2N-185. Withdrawn.
        Ec2n185 = 4,
        /// EC2N over GF[2^163] (Koblitz). draft-ietf-ipsec-ike-ecc-groups.
        Ec2nGf163a = 6,
        /// EC2N over GF[2^163] (random). draft-ietf-ipsec-ike-ecc-groups.
        Ec2nGf163b = 7,
        /// EC2N over GF[2^283] (Koblitz). draft-ietf-ipsec-ike-ecc-groups.
        Ec2nGf283a = 8,
        /// EC2N over GF[2^283] (random). draft-ietf-ipsec-ike-ecc-groups.
        Ec2nGf283b = 9,
        /// EC2N over GF[2^409] (Koblitz). draft-ietf-ipsec-ike-ecc-groups.
        Ec2nGf409a = 10,
        /// EC2N over GF[2^409] (random). draft-ietf-ipsec-ike-ecc-groups.
        Ec2nGf409b = 11,
        /// EC2N over GF[2^571] (Koblitz). draft-ietf-ipsec-ike-ecc-groups.
        Ec2nGf571a = 12,
        /// EC2N over GF[2^571] (random). draft-ietf-ipsec-ike-ecc-groups.
        Ec2nGf571b = 13,
        /// MODP-1536. Marginal. RFC 3526 section 2.
        Modp1536 = 5,
        /// MODP-2048. Current minimum recommended. RFC 3526 section 3.
        Modp2048 = 14,
        /// MODP-3072. RFC 3526 section 4.
        Modp3072 = 15,
        /// MODP-4096. RFC 3526 section 5.
        Modp4096 = 16,
        /// MODP-6144. RFC 3526 section 6.
        Modp6144 = 17,
        /// MODP-8192. RFC 3526 section 7.
        Modp8192 = 18,
        /// ECP-256 (NIST P-256). RFC 5903 section 3.
        Ecp256 = 19,
        /// ECP-384 (NIST P-384). RFC 5903 section 4.
        Ecp384 = 20,
        /// ECP-521 (NIST P-521). RFC 5903 section 5.
        Ecp521 = 21,
        /// MODP-1024 with 160-bit subgroup. RFC 5114 section 2.1.
        Modp1024Sub160 = 22,
        /// MODP-2048 with 224-bit subgroup. RFC 5114 section 2.2.
        Modp2048Sub224 = 23,
        /// MODP-2048 with 256-bit subgroup. RFC 5114 section 2.3.
        Modp2048Sub256 = 24,
        /// ECP-192. RFC 5114 section 2.4.
        Ecp192 = 25,
        /// ECP-224. RFC 5114 section 2.5.
        Ecp224 = 26,
        /// Brainpool-224. RFC 6954.
        Brainpool224 = 27,
        /// Brainpool-256. RFC 6954.
        Brainpool256 = 28,
        /// Brainpool-384. RFC 6954.
        Brainpool384 = 29,
        /// Brainpool-512. RFC 6954.
        Brainpool512 = 30,
        /// Curve25519. RFC 8031 section 3.
        Curve25519 = 31,
        /// Curve448. RFC 8031 section 4.
        Curve448 = 32,
        /// GOST3410-2012-256. RFC 9385.
        Gost2012_256 = 33,
        /// GOST3410-2012-512. RFC 9385.
        Gost2012_512 = 34,
        /// ML-KEM-512 (post-quantum). RFC 9180+.
        MlKem512 = 35,
        /// ML-KEM-768 (post-quantum). RFC 9180+.
        MlKem768 = 36,
        /// ML-KEM-1024 (post-quantum). RFC 9180+.
        MlKem1024 = 37,
    }
}

impl DhGroup {
    /// The KE payload size in bytes for MODP groups (the prime length).
    /// Returns `None` for unknown or ECP groups (which have different sizes).
    #[must_use]
    pub fn ke_len(self) -> Option<usize> {
        match self {
            Self::Ecp192 => Some(48),
            Self::Curve25519 => Some(32),
            Self::Ecp224 | Self::Brainpool224 | Self::Curve448 => Some(56),
            Self::Ecp256 | Self::Brainpool256 | Self::Gost2012_256 => Some(64),
            Self::Modp768 | Self::Ecp384 | Self::Brainpool384 => Some(96),
            Self::Modp1024 | Self::Modp1024Sub160 | Self::Brainpool512 | Self::Gost2012_512 => Some(128),
            Self::Ecp521 => Some(132),
            Self::Modp1536 => Some(192),
            Self::Modp2048 | Self::Modp2048Sub224 | Self::Modp2048Sub256 => Some(256),
            Self::Modp3072 => Some(384),
            Self::Modp4096 => Some(512),
            Self::Modp6144 => Some(768),
            Self::Modp8192 => Some(1024),
            Self::Ec2n155 | Self::Ec2n185 | Self::Ec2nGf163a | Self::Ec2nGf163b | Self::Ec2nGf283a | Self::Ec2nGf283b | Self::Ec2nGf409a | Self::Ec2nGf409b | Self::Ec2nGf571a | Self::Ec2nGf571b | Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 | Self::Other(_) => None,
        }
    }

    /// Whether this group is considered weak by current standards.
    #[must_use]
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Modp768 | Self::Modp1024 | Self::Modp1024Sub160 | Self::Ec2n155 | Self::Ec2n185 | Self::Ec2nGf163a | Self::Ec2nGf163b | Self::Ec2nGf283a | Self::Ec2nGf283b | Self::Ec2nGf409a | Self::Ec2nGf409b | Self::Ec2nGf571a | Self::Ec2nGf571b)
    }

    /// Whether this group is deprecated/marginal.
    #[must_use]
    pub fn is_marginal(self) -> bool {
        matches!(self, Self::Modp1536)
    }
}

// --- Identity Type (RFC 2407 section 4.6.2.1) --------------------------------

registry! {
    /// IKEv1 identification types. RFC 2407 section 4.6.2.1.
    Ikev1IdType: u8 {
        /// IPv4 address (4 bytes).
        Ipv4Addr = 1,
        /// Fully Qualified Domain Name.
        Fqdn = 2,
        /// User Fully Qualified Domain Name (e.g. "user@example.com").
        UserFqdn = 3,
        /// IPv4 address + subnet mask (8 bytes).
        Ipv4AddrSubnet = 4,
        /// IPv6 address (16 bytes).
        Ipv6Addr = 5,
        /// IPv6 address + subnet mask (32 bytes).
        Ipv6AddrSubnet = 6,
        /// IPv4 address range (8 bytes).
        Ipv4AddrRange = 7,
        /// IPv6 address range (32 bytes).
        Ipv6AddrRange = 8,
        /// DER-encoded ASN.1 X.500 Distinguished Name.
        DerAsn1Dn = 9,
        /// DER-encoded ASN.1 X.500 General Name.
        DerAsn1Gn = 10,
        /// Opaque key identifier. Used for VPN group names in Aggressive Mode.
        KeyId = 11,
        /// Fibre Channel Name. RFC 4595.
        FcName = 12,
        /// NULL identity. RFC 7619.
        Null = 13,
    }
}

// --- Protocol ID (RFC 2407 section 4.4.1) ------------------------------------

registry! {
    /// IKEv1 protocol IDs. RFC 2407 section 4.4.1.
    Ikev1ProtocolId: u8 {
        /// Reserved.
        Reserved = 0,
        /// ISAKMP (Phase 1).
        Isakmp = 1,
        /// IPsec AH.
        IpsecAh = 2,
        /// IPsec ESP.
        IpsecEsp = 3,
        /// IP Compression.
        Ipcomp = 4,
        /// Gigabeam Radio. RFC 4705.
        GigabeamRadio = 5,
    }
}

// --- Life Type (attribute class 11) ------------------------------------------

registry! {
    /// Life type values. RFC 2409 Appendix A.
    LifeType: u16 {
        /// Lifetime in seconds.
        Seconds = 1,
        /// Lifetime in kilobytes.
        Kilobytes = 2,
    }
}

// --- Group Type (attribute class 5, RFC 2409 Appendix A) ---------------------

registry! {
    /// IKEv1 group types. RFC 2409 Appendix A, attribute class 5.
    Ikev1GroupType: u16 {
        /// Modular exponentiation (MODP).
        Modp = 1,
        /// Elliptic curve over GF\[P\] (ECP).
        Ecp = 2,
        /// Elliptic curve over GF\[2^N\] (EC2N).
        Ec2n = 3,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn encryption_alg_round_trip() {
        for val in [1, 2, 3, 4, 5, 6, 7, 8] {
            let alg = Ikev1EncryptionAlg::from(val);
            let back: u16 = alg.into();
            assert_eq!(val, back);
        }
        let unknown = Ikev1EncryptionAlg::from(99);
        assert!(matches!(unknown, Ikev1EncryptionAlg::Other(99)));
    }

    #[test]
    fn hash_output_lengths() {
        assert_eq!(Ikev1HashAlg::Md5.output_len(), Some(16));
        assert_eq!(Ikev1HashAlg::Sha1.output_len(), Some(20));
        assert_eq!(Ikev1HashAlg::Sha256.output_len(), Some(32));
        assert_eq!(Ikev1HashAlg::Sha384.output_len(), Some(48));
        assert_eq!(Ikev1HashAlg::Sha512.output_len(), Some(64));
        assert_eq!(Ikev1HashAlg::Other(99).output_len(), None);
    }

    #[test]
    fn auth_method_classification() {
        assert!(Ikev1AuthMethod::PreSharedKey.is_psk());
        assert!(Ikev1AuthMethod::XauthInitPsk.is_psk());
        assert!(!Ikev1AuthMethod::RsaSignatures.is_psk());

        assert!(Ikev1AuthMethod::XauthInitPsk.is_xauth());
        assert!(Ikev1AuthMethod::XauthRespRsaRevEnc.is_xauth());
        assert!(!Ikev1AuthMethod::PreSharedKey.is_xauth());

        assert!(Ikev1AuthMethod::HybridInitRsa.is_hybrid());
        assert!(!Ikev1AuthMethod::XauthInitPsk.is_hybrid());
    }

    #[test]
    fn dh_group_ke_lengths() {
        assert_eq!(DhGroup::Modp768.ke_len(), Some(96));
        assert_eq!(DhGroup::Modp1024.ke_len(), Some(128));
        assert_eq!(DhGroup::Modp2048.ke_len(), Some(256));
        assert_eq!(DhGroup::Ecp256.ke_len(), Some(64));
        assert_eq!(DhGroup::Curve25519.ke_len(), Some(32));
    }

    #[test]
    fn dh_group_weakness() {
        assert!(DhGroup::Modp768.is_weak());
        assert!(DhGroup::Modp1024.is_weak());
        assert!(!DhGroup::Modp2048.is_weak());
        assert!(DhGroup::Modp1536.is_marginal());
        assert!(!DhGroup::Modp2048.is_marginal());
    }

    #[test]
    fn id_type_round_trip() {
        for val in 1..=11 {
            let id = Ikev1IdType::from(val);
            let back: u8 = id.into();
            assert_eq!(val, back);
        }
    }
}
