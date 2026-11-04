//! IKEv2 numeric registries per RFC 7296.
//!
//! IKEv2 uses completely different payload numbering, transform encoding,
//! and algorithm IDs from IKEv1. See [`crate::ikev1::model`] for the v1
//! registries.

use crate::registry;

// --- Transform Types (RFC 7296 section 3.3.2) --------------------------------

registry! {
    /// IKEv2 transform types. RFC 7296 section 3.3.2.
    Ikev2TransformType: u8 {
        /// Encryption Algorithm (ENCR).
        Encryption = 1,
        /// Pseudorandom Function (PRF).
        Prf = 2,
        /// Integrity Algorithm (INTEG).
        Integrity = 3,
        /// Diffie-Hellman Group.
        DhGroup = 4,
        /// Extended Sequence Numbers (ESN).
        Esn = 5,
        /// Additional Key Exchange 1. RFC 9370.
        AddKe1 = 6,
        /// Additional Key Exchange 2. RFC 9370.
        AddKe2 = 7,
        /// Additional Key Exchange 3. RFC 9370.
        AddKe3 = 8,
        /// Additional Key Exchange 4. RFC 9370.
        AddKe4 = 9,
        /// Additional Key Exchange 5. RFC 9370.
        AddKe5 = 10,
        /// Additional Key Exchange 6. RFC 9370.
        AddKe6 = 11,
        /// Additional Key Exchange 7. RFC 9370.
        AddKe7 = 12,
        /// Key Wrap Algorithm (GDOI). RFC 9838.
        KeyWrapAlgorithm = 13,
        /// Group Controller Authentication Method (GDOI). RFC 9838.
        GroupControllerAuth = 14,
    }
}

// --- Encryption Algorithm (Transform Type 1, RFC 7296 section 3.3.2) ---------

registry! {
    /// IKEv2 encryption algorithm IDs. IANA IKEv2 Transform Type 1 registry.
    Ikev2EncryptionAlg: u16 {
        /// DES-IV64. Unspecified.
        DesIv64 = 1,
        /// DES. RFC 2405. 56-bit. Deprecated.
        Des = 2,
        /// 3DES. RFC 2451. Deprecated.
        TripleDes = 3,
        /// RC5. Rare.
        Rc5 = 4,
        /// IDEA. Rare.
        Idea = 5,
        /// CAST. Rare.
        Cast = 6,
        /// Blowfish. Rare.
        Blowfish = 7,
        /// 3IDEA. Unspecified.
        TripleIdea = 8,
        /// DES-IV32. Unspecified.
        DesIv32 = 9,
        /// NULL encryption (auth-only ESP).
        Null = 11,
        /// AES-CBC. RFC 3602. Requires Key Length attribute.
        AesCbc = 12,
        /// AES-CTR. RFC 3686. Requires Key Length attribute.
        AesCtr = 13,
        /// AES-CCM with 8-byte ICV. RFC 4309. AEAD.
        AesCcm8 = 14,
        /// AES-CCM with 12-byte ICV. RFC 4309. AEAD.
        AesCcm12 = 15,
        /// AES-CCM with 16-byte ICV. RFC 4309. AEAD.
        AesCcm16 = 16,
        /// AES-GCM with 8-byte ICV. RFC 4106. AEAD.
        AesGcm8 = 18,
        /// AES-GCM with 12-byte ICV. RFC 4106. AEAD.
        AesGcm12 = 19,
        /// AES-GCM with 16-byte ICV. RFC 4106. AEAD. Recommended.
        AesGcm16 = 20,
        /// NULL-AUTH-AES-GMAC. RFC 4543.
        NullAuthAesGmac = 21,
        /// Camellia-CBC. RFC 5529. Requires Key Length attribute.
        CamelliaCbc = 23,
        /// Camellia-CTR. RFC 5529. Requires Key Length attribute.
        CamelliaCtr = 24,
        /// Camellia-CCM with 8-byte ICV. RFC 5529. AEAD.
        CamelliaCcm8 = 25,
        /// Camellia-CCM with 12-byte ICV. RFC 5529. AEAD.
        CamelliaCcm12 = 26,
        /// Camellia-CCM with 16-byte ICV. RFC 5529. AEAD.
        CamelliaCcm16 = 27,
        /// ChaCha20-Poly1305. RFC 7634. AEAD. Modern.
        ChaCha20Poly1305 = 28,
        /// AES-CCM-8 with implicit IV. RFC 8750.
        AesCcm8Iiv = 29,
        /// AES-GCM-16 with implicit IV. RFC 8750.
        AesGcm16Iiv = 30,
        /// ChaCha20-Poly1305 with implicit IV. RFC 8750.
        ChaCha20Poly1305Iiv = 31,
        /// KUZNYECHIK-MGM-KTREE. RFC 9227. Russian GOST.
        KuznyechikMgm = 32,
        /// MAGMA-MGM-KTREE. RFC 9227. Russian GOST.
        MagmaMgm = 33,
        /// KUZNYECHIK-MGM-MAC-KTREE. RFC 9227. Not allowed for IKEv2 (ESP only).
        KuznyechikMgmMac = 34,
        /// MAGMA-MGM-MAC-KTREE. RFC 9227. Not allowed for IKEv2 (ESP only).
        MagmaMgmMac = 35,
    }
}

impl Ikev2EncryptionAlg {
    /// Whether this is an AEAD cipher (includes integrity, no separate INTEG transform).
    #[must_use]
    pub fn is_aead(self) -> bool {
        matches!(
            self,
            Self::AesCcm8
                | Self::AesCcm12
                | Self::AesCcm16
                | Self::AesGcm8
                | Self::AesGcm12
                | Self::AesGcm16
                | Self::ChaCha20Poly1305
                | Self::CamelliaCcm8
                | Self::CamelliaCcm12
                | Self::CamelliaCcm16
                | Self::AesCcm8Iiv
                | Self::AesGcm16Iiv
                | Self::ChaCha20Poly1305Iiv
                | Self::KuznyechikMgm
                | Self::MagmaMgm
        )
    }

    /// Key lengths to offer for this cipher. Variable-length ciphers return
    /// multiple sizes. Fixed-length and GOST ciphers return `&[None]`.
    #[must_use]
    pub fn key_lengths(self) -> &'static [Option<u16>] {
        match self {
            Self::AesCbc | Self::AesCtr | Self::CamelliaCbc | Self::CamelliaCtr | Self::AesGcm8 | Self::AesGcm12 | Self::AesGcm16 | Self::AesCcm8 | Self::AesCcm12 | Self::AesCcm16 | Self::CamelliaCcm8 | Self::CamelliaCcm12 | Self::CamelliaCcm16 => &[Some(256), Some(192), Some(128)],
            Self::ChaCha20Poly1305 | Self::AesGcm16Iiv | Self::AesCcm8Iiv | Self::ChaCha20Poly1305Iiv => &[Some(256), Some(128)],
            Self::TripleDes | Self::Des | Self::DesIv64 | Self::DesIv32 | Self::TripleIdea | Self::Blowfish | Self::Cast | Self::Idea | Self::Rc5 | Self::Null | Self::NullAuthAesGmac | Self::KuznyechikMgm | Self::MagmaMgm | Self::KuznyechikMgmMac | Self::MagmaMgmMac | Self::Other(_) => &[None],
        }
    }
}

// --- PRF (Transform Type 2, RFC 7296 section 3.3.2) --------------------------

registry! {
    /// IKEv2 pseudorandom function IDs. IANA IKEv2 Transform Type 2 registry.
    Ikev2PrfAlg: u16 {
        /// PRF-HMAC-MD5. Deprecated.
        HmacMd5 = 1,
        /// PRF-HMAC-SHA1. Common.
        HmacSha1 = 2,
        /// PRF-HMAC-TIGER. Unspecified.
        HmacTiger = 3,
        /// PRF-AES128-XCBC. RFC 4434.
        Aes128Xcbc = 4,
        /// PRF-HMAC-SHA2-256. RFC 4868. Recommended.
        HmacSha256 = 5,
        /// PRF-HMAC-SHA2-384. RFC 4868.
        HmacSha384 = 6,
        /// PRF-HMAC-SHA2-512. RFC 4868.
        HmacSha512 = 7,
        /// PRF-AES128-CMAC. RFC 4615.
        Aes128Cmac = 8,
        /// PRF-HMAC-STREEBOG-512. RFC 9385. Russian GOST.
        HmacStreebog512 = 9,
    }
}

// --- Integrity Algorithm (Transform Type 3, RFC 7296 section 3.3.2) ----------

registry! {
    /// IKEv2 integrity algorithm IDs. IANA IKEv2 Transform Type 3 registry.
    Ikev2IntegrityAlg: u16 {
        /// No integrity (only valid with AEAD encryption).
        None = 0,
        /// AUTH-HMAC-MD5-96. RFC 2403. Deprecated.
        HmacMd5_96 = 1,
        /// AUTH-HMAC-SHA1-96. RFC 2404. Common.
        HmacSha1_96 = 2,
        /// AUTH-DES-MAC. Unspecified.
        DesMac = 3,
        /// AUTH-KPDK-MD5. Unspecified.
        KpdkMd5 = 4,
        /// AUTH-AES-XCBC-96. RFC 3566.
        AesXcbc96 = 5,
        /// AUTH-HMAC-MD5-128. RFC 4595.
        HmacMd5_128 = 6,
        /// AUTH-HMAC-SHA1-160. RFC 4595.
        HmacSha1_160 = 7,
        /// AUTH-AES-CMAC-96. RFC 4494.
        AesCmac96 = 8,
        /// AUTH-AES-128-GMAC. RFC 4543.
        Aes128Gmac = 9,
        /// AUTH-AES-192-GMAC. RFC 4543.
        Aes192Gmac = 10,
        /// AUTH-AES-256-GMAC. RFC 4543.
        Aes256Gmac = 11,
        /// AUTH-HMAC-SHA2-256-128. RFC 4868.
        HmacSha256_128 = 12,
        /// AUTH-HMAC-SHA2-384-192. RFC 4868.
        HmacSha384_192 = 13,
        /// AUTH-HMAC-SHA2-512-256. RFC 4868.
        HmacSha512_256 = 14,
    }
}

// --- IKEv2 Notification Types (RFC 7296 section 3.10.1) ----------------------

registry! {
    /// IKEv2 notification message types. IANA IKEv2 Notify Message Types registry.
    /// Types < 16384 are errors; >= 16384 are status notifications.
    Ikev2NotifyType: u16 {
        // --- Error types (< 16384) ---
        /// Unsupported critical payload. RFC 7296.
        UnsupportedCriticalPayload = 1,
        /// Invalid IKE SPI. RFC 7296.
        InvalidIkeSpi = 4,
        /// Invalid major version. RFC 7296.
        InvalidMajorVersion = 5,
        /// Invalid syntax. RFC 7296.
        InvalidSyntax = 7,
        /// Invalid message ID. RFC 7296.
        InvalidMessageId = 9,
        /// Invalid SPI. RFC 7296.
        InvalidSpi = 11,
        /// No proposal chosen (no acceptable transforms). RFC 7296.
        NoProposalChosen = 14,
        /// Invalid KE payload (wrong DH group). Data = 2-byte preferred group. RFC 7296.
        InvalidKePayload = 17,
        /// Authentication failed. RFC 7296.
        AuthenticationFailed = 24,
        /// Single pair required. RFC 7296.
        SinglePairRequired = 34,
        /// No additional SAs. RFC 7296.
        NoAdditionalSas = 35,
        /// Internal address failure. RFC 7296.
        InternalAddressFailure = 36,
        /// Failed CP required. RFC 7296.
        FailedCpRequired = 37,
        /// TS unacceptable. RFC 7296.
        TsUnacceptable = 38,
        /// Invalid selectors. RFC 7296.
        InvalidSelectors = 39,
        /// Unacceptable addresses. RFC 4555.
        UnacceptableAddresses = 40,
        /// Unexpected NAT detected. RFC 4555.
        UnexpectedNatDetected = 41,
        /// Use assigned Home Address. RFC 5026.
        UseAssignedHoa = 42,
        /// Temporary failure. RFC 7296.
        TemporaryFailure = 43,
        /// Child SA not found. RFC 7296.
        ChildSaNotFound = 44,
        /// Invalid group ID. RFC 6054.
        InvalidGroupId = 45,
        /// Authorization failed. RFC 7657.
        AuthorizationFailed = 46,
        /// State not found. RFC 8229.
        StateNotFound = 47,
        /// TS max queue. RFC 9611.
        TsMaxQueue = 48,
        /// Registration failed.
        RegistrationFailed = 49,
        // --- Status notifications (>= 16384) ---
        /// Initial contact. RFC 7296.
        InitialContact = 16384,
        /// Set window size. RFC 7296.
        SetWindowSize = 16385,
        /// Additional TS possible. RFC 7296.
        AdditionalTsPossible = 16386,
        /// IPCOMP supported. RFC 7296.
        IpcompSupported = 16387,
        /// NAT detection source IP. RFC 7296 section 2.23.
        NatDetectionSourceIp = 16388,
        /// NAT detection destination IP. RFC 7296 section 2.23.
        NatDetectionDestinationIp = 16389,
        /// Cookie. RFC 7296 section 2.6. Anti-DoS mechanism.
        Cookie = 16390,
        /// Use transport mode. RFC 7296.
        UseTransportMode = 16391,
        /// HTTP cert lookup supported. RFC 4306.
        HttpCertLookupSupported = 16392,
        /// Rekey SA. RFC 7296.
        RekeySa = 16393,
        /// ESP TFC padding not supported. RFC 7296.
        EspTfcPaddingNotSupported = 16394,
        /// Non-first fragments also. RFC 7296.
        NonFirstFragmentsAlso = 16395,
        /// MOBIKE supported. RFC 4555.
        MobikeSupported = 16396,
        /// Additional IPv4 address. RFC 4555.
        AdditionalIp4Address = 16397,
        /// Additional IPv6 address. RFC 4555.
        AdditionalIp6Address = 16398,
        /// No additional addresses. RFC 4555.
        NoAdditionalAddresses = 16399,
        /// Update SA addresses. RFC 4555.
        UpdateSaAddresses = 16400,
        /// Cookie2. RFC 4555.
        Cookie2 = 16401,
        /// No NATs allowed. RFC 4555.
        NoNatsAllowed = 16402,
        /// Auth lifetime. RFC 6311.
        AuthLifetime = 16403,
        /// Multiple auth supported. RFC 4739.
        MultipleAuthSupported = 16404,
        /// Another auth follows. RFC 4739.
        AnotherAuthFollows = 16405,
        /// Redirect supported. RFC 5685.
        RedirectSupported = 16406,
        /// Redirect. RFC 5685.
        Redirect = 16407,
        /// Redirected from. RFC 5685.
        RedirectedFrom = 16408,
        /// Ticket LT opaque. RFC 5723.
        TicketLtOpaque = 16409,
        /// Ticket request. RFC 5723.
        TicketRequest = 16410,
        /// Ticket ACK. RFC 5723.
        TicketAck = 16411,
        /// Ticket NACK. RFC 5723.
        TicketNack = 16412,
        /// Ticket opaque. RFC 5723.
        TicketOpaque = 16413,
        /// Link ID. RFC 5739.
        LinkId = 16414,
        /// Use WESP mode. RFC 5840.
        UseWespMode = 16415,
        /// ROHC supported. RFC 5857.
        RohcSupported = 16416,
        /// EAP-only authentication. RFC 5998.
        EapOnlyAuthentication = 16417,
        /// Childless IKEv2 supported. RFC 6023.
        ChildlessIkev2Supported = 16418,
        /// Quick crash detection. RFC 6290.
        QuickCrashDetection = 16419,
        /// IKEv2 message ID sync supported. RFC 6311.
        Ikev2MessageIdSyncSupported = 16420,
        /// IPsec replay counter sync supported. RFC 6311.
        IpsecReplayCounterSyncSupported = 16421,
        /// IKEv2 message ID sync. RFC 6311.
        Ikev2MessageIdSync = 16422,
        /// IPsec replay counter sync. RFC 6311.
        IpsecReplayCounterSync = 16423,
        /// Secure password methods. RFC 6467.
        SecurePasswordMethods = 16424,
        /// PSK persist. RFC 6631.
        PskPersist = 16425,
        /// PSK confirm. RFC 6631.
        PskConfirm = 16426,
        /// ERX supported. RFC 6867.
        ErxSupported = 16427,
        /// IFOM capability. 3GPP TS 24.303 v10.6.0.
        IfomCapability = 16428,
        /// Group sender. RFC 6054.
        GroupSender = 16429,
        /// IKEv2 fragmentation supported. RFC 7383.
        Ikev2FragmentationSupported = 16430,
        /// Signature hash algorithms. RFC 7427.
        SignatureHashAlgorithms = 16431,
        /// Clone IKE SA supported. RFC 7791.
        CloneIkeSaSupported = 16432,
        /// Clone IKE SA. RFC 7791.
        CloneIkeSa = 16433,
        /// Puzzle. RFC 8019.
        Puzzle = 16434,
        /// Use PPK. RFC 8784.
        UsePpk = 16435,
        /// PPK identity. RFC 8784.
        PpkIdentity = 16436,
        /// No PPK auth. RFC 8784.
        NoPpkAuth = 16437,
        /// Intermediate exchange supported. RFC 9242.
        IntermediateExchangeSupported = 16438,
        /// IPv4 allowed. RFC 8983.
        Ip4Allowed = 16439,
        /// IPv6 allowed. RFC 8983.
        Ip6Allowed = 16440,
        /// Additional key exchange. RFC 9370.
        AdditionalKeyExchange = 16441,
        /// Use AGGFRAG. RFC 9347.
        UseAggfrag = 16442,
        /// Supported auth methods. RFC 9593.
        SupportedAuthMethods = 16443,
        /// SA resource info. RFC 9611.
        SaResourceInfo = 16444,
        /// Use PPK (intermediate). RFC 9628.
        UsePpkInt = 16445,
        /// PPK identity key. RFC 9628.
        PpkIdentityKey = 16446,
        /// IKE_SA_INIT full transcript auth.
        IkeSaInitFullTranscriptAuth = 16447,
        /// CHILD_SA PFS info supported.
        ChildSaPfsInfoSupported = 16448,
    }
}

impl Ikev2NotifyType {
    /// Whether this is an error notification (type < 16384).
    #[must_use]
    pub fn is_error(self) -> bool {
        let v: u16 = self.into();
        v < 16384
    }
}

// --- Authentication Method (RFC 7296 section 3.8) ----------------------------

registry! {
    /// IKEv2 authentication method. RFC 7296 section 3.8.
    Ikev2AuthMethod: u8 {
        /// RSA Digital Signature. RFC 7296.
        RsaDigitalSignature = 1,
        /// Shared Key Message Integrity Code (PSK). RFC 7296.
        SharedKeyMic = 2,
        /// DSS Digital Signature. RFC 7296.
        DssDigitalSignature = 3,
        /// ECDSA with SHA-256 on P-256. RFC 4754.
        EcdsaSha256P256 = 9,
        /// ECDSA with SHA-384 on P-384. RFC 4754.
        EcdsaSha384P384 = 10,
        /// ECDSA with SHA-512 on P-521. RFC 4754.
        EcdsaSha512P521 = 11,
        /// Generic Secure Password Authentication. RFC 6467.
        GenericSecurePassword = 12,
        /// NULL Authentication. RFC 7619.
        Null = 13,
        /// Digital Signature. RFC 7427.
        DigitalSignature = 14,
    }
}

// --- Certificate Encodings (RFC 7296 section 3.6) ----------------------------

registry! {
    /// IKEv2 certificate encoding types. RFC 7296 section 3.6.
    Ikev2CertEncoding: u8 {
        /// PKCS #7 wrapped X.509 certificate.
        Pkcs7X509 = 1,
        /// PGP Certificate.
        Pgp = 2,
        /// DNS Signed Key.
        DnsSigned = 3,
        /// X.509 Certificate - Signature.
        X509Signature = 4,
        /// Kerberos Token.
        Kerberos = 6,
        /// Certificate Revocation List. RFC 7296.
        Crl = 7,
        /// Authority Revocation List.
        Arl = 8,
        /// SPKI Certificate.
        Spki = 9,
        /// X.509 Certificate - Attribute.
        X509Attribute = 10,
        /// Raw RSA Key (deprecated). RFC 7296.
        RawRsaKey = 11,
        /// Hash and URL of X.509 certificate. RFC 7296.
        HashUrlX509Cert = 12,
        /// Hash and URL of X.509 bundle. RFC 7296.
        HashUrlX509Bundle = 13,
        /// OCSP Content. RFC 4806.
        OcspContent = 14,
        /// Raw Public Key. RFC 7670.
        RawPublicKey = 15,
    }
}

// --- Security Protocol Identifiers (RFC 7296 section 3.3.1) ------------------

registry! {
    /// IKEv2 security protocol identifiers. RFC 7296 section 3.3.1.
    Ikev2ProtocolId: u8 {
        /// IKE protocol.
        Ike = 1,
        /// AH protocol.
        Ah = 2,
        /// ESP protocol.
        Esp = 3,
        /// FC ESP Header. RFC 4595.
        FcEspHeader = 4,
        /// FC CT Authentication. RFC 4595.
        FcCtAuth = 5,
        /// GIKE_UPDATE. RFC 9838.
        GikeUpdate = 6,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn encryption_aead_classification() {
        assert!(Ikev2EncryptionAlg::AesGcm16.is_aead());
        assert!(Ikev2EncryptionAlg::ChaCha20Poly1305.is_aead());
        assert!(!Ikev2EncryptionAlg::AesCbc.is_aead());
        assert!(!Ikev2EncryptionAlg::TripleDes.is_aead());
    }

    #[test]
    fn notify_error_classification() {
        assert!(Ikev2NotifyType::NoProposalChosen.is_error());
        assert!(Ikev2NotifyType::InvalidKePayload.is_error());
        assert!(!Ikev2NotifyType::Cookie.is_error());
        assert!(!Ikev2NotifyType::NatDetectionSourceIp.is_error());
    }

    #[test]
    fn transform_type_round_trip() {
        for val in 1..=5 {
            let tt = Ikev2TransformType::from(val);
            let back: u8 = tt.into();
            assert_eq!(val, back);
        }
    }
}
