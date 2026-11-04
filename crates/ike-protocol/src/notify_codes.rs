//! IKEv1 and IKEv2 notification/error message codes.
//!
//! IKEv1: RFC 2408 section 3.14.1 + RFC 2407 section 4.6.3.
//! IKEv2: RFC 7296 section 3.10.1 (see [`crate::ikev2::model::Ikev2NotifyType`]).

use crate::registry;

registry! {
    /// IKEv1 notification message types. RFC 2408 section 3.14.1 + RFC 2407 section 4.6.3.
    Ikev1NotifyType: u16 {
        /// Invalid Payload Type.
        InvalidPayloadType = 1,
        /// DOI Not Supported.
        DoiNotSupported = 2,
        /// Situation Not Supported.
        SituationNotSupported = 3,
        /// Invalid Cookie.
        InvalidCookie = 4,
        /// Invalid Major Version.
        InvalidMajorVersion = 5,
        /// Invalid Minor Version.
        InvalidMinorVersion = 6,
        /// Invalid Exchange Type.
        InvalidExchangeType = 7,
        /// Invalid Flags.
        InvalidFlags = 8,
        /// Invalid Message ID.
        InvalidMessageId = 9,
        /// Invalid Protocol ID.
        InvalidProtocolId = 10,
        /// Invalid SPI.
        InvalidSpi = 11,
        /// Invalid Transform ID.
        InvalidTransformId = 12,
        /// Attributes Not Supported.
        AttributesNotSupported = 13,
        /// No Proposal Chosen.
        NoProposalChosen = 14,
        /// Bad Proposal Syntax.
        BadProposalSyntax = 15,
        /// Payload Malformed.
        PayloadMalformed = 16,
        /// Invalid Key Information.
        InvalidKeyInformation = 17,
        /// Invalid ID Information.
        InvalidIdInformation = 18,
        /// Invalid Cert Encoding.
        InvalidCertEncoding = 19,
        /// Invalid Certificate.
        InvalidCertificate = 20,
        /// Cert Type Unsupported.
        CertTypeUnsupported = 21,
        /// Invalid Cert Authority.
        InvalidCertAuthority = 22,
        /// Invalid Hash Information.
        InvalidHashInformation = 23,
        /// Authentication Failed.
        AuthenticationFailed = 24,
        /// Invalid Signature.
        InvalidSignature = 25,
        /// Address Notification.
        AddressNotification = 26,
        /// Notify SA Lifetime.
        NotifySaLifetime = 27,
        /// Certificate Unavailable.
        CertificateUnavailable = 28,
        /// Unsupported Exchange Type.
        UnsupportedExchangeType = 29,
        /// Unequal Payload Lengths.
        UnequalPayloadLengths = 30,
        /// --- ISAKMP Status (RFC 2408 section 3.14.1) ---
        /// Connected.
        Connected = 16384,
        /// --- IPsec DOI (RFC 2407 section 4.6.3) ---
        /// Responder Lifetime.
        ResponderLifetime = 24576,
        /// Replay Status.
        ReplayStatus = 24577,
        /// Initial Contact.
        InitialContact = 24578,
    }
}
