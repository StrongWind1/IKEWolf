//! Pure-Rust IKEv1/IKEv2 wire types for the IKE protocol suite.
//!
//! This crate owns the wire format: ISAKMP headers, payload chaining, SA
//! proposals, transforms, vendor IDs, and PSK hash extraction. It has no
//! I/O, no async runtime, and no scanning policy. The binary crate
//! (`ikewolf`) provides the async UDP scanner on top.
//!
//! # Governing specifications
//!
//! - RFC 2408 -- ISAKMP (framing, header, payload types)
//! - RFC 2409 -- IKEv1 (Main Mode, Aggressive Mode, SKEYID/HASH_R)
//! - RFC 2407 -- IPsec DOI (transform IDs, attribute encoding)
//! - RFC 7296 -- IKEv2 (IKE_SA_INIT, SA encoding, notifications)
//! - RFC 3526 -- MODP DH Groups (primes for groups 5, 14-18)
//! - RFC 5903 -- ECP DH Groups (groups 19-21)
//! - RFC 3947 -- NAT-T (NAT detection in IKE)
//! - RFC 4868 -- HMAC-SHA-256/384/512 for IKE

#![forbid(unsafe_code)]

pub mod attribute;
pub mod header;
pub mod ikev1;
pub mod ikev2;
pub mod notify_codes;
pub mod payload;
pub mod vendor;

/// Declares a wire registry: an enum of the values a field is known to take,
/// plus a fallback variant so unknown values survive a decode/encode cycle
/// unchanged. Both `From<repr>` conversions are generated automatically.
///
/// Adapted from ancwrd1/isakmp's `registry!` macro. The fallback variant is
/// named `Other` unless overridden with `as FallbackName`.
///
/// # Example
///
/// ```ignore
/// registry! {
///     /// Exchange types, RFC 7296 section 3.1.
///     ExchangeType: u8 {
///         IkeSaInit = 34,
///         IkeAuth = 35,
///     }
/// }
/// ```
macro_rules! registry {
    (
        $(#[$meta:meta])* $name:ident : $repr:ty as $fallback:ident {
            $($(#[$vmeta:meta])* $variant:ident = $value:expr),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)*
            /// Unknown value not in the registry.
            $fallback($repr),
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    $(Self::$variant => write!(f, stringify!($variant)),)*
                    Self::$fallback(v) => write!(f, "{}({})", stringify!($fallback), v),
                }
            }
        }

        impl From<$repr> for $name {
            fn from(value: $repr) -> Self {
                match value {
                    $($value => Self::$variant,)*
                    other => Self::$fallback(other),
                }
            }
        }

        impl From<$name> for $repr {
            fn from(value: $name) -> Self {
                match value {
                    $($name::$variant => $value,)*
                    $name::$fallback(other) => other,
                }
            }
        }

        impl $name {
            /// All known variants in this registry (excludes the fallback).
            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[$(Self::$variant,)*]
            }
        }
    };

    (
        $(#[$meta:meta])* $name:ident : $repr:ty {
            $($(#[$vmeta:meta])* $variant:ident = $value:expr),* $(,)?
        }
    ) => {
        registry! {
            $(#[$meta])* $name : $repr as Other {
                $($(#[$vmeta])* $variant = $value),*
            }
        }
    };
}

pub(crate) use registry;
