# Changelog

## 0.1.0 (unreleased)

Initial release.

### Features

- IKEv1 Main Mode scanning with modern default transforms (AES+SHA2+DH14)
- IKEv1 Aggressive Mode PSK hash extraction (hashcat 5300/5400/38100)
- IKEv2 IKE_SA_INIT scanning with COOKIE and INVALID_KE detection
- SHA-256/384/512 PSK hash support (beyond ike-scan's MD5+SHA1)
- Multi-target PSK extraction (subnet scanning)
- Async UDP scanner engine with configurable concurrency and rate limiting
- Exponential backoff retransmission
- Progress bar with live response count
- JSON output for pipeline integration
- Console output with colored status lines
- CIDR target parsing with deduplication
- Target file input (`-f`) with comment and blank-line support
- Configurable ID payload type (`--id-type`) for Aggressive Mode
- Vendor ID payload collection
- Notification payload parsing (v1 + v2)
- Shell completion generation (bash, zsh, fish, powershell)

### Protocol Crate (ike-protocol)

- ISAKMP/IKEv2 28-byte header parse/build
- Generic payload header with chaining
- Data attribute TV/TLV encoding
- IKEv1 registries: 8 encryption algorithms, 6 hash algorithms, 22 auth methods (incl. XAUTH/Hybrid), 32 DH groups, 11 ID types
- IKEv2 registries: 16 encryption algorithms (incl. AEAD), 8 PRF algorithms, 15 integrity algorithms, 25 notification types
- SA/Proposal/Transform build+parse for both IKEv1 and IKEv2
- PSK hash extraction with hashcat and psk-crack format output
