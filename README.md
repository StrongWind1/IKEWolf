# IKEWolf

Pure-Rust IKE/IPsec security scanner for authorized penetration testing.

IKEWolf discovers VPN endpoints, enumerates accepted transforms, collects vendor ID payloads, and extracts crackable Aggressive Mode PSK hashes (hashcat modes 5300/5400/38100) -- all at fleet scale via async UDP.

## Features

- **IKEv1 Main Mode scanning** -- enumerate accepted encryption, hash, auth, and DH group combinations
- **IKEv1 Aggressive Mode PSK extraction** -- extract crackable HASH_R in hashcat/psk-crack format
- **IKEv2 IKE_SA_INIT scanning** -- enumerate modern cipher suites, detect COOKIE challenges and INVALID_KE responses
- **Vendor ID collection** -- capture raw Vendor ID payloads for implementation identification
- **Modern defaults** -- AES + SHA-256 + DH group 14 out of the box (not ike-scan's DES+3DES)
- **SHA-256 PSK support** -- crack 32-byte HASH_R that ike-scan cannot handle
- **Multi-target PSK extraction** -- sweep entire subnets for crackable hashes in one run
- **Async UDP engine** -- single-socket, cookie-demuxed, with configurable concurrency and rate limiting
- **Progress bar** -- live response count and ETA
- **JSON output** -- machine-parseable results for pipeline integration
- **Target file input** -- read targets from a file with comment and blank-line support

## Installation

### Pre-built binaries

Download from [Releases](https://github.com/StrongWind1/IKEWolf/releases).

### From source

```bash
cargo install ikewolf
```

### Build from repository

```bash
git clone https://github.com/StrongWind1/IKEWolf.git
cd IKEWolf
make build
```

## Usage

```bash
# Scan a single target (IKEv1 + IKEv2)
ikewolf scan 192.168.1.1

# Scan a subnet with PSK extraction
ikewolf scan 10.0.0.0/24 --psk --id vpngroup

# Aggressive Mode with custom group name and ID type
ikewolf scan 10.0.0.1 --aggressive --id "CompanyVPN" --id-type fqdn

# IKEv2 only, JSON output
ikewolf scan 10.0.0.1 --ikev2 --json

# Read targets from a file
ikewolf scan -f targets.txt --psk --id vpngroup

# Rate-limited scan with custom timeout and concurrency
ikewolf scan 10.0.0.0/16 --rate 500 -t 1000 -c 1024

# Verbose output
ikewolf scan 10.0.0.1 -vv
```

## Hashcat Integration

IKEWolf outputs hashes in hashcat-compatible format (9 colon-separated hex fields):

```bash
# Extract PSK hashes
ikewolf scan 10.0.0.1 --psk --json | jq -r '.hosts[].psk_hash.hashcat_line' > hashes.txt

# Crack with hashcat
hashcat -m 5300 hashes.txt wordlist.txt   # MD5
hashcat -m 5400 hashes.txt wordlist.txt   # SHA1
hashcat -m 38100 hashes.txt wordlist.txt  # SHA256
```

## Comparison with ike-scan

| Feature | ike-scan | IKEWolf |
|---------|----------|---------|
| Default transforms | DES+3DES only | AES+SHA2+DH14 |
| SHA-256 PSK | Broken | Full support |
| IKEv2 | "Experimental" | Full IKE_SA_INIT |
| Multi-target PSK | Single target only | Native multi-target |
| Performance | Single-threaded | Async, configurable concurrency |
| Output | Custom text | Console + JSON |
| Progress | None | Progress bar + ETA |
| Language | C | Rust (no C deps) |

## Governing Specifications

- RFC 2408 -- ISAKMP (framing, header, payload types)
- RFC 2409 -- IKEv1 (Main Mode, Aggressive Mode, SKEYID/HASH_R)
- RFC 2407 -- IPsec DOI (transform IDs, attribute encoding)
- RFC 7296 -- IKEv2 (IKE_SA_INIT, SA encoding, notifications)
- RFC 3526 -- MODP DH Groups
- RFC 5903 -- ECP DH Groups
- RFC 3947 -- NAT-T
- RFC 4868 -- HMAC-SHA-256/384/512 for IKE

## Legal

For authorized security testing only. Unauthorized scanning of networks you do not own or have written permission to test is illegal in most jurisdictions.

## License

Apache-2.0
