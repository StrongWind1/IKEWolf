<h1 align="center">IKEWolf</h1>

<p align="center"><strong>Find IPsec VPNs. Enumerate what they accept. Pull Aggressive Mode PSK hashes for hashcat.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/IKEWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/IKEWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.95-informational" alt="MSRV 1.95"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> &bull;
  <a href="#quick-start">Quick start</a> &bull;
  <a href="#comparison-with-ike-scan">Comparison with ike-scan</a>
</p>

---

IKEWolf is a pure-Rust IKE/IPsec scanner: it discovers VPN endpoints, enumerates accepted transforms, collects Vendor ID payloads, and extracts crackable Aggressive Mode PSK hashes (hashcat modes 5300, 5400, and 38100). It replaces ike-scan with an async UDP engine that sweeps whole subnets in one run, modern default transforms, and SHA-256 hash support.

## Example

```sh
ikewolf scan 10.0.0.1 --psk --id vpngroup --json results.json
jq -r '.hosts[].psk_hashes[].hashcat_line' results.json > hashes.txt
hashcat -m 5400 hashes.txt wordlist.txt
```

Each hash is nine colon-separated hex fields, the format hashcat and ike-scan's `psk-crack` read. Pick the hashcat mode from the HASH_R type: 5300 for MD5, 5400 for SHA1, 38100 for SHA-256. The JSON records it per hash in `hashcat_mode`.

## Features

- **IKEv1 Main Mode scanning**: enumerates accepted encryption, hash, auth, and DH group combinations.
- **Aggressive Mode PSK extraction**: crackable HASH_R in hashcat / `psk-crack` format, including the 32-byte SHA-256 HASH_R that ike-scan cannot handle, across a whole subnet in one run.
- **IKEv2 IKE_SA_INIT scanning**: enumerates modern cipher suites and detects COOKIE challenges and INVALID_KE responses.
- **Vendor ID collection**: captures raw Vendor ID payloads for implementation identification.
- **Group name enumeration**: `enum-groups` sends one Aggressive Mode probe per name in a wordlist; valid names get a full SA + KE + HASH_R response.
- **Modern defaults**: AES + SHA-256 + DH group 14 out of the box (not ike-scan's DES+3DES).
- **Async UDP engine**: one socket, cookie-demultiplexed, with configurable concurrency, rate limiting, and a live progress bar with response count and ETA.
- **Input and output**: targets as IPs, CIDRs, or a file (`-f`, with comment and blank-line support); results to the console, a JSON file for pipelines (`--json`), a text file (`-o`), or an `ip:hash` list (`--hashes`).

## Installation

IKEWolf is not on crates.io and has no prebuilt releases. Build it from source with Rust 1.95 or newer:

```sh
cargo install --git https://github.com/StrongWind1/IKEWolf
```

Or from a clone (the binary lands in `target/release/ikewolf`):

```sh
git clone https://github.com/StrongWind1/IKEWolf.git && cd IKEWolf && make build
```

## Quick start

```sh
# Scan a single target (IKEv1 + IKEv2)
ikewolf scan 192.168.1.1

# Scan a subnet with PSK extraction
ikewolf scan 10.0.0.0/24 --psk --id vpngroup

# Aggressive Mode with a custom group name and ID type
ikewolf scan 10.0.0.1 --aggressive --id "CompanyVPN" --id-type fqdn

# IKEv2 only, JSON results to a file
ikewolf scan 10.0.0.1 --ikev2 --json results.json

# Targets from a file, 500 packets/s, 1000 ms timeout, 1024 probes in flight
ikewolf scan -f targets.txt --rate 500 -t 1000 -c 1024

# Enumerate valid VPN group names from a wordlist
ikewolf enum-groups 10.0.0.1 -w groups.txt
```

Add `-v`, `-vv`, or `-vvv` for more logging. `ikewolf scan --help` and `ikewolf enum-groups --help` list every flag.

## Comparison with ike-scan

| Feature | ike-scan | IKEWolf |
| --- | --- | --- |
| Default transforms | DES+3DES only | AES+SHA2+DH14 |
| SHA-256 PSK | Broken | Full support |
| IKEv2 | "Experimental" | Full IKE_SA_INIT |
| Multi-target PSK | Single target only | Native multi-target |
| Performance | Single-threaded | Async, configurable concurrency |
| Output | Custom text | Console + JSON |
| Progress | None | Progress bar + ETA |
| Language | C | Rust (no C deps) |

## Credits

IKEWolf implements these specifications:

- RFC 2408: ISAKMP (framing, header, payload types)
- RFC 2409: IKEv1 (Main Mode, Aggressive Mode, SKEYID/HASH_R)
- RFC 2407: IPsec DOI (transform IDs, attribute encoding)
- RFC 7296: IKEv2 (IKE_SA_INIT, SA encoding, notifications)
- RFC 3526: MODP DH groups
- RFC 5903: ECP DH groups
- RFC 3947: NAT-T
- RFC 4868: HMAC-SHA-256/384/512 for IKE

## Related tools

- [**NFSWolf**](https://github.com/StrongWind1/NFSWolf): Native NFSv2/v3/v4 recon, enumeration, exploitation, and interactive shell

All tools: [strongwind.dev](https://strongwind.dev)

## Disclaimer

IKEWolf is for authorized security testing, research, and education. Use it only against systems and data you own or have written permission to test. You are responsible for how you use it.

## License

[Apache License 2.0](LICENSE)
