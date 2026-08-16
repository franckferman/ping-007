# PING-007 — Roadmap

Current release: **v3.0.1** · 250 tests · Go 1.25+

---

## Next

### ICMPv6 support
ICMP transport is currently hardcoded to `ip4:icmp`. IPv6-only networks and dual-stack targets are not reachable.

- Abstract socket creation behind `newConn(network string)` — `ip4:icmp` or `ip6:ipv6-icmp`
- Global `--ipv6 / -6` flag to switch transport
- ICMPv6 checksum uses pseudo-header (src/dst IPv6 + next-header 58)
- Hop Limit (`IPV6_UNICAST_HOPS`) replaces TTL — same values (64/128) apply
- Auto-detect from target address family when no flag is given

### Certificate-based auth + ECDH key exchange
Password mode (`-p`) embeds a fixed shared secret with no expiry and no forward secrecy.

- `ping-007 keygen --op fra1-c2 --ttl 48h` — emit ECDSA P-256 keypair with hard Not-After
- `listen --cert fra1-c2.crt` / `exfil --key fra1-c2.key`
- Session key = HKDF(ECDH shared secret) — never stored, never in the binary
- Revocation: destroy the key file → all in-transit captures become undecryptable
- KX handshake fragmented across standard 64B ICMP packets (same CX mechanism)
- Password mode remains the default; cert mode is opt-in via `--key`/`--cert`

### Multi-target orchestration (`orchestra` command)
- Coordinated C2 across a list of agents (`--targets hosts.txt`)
- Synchronized command execution, results aggregation
- `--max-concurrent` for resource control

### Windows end-to-end validation
Cross-compiled binaries exist. Raw socket receive path is untested on Windows.

- End-to-end exfil + listen test on Windows 10/11
- `SIO_RCVALL` vs `IPPROTO_IP / IP_HDRINCL` behaviour differences
- Windows Defender evasion notes in documentation

---

## Done

- OS signature mimicry: exact Linux (64B) and Windows (40B) packet format
- AES-256-GCM / ChaCha20-Poly1305 / XOR-CFB-HMAC with PBKDF2-SHA256 (100k iter)
- Per-session algorithm rotation, random nonce; OS-native ICMP ID (PID on Linux / 0x0001 on Windows) + seq start at 1
- `--icmp-id` flag: override ICMP identifier (os / random / 0-65535)
- 16B struct timeval (64-bit Linux) + payload pattern starts at 0x10 — byte-identical to iputils ping
- File exfiltration with steganographic fragmentation across N×64B pings
- Bidirectional C2 shell over ICMP
- APT timing profiles: Lazarus, APT29, APT28, Equation Group
- Sandbox detection (uptime, process count, resources)
- Decoy pings, after-pings, human timing, shell jitter
- `--quiet` listener mode (OPSEC: suppress stdout during live ops)
- Build variants: standard / stealth / ghost / no-c2 / compressed / armored / all-platforms
- 250 tests, `-race` clean, no root or network required for test suite
