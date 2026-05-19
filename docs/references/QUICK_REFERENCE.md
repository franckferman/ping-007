# PING-007 Quick Reference

## Rapid Usage (Makefile)
```bash
make basic TARGET=192.168.1.100 PASSWORD='secret123'
make ultra-stealth TARGET=test-environment.local PASSWORD='ops2024'
make ghost-mode TARGET=target.local PASSWORD='stealth'
```

## Custom Usage (Direct Flags)
```bash
sudo ./build/ping-007 basic --target IP --password PWD [OPTIONS]
```

## Available Flags

### Basic Command
- `-t, --target string` : Target IP address (REQUIRED)
- `-d, --data string` : Data to transmit
- `-p, --password string` : Shared password for encryption
- `-s, --stealth` : Stealth mode (mimics legitimate ping)
- `--signature string` : OS signature (linux, windows, none)
- `--no-signature` : Disable OS signature mimicking
- `--delay duration` : Delay before transmission (ex: 2s, 500ms)
- `--human-timing` : Random human timing (1-5s)
- `--ultra-stealth` : Maximum evasion
- `-i, --interactive` : Interactive mode

### Global Flags
- `-c, --config string` : Configuration file
- `-v, --verbose` : Verbose output
- `--no-banner` : Suppress banner

## Usage Examples

### Ultra-Custom
```bash
sudo ./build/ping-007 basic \
  --target 10.0.1.50 \
  --data "Custom assessment data" \
  --password "security-assessment-alpha-2024" \
  --signature windows \
  --delay 8s \
  --stealth \
  --ultra-stealth
```

### Test Sequence
```bash
# Test 1: Linux signature with delay
sudo ./build/ping-007 basic -t 192.168.1.100 -p "test123" --signature linux --delay 2s

# Test 2: Windows signature with human timing
sudo ./build/ping-007 basic -t 192.168.1.100 -p "test123" --signature windows --human-timing

# Test 3: Raw ICMP ultra-stealth
sudo ./build/ping-007 basic -t 192.168.1.100 -p "test123" --no-signature --ultra-stealth
```

### Custom Listener
```bash
sudo ./build/ping-007 listen \
  --output ./custom_output \
  --interface eth1 \
  --timeout 300 \
  --password "listener-key-2024"
```

## Makefile + Variables Combination
```bash
# Use Makefile with custom parameters
make basic TARGET=192.168.1.100 PASSWORD='custom' SIGNATURE='windows' DELAY='5s'
```