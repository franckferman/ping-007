# PING-007 Key Exchange Implementation

## Current Problem

Without password, each instance generates random keys independently:
- Sender: random key A
- Receiver: random key B (≠ A)
- Result: Communication impossible

## Solutions

### 1. ECDH Key Exchange (Recommended)
```
Phase 1: Key Agreement
Sender → Receiver: ICMP packet with ECDH public key
Receiver → Sender: ICMP packet with ECDH public key
Both: Compute shared secret using ECDH

Phase 2: Secure Communication  
Sender ↔ Receiver: Normal encrypted ICMP with derived shared key
```

### 2. Pre-shared Key File
```bash
# Generate once
ping-007 keygen --output shared.key

# Use everywhere
ping-007 basic -t target --keyfile shared.key
ping-007 listen --keyfile shared.key
```

### 3. RSA Key Exchange
```
Phase 1: RSA Exchange
Sender → Receiver: RSA public key in ICMP
Receiver: Generate AES key, encrypt with RSA public key
Receiver → Sender: Encrypted AES key in ICMP
Both: Use exchanged AES key

Phase 2: Secure Communication
Sender ↔ Receiver: AES encrypted ICMP
```

## Implementation Plan

### Phase 1: Add keyfile support (Easy)
```bash
# Add flags:
--keyfile string    # Path to pre-shared key file
--generate-key      # Generate new key file
```

### Phase 2: ECDH exchange (Medium)
```bash
# Add flags:
--key-exchange      # Enable automatic key exchange
--kx-timeout 10s    # Key exchange timeout
```

### Phase 3: Advanced features (Hard)
```bash
# Add flags:
--kx-method ecdh    # Key exchange method (ecdh, rsa)
--forward-secrecy   # Enable perfect forward secrecy
```

## Quick Implementation: Keyfile Support

Add to main.go:
```go
cmd.Flags().String("keyfile", "", "path to pre-shared key file")
cmd.Flags().Bool("generate-key", false, "generate new key file")
```

Add to crypto providers:
```go
func (p *Provider) LoadKeyFile(path string) error {
    keyData, err := os.ReadFile(path)
    if err != nil {
        return fmt.Errorf("failed to read key file: %w", err)
    }
    
    if len(keyData) != 32 {
        return fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(keyData))
    }
    
    copy(p.key[:], keyData)
    return nil
}
```