# PING-007 Diffie-Hellman Key Exchange Implementation

## ECDH Key Exchange via ICMP

### Phase 1: Key Agreement Protocol

```
Alice (Sender)                           Bob (Receiver)
   |                                          |
   |  1. Generate ECDH keypair               |  1. Start listener with --key-exchange
   |     (private_A, public_A)               |
   |                                          |
   |  2. ICMP KX_REQUEST                     |
   |     [public_A | nonce_A | timestamp]    |
   |  ----------------------------------------> |
   |                                          |  2. Generate ECDH keypair
   |                                          |     (private_B, public_B)
   |                                          |
   |  3. ICMP KX_RESPONSE                    |
   |     [public_B | nonce_B | timestamp]    |
   |  <---------------------------------------- |
   |                                          |
   |  4. Compute shared_secret               |  3. Compute shared_secret
   |     = ECDH(private_A, public_B)         |     = ECDH(private_B, public_A)
   |                                          |
   |  5. Derive AES key                      |  4. Derive same AES key
   |     key = HKDF(shared_secret)           |     key = HKDF(shared_secret)
   |                                          |
```

### Phase 2: Secure Communication

```
Alice                                    Bob
   |                                          |
   |  ICMP DATA (encrypted with derived key)  |
   |  ----------------------------------------> |
   |                                          |
   |  ICMP DATA (encrypted with derived key)  |
   |  <---------------------------------------- |
```

## Implementation Plan

### 1. Add ECDH Support to main.go

```go
// Add to basic command flags
cmd.Flags().Bool("key-exchange", false, "enable automatic ECDH key exchange")
cmd.Flags().Duration("kx-timeout", 30*time.Second, "key exchange timeout")

// Add to listen command flags  
cmd.Flags().Bool("key-exchange", false, "accept ECDH key exchange requests")
```

### 2. Create Key Exchange Module

```go
// internal/crypto/keyexchange.go
package crypto

import (
    "crypto/ecdh"
    "crypto/rand"
    "crypto/sha256"
    "golang.org/x/crypto/hkdf"
)

type KeyExchangeManager struct {
    privateKey *ecdh.PrivateKey
    publicKey  *ecdh.PublicKey
    curve      ecdh.Curve
}

func NewKeyExchangeManager() (*KeyExchangeManager, error) {
    curve := ecdh.P256() // NIST P-256
    privateKey, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }
    
    return &KeyExchangeManager{
        privateKey: privateKey,
        publicKey:  privateKey.PublicKey(),
        curve:      curve,
    }, nil
}

func (kxm *KeyExchangeManager) ComputeSharedSecret(peerPublicKey []byte) ([]byte, error) {
    peerKey, err := kxm.curve.NewPublicKey(peerPublicKey)
    if err != nil {
        return nil, err
    }
    
    sharedSecret, err := kxm.privateKey.ECDH(peerKey)
    if err != nil {
        return nil, err
    }
    
    // Derive 256-bit key using HKDF
    hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("ping007-v2"))
    derivedKey := make([]byte, 32)
    if _, err := hkdf.Read(derivedKey); err != nil {
        return nil, err
    }
    
    return derivedKey, nil
}

func (kxm *KeyExchangeManager) GetPublicKeyBytes() []byte {
    return kxm.publicKey.Bytes()
}
```

### 3. ICMP Key Exchange Packets

```go
// internal/network/keyexchange.go
package network

type KXPacketType uint8

const (
    KX_REQUEST  KXPacketType = 1
    KX_RESPONSE KXPacketType = 2
    KX_CONFIRM  KXPacketType = 3
)

type KXPacket struct {
    Type      KXPacketType
    PublicKey []byte    // 65 bytes for P-256 uncompressed
    Nonce     [16]byte  // Random nonce
    Timestamp int64     // Unix timestamp
    Signature []byte    // Optional: HMAC for authenticity
}

func (pb *PacketBuilder) CreateKXPacket(kxType KXPacketType, publicKey []byte) (*types.NetworkPacket, error) {
    packet := &KXPacket{
        Type:      kxType,
        PublicKey: publicKey,
        Timestamp: time.Now().Unix(),
    }
    
    // Generate random nonce
    if _, err := rand.Read(packet.Nonce[:]); err != nil {
        return nil, err
    }
    
    // Serialize packet
    data, err := packet.Marshal()
    if err != nil {
        return nil, err
    }
    
    icmpPacket := pb.CreateDataPacket(data, "key-exchange")
    icmpPacket.Headers["kx_type"] = kxType
    
    return icmpPacket, nil
}
```

### 4. Integration with Orchestrator

```go
// internal/orchestrator/keyexchange.go
func (o *Orchestrator) PerformKeyExchange(target string, timeout time.Duration) error {
    // 1. Create key exchange manager
    kxManager, err := crypto.NewKeyExchangeManager()
    if err != nil {
        return err
    }
    
    // 2. Send KX_REQUEST
    kxPacket, err := o.packetBuilder.CreateKXPacket(network.KX_REQUEST, kxManager.GetPublicKeyBytes())
    if err != nil {
        return err
    }
    
    if err := o.networkService.SendPacket(kxPacket, target); err != nil {
        return err
    }
    
    // 3. Wait for KX_RESPONSE
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    
    response, err := o.waitForKXResponse(ctx)
    if err != nil {
        return err
    }
    
    // 4. Compute shared secret
    sharedSecret, err := kxManager.ComputeSharedSecret(response.PublicKey)
    if err != nil {
        return err
    }
    
    // 5. Set derived key as password
    keyHex := fmt.Sprintf("ecdh:%x", sharedSecret)
    return o.SetPassword(keyHex)
}

func (o *Orchestrator) HandleKeyExchangeRequest(packet *types.NetworkPacket) error {
    // Parse KX packet
    kxPacket, err := network.ParseKXPacket(packet.Payload)
    if err != nil {
        return err
    }
    
    // Create key exchange manager
    kxManager, err := crypto.NewKeyExchangeManager()
    if err != nil {
        return err
    }
    
    // Send KX_RESPONSE
    responsePacket, err := o.packetBuilder.CreateKXPacket(network.KX_RESPONSE, kxManager.GetPublicKeyBytes())
    if err != nil {
        return err
    }
    
    sourceIP := packet.Metadata.SourceIP
    if err := o.networkService.SendPacket(responsePacket, sourceIP); err != nil {
        return err
    }
    
    // Compute shared secret
    sharedSecret, err := kxManager.ComputeSharedSecret(kxPacket.PublicKey)
    if err != nil {
        return err
    }
    
    // Set derived key as password
    keyHex := fmt.Sprintf("ecdh:%x", sharedSecret)
    return o.SetPassword(keyHex)
}
```

### 5. Usage Examples

```bash
# Automatic key exchange (no pre-shared secret needed)
sudo ./build/ping-007 basic -t 192.168.1.100 -d "test" --key-exchange --kx-timeout 30s

# Receiver with key exchange support
sudo ./build/ping-007 listen -o ./received --key-exchange --timeout 300
```

## Security Properties

### Advantages
- **Perfect Forward Secrecy**: New key per session
- **No Pre-shared Secret**: Automatic negotiation  
- **ECDH Security**: Industry-standard key agreement
- **HKDF Key Derivation**: Proper key expansion
- **Nonce Protection**: Replay attack prevention

### Considerations
- **Active MitM**: Requires cert/signature verification for full security
- **Traffic Analysis**: Key exchange packets visible
- **Timing**: Additional RTT for key agreement

## Implementation Phases

### Phase 1: Basic ECDH (1-2 days)
- [ ] Add keyexchange.go module
- [ ] Create KX packet types
- [ ] Basic ECDH handshake
- [ ] Integration with existing crypto

### Phase 2: Advanced Features (2-3 days)
- [ ] Signature verification
- [ ] Perfect forward secrecy
- [ ] Key rotation support
- [ ] Error handling & fallback

### Phase 3: Production Ready (1 day)
- [ ] Comprehensive testing
- [ ] Documentation
- [ ] Performance optimization
- [ ] Security audit

**Total: ~5 days for complete ECDH implementation**