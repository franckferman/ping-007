package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"ping007/pkg/types"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// generateAAD creates Additional Associated Data from contextual information
func generateAAD(context *ContextualData) []byte {
	if context == nil {
		return nil
	}

	// Create deterministic AAD from available context
	aad := fmt.Sprintf("ping007|%s|%s|%s|%d|%d|%s",
		context.TargetIP,
		context.SourceIP,
		context.SessionID,
		context.SequenceID,
		context.Timestamp,
		context.PacketType)

	return []byte(aad)
}

// encodeCryptoHeader encodes a crypto header into 4 bytes
func encodeCryptoHeader(algorithm uint8) []byte {
	header := CryptoHeader{
		Algorithm: algorithm,
		Version:   1,  // Protocol version 1
		Reserved:  [2]byte{0, 0},
	}

	encoded := make([]byte, 4)
	encoded[0] = header.Algorithm
	encoded[1] = header.Version
	encoded[2] = header.Reserved[0]
	encoded[3] = header.Reserved[1]

	return encoded
}

// decodeCryptoHeader decodes a crypto header from 4 bytes
func decodeCryptoHeader(data []byte) (*CryptoHeader, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("header too short: %d bytes", len(data))
	}

	header := &CryptoHeader{
		Algorithm: data[0],
		Version:   data[1],
		Reserved:  [2]byte{data[2], data[3]},
	}

	// Validate algorithm
	switch header.Algorithm {
	case AlgorithmAES256, AlgorithmChaCha20, AlgorithmCustomXOR:
		// Valid algorithms
	default:
		return nil, fmt.Errorf("unknown algorithm: %d", header.Algorithm)
	}

	// Validate version
	if header.Version != 1 {
		return nil, fmt.Errorf("unsupported version: %d", header.Version)
	}

	return header, nil
}

// algorithmFromType converts types.CryptoAlgorithm to header algorithm ID
func algorithmFromType(alg types.CryptoAlgorithm) uint8 {
	switch alg {
	case types.CryptoAES256:
		return AlgorithmAES256
	case types.CryptoChaCha20:
		return AlgorithmChaCha20
	case types.CryptoCustomXOR:
		return AlgorithmCustomXOR
	default:
		return 0 // Unknown
	}
}

// typeFromAlgorithm converts header algorithm ID to types.CryptoAlgorithm
func typeFromAlgorithm(alg uint8) types.CryptoAlgorithm {
	switch alg {
	case AlgorithmAES256:
		return types.CryptoAES256
	case AlgorithmChaCha20:
		return types.CryptoChaCha20
	case AlgorithmCustomXOR:
		return types.CryptoCustomXOR
	default:
		return ""
	}
}

// NonceManager provides collision-resistant nonce generation
// Uses hybrid counter+random approach to eliminate birthday bound collision risk
type NonceManager struct {
	counter uint64    // Incrementing counter
	mu      sync.Mutex // Thread-safe counter access
}

// NewNonceManager creates a new nonce manager
func NewNonceManager() *NonceManager {
	return &NonceManager{
		counter: 0,
	}
}

// GenerateNonce creates a collision-resistant nonce
// Format: [8B counter][4B random] for 12-byte nonces (GCM standard)
// This eliminates birthday bound collision risk completely
func (nm *NonceManager) GenerateNonce() ([]byte, error) {
	nm.mu.Lock()
	nm.counter++
	counter := nm.counter
	nm.mu.Unlock()

	nonce := make([]byte, 12)

	// First 8 bytes: incrementing counter (ensures uniqueness)
	binary.BigEndian.PutUint64(nonce[0:8], counter)

	// Last 4 bytes: cryptographically secure random (adds unpredictability)
	if _, err := rand.Read(nonce[8:12]); err != nil {
		return nil, fmt.Errorf("failed to generate random component: %w", err)
	}

	return nonce, nil
}

// GenerateNonceSize creates a nonce of specified size
func (nm *NonceManager) GenerateNonceSize(size int) ([]byte, error) {
	if size < 8 {
		return nil, fmt.Errorf("nonce size too small: %d (minimum 8 for counter)", size)
	}

	nm.mu.Lock()
	nm.counter++
	counter := nm.counter
	nm.mu.Unlock()

	nonce := make([]byte, size)

	// First 8 bytes: incrementing counter
	binary.BigEndian.PutUint64(nonce[0:8], counter)

	// Remaining bytes: cryptographically secure random
	if size > 8 {
		if _, err := rand.Read(nonce[8:]); err != nil {
			return nil, fmt.Errorf("failed to generate random component: %w", err)
		}
	}

	return nonce, nil
}

// Reset resets the counter (useful for key rotation)
func (nm *NonceManager) Reset() {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.counter = 0
}

// CryptoEngine handles encryption with algorithm rotation
type CryptoEngine struct {
	providers       map[types.CryptoAlgorithm]CryptoProvider
	activeAlgorithm types.CryptoAlgorithm
	rotationTicker  *time.Ticker
	config          CryptoConfig
	mu              sync.RWMutex
}

type CryptoConfig struct {
	Enabled          bool
	Algorithms       []string
	RotationInterval time.Duration
	DefaultAlgorithm string
	SharedPassword   string // Password for key derivation - if empty, generates random keys
}

// CryptoHeader represents algorithm identification in encrypted packets
type CryptoHeader struct {
	Algorithm uint8     // Algorithm ID: AES=1, ChaCha20=2, XOR=3
	Version   uint8     // Protocol version for future compatibility
	Reserved  [2]byte   // Padding for 4-byte alignment
}

// Algorithm constants for CryptoHeader
const (
	AlgorithmAES256    uint8 = 1
	AlgorithmChaCha20  uint8 = 2
	AlgorithmCustomXOR uint8 = 3
)

// ContextualData represents metadata for authenticated encryption
type ContextualData struct {
	TargetIP    string
	SourceIP    string
	SessionID   string
	SequenceID  uint64
	Timestamp   int64
	PacketType  string
}

// CryptoProvider interface for pluggable crypto implementations
type CryptoProvider interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	EncryptWithContext(data []byte, context *ContextualData) ([]byte, error)
	DecryptWithContext(data []byte, context *ContextualData) ([]byte, error)
	KeyRotation() error
	Name() string
	SetPassword(password string) error // Set shared password for key derivation
	Close() error                      // Secure cleanup of cryptographic material
}

func NewCryptoEngine(config CryptoConfig) (*CryptoEngine, error) {
	engine := &CryptoEngine{
		providers: make(map[types.CryptoAlgorithm]CryptoProvider),
		config:    config,
	}

	// Initialize providers
	if err := engine.initializeProviders(); err != nil {
		return nil, fmt.Errorf("failed to initialize crypto providers: %w", err)
	}

	// Set default algorithm
	engine.activeAlgorithm = types.CryptoAlgorithm(config.DefaultAlgorithm)

	// Start rotation if enabled
	if config.Enabled && config.RotationInterval > 0 {
		engine.startKeyRotation()
	}

	return engine, nil
}

// initializeProviders sets up all crypto providers
func (e *CryptoEngine) initializeProviders() error {
	// AES256 Provider
	aesProvider, err := NewAES256Provider()
	if err != nil {
		return fmt.Errorf("failed to create AES256 provider: %w", err)
	}
	if e.config.SharedPassword != "" {
		if err := aesProvider.SetPassword(e.config.SharedPassword); err != nil {
			return fmt.Errorf("failed to set AES256 password: %w", err)
		}
	}
	e.providers[types.CryptoAES256] = aesProvider

	// ChaCha20 Provider
	chachaProvider, err := NewChaCha20Provider()
	if err != nil {
		return fmt.Errorf("failed to create ChaCha20 provider: %w", err)
	}
	if e.config.SharedPassword != "" {
		if err := chachaProvider.SetPassword(e.config.SharedPassword); err != nil {
			return fmt.Errorf("failed to set ChaCha20 password: %w", err)
		}
	}
	e.providers[types.CryptoChaCha20] = chachaProvider

	// Custom XOR Provider
	xorProvider := NewCustomXORProvider()
	if e.config.SharedPassword != "" {
		if err := xorProvider.SetPassword(e.config.SharedPassword); err != nil {
			return fmt.Errorf("failed to set XOR password: %w", err)
		}
	}
	e.providers[types.CryptoCustomXOR] = xorProvider

	return nil
}

// Encrypt encrypts data using the active algorithm
func (e *CryptoEngine) Encrypt(data []byte) ([]byte, error) {
	return e.EncryptWithContext(data, nil)
}

// Decrypt decrypts data using the active algorithm
func (e *CryptoEngine) Decrypt(data []byte) ([]byte, error) {
	return e.DecryptWithContext(data, nil)
}

// EncryptWithContext encrypts data with contextual binding using the active algorithm
func (e *CryptoEngine) EncryptWithContext(data []byte, context *ContextualData) ([]byte, error) {
	e.mu.RLock()
	provider, exists := e.providers[e.activeAlgorithm]
	activeAlgorithm := e.activeAlgorithm
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no provider for algorithm: %s", e.activeAlgorithm)
	}

	// Encrypt data with provider
	encryptedData, err := provider.EncryptWithContext(data, context)
	if err != nil {
		return nil, err
	}

	// Prepend algorithm header for receiver synchronization
	header := encodeCryptoHeader(algorithmFromType(activeAlgorithm))

	// Format: [CryptoHeader 4B][Encrypted Data N bytes]
	result := make([]byte, 4+len(encryptedData))
	copy(result[0:4], header)
	copy(result[4:], encryptedData)

	return result, nil
}

// DecryptWithContext decrypts data with algorithm auto-detection
func (e *CryptoEngine) DecryptWithContext(data []byte, context *ContextualData) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for crypto header")
	}

	// Extract and decode algorithm header
	header, err := decodeCryptoHeader(data[0:4])
	if err != nil {
		return nil, fmt.Errorf("failed to decode crypto header: %w", err)
	}

	// Get provider for detected algorithm
	algorithm := typeFromAlgorithm(header.Algorithm)
	e.mu.RLock()
	provider, exists := e.providers[algorithm]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no provider for detected algorithm: %s", algorithm)
	}

	// Decrypt using detected algorithm
	encryptedData := data[4:] // Skip header
	return provider.DecryptWithContext(encryptedData, context)
}

// DecryptWithAlgorithmDetection attempts to decrypt with automatic algorithm detection
func (e *CryptoEngine) DecryptWithAlgorithmDetection(data []byte, context *ContextualData) ([]byte, types.CryptoAlgorithm, error) {
	if len(data) >= 4 {
		// Try with algorithm header first
		if header, err := decodeCryptoHeader(data[0:4]); err == nil {
			algorithm := typeFromAlgorithm(header.Algorithm)
			if provider, exists := e.providers[algorithm]; exists {
				if decrypted, err := provider.DecryptWithContext(data[4:], context); err == nil {
					return decrypted, algorithm, nil
				}
			}
		}
	}

	// Fallback: try all algorithms (for backward compatibility)
	e.mu.RLock()
	defer e.mu.RUnlock()

	for algorithm, provider := range e.providers {
		// Try legacy decryption (no header)
		if decrypted, err := provider.DecryptWithContext(data, context); err == nil {
			return decrypted, algorithm, nil
		}
	}

	return nil, "", fmt.Errorf("failed to decrypt with any available algorithm")
}

// RotateAlgorithm switches to a different crypto algorithm using cryptographically secure randomness
func (e *CryptoEngine) RotateAlgorithm() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Get available algorithms
	available := make([]types.CryptoAlgorithm, 0, len(e.providers))
	for alg := range e.providers {
		if alg != e.activeAlgorithm {
			available = append(available, alg)
		}
	}

	if len(available) == 0 {
		return fmt.Errorf("no alternative algorithms available")
	}

	// Use cryptographically secure random selection to avoid bias
	index, err := e.secureRandomIndex(len(available))
	if err != nil {
		return fmt.Errorf("failed to generate secure random index: %w", err)
	}

	newAlg := available[index]

	// Rotate keys for new algorithm
	if err := e.providers[newAlg].KeyRotation(); err != nil {
		return fmt.Errorf("key rotation failed for %s: %w", newAlg, err)
	}

	e.activeAlgorithm = newAlg
	return nil
}

// secureRandomIndex generates a cryptographically secure random index without modulo bias
func (e *CryptoEngine) secureRandomIndex(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("invalid max value: %d", max)
	}

	if max == 1 {
		return 0, nil
	}

	// Use rejection sampling to avoid modulo bias
	// Calculate the largest multiple of max that fits in uint32
	maxUint32 := uint32(1<<32 - 1)
	threshold := maxUint32 - (maxUint32 % uint32(max))

	for {
		randomBytes := make([]byte, 4)
		if _, err := rand.Read(randomBytes); err != nil {
			return 0, fmt.Errorf("failed to read random bytes: %w", err)
		}

		randomUint32 := binary.BigEndian.Uint32(randomBytes)

		// Reject values that would cause modulo bias
		if randomUint32 < threshold {
			return int(randomUint32 % uint32(max)), nil
		}
		// Otherwise, try again with new random bytes
	}
}

// startKeyRotation begins automatic key rotation
func (e *CryptoEngine) startKeyRotation() {
	e.rotationTicker = time.NewTicker(e.config.RotationInterval)
	go func() {
		for range e.rotationTicker.C {
			if err := e.RotateAlgorithm(); err != nil {
				// Log error but continue rotation attempts
				fmt.Printf("Crypto rotation failed: %v\n", err)
			}
		}
	}()
}

// Close stops the crypto engine and securely cleans up all providers
func (e *CryptoEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Stop rotation ticker
	if e.rotationTicker != nil {
		e.rotationTicker.Stop()
	}

	// Securely close all crypto providers
	for _, provider := range e.providers {
		if err := provider.Close(); err != nil {
			// Log error but continue cleanup
			fmt.Printf("Warning: failed to close crypto provider %s: %v\n", provider.Name(), err)
		}
	}

	// Clear provider map
	e.providers = make(map[types.CryptoAlgorithm]CryptoProvider)

	return nil
}

// GetActiveAlgorithm returns the current active algorithm
func (e *CryptoEngine) GetActiveAlgorithm() types.CryptoAlgorithm {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeAlgorithm
}

// AES256Provider implements AES-256-GCM encryption
type AES256Provider struct {
	key          []byte
	gcm          cipher.AEAD
	password     string       // Shared password for key derivation
	salt         []byte       // Salt for PBKDF2, fixed per instance for reproducibility
	nonceManager *NonceManager // Collision-resistant nonce generation
	mu           sync.RWMutex
}

// NewAES256Provider creates a new AES256 provider
func NewAES256Provider() (*AES256Provider, error) {
	provider := &AES256Provider{
		salt:         []byte("ping007-aes-salt-v1"), // Fixed salt for reproducible key derivation
		nonceManager: NewNonceManager(),             // Collision-resistant nonce generation
	}
	if err := provider.generateKey(); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *AES256Provider) generateKey() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Generate 256-bit key
	if p.password != "" {
		// Derive key from password using PBKDF2
		p.key = pbkdf2.Key([]byte(p.password), p.salt, 100000, 32, sha256.New)
	} else {
		// Generate random key if no password is set
		p.key = make([]byte, 32)
		if _, err := rand.Read(p.key); err != nil {
			return fmt.Errorf("failed to generate AES key: %w", err)
		}
	}

	// Create AES cipher
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	p.gcm = gcm
	return nil
}

func (p *AES256Provider) Encrypt(data []byte) ([]byte, error) {
	return p.EncryptWithContext(data, nil)
}

func (p *AES256Provider) EncryptWithContext(data []byte, context *ContextualData) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.gcm == nil {
		return nil, fmt.Errorf("AES-GCM not initialized")
	}

	// Generate collision-resistant nonce using counter+random hybrid
	nonce, err := p.nonceManager.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate collision-resistant nonce: %w", err)
	}

	// Generate AAD from contextual data
	aad := generateAAD(context)

	// Encrypt with Additional Associated Data for context binding
	ciphertext := p.gcm.Seal(nonce, nonce, data, aad)
	return ciphertext, nil
}

func (p *AES256Provider) Decrypt(data []byte) ([]byte, error) {
	return p.DecryptWithContext(data, nil)
}

func (p *AES256Provider) DecryptWithContext(data []byte, context *ContextualData) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.gcm == nil {
		return nil, fmt.Errorf("AES-GCM not initialized")
	}

	if len(data) < p.gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:p.gcm.NonceSize()]
	ciphertext := data[p.gcm.NonceSize():]

	// Generate AAD from contextual data (must match encryption)
	aad := generateAAD(context)

	// Decrypt with Additional Associated Data verification
	plaintext, err := p.gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong key or context): %w", err)
	}

	return plaintext, nil
}

func (p *AES256Provider) KeyRotation() error {
	return p.generateKey()
}

func (p *AES256Provider) Name() string {
	return "AES256-GCM"
}

func (p *AES256Provider) SetPassword(password string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Securely zero out old key before generating new one
	p.zeroKey()

	p.password = password

	// Reset nonce counter for new key (important for security)
	p.nonceManager.Reset()

	// Regenerate key with new password
	return p.generateKey()
}

// zeroKey securely clears the AES key from memory
func (p *AES256Provider) zeroKey() {
	for i := range p.key {
		p.key[i] = 0
	}
}

// Close securely clears all cryptographic material
func (p *AES256Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.zeroKey()
	p.password = ""
	p.gcm = nil
	return nil
}

// ChaCha20Provider implements ChaCha20-Poly1305 encryption
type ChaCha20Provider struct {
	aead         cipher.AEAD
	password     string       // Shared password for key derivation
	salt         []byte       // Salt for PBKDF2, fixed per instance for reproducibility
	nonceManager *NonceManager // Collision-resistant nonce generation
	mu           sync.RWMutex
}

// NewChaCha20Provider creates a new ChaCha20 provider
func NewChaCha20Provider() (*ChaCha20Provider, error) {
	provider := &ChaCha20Provider{
		salt:         []byte("ping007-chacha20-salt-v1"), // Fixed salt for reproducible key derivation
		nonceManager: NewNonceManager(),                  // Collision-resistant nonce generation
	}
	if err := provider.generateKey(); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *ChaCha20Provider) generateKey() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var key []byte
	if p.password != "" {
		// Derive key from password using PBKDF2
		key = pbkdf2.Key([]byte(p.password), p.salt, 100000, chacha20poly1305.KeySize, sha256.New)
	} else {
		// Generate random key if no password is set
		key = make([]byte, chacha20poly1305.KeySize)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("failed to generate ChaCha20 key: %w", err)
		}
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("failed to create ChaCha20 cipher: %w", err)
	}

	p.aead = aead
	return nil
}

func (p *ChaCha20Provider) Encrypt(data []byte) ([]byte, error) {
	return p.EncryptWithContext(data, nil)
}

func (p *ChaCha20Provider) EncryptWithContext(data []byte, context *ContextualData) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.aead == nil {
		return nil, fmt.Errorf("ChaCha20-Poly1305 not initialized")
	}

	// Generate collision-resistant nonce using counter+random hybrid
	nonce, err := p.nonceManager.GenerateNonceSize(p.aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("failed to generate collision-resistant nonce: %w", err)
	}

	// Generate AAD from contextual data
	aad := generateAAD(context)

	// Encrypt with Additional Associated Data for context binding
	ciphertext := p.aead.Seal(nonce, nonce, data, aad)
	return ciphertext, nil
}

func (p *ChaCha20Provider) Decrypt(data []byte) ([]byte, error) {
	return p.DecryptWithContext(data, nil)
}

func (p *ChaCha20Provider) DecryptWithContext(data []byte, context *ContextualData) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.aead == nil {
		return nil, fmt.Errorf("ChaCha20-Poly1305 not initialized")
	}

	if len(data) < p.aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:p.aead.NonceSize()]
	ciphertext := data[p.aead.NonceSize():]

	// Generate AAD from contextual data (must match encryption)
	aad := generateAAD(context)

	// Decrypt with Additional Associated Data verification
	plaintext, err := p.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong key or context): %w", err)
	}

	return plaintext, nil
}

func (p *ChaCha20Provider) KeyRotation() error {
	return p.generateKey()
}

func (p *ChaCha20Provider) Name() string {
	return "ChaCha20-Poly1305"
}

func (p *ChaCha20Provider) SetPassword(password string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.password = password

	// Reset nonce counter for new key (important for security)
	p.nonceManager.Reset()

	// Regenerate key with new password
	return p.generateKey()
}

// Close securely clears all cryptographic material
func (p *ChaCha20Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.password = ""
	p.aead = nil
	return nil
}

// CustomXORProvider implements a secure XOR cipher with integrity protection
type CustomXORProvider struct {
	encryptionKey []byte // Key for XOR encryption (32 bytes)
	macKey        []byte // Key for HMAC authentication (32 bytes)
	password      string // Shared password for key derivation
	salt          []byte // Salt for PBKDF2, fixed per instance for reproducibility
	mu            sync.RWMutex
}

func NewCustomXORProvider() *CustomXORProvider {
	provider := &CustomXORProvider{
		salt: []byte("ping007-xor-salt-v1"), // Fixed salt for reproducible key derivation
	}
	provider.generateKey()
	return provider
}

func (p *CustomXORProvider) generateKey() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.password != "" {
		// Derive two separate keys from password using PBKDF2
		// 64 bytes total: 32 for encryption + 32 for HMAC
		masterKey := pbkdf2.Key([]byte(p.password), p.salt, 100000, 64, sha256.New)

		// Split into encryption key and MAC key
		p.encryptionKey = masterKey[:32]
		p.macKey = masterKey[32:64]
	} else {
		// SECURITY FIX: Use crypto/rand instead of timestamp-based key
		// Generate two separate random keys
		p.encryptionKey = make([]byte, 32)
		p.macKey = make([]byte, 32)

		if _, err := rand.Read(p.encryptionKey); err != nil {
			return fmt.Errorf("failed to generate XOR encryption key: %w", err)
		}
		if _, err := rand.Read(p.macKey); err != nil {
			return fmt.Errorf("failed to generate XOR MAC key: %w", err)
		}
	}
	return nil
}

func (p *CustomXORProvider) Encrypt(data []byte) ([]byte, error) {
	return p.EncryptWithContext(data, nil)
}

func (p *CustomXORProvider) EncryptWithContext(data []byte, context *ContextualData) ([]byte, error) {
	p.mu.RLock()
	encKey := p.encryptionKey
	macKey := p.macKey
	p.mu.RUnlock()

	if len(encKey) == 0 || len(macKey) == 0 {
		return nil, fmt.Errorf("encryption keys not initialized")
	}

	// Generate random IV (8 bytes) for cipher feedback mode
	iv := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt using XOR with cipher feedback mode (CFB-like)
	// This prevents frequency analysis by making identical plaintexts produce different ciphertexts
	ciphertext := make([]byte, len(data))
	keystream := iv // Start with IV as initial keystream

	for i := 0; i < len(data); i++ {
		// Update keystream based on previous ciphertext (feedback)
		if i > 0 {
			// Hash previous ciphertext byte with encryption key to generate new keystream
			h := sha256.New()
			h.Write(encKey)
			h.Write([]byte{ciphertext[i-1]})
			h.Write(keystream)
			keystream = h.Sum(nil)[:8] // Use first 8 bytes as keystream
		}

		// XOR with rotating keystream
		keystreamByte := keystream[i%len(keystream)]
		keyByte := encKey[i%len(encKey)]
		ciphertext[i] = data[i] ^ keystreamByte ^ keyByte
	}

	// Calculate HMAC for integrity protection (includes context binding)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(iv)                // Include IV in authentication
	mac.Write(ciphertext)        // Include ciphertext in authentication

	// Include contextual data in HMAC for binding
	if context != nil {
		aad := generateAAD(context)
		mac.Write(aad)
	}

	tag := mac.Sum(nil)[:16]     // Use first 16 bytes as authentication tag

	// Format: [IV 8B][Ciphertext N bytes][HMAC-SHA256 tag 16B]
	result := make([]byte, 8+len(ciphertext)+16)
	copy(result[0:8], iv)
	copy(result[8:8+len(ciphertext)], ciphertext)
	copy(result[8+len(ciphertext):], tag)

	return result, nil
}

func (p *CustomXORProvider) Decrypt(data []byte) ([]byte, error) {
	return p.DecryptWithContext(data, nil)
}

func (p *CustomXORProvider) DecryptWithContext(data []byte, context *ContextualData) ([]byte, error) {
	p.mu.RLock()
	encKey := p.encryptionKey
	macKey := p.macKey
	p.mu.RUnlock()

	if len(encKey) == 0 || len(macKey) == 0 {
		return nil, fmt.Errorf("encryption keys not initialized")
	}

	// Minimum size: IV (8) + at least 1 byte of data + HMAC tag (16) = 25 bytes
	if len(data) < 25 {
		return nil, fmt.Errorf("ciphertext too short (minimum 25 bytes)")
	}

	// Parse components: [IV 8B][Ciphertext N bytes][HMAC tag 16B]
	iv := data[0:8]
	ciphertext := data[8 : len(data)-16]
	tag := data[len(data)-16:]

	// Verify HMAC integrity (includes context binding)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(iv)
	mac.Write(ciphertext)

	// Include contextual data in HMAC verification (must match encryption)
	if context != nil {
		aad := generateAAD(context)
		mac.Write(aad)
	}

	expectedTag := mac.Sum(nil)[:16]

	// Constant-time comparison to prevent timing attacks
	if !hmac.Equal(tag, expectedTag) {
		return nil, fmt.Errorf("authentication failed: invalid HMAC (wrong key or context)")
	}

	// Decrypt using the same cipher feedback mode as encryption
	plaintext := make([]byte, len(ciphertext))
	keystream := iv // Start with IV as initial keystream

	for i := 0; i < len(ciphertext); i++ {
		// Update keystream based on previous ciphertext (feedback)
		if i > 0 {
			// Hash previous ciphertext byte with encryption key to generate new keystream
			h := sha256.New()
			h.Write(encKey)
			h.Write([]byte{ciphertext[i-1]})
			h.Write(keystream)
			keystream = h.Sum(nil)[:8] // Use first 8 bytes as keystream
		}

		// XOR with rotating keystream (same as encryption)
		keystreamByte := keystream[i%len(keystream)]
		keyByte := encKey[i%len(encKey)]
		plaintext[i] = ciphertext[i] ^ keystreamByte ^ keyByte
	}

	return plaintext, nil
}

func (p *CustomXORProvider) KeyRotation() error {
	return p.generateKey()
}

func (p *CustomXORProvider) Name() string {
	return "XOR-CFB-HMAC"
}

func (p *CustomXORProvider) SetPassword(password string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Securely zero out old keys before generating new ones
	p.zeroKeys()

	p.password = password
	// Regenerate keys with new password
	return p.generateKey()
}

// zeroKeys securely clears cryptographic keys from memory
func (p *CustomXORProvider) zeroKeys() {
	// Zero out encryption key
	for i := range p.encryptionKey {
		p.encryptionKey[i] = 0
	}
	// Zero out MAC key
	for i := range p.macKey {
		p.macKey[i] = 0
	}
}

// Close securely clears all cryptographic material
func (p *CustomXORProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.zeroKeys()
	p.password = ""
	return nil
}