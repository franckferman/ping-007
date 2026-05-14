package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	"ping007/pkg/types"

	"golang.org/x/crypto/chacha20poly1305"
)

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
}

// CryptoProvider interface for pluggable crypto implementations
type CryptoProvider interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	KeyRotation() error
	Name() string
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
	e.providers[types.CryptoAES256] = aesProvider

	// ChaCha20 Provider
	chachaProvider, err := NewChaCha20Provider()
	if err != nil {
		return fmt.Errorf("failed to create ChaCha20 provider: %w", err)
	}
	e.providers[types.CryptoChaCha20] = chachaProvider

	// Custom XOR Provider
	xorProvider := NewCustomXORProvider()
	e.providers[types.CryptoCustomXOR] = xorProvider

	return nil
}

// Encrypt encrypts data using the active algorithm
func (e *CryptoEngine) Encrypt(data []byte) ([]byte, error) {
	e.mu.RLock()
	provider, exists := e.providers[e.activeAlgorithm]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no provider for algorithm: %s", e.activeAlgorithm)
	}

	return provider.Encrypt(data)
}

// Decrypt decrypts data using the active algorithm
func (e *CryptoEngine) Decrypt(data []byte) ([]byte, error) {
	e.mu.RLock()
	provider, exists := e.providers[e.activeAlgorithm]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no provider for algorithm: %s", e.activeAlgorithm)
	}

	return provider.Decrypt(data)
}

// RotateAlgorithm switches to a different crypto algorithm
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

	// Select random algorithm
	newAlg := available[time.Now().UnixNano()%int64(len(available))]

	// Rotate keys for new algorithm
	if err := e.providers[newAlg].KeyRotation(); err != nil {
		return fmt.Errorf("key rotation failed for %s: %w", newAlg, err)
	}

	e.activeAlgorithm = newAlg
	return nil
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

// Close stops the crypto engine
func (e *CryptoEngine) Close() error {
	if e.rotationTicker != nil {
		e.rotationTicker.Stop()
	}
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
	key    []byte
	gcm    cipher.AEAD
	mu     sync.RWMutex
}

// NewAES256Provider creates a new AES256 provider
func NewAES256Provider() (*AES256Provider, error) {
	provider := &AES256Provider{}
	if err := provider.generateKey(); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *AES256Provider) generateKey() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Generate 256-bit key
	p.key = make([]byte, 32)
	if _, err := rand.Read(p.key); err != nil {
		return fmt.Errorf("failed to generate AES key: %w", err)
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
	p.mu.RLock()
	defer p.mu.RUnlock()

	nonce := make([]byte, p.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := p.gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (p *AES256Provider) Decrypt(data []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(data) < p.gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:p.gcm.NonceSize()]
	ciphertext := data[p.gcm.NonceSize():]

	plaintext, err := p.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (p *AES256Provider) KeyRotation() error {
	return p.generateKey()
}

func (p *AES256Provider) Name() string {
	return "AES256-GCM"
}

// ChaCha20Provider implements ChaCha20-Poly1305 encryption
type ChaCha20Provider struct {
	aead cipher.AEAD
	mu   sync.RWMutex
}

// NewChaCha20Provider creates a new ChaCha20 provider
func NewChaCha20Provider() (*ChaCha20Provider, error) {
	provider := &ChaCha20Provider{}
	if err := provider.generateKey(); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *ChaCha20Provider) generateKey() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate ChaCha20 key: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("failed to create ChaCha20 cipher: %w", err)
	}

	p.aead = aead
	return nil
}

func (p *ChaCha20Provider) Encrypt(data []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	nonce := make([]byte, p.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := p.aead.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (p *ChaCha20Provider) Decrypt(data []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(data) < p.aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:p.aead.NonceSize()]
	ciphertext := data[p.aead.NonceSize():]

	plaintext, err := p.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (p *ChaCha20Provider) KeyRotation() error {
	return p.generateKey()
}

func (p *ChaCha20Provider) Name() string {
	return "ChaCha20-Poly1305"
}

// CustomXORProvider implements a custom XOR cipher for obfuscation
type CustomXORProvider struct {
	key []byte
	mu  sync.RWMutex
}

func NewCustomXORProvider() *CustomXORProvider {
	provider := &CustomXORProvider{}
	provider.generateKey()
	return provider
}

func (p *CustomXORProvider) generateKey() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Generate key based on current timestamp for pseudo-randomness
	timestamp := time.Now().UnixNano()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", timestamp)))
	p.key = hash[:]
	return nil
}

func (p *CustomXORProvider) Encrypt(data []byte) ([]byte, error) {
	p.mu.RLock()
	key := p.key
	p.mu.RUnlock()

	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result, nil
}

func (p *CustomXORProvider) Decrypt(data []byte) ([]byte, error) {
	// XOR encryption is symmetric
	return p.Encrypt(data)
}

func (p *CustomXORProvider) KeyRotation() error {
	return p.generateKey()
}

func (p *CustomXORProvider) Name() string {
	return "Custom-XOR"
}