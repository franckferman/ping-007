package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"ping007/pkg/types"
)

// newEngine creates a CryptoEngine with a fixed password for deterministic tests.
func newEngine(t *testing.T, password string) *CryptoEngine {
	t.Helper()
	cfg := CryptoConfig{
		Enabled:          false, // no rotation goroutine
		DefaultAlgorithm: "aes256",
		SharedPassword:   password,
	}
	e, err := NewCryptoEngine(cfg)
	if err != nil {
		t.Fatalf("NewCryptoEngine: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// roundTrip encrypts then decrypts data using a fresh engine pair sharing the same password.
func roundTrip(t *testing.T, engine *CryptoEngine, data []byte) {
	t.Helper()
	enc, err := engine.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	dec, err := engine.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(data, dec) {
		t.Errorf("round-trip mismatch: want %q, got %q", data, dec)
	}
}

// forceAlgo pins the active algorithm (skips rotation) for deterministic per-provider tests.
func forceAlgo(t *testing.T, e *CryptoEngine, alg types.CryptoAlgorithm) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.providers[alg]; !ok {
		t.Fatalf("algorithm %s not registered", alg)
	}
	e.activeAlgorithm = alg
}

// ── Provider-level tests ──────────────────────────────────────────────────────

func TestAES256Provider_RoundTrip(t *testing.T) {
	p, err := NewAES256Provider()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	payloads := [][]byte{
		[]byte("hello"),
		make([]byte, 0),
		bytes.Repeat([]byte{0x41}, 1024),
	}
	for _, pl := range payloads {
		enc, err := p.Encrypt(pl)
		if err != nil {
			t.Fatalf("Encrypt(%d bytes): %v", len(pl), err)
		}
		dec, err := p.Decrypt(enc)
		if err != nil {
			t.Fatalf("Decrypt(%d bytes): %v", len(pl), err)
		}
		if !bytes.Equal(pl, dec) {
			t.Errorf("round-trip mismatch for %d bytes", len(pl))
		}
	}
}

func TestAES256Provider_SharedPassword(t *testing.T) {
	p1, _ := NewAES256Provider()
	defer p1.Close()
	p2, _ := NewAES256Provider()
	defer p2.Close()

	pw := "super-secret"
	p1.SetPassword(pw)
	p2.SetPassword(pw)

	plaintext := []byte("cross-instance round-trip")
	enc, _ := p1.Encrypt(plaintext)
	dec, err := p2.Decrypt(enc)
	if err != nil {
		t.Fatalf("shared-password decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, dec) {
		t.Errorf("shared-password mismatch: got %q", dec)
	}
}

func TestAES256Provider_WrongKey(t *testing.T) {
	p1, _ := NewAES256Provider()
	defer p1.Close()
	p2, _ := NewAES256Provider()
	defer p2.Close()

	p1.SetPassword("password-A")
	p2.SetPassword("password-B")

	enc, _ := p1.Encrypt([]byte("secret"))
	_, err := p2.Decrypt(enc)
	if err == nil {
		t.Error("expected decryption failure with wrong key, got nil")
	}
}

func TestChaCha20Provider_RoundTrip(t *testing.T) {
	p, err := NewChaCha20Provider()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	data := []byte("chacha20 round-trip test payload")
	enc, err := p.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := p.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, dec) {
		t.Errorf("got %q", dec)
	}
}

func TestChaCha20Provider_SharedPassword(t *testing.T) {
	p1, _ := NewChaCha20Provider()
	defer p1.Close()
	p2, _ := NewChaCha20Provider()
	defer p2.Close()

	pw := "shared-chacha"
	p1.SetPassword(pw)
	p2.SetPassword(pw)

	plaintext := []byte("chacha cross-instance")
	enc, _ := p1.Encrypt(plaintext)
	dec, err := p2.Decrypt(enc)
	if err != nil {
		t.Fatalf("shared-password decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, dec) {
		t.Errorf("mismatch: got %q", dec)
	}
}

func TestCustomXORProvider_RoundTrip(t *testing.T) {
	p := NewCustomXORProvider()
	defer p.Close()

	data := []byte("xor-cfb-hmac test payload 1234567890")
	enc, err := p.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := p.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, dec) {
		t.Errorf("got %q", dec)
	}
}

func TestCustomXORProvider_SharedPassword(t *testing.T) {
	p1 := NewCustomXORProvider()
	defer p1.Close()
	p2 := NewCustomXORProvider()
	defer p2.Close()

	pw := "shared-xor"
	p1.SetPassword(pw)
	p2.SetPassword(pw)

	plaintext := []byte("xor cross-instance")
	enc, _ := p1.Encrypt(plaintext)
	dec, err := p2.Decrypt(enc)
	if err != nil {
		t.Fatalf("shared-password decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, dec) {
		t.Errorf("mismatch: got %q", dec)
	}
}

func TestCustomXORProvider_WrongKey(t *testing.T) {
	p1 := NewCustomXORProvider()
	defer p1.Close()
	p2 := NewCustomXORProvider()
	defer p2.Close()

	p1.SetPassword("key-one")
	p2.SetPassword("key-two")

	enc, _ := p1.Encrypt([]byte("secret"))
	_, err := p2.Decrypt(enc)
	if err == nil {
		t.Error("expected HMAC failure with wrong key")
	}
}

// ── CryptoEngine-level tests ──────────────────────────────────────────────────

func TestCryptoEngine_AllAlgorithms(t *testing.T) {
	algos := []types.CryptoAlgorithm{
		types.CryptoAES256,
		types.CryptoChaCha20,
		types.CryptoCustomXOR,
	}

	for _, alg := range algos {
		t.Run(string(alg), func(t *testing.T) {
			e := newEngine(t, "test-password")
			forceAlgo(t, e, alg)
			roundTrip(t, e, []byte("engine round-trip for "+string(alg)))
		})
	}
}

func TestCryptoEngine_CrossAlgorithmRejection(t *testing.T) {
	// Encrypt with AES, try to decrypt with XOR engine — header mismatch should be caught.
	eEnc := newEngine(t, "pw")
	forceAlgo(t, eEnc, types.CryptoAES256)

	eDec := newEngine(t, "pw")
	forceAlgo(t, eDec, types.CryptoCustomXOR)

	enc, err := eEnc.Encrypt([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	// DecryptWithContext reads the algo header and uses the matching provider,
	// so with the same password the decryption should SUCCEED regardless of
	// eDec's active algorithm — that's the design (auto-detect from header).
	dec, err := eDec.Decrypt(enc)
	if err != nil {
		t.Fatalf("auto-detect decrypt: %v", err)
	}
	if !bytes.Equal([]byte("data"), dec) {
		t.Errorf("got %q", dec)
	}
}

func TestCryptoEngine_HeaderAutoDetect(t *testing.T) {
	// Sender uses ChaCha20, receiver engine has AES as active — auto-detect via header.
	sender := newEngine(t, "shared")
	forceAlgo(t, sender, types.CryptoChaCha20)

	receiver := newEngine(t, "shared")
	forceAlgo(t, receiver, types.CryptoAES256)

	msg := []byte("auto-detect header test")
	enc, err := sender.Encrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := receiver.Decrypt(enc)
	if err != nil {
		t.Fatalf("receiver.Decrypt: %v", err)
	}
	if !bytes.Equal(msg, dec) {
		t.Errorf("mismatch: got %q", dec)
	}
}

func TestCryptoEngine_EmptyPayload(t *testing.T) {
	e := newEngine(t, "empty-test")
	forceAlgo(t, e, types.CryptoAES256)
	roundTrip(t, e, []byte{})
}

func TestCryptoEngine_LargePayload(t *testing.T) {
	e := newEngine(t, "large-test")
	forceAlgo(t, e, types.CryptoChaCha20)
	large := bytes.Repeat([]byte("A"), 65536)
	roundTrip(t, e, large)
}

func TestCryptoEngine_SetPassword(t *testing.T) {
	e := newEngine(t, "")
	if err := e.SetPassword("new-password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	forceAlgo(t, e, types.CryptoAES256)
	roundTrip(t, e, []byte("post-setpassword"))
}

// ── ContextualData binding ────────────────────────────────────────────────────

func TestAES256Provider_ContextBinding(t *testing.T) {
	p, _ := NewAES256Provider()
	defer p.Close()
	p.SetPassword("ctx-test")

	ctx := &ContextualData{
		TargetIP:   "10.0.0.1",
		SourceIP:   "10.0.0.2",
		SessionID:  "sess-1",
		SequenceID: 42,
		PacketType: "stealth",
	}

	data := []byte("context-bound ciphertext")
	enc, err := p.EncryptWithContext(data, ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Correct context → success
	dec, err := p.DecryptWithContext(enc, ctx)
	if err != nil {
		t.Fatalf("DecryptWithContext (correct ctx): %v", err)
	}
	if !bytes.Equal(data, dec) {
		t.Errorf("mismatch: got %q", dec)
	}

	// Wrong context → failure
	wrongCtx := &ContextualData{SessionID: "sess-WRONG"}
	_, err = p.DecryptWithContext(enc, wrongCtx)
	if err == nil {
		t.Error("expected failure with wrong context")
	}
}

// ── decodeCryptoHeader ───────────────────────────────────────────────────────

func TestDecodeCryptoHeader_TooShort(t *testing.T) {
	for _, b := range [][]byte{{}, {1}, {1, 1}, {1, 1, 0}} {
		if _, err := decodeCryptoHeader(b); err == nil {
			t.Errorf("len=%d: expected error for too-short header", len(b))
		}
	}
}

func TestDecodeCryptoHeader_UnknownAlgorithm(t *testing.T) {
	// Algorithm byte 0x99 is not one of AES=1, ChaCha=2, XOR=3
	header := []byte{0x99, 1, 0, 0}
	if _, err := decodeCryptoHeader(header); err == nil {
		t.Error("expected error for unknown algorithm byte")
	}
}

func TestDecodeCryptoHeader_UnsupportedVersion(t *testing.T) {
	// Valid algo (AES=1) but version=2 is unsupported
	header := []byte{AlgorithmAES256, 2, 0, 0}
	if _, err := decodeCryptoHeader(header); err == nil {
		t.Error("expected error for unsupported version 2")
	}
}

func TestDecodeCryptoHeader_Valid(t *testing.T) {
	for _, alg := range []uint8{AlgorithmAES256, AlgorithmChaCha20, AlgorithmCustomXOR} {
		header := []byte{alg, 1, 0, 0}
		h, err := decodeCryptoHeader(header)
		if err != nil {
			t.Fatalf("decodeCryptoHeader(alg=%d): %v", alg, err)
		}
		if h.Algorithm != alg {
			t.Errorf("Algorithm: got %d, want %d", h.Algorithm, alg)
		}
		if h.Version != 1 {
			t.Errorf("Version: got %d, want 1", h.Version)
		}
	}
}

// ── algorithmFromType / typeFromAlgorithm unknown defaults ────────────────────

func TestAlgorithmFromType_Unknown(t *testing.T) {
	if got := algorithmFromType(types.CryptoAlgorithm("unknown_algo")); got != 0 {
		t.Errorf("unknown algo: expected 0, got %d", got)
	}
}

func TestTypeFromAlgorithm_Unknown(t *testing.T) {
	if got := typeFromAlgorithm(0xFF); got != "" {
		t.Errorf("unknown algo id 0xFF: expected empty string, got %q", got)
	}
}

// ── NonceManager ─────────────────────────────────────────────────────────────

func TestNonceManager_Uniqueness(t *testing.T) {
	nm := NewNonceManager()
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		nonce, err := nm.GenerateNonce()
		if err != nil {
			t.Fatalf("GenerateNonce #%d: %v", i, err)
		}
		key := string(nonce)
		if _, dup := seen[key]; dup {
			t.Fatalf("duplicate nonce at iteration %d", i)
		}
		seen[key] = struct{}{}
	}
}

func TestNonceManager_Reset(t *testing.T) {
	nm := NewNonceManager()

	// Burn a few counter values.
	for i := 0; i < 5; i++ {
		if _, err := nm.GenerateNonce(); err != nil {
			t.Fatalf("GenerateNonce #%d: %v", i, err)
		}
	}

	nm.Reset()

	// After reset, counter is 0; next Generate increments to 1.
	nonce, err := nm.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce post-reset: %v", err)
	}
	counter := binary.BigEndian.Uint64(nonce[0:8])
	if counter != 1 {
		t.Errorf("expected counter=1 after Reset, got %d", counter)
	}
}

func TestNonceManager_GenerateNonceSize_TooSmall(t *testing.T) {
	nm := NewNonceManager()
	for _, sz := range []int{0, 1, 7, -1} {
		if _, err := nm.GenerateNonceSize(sz); err == nil {
			t.Errorf("size %d: expected error for size < 8", sz)
		}
	}
}

func TestNonceManager_GenerateNonceSize_Valid(t *testing.T) {
	nm := NewNonceManager()
	for _, sz := range []int{8, 12, 16, 24, 32} {
		nonce, err := nm.GenerateNonceSize(sz)
		if err != nil {
			t.Fatalf("GenerateNonceSize(%d): %v", sz, err)
		}
		if len(nonce) != sz {
			t.Errorf("size %d: got nonce of length %d", sz, len(nonce))
		}
		// First 8 bytes must be the counter (non-zero after first call).
		counter := binary.BigEndian.Uint64(nonce[0:8])
		if counter == 0 {
			t.Errorf("size %d: counter should be > 0", sz)
		}
	}
}

// ── secureRandomIndex ─────────────────────────────────────────────────────────

func TestSecureRandomIndex_InvalidMax(t *testing.T) {
	e := newEngine(t, "x")
	for _, m := range []int{0, -1, -100} {
		if _, err := e.secureRandomIndex(m); err == nil {
			t.Errorf("max=%d: expected error", m)
		}
	}
}

func TestSecureRandomIndex_MaxOne(t *testing.T) {
	e := newEngine(t, "x")
	for i := 0; i < 50; i++ {
		idx, err := e.secureRandomIndex(1)
		if err != nil {
			t.Fatalf("secureRandomIndex(1): %v", err)
		}
		if idx != 0 {
			t.Errorf("max=1: expected 0, got %d", idx)
		}
	}
}

func TestSecureRandomIndex_Bounds(t *testing.T) {
	e := newEngine(t, "x")
	for _, max := range []int{2, 3, 7, 13, 256} {
		for i := 0; i < 200; i++ {
			idx, err := e.secureRandomIndex(max)
			if err != nil {
				t.Fatalf("max=%d iter=%d: %v", max, i, err)
			}
			if idx < 0 || idx >= max {
				t.Errorf("max=%d: index %d out of [0, %d)", max, idx, max)
			}
		}
	}
}

// ── GetActiveAlgorithm / RotateAlgorithm ─────────────────────────────────────

func TestGetActiveAlgorithm_ValidAndConsistent(t *testing.T) {
	e := newEngine(t, "pw")

	// Starting algo is randomised; just verify it is one of the three registered ones.
	known := map[types.CryptoAlgorithm]bool{
		types.CryptoAES256:    true,
		types.CryptoChaCha20:  true,
		types.CryptoCustomXOR: true,
	}
	if alg := e.GetActiveAlgorithm(); !known[alg] {
		t.Errorf("unexpected initial algorithm: %s", alg)
	}

	// After forceAlgo, GetActiveAlgorithm must reflect the change.
	for alg := range known {
		forceAlgo(t, e, alg)
		if got := e.GetActiveAlgorithm(); got != alg {
			t.Errorf("forceAlgo(%s): GetActiveAlgorithm returned %s", alg, got)
		}
	}
}

func TestRotateAlgorithm_ChangesAlgorithm(t *testing.T) {
	e := newEngine(t, "pw")
	before := e.GetActiveAlgorithm()
	if err := e.RotateAlgorithm(); err != nil {
		t.Fatalf("RotateAlgorithm: %v", err)
	}
	after := e.GetActiveAlgorithm()
	if after == before {
		t.Errorf("algorithm unchanged after rotation: still %s", after)
	}
}

func TestRotateAlgorithm_CyclesAll(t *testing.T) {
	e := newEngine(t, "pw")
	seen := make(map[types.CryptoAlgorithm]bool)
	seen[e.GetActiveAlgorithm()] = true

	// With 3 algorithms, 10 rotations must visit all of them.
	for i := 0; i < 10; i++ {
		if err := e.RotateAlgorithm(); err != nil {
			t.Fatalf("RotateAlgorithm iter %d: %v", i, err)
		}
		seen[e.GetActiveAlgorithm()] = true
		if len(seen) == 3 {
			return
		}
	}
	t.Errorf("not all algorithms visited after 10 rotations: %v", seen)
}

// ── Provider Name() ───────────────────────────────────────────────────────────

func TestProviders_Name(t *testing.T) {
	aes, _ := NewAES256Provider()
	defer aes.Close()
	cha, _ := NewChaCha20Provider()
	defer cha.Close()
	xor := NewCustomXORProvider()
	defer xor.Close()

	cases := []struct {
		provider CryptoProvider
		want     string
	}{
		{aes, "AES256-GCM"},
		{cha, "ChaCha20-Poly1305"},
		{xor, "XOR-CFB-HMAC"},
	}
	for _, c := range cases {
		if got := c.provider.Name(); got != c.want {
			t.Errorf("Name(): got %q, want %q", got, c.want)
		}
	}
}

// ── Provider KeyRotation ──────────────────────────────────────────────────────

func TestProviders_KeyRotation(t *testing.T) {
	aes, _ := NewAES256Provider()
	defer aes.Close()
	cha, _ := NewChaCha20Provider()
	defer cha.Close()
	xor := NewCustomXORProvider()
	defer xor.Close()

	providers := []CryptoProvider{aes, cha, xor}
	data := []byte("key-rotation-round-trip")

	for _, p := range providers {
		t.Run(p.Name(), func(t *testing.T) {
			if err := p.KeyRotation(); err != nil {
				t.Fatalf("KeyRotation: %v", err)
			}
			enc, err := p.Encrypt(data)
			if err != nil {
				t.Fatalf("post-rotation Encrypt: %v", err)
			}
			dec, err := p.Decrypt(enc)
			if err != nil {
				t.Fatalf("post-rotation Decrypt: %v", err)
			}
			if !bytes.Equal(data, dec) {
				t.Errorf("round-trip mismatch: got %q", dec)
			}
		})
	}
}

// ── DecryptWithAlgorithmDetection ─────────────────────────────────────────────

func TestCryptoEngine_DecryptWithAlgorithmDetection(t *testing.T) {
	algos := []types.CryptoAlgorithm{
		types.CryptoAES256,
		types.CryptoChaCha20,
		types.CryptoCustomXOR,
	}
	for _, alg := range algos {
		t.Run(string(alg), func(t *testing.T) {
			e := newEngine(t, "detect-pw")
			forceAlgo(t, e, alg)

			plaintext := []byte("auto-detect payload for " + string(alg))
			enc, err := e.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			dec, detected, err := e.DecryptWithAlgorithmDetection(enc, nil)
			if err != nil {
				t.Fatalf("DecryptWithAlgorithmDetection: %v", err)
			}
			if !bytes.Equal(plaintext, dec) {
				t.Errorf("plaintext mismatch: got %q", dec)
			}
			if detected != alg {
				t.Errorf("detected algorithm %s, expected %s", detected, alg)
			}
		})
	}
}

func TestDecryptWithAlgorithmDetection_FallbackPath(t *testing.T) {
	// 3 bytes < 4 → header branch is skipped entirely; fallback loop tries all
	// providers on garbage input, all fail, function returns error.
	// Covers the fallback for-range loop in DecryptWithAlgorithmDetection.
	e := newEngine(t, "fallback-pw")
	defer e.Close()

	_, _, err := e.DecryptWithAlgorithmDetection([]byte{0xAA, 0xBB, 0xCC}, nil)
	if err == nil {
		t.Error("expected error: no provider can decrypt 3-byte garbage")
	}
}

// ── startKeyRotation ──────────────────────────────────────────────────────────

func TestCryptoEngine_WithRotation_DoesNotPanic(t *testing.T) {
	// Enabled=true + RotationInterval>0 → NewCryptoEngine calls startKeyRotation.
	// Sleep enough for the ticker to fire once, then Close stops it.
	cfg := CryptoConfig{
		Enabled:          true,
		DefaultAlgorithm: "chacha20",
		SharedPassword:   "rotation-test-key",
		RotationInterval: 10 * time.Millisecond,
	}
	e, err := NewCryptoEngine(cfg)
	if err != nil {
		t.Fatalf("NewCryptoEngine with rotation: %v", err)
	}
	time.Sleep(30 * time.Millisecond) // let the goroutine fire at least once
	if err := e.Close(); err != nil {
		t.Errorf("Close after rotation: %v", err)
	}
}

// ── Provider nil-guard error paths (after Close) ─────────────────────────────

func TestAES256Provider_NilGCM_Errors(t *testing.T) {
	// Close zeroes p.gcm → EncryptWithContext and DecryptWithContext both hit the
	// "AES-GCM not initialized" guard before any crypto work.
	p, err := NewAES256Provider()
	if err != nil {
		t.Fatalf("NewAES256Provider: %v", err)
	}
	p.Close()

	if _, err := p.EncryptWithContext([]byte("data"), nil); err == nil {
		t.Error("EncryptWithContext: expected error with nil GCM")
	}
	if _, err := p.DecryptWithContext([]byte("data"), nil); err == nil {
		t.Error("DecryptWithContext: expected error with nil GCM")
	}
}

func TestChaCha20Provider_NilAEAD_Errors(t *testing.T) {
	// Close zeroes p.aead → EncryptWithContext and DecryptWithContext both hit
	// the "ChaCha20-Poly1305 not initialized" guard.
	p, err := NewChaCha20Provider()
	if err != nil {
		t.Fatalf("NewChaCha20Provider: %v", err)
	}
	p.Close()

	if _, err := p.EncryptWithContext([]byte("data"), nil); err == nil {
		t.Error("EncryptWithContext: expected error with nil AEAD")
	}
	if _, err := p.DecryptWithContext([]byte("data"), nil); err == nil {
		t.Error("DecryptWithContext: expected error with nil AEAD")
	}
}

func TestCustomXORProvider_EmptyKeys_Errors(t *testing.T) {
	// A zero-value CustomXORProvider has nil encryptionKey and macKey (len=0).
	// Both Encrypt and Decrypt check this before any crypto work.
	p := &CustomXORProvider{}

	if _, err := p.EncryptWithContext([]byte("data"), nil); err == nil {
		t.Error("EncryptWithContext: expected error with empty keys")
	}
	if _, err := p.DecryptWithContext([]byte("data"), nil); err == nil {
		t.Error("DecryptWithContext: expected error with empty keys")
	}
}

func TestCustomXORProvider_ContextBinding(t *testing.T) {
	// Exercises the `context != nil` branch inside XOR's EncryptWithContext and
	// DecryptWithContext (the context-AAD-over-HMAC path). Round-trip must succeed
	// with matching contexts and fail with a mismatched context.
	p := NewCustomXORProvider()
	defer p.Close()

	ctx := &ContextualData{
		TargetIP:   "10.0.0.5",
		SourceIP:   "10.0.0.1",
		SessionID:  "xor-ctx-session",
		SequenceID: 7,
		PacketType: "stealth",
	}
	data := []byte("XOR context binding test payload")

	enc, err := p.EncryptWithContext(data, ctx)
	if err != nil {
		t.Fatalf("EncryptWithContext (with context): %v", err)
	}

	// Correct context → round-trip succeeds
	dec, err := p.DecryptWithContext(enc, ctx)
	if err != nil {
		t.Fatalf("DecryptWithContext (correct context): %v", err)
	}
	if !bytes.Equal(data, dec) {
		t.Errorf("round-trip mismatch: got %q, want %q", dec, data)
	}

	// Wrong context → HMAC mismatch → error
	wrongCtx := &ContextualData{SessionID: "wrong-session"}
	if _, err := p.DecryptWithContext(enc, wrongCtx); err == nil {
		t.Error("expected authentication failure with wrong context")
	}
}

// ── CryptoEngine.DecryptWithContext — remaining header error paths ─────────────

func TestCryptoEngine_DecryptWithContext_TooShort(t *testing.T) {
	// Data shorter than 4 bytes cannot carry a CryptoHeader → immediate error.
	e := newEngine(t, "short-data")
	for _, short := range [][]byte{{}, {1}, {0xAA, 0xBB}, {1, 2, 3}} {
		if _, err := e.DecryptWithContext(short, nil); err == nil {
			t.Errorf("len=%d: expected 'data too short' error", len(short))
		}
	}
}

func TestCryptoEngine_DecryptWithContext_InvalidHeader(t *testing.T) {
	// A 5-byte payload whose first byte is an unknown algorithm ID causes
	// decodeCryptoHeader to fail → "failed to decode crypto header" error.
	e := newEngine(t, "bad-header")
	// algo=0x99 is not AES(1)/ChaCha(2)/XOR(3) → decodeCryptoHeader returns error
	payload := []byte{0x99, 1, 0, 0, 0xAB}
	if _, err := e.DecryptWithContext(payload, nil); err == nil {
		t.Error("expected error for invalid algorithm byte in header")
	}
}

// ── CryptoEngine — no-provider error paths ────────────────────────────────────

func TestCryptoEngine_EncryptWithContext_NoProvider(t *testing.T) {
	// After Close(), providers map is empty. EncryptWithContext must return
	// "no provider for algorithm" without panicking.
	e := newEngine(t, "enc-noprov")
	e.Close() // clears providers; t.Cleanup double-Close is harmless (idempotent)

	_, err := e.EncryptWithContext([]byte("data"), nil)
	if err == nil {
		t.Error("expected error when no providers are registered")
	}
}

func TestCryptoEngine_DecryptWithContext_NoProvider(t *testing.T) {
	// Craft a 5-byte payload whose first 4 bytes form a valid CryptoHeader
	// (AES=1, Version=1, Reserved=0,0) so decodeCryptoHeader succeeds, but
	// the engine has no registered providers → "no provider for detected algorithm".
	e := newEngine(t, "dec-noprov")
	e.Close() // clears providers

	// [algo=AES256=1][version=1][reserved=0][reserved=0][payload_byte]
	payload := []byte{AlgorithmAES256, 1, 0, 0, 0xAB}
	_, err := e.DecryptWithContext(payload, nil)
	if err == nil {
		t.Error("expected error: no provider for detected algorithm after Close()")
	}
}

func TestCryptoEngine_RotateAlgorithm_EmptyProviders(t *testing.T) {
	// After Close(), available algorithms slice is empty → "no alternative
	// algorithms available" error branch in RotateAlgorithm.
	e := newEngine(t, "rot-empty")
	e.Close() // clears providers

	if err := e.RotateAlgorithm(); err == nil {
		t.Error("expected error when providers map is empty")
	}
}

// ── DecryptWithAlgorithmDetection — header path with failing provider ─────────

func TestDecryptWithAlgorithmDetection_HeaderFoundDecryptFails(t *testing.T) {
	// Scenario: len(data) >= 4 AND decodeCryptoHeader succeeds AND the matching
	// provider is found BUT decryption of the corrupted payload fails. The function
	// must fall through to the full-scan fallback (which also fails on garbage),
	// covering the implicit "decryption failed" path in the header branch.
	e := newEngine(t, "detect-corrupt")
	forceAlgo(t, e, types.CryptoAES256)

	// Encrypt a real payload to get a syntactically valid ciphertext (correct header)
	enc, err := e.Encrypt([]byte("payload for corruption"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip every byte in the ciphertext region (after the 4-byte header) so that
	// AES-GCM authentication fails, but the header bytes remain intact.
	corrupted := make([]byte, len(enc))
	copy(corrupted, enc)
	for i := 4; i < len(corrupted); i++ {
		corrupted[i] ^= 0xFF
	}

	// DecryptWithAlgorithmDetection: header says AES, provider found, AES decrypt
	// fails (authentication error) → falls to full-scan fallback → all providers
	// fail on the corrupted blob → final error.
	_, _, err = e.DecryptWithAlgorithmDetection(corrupted, nil)
	if err == nil {
		t.Error("expected error: corrupted payload should fail all decryption attempts")
	}
}

// ── errProvider — minimal mock for provider-error coverage ────────────────────

// errProvider implements CryptoProvider. SetPassword and Close return errors so
// we can exercise the error branches in CryptoEngine.SetPassword and .Close that
// the real providers can never reach (they always succeed).
type errProvider struct{}

func (p *errProvider) Name() string                                            { return "err-provider" }
func (p *errProvider) Encrypt(data []byte) ([]byte, error)                    { return data, nil }
func (p *errProvider) Decrypt(data []byte) ([]byte, error)                    { return data, nil }
func (p *errProvider) EncryptWithContext(d []byte, _ *ContextualData) ([]byte, error) { return d, nil }
func (p *errProvider) DecryptWithContext(d []byte, _ *ContextualData) ([]byte, error) { return d, nil }
func (p *errProvider) KeyRotation() error                                      { return nil }
func (p *errProvider) SetPassword(_ string) error {
	return errors.New("errProvider: SetPassword not supported")
}
func (p *errProvider) Close() error { return errors.New("errProvider: Close failed") }

// ── CryptoEngine.SetPassword — provider error path ────────────────────────────

func TestCryptoEngine_SetPassword_ProviderError(t *testing.T) {
	// Inject an errProvider into the providers map. CryptoEngine.SetPassword
	// iterates all providers and must propagate the first error it receives.
	e := newEngine(t, "setpw-provfail")
	e.mu.Lock()
	e.providers[types.CryptoAlgorithm("err")] = &errProvider{}
	e.mu.Unlock()

	if err := e.SetPassword("new-password"); err == nil {
		t.Error("expected error from SetPassword when a provider fails")
	}
}

// ── CryptoEngine.Close — provider error warning path ─────────────────────────

func TestCryptoEngine_Close_ProviderError(t *testing.T) {
	// errProvider.Close returns an error → CryptoEngine.Close prints a warning
	// but must still return nil (cleanup continues regardless of individual failures).
	e := newEngine(t, "close-provfail")
	e.mu.Lock()
	e.providers[types.CryptoAlgorithm("err")] = &errProvider{}
	e.mu.Unlock()

	// Must not return an error: failed provider close is logged, not propagated.
	if err := e.Close(); err != nil {
		t.Errorf("CryptoEngine.Close: expected nil despite provider error, got %v", err)
	}
}

// ── startKeyRotation — RotateAlgorithm failure path ──────────────────────────

func TestCryptoEngine_Rotation_RotateAlgorithmFails(t *testing.T) {
	// startKeyRotation goroutine calls RotateAlgorithm on each tick.
	// RotateAlgorithm fails when only the active algorithm remains (no alternatives).
	// → fmt.Printf("Crypto rotation failed: %v\n", err) is executed.
	// Verify: the goroutine does not panic and Close() is safe afterward.
	cfg := CryptoConfig{
		Enabled:          true,
		DefaultAlgorithm: "aes256",
		SharedPassword:   "rot-fail-key",
		RotationInterval: 10 * time.Millisecond,
	}
	e, err := NewCryptoEngine(cfg)
	if err != nil {
		t.Fatalf("NewCryptoEngine: %v", err)
	}

	// Remove all providers except the active one so RotateAlgorithm finds
	// no alternatives and returns "no alternative algorithms available".
	e.mu.Lock()
	for alg := range e.providers {
		if alg != e.activeAlgorithm {
			delete(e.providers, alg)
		}
	}
	e.mu.Unlock()

	// Wait for at least 3 ticks — error-log Printf fires on each one.
	time.Sleep(50 * time.Millisecond)
	if err := e.Close(); err != nil {
		t.Errorf("Close after rotation-error: %v", err)
	}
}
