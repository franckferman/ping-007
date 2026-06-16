package orchestrator

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"ping007/pkg/types"
)

// minOrch returns a zero-value Orchestrator sufficient for methods that only
// use the receiver for dispatch (extractStealthData, extractLinuxPattern, etc.).
func minOrch() *Orchestrator {
	return &Orchestrator{}
}

// ── extractLinuxPattern ───────────────────────────────────────────────────────

// buildLinuxPayload replicates the XOR encoding used by network.createLinuxPingPayload.
// Format: payload[8] ^= hi(len), payload[9] ^= lo(len), payload[10+i] ^= data[i]
// Sequential pattern at byte N = N (same as iputils ping).
func buildLinuxPayload(data []byte) []byte {
	payload := make([]byte, 56)
	// Bytes 0-7: fake timeval (left at zero for test purposes)
	// Bytes 8-55: sequential fill 0x08, 0x09, 0x0a…
	for i := 8; i < 56; i++ {
		payload[i] = byte(i)
	}
	if len(data) > 0 {
		payload[8] ^= byte(len(data) >> 8)
		payload[9] ^= byte(len(data))
		for i, b := range data {
			payload[10+i] ^= b
		}
	}
	return payload
}

func TestExtractLinuxPattern_RoundTrip(t *testing.T) {
	o := minOrch()
	cases := [][]byte{
		[]byte("hello"),
		[]byte("ping-007 stealth"),
		bytes.Repeat([]byte{0xFF}, 46), // max capacity
		{},                             // empty = decoy ping
	}
	for _, data := range cases {
		payload := buildLinuxPayload(data)
		patternData := payload[8:] // pass everything after the 8-byte timeval

		got, err := o.extractLinuxPattern(patternData)
		if err != nil {
			t.Fatalf("extractLinuxPattern(%q): %v", data, err)
		}
		if len(data) == 0 {
			// decoy: no embedded data
			if got != nil {
				t.Errorf("decoy ping: expected nil, got %q", got)
			}
			continue
		}
		if !bytes.Equal(data, got) {
			t.Errorf("round-trip failed: want %q, got %q", data, got)
		}
	}
}

func TestExtractLinuxPattern_TooShort(t *testing.T) {
	o := minOrch()
	_, err := o.extractLinuxPattern([]byte{0x00}) // needs ≥2 bytes
	if err == nil {
		t.Error("expected error for too-short pattern data")
	}
}

func TestExtractLinuxPattern_InvalidLength(t *testing.T) {
	o := minOrch()
	// Declare length 47 (> 46 max) — XOR'd with pattern bytes 0x08/0x09
	badHi := byte(0) ^ 0x08
	badLo := byte(47) ^ 0x09
	patternData := make([]byte, 48)
	patternData[0] = badHi
	patternData[1] = badLo
	_, err := o.extractLinuxPattern(patternData)
	if err == nil {
		t.Error("expected error for oversized declared length")
	}
}

// ── extractWindowsPattern ─────────────────────────────────────────────────────

const windowsAlphabet = "abcdefghijklmnopqrstuvwabcdefghi"

// buildWindowsPayload replicates network.createWindowsPingPayload.
func buildWindowsPayload(data []byte) []byte {
	payload := make([]byte, 32)
	copy(payload, []byte(windowsAlphabet))
	if len(data) > 0 {
		payload[8] ^= byte(len(data) >> 8)
		payload[9] ^= byte(len(data))
		for i, b := range data {
			payload[10+i] ^= b
		}
	}
	return payload
}

func TestExtractWindowsPattern_RoundTrip(t *testing.T) {
	o := minOrch()
	cases := [][]byte{
		[]byte("win"),
		[]byte("windows payload"),
		bytes.Repeat([]byte{0xAA}, 22), // max capacity
		{},                             // decoy
	}
	for _, data := range cases {
		payload := buildWindowsPayload(data)
		patternData := payload[8:]

		got, err := o.extractWindowsPattern(patternData)
		if err != nil {
			t.Fatalf("extractWindowsPattern(%q): %v", data, err)
		}
		if len(data) == 0 {
			if got != nil {
				t.Errorf("decoy ping: expected nil, got %q", got)
			}
			continue
		}
		if !bytes.Equal(data, got) {
			t.Errorf("round-trip failed: want %q, got %q", data, got)
		}
	}
}

func TestExtractWindowsPattern_TooShort(t *testing.T) {
	o := minOrch()
	_, err := o.extractWindowsPattern([]byte{0x00})
	if err == nil {
		t.Error("expected error for too-short pattern data")
	}
}

func TestExtractWindowsPattern_InvalidLength(t *testing.T) {
	o := minOrch()
	// Declare length 23 (> 22 max) — XOR'd with alphabet[8]='i' and alphabet[9]='j'
	badHi := byte(0) ^ windowsAlphabet[8]
	badLo := byte(23) ^ windowsAlphabet[9]
	patternData := make([]byte, 25)
	patternData[0] = badHi
	patternData[1] = badLo
	_, err := o.extractWindowsPattern(patternData)
	if err == nil {
		t.Error("expected error for oversized declared length")
	}
}

// ── extractStealthData dispatch ───────────────────────────────────────────────

func TestExtractStealthData_Linux56(t *testing.T) {
	o := minOrch()
	data := []byte("stealth dispatch")
	payload := buildLinuxPayload(data)
	if len(payload) != 56 {
		t.Fatalf("buildLinuxPayload must produce 56 bytes, got %d", len(payload))
	}
	got, err := o.extractStealthData(payload)
	if err != nil {
		t.Fatalf("extractStealthData: %v", err)
	}
	if !bytes.Equal(data, got) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestExtractStealthData_Windows32(t *testing.T) {
	o := minOrch()
	data := []byte("win")
	payload := buildWindowsPayload(data)
	if len(payload) != 32 {
		t.Fatalf("buildWindowsPayload must produce 32 bytes, got %d", len(payload))
	}
	got, err := o.extractStealthData(payload)
	if err != nil {
		t.Fatalf("extractStealthData: %v", err)
	}
	if !bytes.Equal(data, got) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestExtractStealthData_RawPayload(t *testing.T) {
	// Non-56, non-32 length → returned as-is (raw ICMP)
	o := minOrch()
	raw := []byte("raw icmp data that is not 32 or 56 bytes long")
	got, err := o.extractStealthData(raw)
	if err != nil {
		t.Fatalf("extractStealthData(raw): %v", err)
	}
	if !bytes.Equal(raw, got) {
		t.Errorf("raw payload should be returned unchanged")
	}
}

func TestExtractStealthData_TooShort(t *testing.T) {
	o := minOrch()
	_, err := o.extractStealthData([]byte{0x01, 0x02, 0x03}) // < 8 bytes
	if err == nil {
		t.Error("expected error for payload shorter than 8 bytes")
	}
}

// ── calculateEntropy ──────────────────────────────────────────────────────────

func TestCalculateEntropy_Empty(t *testing.T) {
	if e := calculateEntropy(nil); e != 0 {
		t.Errorf("empty data: want 0, got %f", e)
	}
	if e := calculateEntropy([]byte{}); e != 0 {
		t.Errorf("empty slice: want 0, got %f", e)
	}
}

func TestCalculateEntropy_SingleByte(t *testing.T) {
	// All identical bytes → entropy = 0
	data := bytes.Repeat([]byte{0x41}, 1000)
	if e := calculateEntropy(data); e != 0 {
		t.Errorf("constant data: want 0, got %f", e)
	}
}

func TestCalculateEntropy_TwoValues(t *testing.T) {
	// 50/50 split between two byte values → Shannon entropy = 1 bit/byte (log2(2) = 1).
	// The old buggy code returned this × 8 = 8; the correct value is 1.
	data := make([]byte, 1000)
	for i := range data {
		if i%2 == 0 {
			data[i] = 0x00
		} else {
			data[i] = 0xFF
		}
	}
	e := calculateEntropy(data)
	if e < 0.99 || e > 1.01 {
		t.Errorf("50/50 binary: expected ~1.0 bit entropy, got %f", e)
	}
}

func TestCalculateEntropy_AESLike(t *testing.T) {
	// 256 unique bytes (perfectly uniform) → Shannon entropy = log2(256) = 8 bits/byte.
	// This is the maximum possible byte-level entropy and is what AES-GCM output approaches.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	e := calculateEntropy(data)
	if e < 7.9 || e > 8.1 {
		t.Errorf("uniform 256 bytes: expected ~8.0 bits entropy, got %f", e)
	}
}

// ── generateSessionID / generateJobID ─────────────────────────────────────────

func TestGenerateSessionID_Format(t *testing.T) {
	id, err := generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID: %v", err)
	}
	if len(id) == 0 {
		t.Error("empty session ID")
	}
	if id[:8] != "ping007-" {
		t.Errorf("session ID prefix: got %q, want %q", id[:8], "ping007-")
	}
}

func TestGenerateSessionID_Unique(t *testing.T) {
	ids := make(map[string]struct{}, 50)
	for i := 0; i < 50; i++ {
		id, err := generateSessionID()
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if _, dup := ids[id]; dup {
			t.Fatalf("duplicate session ID at iteration %d: %s", i, id)
		}
		ids[id] = struct{}{}
	}
}

func TestGenerateJobID_Format(t *testing.T) {
	id, err := generateJobID()
	if err != nil {
		t.Fatalf("generateJobID: %v", err)
	}
	if id[:6] != "exfil-" {
		t.Errorf("job ID prefix: got %q, want %q", id[:6], "exfil-")
	}
}

// ── isLegitimateLinuxPing ─────────────────────────────────────────────────────

func TestIsLegitimateLinuxPing_Clean(t *testing.T) {
	// Exact iputils sequential pattern → must be recognized as legitimate
	o := minOrch()
	payload := make([]byte, 56)
	for i := 8; i < 56; i++ {
		payload[i] = byte(i)
	}
	if !o.isLegitimateLinuxPing(payload) {
		t.Error("clean sequential pattern should be recognized as legitimate Linux ping")
	}
}

func TestIsLegitimateLinuxPing_WithStealthData(t *testing.T) {
	// XOR steganography with small deviation (diff ≤ 127) → still recognized as legit
	o := minOrch()
	payload := buildLinuxPayload([]byte("hi")) // 2-byte embed, diff is tiny
	if !o.isLegitimateLinuxPing(payload) {
		t.Error("small-deviation stealth payload should still look like a legitimate ping")
	}
}

func TestIsLegitimateLinuxPing_WrongLength(t *testing.T) {
	o := minOrch()
	// 32-byte Windows payload → not Linux ping
	if o.isLegitimateLinuxPing(make([]byte, 32)) {
		t.Error("32-byte payload should not be recognized as Linux ping (wrong length)")
	}
	// Short payload
	if o.isLegitimateLinuxPing([]byte{0x08, 0x09}) {
		t.Error("2-byte payload should not be recognized as Linux ping")
	}
}

func TestIsLegitimateLinuxPing_HighDeviation(t *testing.T) {
	// Bytes 8-15 inverted → diff = 0xFF ^ byte(i), easily > 127 → not legit
	o := minOrch()
	payload := make([]byte, 56)
	for i := 8; i < 56; i++ {
		payload[i] = ^byte(i) // bitwise complement → maximum deviation
	}
	if o.isLegitimateLinuxPing(payload) {
		t.Error("inverted pattern should not be recognized as a legitimate Linux ping")
	}
}

// ── analyzeForFrameworkTraffic ────────────────────────────────────────────────

func TestAnalyzeForFrameworkTraffic_SessionIDHeader(t *testing.T) {
	// Legacy session_id header with "ping007-" prefix → detected
	o := minOrch()
	pkt := &types.NetworkPacket{
		Headers: map[string]any{"session_id": "ping007-abc123"},
	}
	if !o.analyzeForFrameworkTraffic(pkt) {
		t.Error("packet with ping007- session_id should be flagged as framework traffic")
	}
}

func TestAnalyzeForFrameworkTraffic_HighEntropyPayload(t *testing.T) {
	// Uniform 256-byte payload → entropy ≈ 8.0 > threshold 7.5 → detected
	o := minOrch()
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := &types.NetworkPacket{
		Payload: payload,
		Headers: map[string]any{},
	}
	if !o.analyzeForFrameworkTraffic(pkt) {
		t.Error("high-entropy payload should be flagged as framework traffic")
	}
}

func TestAnalyzeForFrameworkTraffic_LegitLinuxPing(t *testing.T) {
	// 56-byte Linux ping pattern → isLegitimateLinuxPing returns true → not flagged
	o := minOrch()
	pkt := &types.NetworkPacket{
		Payload: buildLinuxPayload([]byte{}), // decoy: no embedded data
		Headers: map[string]any{},
	}
	if o.analyzeForFrameworkTraffic(pkt) {
		t.Error("legitimate Linux ping payload should NOT be flagged as framework traffic")
	}
}

func TestAnalyzeForFrameworkTraffic_LowEntropyNonPing(t *testing.T) {
	// All-zero payload → entropy = 0, length ≠ 56 → not flagged
	o := minOrch()
	pkt := &types.NetworkPacket{
		Payload: make([]byte, 40),
		Headers: map[string]any{},
	}
	if o.analyzeForFrameworkTraffic(pkt) {
		t.Error("low-entropy non-ping payload should NOT be flagged as framework traffic")
	}
}

func TestAnalyzeForFrameworkTraffic_EmptyPayload(t *testing.T) {
	o := minOrch()
	pkt := &types.NetworkPacket{
		Payload: []byte{},
		Headers: map[string]any{},
	}
	if o.analyzeForFrameworkTraffic(pkt) {
		t.Error("empty payload should not be flagged as framework traffic")
	}
}

// ── getMaxDataSize ────────────────────────────────────────────────────────────

func TestGetMaxDataSize_Windows(t *testing.T) {
	if got := getMaxDataSize("windows"); got != 22 {
		t.Errorf("windows: got %d, want 22", got)
	}
}

func TestGetMaxDataSize_Linux(t *testing.T) {
	if got := getMaxDataSize("linux"); got != 46 {
		t.Errorf("linux: got %d, want 46", got)
	}
}

func TestGetMaxDataSize_Default(t *testing.T) {
	for _, sig := range []string{"", "darwin", "freebsd", "unknown"} {
		if got := getMaxDataSize(sig); got != 46 {
			t.Errorf("getMaxDataSize(%q): got %d, want 46 (default)", sig, got)
		}
	}
}

// ── generateAPTData ───────────────────────────────────────────────────────────

func TestGenerateAPTData_Format(t *testing.T) {
	cases := []struct {
		profile  types.APTProfile
		sequence int
	}{
		{types.APTLazarus, 1},
		{types.APTAPT29, 42},
		{types.APTEquation, 0},
	}
	for _, c := range cases {
		result := generateAPTData(c.profile, c.sequence)
		if result == "" {
			t.Errorf("generateAPTData(%s, %d): empty result", c.profile, c.sequence)
		}
		if !strings.Contains(result, string(c.profile)) {
			t.Errorf("result %q does not contain profile %q", result, c.profile)
		}
		if !strings.Contains(result, fmt.Sprintf("%d", c.sequence)) {
			t.Errorf("result %q does not contain sequence %d", result, c.sequence)
		}
	}
}

// ── SetPassword (nil cryptoEngine path) ───────────────────────────────────────

func TestSetPassword_NilCryptoEngine(t *testing.T) {
	o := minOrch() // cryptoEngine is nil
	if err := o.SetPassword("any-password"); err == nil {
		t.Error("expected error when cryptoEngine is nil")
	}
}

// ── extractStealthData — empty patternData (exactly 8 bytes) ─────────────────

func TestExtractStealthData_EmptyPatternData(t *testing.T) {
	// Exactly 8 bytes: passes len < 8 guard, but patternData = payload[8:] is empty.
	// Neither the linux-56 nor the windows-32 branch is taken (len != 56, != 32),
	// but len(patternData) == 0 fires first and returns an error.
	o := minOrch()
	_, err := o.extractStealthData(make([]byte, 8))
	if err == nil {
		t.Error("expected error for payload with empty pattern data (exactly 8 bytes)")
	}
}
