//go:build !noc2

package shell

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"ping007/internal/crypto"
	"ping007/pkg/types"
)

// minEngine returns a ShellEngine suitable for tests that never touch the
// network (nil networkService / cryptoEngine are safe as long as we don't
// call methods that send/receive ICMP packets).
func minEngine() *ShellEngine {
	return NewShellEngine(nil, nil, ShellConfig{
		MaxSessions:    5,
		SessionTimeout: 30 * time.Second,
	})
}

// ── randJitter ────────────────────────────────────────────────────────────────

func TestRandJitter_ZeroOrNegativeMax(t *testing.T) {
	for _, max := range []time.Duration{0, -1, -time.Second} {
		for i := 0; i < 100; i++ {
			if d := randJitter(max); d != 0 {
				t.Fatalf("randJitter(%v) = %v, want 0", max, d)
			}
		}
	}
}

func TestRandJitter_Bounds(t *testing.T) {
	const max = 100 * time.Millisecond
	for i := 0; i < 5000; i++ {
		d := randJitter(max)
		if d < 0 || d >= max {
			t.Fatalf("randJitter(%v) = %v, out of [0, %v)", max, d, max)
		}
	}
}

// ── NewShellEngine / GetActiveSessions / GetSessionStats ─────────────────────

func TestNewShellEngine_InitialState(t *testing.T) {
	e := minEngine()
	if e.activeSessions == nil {
		t.Error("activeSessions map must not be nil after construction")
	}
	if e.config.MaxSessions != 5 {
		t.Errorf("MaxSessions: got %d, want 5", e.config.MaxSessions)
	}
}

func TestGetActiveSessions_InitiallyEmpty(t *testing.T) {
	e := minEngine()
	if sessions := e.GetActiveSessions(); len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestGetSessionStats_InitiallyEmpty(t *testing.T) {
	e := minEngine()
	stats := e.GetSessionStats()
	if stats["active_sessions"] != 0 {
		t.Errorf("active_sessions: got %v, want 0", stats["active_sessions"])
	}
	if stats["total_sessions"] != 0 {
		t.Errorf("total_sessions: got %v, want 0", stats["total_sessions"])
	}
	if stats["total_commands"] != 0 {
		t.Errorf("total_commands: got %v, want 0", stats["total_commands"])
	}
	if stats["max_sessions"] != 5 {
		t.Errorf("max_sessions: got %v, want 5", stats["max_sessions"])
	}
}

// ── StartSession error paths (no network involved) ───────────────────────────

func TestStartSession_MaxSessionsReached(t *testing.T) {
	e := &ShellEngine{
		activeSessions: map[string]*ShellSession{
			"a": {ID: "a", Active: true},
			"b": {ID: "b", Active: true},
		},
		config: ShellConfig{MaxSessions: 2},
	}
	_, err := e.StartSession("c", "10.0.0.1", "interactive")
	if err == nil {
		t.Error("expected error when MaxSessions is reached")
	}
}

func TestStartSession_DuplicateID(t *testing.T) {
	e := &ShellEngine{
		activeSessions: map[string]*ShellSession{
			"dup": {ID: "dup", Active: true},
		},
		config: ShellConfig{MaxSessions: 5},
	}
	_, err := e.StartSession("dup", "10.0.0.1", "interactive")
	if err == nil {
		t.Error("expected error for duplicate session ID")
	}
}

// ── getSession (unexported) ───────────────────────────────────────────────────

func TestGetSession_NotFound(t *testing.T) {
	e := minEngine()
	_, err := e.getSession("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent session ID")
	}
}

func TestGetSession_InactiveSession(t *testing.T) {
	e := &ShellEngine{
		activeSessions: map[string]*ShellSession{
			"s1": {ID: "s1", Active: false, LastActivity: time.Now()},
		},
		config: ShellConfig{SessionTimeout: 30 * time.Second},
	}
	_, err := e.getSession("s1")
	if err == nil {
		t.Error("expected error for inactive session")
	}
}

func TestGetSession_ExpiredSession_NoRace(t *testing.T) {
	// Regression: getSession must not write session.Active under a read lock.
	// Concurrently calling getSession on an expired session would data-race.
	e := &ShellEngine{
		activeSessions: map[string]*ShellSession{
			"expired": {
				ID:           "expired",
				Active:       true,
				LastActivity: time.Now().Add(-10 * time.Second),
			},
		},
		config: ShellConfig{SessionTimeout: 1 * time.Second},
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.getSession("expired") //nolint:errcheck
		}()
	}
	wg.Wait()
	// If the write-under-RLock bug were present, -race would flag this.
}

// ── CleanupExpiredSessions ────────────────────────────────────────────────────

func TestCleanupExpiredSessions_RemovesStale(t *testing.T) {
	e := &ShellEngine{
		activeSessions: map[string]*ShellSession{
			"old": {
				ID:           "old",
				Active:       true,
				LastActivity: time.Now().Add(-2 * time.Second),
			},
			"fresh": {
				ID:           "fresh",
				Active:       true,
				LastActivity: time.Now(),
			},
		},
		config: ShellConfig{SessionTimeout: 1 * time.Second},
	}

	e.CleanupExpiredSessions()

	if _, exists := e.activeSessions["old"]; exists {
		t.Error("expired session 'old' should have been removed")
	}
	if _, exists := e.activeSessions["fresh"]; !exists {
		t.Error("fresh session 'fresh' should not have been removed")
	}
}

func TestCleanupExpiredSessions_PreservesAll(t *testing.T) {
	e := &ShellEngine{
		activeSessions: make(map[string]*ShellSession),
		config:         ShellConfig{SessionTimeout: 30 * time.Second},
	}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("sess-%d", i)
		e.activeSessions[id] = &ShellSession{
			ID:           id,
			Active:       true,
			LastActivity: time.Now(),
		}
	}

	e.CleanupExpiredSessions()

	if got := len(e.activeSessions); got != 3 {
		t.Errorf("expected 3 sessions to survive cleanup, got %d", got)
	}
}

func TestCleanupExpiredSessions_RemovesInactive(t *testing.T) {
	// inactive sessions (Active=false) have already been logically closed —
	// CleanupExpiredSessions only checks LastActivity, so they stay until their
	// timeout elapses. Confirm an inactive-but-fresh session is NOT removed.
	e := &ShellEngine{
		activeSessions: map[string]*ShellSession{
			"closed": {
				ID:           "closed",
				Active:       false,
				LastActivity: time.Now(),
			},
		},
		config: ShellConfig{SessionTimeout: 30 * time.Second},
	}
	e.CleanupExpiredSessions()
	if _, exists := e.activeSessions["closed"]; !exists {
		t.Error("recently-closed (but within timeout) session should not be evicted yet")
	}
}

// ── GetActiveSessions — only Active=true sessions are returned ─────────────

func TestGetActiveSessions_FiltersInactive(t *testing.T) {
	e := &ShellEngine{
		activeSessions: map[string]*ShellSession{
			"live":   {ID: "live", Active: true},
			"closed": {ID: "closed", Active: false},
		},
	}
	got := e.GetActiveSessions()
	if len(got) != 1 || got[0].ID != "live" {
		t.Errorf("GetActiveSessions: expected only 'live', got %v", got)
	}
}

// ── parseResponse ─────────────────────────────────────────────────────────────

func makePacket(payload string) *types.NetworkPacket {
	return &types.NetworkPacket{
		Payload: []byte(payload),
		Headers: map[string]any{},
	}
}

func TestParseResponse_ValidFull(t *testing.T) {
	e := minEngine()
	pkt := makePacket("RESP:cmd-001:true:0:hello world:some error")
	resp, err := e.parseResponse(pkt)
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if resp.CommandID != "cmd-001" {
		t.Errorf("CommandID: got %q, want %q", resp.CommandID, "cmd-001")
	}
	if !resp.Success {
		t.Error("Success: expected true")
	}
	if resp.ReturnCode != 0 {
		t.Errorf("ReturnCode: got %d, want 0", resp.ReturnCode)
	}
	if resp.Stdout != "hello world" {
		t.Errorf("Stdout: got %q, want %q", resp.Stdout, "hello world")
	}
	if resp.Stderr != "some error" {
		t.Errorf("Stderr: got %q, want %q", resp.Stderr, "some error")
	}
}

func TestParseResponse_SuccessFalseNonZeroRC(t *testing.T) {
	e := minEngine()
	pkt := makePacket("RESP:cmd-002:false:127:cmd not found:bash: cmd: not found")
	resp, err := e.parseResponse(pkt)
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if resp.Success {
		t.Error("Success: expected false")
	}
	if resp.ReturnCode != 127 {
		t.Errorf("ReturnCode: got %d, want 127", resp.ReturnCode)
	}
}

func TestParseResponse_PartialNoStdoutStderr(t *testing.T) {
	// Only 4 parts (no stdout, no stderr)
	e := minEngine()
	pkt := makePacket("RESP:cmd-003:true:0")
	resp, err := e.parseResponse(pkt)
	if err != nil {
		t.Fatalf("parseResponse with 4 parts: %v", err)
	}
	if resp.Stdout != "" {
		t.Errorf("Stdout should be empty, got %q", resp.Stdout)
	}
	if resp.Stderr != "" {
		t.Errorf("Stderr should be empty, got %q", resp.Stderr)
	}
}

func TestParseResponse_InvalidFormat(t *testing.T) {
	e := minEngine()
	for _, bad := range []string{"INVALID:format", "no-colons", "", "RESP"} {
		pkt := makePacket(bad)
		if _, err := e.parseResponse(pkt); err == nil {
			t.Errorf("payload %q: expected error for invalid format", bad)
		}
	}
}

func TestParseResponse_ColonInStdout(t *testing.T) {
	// SplitN 6 — colon in stdout should not split further
	e := minEngine()
	pkt := makePacket("RESP:cmd-004:true:0:path:/usr/bin/go")
	resp, err := e.parseResponse(pkt)
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if resp.Stdout != "path" {
		t.Errorf("Stdout: got %q, want %q", resp.Stdout, "path")
	}
	if resp.Stderr != "/usr/bin/go" {
		t.Errorf("Stderr (6th field): got %q, want %q", resp.Stderr, "/usr/bin/go")
	}
}

// ── parseResponse — encrypted payload paths ───────────────────────────────────

func TestParseResponse_EncryptedNilEngine(t *testing.T) {
	// encrypted=true but cryptoEngine==nil: no decryption attempted, raw payload used.
	e := minEngine() // cryptoEngine is nil
	pkt := makePacket("RESP:cmd-enc:true:0:output:")
	pkt.Headers["encrypted"] = true

	resp, err := e.parseResponse(pkt)
	if err != nil {
		t.Fatalf("parseResponse encrypted+nil engine: %v", err)
	}
	if resp.CommandID != "cmd-enc" {
		t.Errorf("CommandID: got %q, want %q", resp.CommandID, "cmd-enc")
	}
}

func TestParseResponse_DecryptionError(t *testing.T) {
	// Closed CryptoEngine has no providers → Decrypt returns error.
	ce, err := crypto.NewCryptoEngine(crypto.CryptoConfig{
		Enabled:          false,
		DefaultAlgorithm: "aes256",
		SharedPassword:   "test-shell-key",
	})
	if err != nil {
		t.Fatalf("NewCryptoEngine: %v", err)
	}
	ce.Close() // clears all providers

	e := NewShellEngine(nil, ce, ShellConfig{MaxSessions: 5})
	pkt := makePacket("garbage-not-valid-ciphertext")
	pkt.Headers["encrypted"] = true

	if _, err := e.parseResponse(pkt); err == nil {
		t.Error("expected decryption error when CryptoEngine has no providers")
	}
}

// ── GetSessionStats — active session loop ─────────────────────────────────────

func TestGetSessionStats_WithActiveSessions(t *testing.T) {
	e := minEngine()
	e.activeSessions["s-active"] = &ShellSession{
		ID:     "s-active",
		Active: true,
		Commands: []*types.ShellCommand{
			{ID: "c1"},
			{ID: "c2"},
		},
	}
	e.activeSessions["s-inactive"] = &ShellSession{
		ID:     "s-inactive",
		Active: false,
	}

	stats := e.GetSessionStats()
	if stats["active_sessions"] != 1 {
		t.Errorf("active_sessions: got %v, want 1", stats["active_sessions"])
	}
	if stats["total_sessions"] != 2 {
		t.Errorf("total_sessions: got %v, want 2", stats["total_sessions"])
	}
	if stats["total_commands"] != 2 {
		t.Errorf("total_commands: got %v, want 2", stats["total_commands"])
	}
}

// ── parseResponse — encrypted success (payload = decryptedData) ──────────────

func TestParseResponse_EncryptedSuccess(t *testing.T) {
	// Encrypt a valid RESP payload so decryption succeeds → payload = decryptedData
	ce, err := crypto.NewCryptoEngine(crypto.CryptoConfig{
		Enabled:          true,
		DefaultAlgorithm: "aes256",
		SharedPassword:   "test-resp-key",
	})
	if err != nil {
		t.Fatalf("NewCryptoEngine: %v", err)
	}
	defer ce.Close()

	ciphertext, err := ce.Encrypt([]byte("RESP:cmd-dec:true:0:stdout-data:"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	e := NewShellEngine(nil, ce, ShellConfig{MaxSessions: 5})
	pkt := &types.NetworkPacket{
		Payload: ciphertext,
		Headers: map[string]any{"encrypted": true},
	}
	resp, err := e.parseResponse(pkt)
	if err != nil {
		t.Fatalf("parseResponse (encrypted success): %v", err)
	}
	if resp.CommandID != "cmd-dec" {
		t.Errorf("CommandID: got %q, want %q", resp.CommandID, "cmd-dec")
	}
	if resp.Stdout != "stdout-data" {
		t.Errorf("Stdout: got %q, want %q", resp.Stdout, "stdout-data")
	}
}

// ── parseResponse — Sscanf error on non-integer return code ──────────────────

func TestParseResponse_NonIntegerReturnCode(t *testing.T) {
	// parts[3] cannot be parsed as int → Sscanf returns error → ReturnCode set to -1
	e := minEngine()
	pkt := makePacket("RESP:cmd-bad-rc:true:notanumber")
	resp, err := e.parseResponse(pkt)
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if resp.ReturnCode != -1 {
		t.Errorf("ReturnCode: got %d, want -1 (Sscanf error on non-integer field)", resp.ReturnCode)
	}
}
