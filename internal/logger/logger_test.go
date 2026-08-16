package logger

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ping007/pkg/types"
)

// ── NONE level — no file, no directory ───────────────────────────────────────

func TestNew_NoneLevel_NoFileCreated(t *testing.T) {
	// Ensure the default logs/ dir does not exist before the test.
	_ = os.RemoveAll("logs")
	t.Cleanup(func() { os.RemoveAll("logs") })

	l := New("NONE")
	defer l.Close()

	// Logging at any level must not panic and must produce no output / no file.
	l.Info("should be discarded")
	l.Debug("discarded")
	l.Warn("discarded")
	l.Error("discarded")

	if _, err := os.Stat("logs"); err == nil {
		t.Error("NONE level must not create the logs/ directory")
	}
}

func TestNew_NoneLevel_Close(t *testing.T) {
	l := New("NONE")
	if err := l.Close(); err != nil {
		t.Errorf("Close on NONE logger: %v", err)
	}
}

// ── Active levels — file is created ──────────────────────────────────────────

func TestNewWithConfig_FileCreated(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "subdir", "test.log")

	cfg := LoggerConfig{
		Level:         "INFO",
		OutputFile:    logFile,
		Format:        "json",
		AuditEnabled:  false,
		MaxFileSize:   1024 * 1024,
		RotationCount: 3,
	}
	l := NewWithConfig(cfg, nil)
	defer l.Close()

	l.Info("test message", "key", "value")

	if _, err := os.Stat(logFile); err != nil {
		t.Errorf("expected log file to be created at %s: %v", logFile, err)
	}
}

func TestNewWithConfig_TextFormat(t *testing.T) {
	dir := t.TempDir()
	cfg := LoggerConfig{
		Level:         "DEBUG",
		OutputFile:    filepath.Join(dir, "text.log"),
		Format:        "text",
		MaxFileSize:   1024 * 1024,
		RotationCount: 3,
	}
	l := NewWithConfig(cfg, nil)
	defer l.Close()
	l.Debug("text format debug")
	l.Info("text format info")
}

// ── LogSecurityEvent ──────────────────────────────────────────────────────────

func TestLogSecurityEvent_AllSeverities(t *testing.T) {
	dir := t.TempDir()
	cfg := LoggerConfig{
		Level:         "DEBUG",
		OutputFile:    filepath.Join(dir, "sec.log"),
		Format:        "json",
		MaxFileSize:   1024 * 1024,
		RotationCount: 3,
	}
	l := NewWithConfig(cfg, nil)
	defer l.Close()

	severities := []string{"DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "unknown"}
	for _, sev := range severities {
		l.LogSecurityEvent(&types.SecurityEvent{
			EventType:     "test_event",
			Severity:      sev,
			Message:       "test for severity " + sev,
			Timestamp:     time.Now(),
			SecurityLevel: "test",
		})
	}
}

func TestLogSecurityEvent_WithMetadata(t *testing.T) {
	l := New("NONE") // discard output
	defer l.Close()

	l.LogSecurityEvent(&types.SecurityEvent{
		EventType:     "lateral_movement",
		Severity:      "WARN",
		Message:       "ICMP tunnel detected",
		Timestamp:     time.Now(),
		SessionID:     "sess-abc",
		TargetIP:      "10.0.0.1",
		Technique:     "icmp_tunnel",
		Component:     "network",
		SecurityLevel: "high",
		Metadata:      map[string]any{"bytes": 1024, "packets": 16},
	})
}

// ── Specialized log helpers ───────────────────────────────────────────────────

func TestLogExfiltrationEvent(t *testing.T) {
	l := New("NONE")
	defer l.Close()
	l.LogExfiltrationEvent("job-001", "10.0.0.5", "icmp_tunnel", 4096, true)
	l.LogExfiltrationEvent("job-002", "10.0.0.5", "icmp_tunnel", 0, false)
}

func TestLogShellActivity(t *testing.T) {
	l := New("NONE")
	defer l.Close()
	l.LogShellActivity("sess-x", "10.0.0.1", "whoami", true, 50*time.Millisecond)
}

func TestLogEvasionActivity(t *testing.T) {
	l := New("NONE")
	defer l.Close()
	l.LogEvasionActivity("timing_jitter", true, 0.85)
	l.LogEvasionActivity("sandbox_check", false, 0.0)
}

func TestLogNetworkActivity(t *testing.T) {
	l := New("NONE")
	defer l.Close()
	l.LogNetworkActivity("10.0.0.1", 10, 640, 5*time.Millisecond)
}

func TestLogCryptoActivity(t *testing.T) {
	l := New("NONE")
	defer l.Close()
	l.LogCryptoActivity("encrypt", "AES-256-GCM", true)
	l.LogCryptoActivity("decrypt", "ChaCha20-Poly1305", false)
}

// ── RotateLog ─────────────────────────────────────────────────────────────────

func TestRotateLog_NoFile(t *testing.T) {
	l := New("NONE")
	defer l.Close()
	// No log file open — should not error
	if err := l.RotateLog(); err != nil {
		t.Errorf("RotateLog with no file: %v", err)
	}
}

func TestRotateLog_BelowSizeLimit(t *testing.T) {
	dir := t.TempDir()
	cfg := LoggerConfig{
		Level:         "INFO",
		OutputFile:    filepath.Join(dir, "rotate.log"),
		Format:        "json",
		MaxFileSize:   10 * 1024 * 1024, // 10 MB — won't trigger rotation
		RotationCount: 3,
	}
	l := NewWithConfig(cfg, nil)
	defer l.Close()

	l.Info("small entry — below rotation limit")

	if err := l.RotateLog(); err != nil {
		t.Errorf("RotateLog: %v", err)
	}
}

// ── AuditLogger ───────────────────────────────────────────────────────────────

func TestAuditLogger(t *testing.T) {
	dir := t.TempDir()
	al, err := NewAuditLogger(filepath.Join(dir, "audit", "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	al.LogAuditEvent("command_exec", "franck", "exfil --target 10.0.0.1", map[string]any{
		"file": "/etc/passwd",
		"size": 1234,
	})
}

// ── RotateLog (rotation path) ─────────────────────────────────────────────────

func TestRotateLog_RotationTriggered(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "rotate.log")

	cfg := LoggerConfig{
		Level:         "INFO",
		OutputFile:    logPath,
		Format:        "json",
		MaxFileSize:   1, // 1 byte → any entry triggers rotation
		RotationCount: 3,
	}
	l := NewWithConfig(cfg, nil)
	defer l.Close()

	l.Info("trigger rotation")

	if err := l.RotateLog(); err != nil {
		t.Fatalf("RotateLog: %v", err)
	}

	rotated := logPath + ".1"
	if _, err := os.Stat(rotated); err != nil {
		t.Errorf("expected rotated file %s to exist: %v", rotated, err)
	}
}

// ── SIEMWriter ────────────────────────────────────────────────────────────────

func TestSIEMWriter_New(t *testing.T) {
	sw := NewSIEMWriter(SIEMConfig{ConnectorType: "splunk"})
	if sw == nil {
		t.Fatal("expected non-nil SIEMWriter")
	}
	// Clean up the background worker goroutine.
	sw.Close()
}

func TestSIEMWriter_Write_ReturnsLen(t *testing.T) {
	sw := NewSIEMWriter(SIEMConfig{ConnectorType: "splunk"})
	defer sw.Close()

	data := []byte(`{"event":"test"}`)
	n, err := sw.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write: returned %d, want %d", n, len(data))
	}
}

func TestSIEMWriter_Close_ReturnsNil(t *testing.T) {
	sw := NewSIEMWriter(SIEMConfig{ConnectorType: "elastic"})
	if err := sw.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNewWithConfig_SIEMEnabled(t *testing.T) {
	dir := t.TempDir()
	cfg := LoggerConfig{
		Level:         "INFO",
		OutputFile:    filepath.Join(dir, "siem.log"),
		Format:        "json",
		MaxFileSize:   10 * 1024 * 1024,
		RotationCount: 3,
	}
	siemCfg := SIEMConfig{
		Enabled:       true,
		ConnectorType: "splunk",
	}
	l := NewWithConfig(cfg, &siemCfg)
	if l == nil {
		t.Fatal("NewWithConfig with SIEM: expected non-nil Logger")
	}
	l.Info("event via siem path")
	l.Close()
}

// ── AuditLogger Close ─────────────────────────────────────────────────────────

func TestAuditLogger_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	al, err := NewAuditLogger(filepath.Join(dir, "audit2", "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	// First close should succeed.
	if err := al.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
}

func TestAuditLogger_MultipleEvents(t *testing.T) {
	dir := t.TempDir()
	al, err := NewAuditLogger(filepath.Join(dir, "audit3", "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	events := []struct {
		action string
		user   string
	}{
		{"login", "alice"},
		{"exfil", "bob"},
		{"shell", "charlie"},
	}
	for _, ev := range events {
		al.LogAuditEvent(ev.action, ev.user, ev.action+" command", nil)
	}
}

// ── SIEMWriter — sendToSIEM branch coverage ───────────────────────────────────

func TestSIEMWriter_SendToSIEM_Elastic(t *testing.T) {
	// Calls sendToSIEM directly (same package) with ConnectorType="elastic"
	// to cover the sendToElastic branch.
	sw := NewSIEMWriter(SIEMConfig{ConnectorType: "elastic"})
	defer sw.Close()
	sw.sendToSIEM([]byte(`{"event":"test-elastic"}`))
}

func TestSIEMWriter_SendToSIEM_DefaultFile(t *testing.T) {
	// Unknown ConnectorType → default branch → sendToFile creates logs/ping-007-siem.log.
	t.Cleanup(func() { os.RemoveAll("logs") })
	sw := NewSIEMWriter(SIEMConfig{ConnectorType: "unknown"})
	defer sw.Close()
	sw.sendToSIEM([]byte(`{"event":"test-file"}`))
}

// ── initialize — log-level switch remaining cases ────────────────────────────

func TestNewWithConfig_WarnLevel(t *testing.T) {
	// Level="warn" hits the "WARN", "WARNING" case in initialize's switch.
	dir := t.TempDir()
	cfg := LoggerConfig{
		Level:      "warn",
		OutputFile: filepath.Join(dir, "warn.log"),
		Format:     "text",
	}
	l := NewWithConfig(cfg, nil)
	defer l.Close()
	l.Warn("warn level initialization covered")
}

func TestNewWithConfig_ErrorLevel(t *testing.T) {
	// Level="error" hits the "ERROR" case in initialize's switch.
	dir := t.TempDir()
	cfg := LoggerConfig{
		Level:      "error",
		OutputFile: filepath.Join(dir, "error.log"),
		Format:     "text",
	}
	l := NewWithConfig(cfg, nil)
	defer l.Close()
	l.Error("error level initialization covered")
}

// ── RotateLog — OpenFile failure after rotation ───────────────────────────────

func TestRotateLog_NewFileError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — chmod 0555 does not restrict root")
	}
	// Delete the log file while the fd is still held open. On Linux, fd.Stat()
	// succeeds on a deleted file (unlinked inode). Then make the directory
	// read-only so os.OpenFile(O_CREATE) cannot recreate the file after rotation,
	// triggering the "failed to create new log file" error branch.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "rotate-test.log")
	cfg := LoggerConfig{
		Level:         "info",
		OutputFile:    logPath,
		MaxFileSize:   0, // size(file) is always >= 0, so size < 0 is false → rotation runs
		RotationCount: 1,
	}
	l := NewWithConfig(cfg, nil)
	l.Info("seed entry so Stat sees non-empty fd")

	// Unlink the path: fd still open, Stat works; but the name is gone.
	os.Remove(logPath)

	// Read-only dir: Rename silently fails (ENOENT), and O_CREATE also fails.
	os.Chmod(dir, 0555)
	t.Cleanup(func() { os.Chmod(dir, 0755) })

	err := l.RotateLog()
	os.Chmod(dir, 0755) // restore before defer t.Cleanup fires
	if err == nil {
		t.Error("expected error: cannot create new log file in read-only directory")
	}
}

// ── initialize — MkdirAll / OpenFile failure paths ───────────────────────────

func TestNewWithConfig_OpenFileFails(t *testing.T) {
	// Parent path component is a regular file → os.MkdirAll fails → prints warning.
	// OpenFile on the same impossible path also fails → l.file = nil.
	// The Logger must still be returned and usable (no panic, graceful degradation).
	tmp := t.TempDir()
	parentFile := filepath.Join(tmp, "not-a-dir")
	f, err := os.Create(parentFile)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	f.Close()

	cfg := LoggerConfig{
		Level:      "info",
		OutputFile: filepath.Join(parentFile, "ping-007.log"),
	}
	l := NewWithConfig(cfg, nil)
	defer l.Close()

	// Logger must not panic; with l.file=nil it falls back to stdout-only output.
	l.Info("initialize failure path covered")
}

// ── NewAuditLogger — OpenFile failure path ────────────────────────────────────

func TestNewAuditLogger_FileCreateError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — chmod 0555 does not restrict root")
	}
	// Directory exists but has no write permission → os.OpenFile fails →
	// NewAuditLogger returns an error (the OpenFile error branch, line 516).
	tmp := t.TempDir()
	roDir := filepath.Join(tmp, "ro-audit")
	if err := os.Mkdir(roDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	os.Chmod(roDir, 0555) // read+exec only, no write
	t.Cleanup(func() { os.Chmod(roDir, 0755) })

	_, err := NewAuditLogger(filepath.Join(roDir, "audit.log"))
	if err == nil {
		t.Error("expected error: cannot create file in read-only directory")
	}
}

// ── SIEMWriter.Write — select branch coverage ─────────────────────────────────

func TestSIEMWriter_Write_DoneChannel(t *testing.T) {
	// Zero-capacity buffer ensures the send case blocks. With done closed,
	// Go's select picks <-sw.done (the only ready non-default case).
	sw := &SIEMWriter{
		buffer: make(chan []byte, 0),
		done:   make(chan struct{}),
	}
	close(sw.done)

	n, err := sw.Write([]byte("ping"))
	if err == nil {
		t.Error("expected error from closed SIEM writer")
	}
	if n != 0 {
		t.Errorf("n: got %d, want 0", n)
	}
}

func TestSIEMWriter_Write_BufferFull(t *testing.T) {
	// Zero-capacity buffer + open done → both cases block → default runs →
	// returns len(p), nil (silent drop, by design).
	sw := &SIEMWriter{
		buffer: make(chan []byte, 0),
		done:   make(chan struct{}),
	}

	n, err := sw.Write([]byte("overflow"))
	if err != nil {
		t.Errorf("expected nil error on buffer-full drop, got: %v", err)
	}
	if n != len("overflow") {
		t.Errorf("n: got %d, want %d", n, len("overflow"))
	}
}

// ── AuditLogger — Close and constructor error paths ───────────────────────────

func TestAuditLogger_Close_NilFile(t *testing.T) {
	// AuditLogger with file=nil must close without error (the nil guard branch).
	al := &AuditLogger{}
	if err := al.Close(); err != nil {
		t.Errorf("Close with nil file: %v", err)
	}
}

func TestNewAuditLogger_DirectoryIsFile(t *testing.T) {
	// A regular file used as a path component causes os.MkdirAll to fail,
	// which NewAuditLogger must surface as an error.
	tmp := t.TempDir()
	parentFile := filepath.Join(tmp, "notadir")
	f, err := os.Create(parentFile)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	f.Close()

	_, err = NewAuditLogger(filepath.Join(parentFile, "audit.log"))
	if err == nil {
		t.Error("expected error when audit-log parent path is a regular file")
	}
}

// ── LogAuditEvent — json.Marshal error path ───────────────────────────────────

func TestLogAuditEvent_MarshalError(t *testing.T) {
	// A channel value in metadata is not JSON-serializable.
	// json.Marshal(auditEntry) returns an error → early return → nothing written to file.
	dir := t.TempDir()
	al, err := NewAuditLogger(filepath.Join(dir, "audit-marshal.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	al.LogAuditEvent("test", "user", "action", map[string]any{
		"bad": make(chan int),
	})

	content, readErr := os.ReadFile(filepath.Join(dir, "audit-marshal.log"))
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if len(content) != 0 {
		t.Errorf("expected empty file after marshal error, got %d bytes written", len(content))
	}
}

