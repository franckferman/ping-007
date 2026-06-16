package exfiltration

import (
	"os"
	"testing"

	"ping007/internal/crypto"
	"ping007/pkg/types"
)

// newEngine returns an ExfiltrationEngine with nil network/crypto/evasion services.
// Only usable for tests that don't trigger actual network sends or encryption.
func newEngine(chunkSize, maxJobs, maxRetries int) *ExfiltrationEngine {
	return NewExfiltrationEngine(nil, nil, nil, ExfiltrationConfig{
		MaxConcurrentJobs: maxJobs,
		DefaultChunkSize:  chunkSize,
		MaxRetries:        maxRetries,
	})
}

func baseJob() *types.ExfilJob {
	return &types.ExfilJob{
		ID:             "test-job-001",
		Target:         "10.0.0.1",
		Method:         types.ExfilICMPTunnel,
		Mode:           types.ModeFast,
		Data:           []byte("hello world"),
		EncryptEnabled: false,
		Metadata:       make(map[string]any),
	}
}

// ── randInRange ───────────────────────────────────────────────────────────────

func TestRandInRange_AlwaysInBounds(t *testing.T) {
	for i := 0; i < 5000; i++ {
		v := randInRange(10, 20)
		if v < 10 || v > 20 {
			t.Fatalf("iter %d: randInRange(10,20) = %d, out of [10,20]", i, v)
		}
	}
}

func TestRandInRange_MinEqualsMax(t *testing.T) {
	for i := 0; i < 100; i++ {
		if v := randInRange(7, 7); v != 7 {
			t.Fatalf("randInRange(7,7) = %d, want 7", v)
		}
	}
}

func TestRandInRange_MinGreaterThanMax(t *testing.T) {
	// min > max → should return min (guard clause)
	if v := randInRange(20, 10); v != 20 {
		t.Fatalf("randInRange(20,10) = %d, want 20", v)
	}
}

// ── validateJob ───────────────────────────────────────────────────────────────

func TestValidateJob_Valid(t *testing.T) {
	e := newEngine(512, 5, 3)
	if err := e.validateJob(baseJob()); err != nil {
		t.Errorf("valid job should pass: %v", err)
	}
}

func TestValidateJob_MissingID(t *testing.T) {
	e := newEngine(512, 5, 3)
	j := baseJob()
	j.ID = ""
	if err := e.validateJob(j); err == nil {
		t.Error("expected error for missing job ID")
	}
}

func TestValidateJob_MissingTarget(t *testing.T) {
	e := newEngine(512, 5, 3)
	j := baseJob()
	j.Target = ""
	if err := e.validateJob(j); err == nil {
		t.Error("expected error for missing target")
	}
}

func TestValidateJob_NoDataNoPath(t *testing.T) {
	e := newEngine(512, 5, 3)
	j := baseJob()
	j.Data = nil
	j.SourcePath = ""
	if err := e.validateJob(j); err == nil {
		t.Error("expected error when neither data nor source path set")
	}
}

func TestValidateJob_NegativeChunkSize(t *testing.T) {
	e := newEngine(512, 5, 3)
	j := baseJob()
	j.ChunkSize = -1
	if err := e.validateJob(j); err == nil {
		t.Error("expected error for negative chunk size")
	}
}

func TestValidateJob_InvalidMethod(t *testing.T) {
	e := newEngine(512, 5, 3)
	j := baseJob()
	j.Method = types.ExfiltrationMethod("unknown_method")
	if err := e.validateJob(j); err == nil {
		t.Error("expected error for unknown exfiltration method")
	}
}

func TestValidateJob_AllMethods(t *testing.T) {
	e := newEngine(512, 5, 3)
	methods := []types.ExfiltrationMethod{
		types.ExfilICMPTunnel,
		types.ExfilICMPPayload,
		types.ExfilICMPTiming,
		types.ExfilICMPSeq,
	}
	for _, m := range methods {
		j := baseJob()
		j.Method = m
		if err := e.validateJob(j); err != nil {
			t.Errorf("method %s should be valid: %v", m, err)
		}
	}
}

// ── createChunks ──────────────────────────────────────────────────────────────

func TestCreateChunks_SingleChunk(t *testing.T) {
	e := newEngine(1024, 5, 3)
	j := baseJob()
	j.Data = []byte("small payload")
	j.ChunkSize = 1024

	chunks, err := e.createChunks(j)
	if err != nil {
		t.Fatalf("createChunks: %v", err)
	}
	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk, got %d", len(chunks))
	}
}

func TestCreateChunks_MultipleChunks(t *testing.T) {
	e := newEngine(100, 5, 3)
	j := baseJob()
	j.Data = make([]byte, 500)
	for i := range j.Data {
		j.Data[i] = byte(i % 256)
	}
	j.ChunkSize = 100

	chunks, err := e.createChunks(j)
	if err != nil {
		t.Fatalf("createChunks: %v", err)
	}
	if len(chunks) < 4 || len(chunks) > 7 {
		// With ±25% jitter, 500/100 = 5 chunks nominal; expect 4–7
		t.Errorf("unexpected chunk count: %d (want 4–7)", len(chunks))
	}

	// All data must be accounted for
	var total int
	for _, ch := range chunks {
		total += len(ch.Data)
	}
	if total != len(j.Data) {
		t.Errorf("total chunk bytes %d != original %d", total, len(j.Data))
	}
}

func TestCreateChunks_TotalChunksPatchedCorrectly(t *testing.T) {
	e := newEngine(50, 5, 3)
	j := baseJob()
	j.Data = make([]byte, 300)
	j.ChunkSize = 50

	chunks, err := e.createChunks(j)
	if err != nil {
		t.Fatal(err)
	}
	real := len(chunks)
	for i, ch := range chunks {
		if ch.TotalChunks != real {
			t.Errorf("chunk[%d].TotalChunks = %d, want %d", i, ch.TotalChunks, real)
		}
	}
}

func TestCreateChunks_ChecksumPresent(t *testing.T) {
	e := newEngine(512, 5, 3)
	j := baseJob()

	chunks, err := e.createChunks(j)
	if err != nil {
		t.Fatal(err)
	}
	for i, ch := range chunks {
		if ch.Checksum == "" {
			t.Errorf("chunk[%d]: empty checksum", i)
		}
	}
}

func TestCreateChunks_StatusPending(t *testing.T) {
	e := newEngine(512, 5, 3)
	j := baseJob()

	chunks, err := e.createChunks(j)
	if err != nil {
		t.Fatal(err)
	}
	for i, ch := range chunks {
		if ch.Status != types.StatusPending {
			t.Errorf("chunk[%d]: status = %q, want %q", i, ch.Status, types.StatusPending)
		}
	}
}

func TestCreateChunks_EmptyData(t *testing.T) {
	e := newEngine(512, 5, 3)
	j := baseJob()
	j.Data = []byte{}

	chunks, err := e.createChunks(j)
	if err != nil {
		t.Fatalf("createChunks with empty data: %v", err)
	}
	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for empty data, got %d", len(chunks))
	}
}

func TestCreateChunks_DefaultChunkSize(t *testing.T) {
	// When job.ChunkSize == 0, engine.DefaultChunkSize (512) is used
	e := newEngine(512, 5, 3)
	j := baseJob()
	j.Data = make([]byte, 512)
	j.ChunkSize = 0 // triggers default

	chunks, err := e.createChunks(j)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) == 0 {
		t.Error("expected at least one chunk")
	}
}

// ── loadFile ──────────────────────────────────────────────────────────────────

func TestLoadFile_ExistingFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "ping007-test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("secret exfil data 1234")
	f.Write(content)
	f.Close()

	e := newEngine(512, 5, 3)
	data, err := e.loadFile(f.Name())
	if err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("got %q, want %q", data, content)
	}
}

func TestLoadFile_NonExistent(t *testing.T) {
	e := newEngine(512, 5, 3)
	_, err := e.loadFile("/nonexistent/path/file.bin")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadFile_Directory(t *testing.T) {
	e := newEngine(512, 5, 3)
	_, err := e.loadFile(t.TempDir()) // directory, not a regular file
	if err == nil {
		t.Error("expected error when path is a directory")
	}
}

// ── GetJobStats / GetActiveJobs ───────────────────────────────────────────────

func TestGetJobStats(t *testing.T) {
	e := newEngine(256, 3, 2)
	stats := e.GetJobStats()

	if stats["max_concurrent"] != 3 {
		t.Errorf("max_concurrent: got %v, want 3", stats["max_concurrent"])
	}
	if stats["default_chunk_size"] != 256 {
		t.Errorf("default_chunk_size: got %v, want 256", stats["default_chunk_size"])
	}
	if stats["max_retries"] != 2 {
		t.Errorf("max_retries: got %v, want 2", stats["max_retries"])
	}
	if stats["active_jobs"] != 0 {
		t.Errorf("active_jobs: got %v, want 0", stats["active_jobs"])
	}
}

func TestCreateChunks_WithEncryption(t *testing.T) {
	cryptoCfg := crypto.CryptoConfig{
		Enabled:          false,
		DefaultAlgorithm: "aes256",
		SharedPassword:   "test-exfil-key",
	}
	cryptoEngine, err := crypto.NewCryptoEngine(cryptoCfg)
	if err != nil {
		t.Fatalf("NewCryptoEngine: %v", err)
	}
	defer cryptoEngine.Close()

	e := NewExfiltrationEngine(nil, cryptoEngine, nil, ExfiltrationConfig{
		DefaultChunkSize: 100,
	})

	job := baseJob()
	job.EncryptEnabled = true
	job.Data = []byte("sensitive data that must be encrypted before chunking")

	chunks, err := e.createChunks(job)
	if err != nil {
		t.Fatalf("createChunks with encryption: %v", err)
	}
	if len(chunks) == 0 {
		t.Fatal("expected at least 1 chunk")
	}
	// Verify each chunk has a checksum (encryption path still sets it)
	for i, ch := range chunks {
		if ch.Checksum == "" {
			t.Errorf("chunk %d: missing checksum", i)
		}
		if ch.Status != types.StatusPending {
			t.Errorf("chunk %d: expected StatusPending, got %v", i, ch.Status)
		}
	}
}

func TestGetActiveJobs_InitiallyEmpty(t *testing.T) {
	e := newEngine(512, 5, 3)
	jobs := e.GetActiveJobs()
	if len(jobs) != 0 {
		t.Errorf("expected 0 active jobs initially, got %d", len(jobs))
	}
}

// ── CancelJob ─────────────────────────────────────────────────────────────────

func TestCancelJob_NotFound(t *testing.T) {
	e := newEngine(512, 5, 3)
	if err := e.CancelJob("nonexistent-id"); err == nil {
		t.Error("expected error for unknown job ID")
	}
}

func TestCancelJob_RemovesJob(t *testing.T) {
	e := newEngine(512, 5, 3)

	// Insert a job directly (same package — access activeJobs).
	job := baseJob()
	e.activeJobs[job.ID] = job

	if err := e.CancelJob(job.ID); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	jobs := e.GetActiveJobs()
	for _, j := range jobs {
		if j.ID == job.ID {
			t.Errorf("cancelled job %q still in active list", job.ID)
		}
	}
}

// ── ExfiltrationMonitor ───────────────────────────────────────────────────────

func TestNewExfiltrationMonitor(t *testing.T) {
	e := newEngine(512, 5, 3)
	m := NewExfiltrationMonitor(e)
	if m == nil {
		t.Fatal("expected non-nil ExfiltrationMonitor")
	}
}

func TestGetProgress_NotFound(t *testing.T) {
	e := newEngine(512, 5, 3)
	m := NewExfiltrationMonitor(e)
	if _, err := m.GetProgress("ghost-job"); err == nil {
		t.Error("expected error for unknown job ID")
	}
}

func TestGetProgress_ZeroDefault(t *testing.T) {
	e := newEngine(512, 5, 3)
	job := baseJob()
	e.activeJobs[job.ID] = job

	m := NewExfiltrationMonitor(e)
	progress, err := m.GetProgress(job.ID)
	if err != nil {
		t.Fatalf("GetProgress: %v", err)
	}
	if progress != 0.0 {
		t.Errorf("expected 0.0 for job with no progress metadata, got %f", progress)
	}
}

func TestGetProgress_WithMetadata(t *testing.T) {
	e := newEngine(512, 5, 3)
	job := baseJob()
	job.Metadata["progress"] = float64(0.75)
	e.activeJobs[job.ID] = job

	m := NewExfiltrationMonitor(e)
	progress, err := m.GetProgress(job.ID)
	if err != nil {
		t.Fatalf("GetProgress: %v", err)
	}
	if progress != 0.75 {
		t.Errorf("expected 0.75, got %f", progress)
	}
}

// ── createChunks — encryption error path ─────────────────────────────────────

func TestCreateChunks_EncryptionError(t *testing.T) {
	// Close the CryptoEngine before use — providers map is cleared → Encrypt fails.
	ce, err := crypto.NewCryptoEngine(crypto.CryptoConfig{
		Enabled:          false,
		DefaultAlgorithm: "aes256",
		SharedPassword:   "test-key",
	})
	if err != nil {
		t.Fatalf("NewCryptoEngine: %v", err)
	}
	ce.Close() // clears providers → Encrypt returns "no provider" error

	e := NewExfiltrationEngine(nil, ce, nil, ExfiltrationConfig{DefaultChunkSize: 64})
	job := baseJob()
	job.EncryptEnabled = true
	job.Data = []byte("payload that triggers encryption")

	_, err = e.createChunks(job)
	if err == nil {
		t.Error("expected error from createChunks when CryptoEngine has no providers")
	}
}

// ── loadFile — unreadable file ────────────────────────────────────────────────

func TestLoadFile_NoReadPermission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — chmod 000 cannot prevent file reads")
	}
	f, err := os.CreateTemp(t.TempDir(), "noperm-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("secret"))
	f.Close()

	if err := os.Chmod(f.Name(), 0000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(f.Name(), 0644) })

	e := newEngine(512, 5, 3)
	_, err = e.loadFile(f.Name())
	if err == nil {
		t.Error("expected error for file with mode 000")
	}
}
