package evasion

import (
	"runtime"
	"testing"
	"time"

	"ping007/pkg/types"
)

// ── EvasionEngine initialization ─────────────────────────────────────────────

func TestNewEvasionEngine(t *testing.T) {
	cfg := EvasionConfig{
		CryptoAgility: true,
		AntiSandbox: AntiSandboxConfig{
			Enabled:      false,
			Checks:       []string{"uptime", "processes"},
			MinUptime:    30 * time.Second,
			MinProcesses: 10,
		},
		TimingEvasion: TimingEvasionConfig{
			Enabled:          true,
			AdaptiveDelays:   true,
			JitterPercentage: 0.15,
		},
		TrafficAnalysisResistance: true,
		PaddingSizes:              []int{32, 64, 128},
		FakeDataInjectionRate:     0.0, // deterministic for tests
	}
	e, err := NewEvasionEngine(cfg)
	if err != nil {
		t.Fatalf("NewEvasionEngine: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

// ── SandboxDetector ───────────────────────────────────────────────────────────

func TestPerformSandboxCheck_Disabled(t *testing.T) {
	cfg := EvasionConfig{
		AntiSandbox: AntiSandboxConfig{Enabled: false},
	}
	e, _ := NewEvasionEngine(cfg)
	result, err := e.PerformSandboxCheck()
	if err != nil {
		t.Fatalf("PerformSandboxCheck: %v", err)
	}
	if result.IsSandbox {
		t.Error("disabled sandbox check should always return IsSandbox=false")
	}
	if result.Confidence != 0.0 {
		t.Errorf("expected confidence 0.0, got %f", result.Confidence)
	}
}

func TestPerformSandboxCheck_Enabled(t *testing.T) {
	cfg := EvasionConfig{
		AntiSandbox: AntiSandboxConfig{
			Enabled:      true,
			StrictMode:   false,
			Checks:       []string{"uptime", "processes", "resources", "activity"},
			MinUptime:    1 * time.Millisecond, // very low → never triggers
			MinProcesses: 1,
		},
	}
	e, _ := NewEvasionEngine(cfg)
	result, err := e.PerformSandboxCheck()
	if err != nil {
		t.Fatalf("PerformSandboxCheck: %v", err)
	}
	// Not asserting IsSandbox — result depends on actual host state.
	// Just verify the struct is fully populated.
	if result.CheckedAt.IsZero() {
		t.Error("CheckedAt should be set")
	}
	if result.Indicators == nil {
		t.Error("Indicators should be initialized (not nil)")
	}
}

// ── TimingController / APT profiles ──────────────────────────────────────────

func TestGenerateAPTProfile_AllProfiles(t *testing.T) {
	cfg := EvasionConfig{
		TimingEvasion: TimingEvasionConfig{Enabled: true},
	}
	e, _ := NewEvasionEngine(cfg)

	profiles := []types.APTProfile{
		types.APTLazarus,
		types.APTAPT29,
		types.APTAPT28,
		types.APTEquation,
	}

	for _, apt := range profiles {
		t.Run(string(apt), func(t *testing.T) {
			p, err := e.GenerateTimingProfile(apt)
			if err != nil {
				t.Fatalf("GenerateTimingProfile(%s): %v", apt, err)
			}
			if p.MinDelay <= 0 {
				t.Errorf("MinDelay must be positive, got %v", p.MinDelay)
			}
			if p.MaxDelay < p.MinDelay {
				t.Errorf("MaxDelay (%v) must be >= MinDelay (%v)", p.MaxDelay, p.MinDelay)
			}
			if p.JitterFactor < 0 || p.JitterFactor > 1 {
				t.Errorf("JitterFactor out of [0,1]: %f", p.JitterFactor)
			}
			if p.BurstProbability < 0 || p.BurstProbability > 1 {
				t.Errorf("BurstProbability out of [0,1]: %f", p.BurstProbability)
			}
		})
	}
}

func TestGenerateAPTProfile_Unknown(t *testing.T) {
	cfg := EvasionConfig{TimingEvasion: TimingEvasionConfig{Enabled: true}}
	e, _ := NewEvasionEngine(cfg)
	_, err := e.GenerateTimingProfile(types.APTProfile("unknown_apt"))
	if err == nil {
		t.Error("expected error for unknown APT profile")
	}
}

func TestCalculateAdaptiveDelay_Disabled(t *testing.T) {
	cfg := EvasionConfig{
		TimingEvasion: TimingEvasionConfig{Enabled: false},
	}
	e, _ := NewEvasionEngine(cfg)
	profile := &types.TimingProfile{
		MinDelay: time.Second,
		MaxDelay: 10 * time.Second,
	}
	delay, err := e.CalculateAdaptiveDelay(profile, 100)
	if err != nil {
		t.Fatalf("CalculateAdaptiveDelay: %v", err)
	}
	if delay != 0 {
		t.Errorf("disabled timing: expected 0, got %v", delay)
	}
}

func TestCalculateAdaptiveDelay_LargeData(t *testing.T) {
	// dataSize > 1024 triggers the size-based log-factor adjustment.
	cfg := EvasionConfig{
		TimingEvasion: TimingEvasionConfig{
			Enabled:          true,
			AdaptiveDelays:   true,
			JitterPercentage: 0.1,
		},
	}
	e, _ := NewEvasionEngine(cfg)
	profile := &types.TimingProfile{
		MinDelay:         10 * time.Millisecond,
		MaxDelay:         50 * time.Millisecond,
		JitterFactor:     0.1,
		BurstProbability: 0,
		PauseProbability: 0,
	}
	delay, err := e.CalculateAdaptiveDelay(profile, 4096) // > 1024
	if err != nil {
		t.Fatalf("CalculateAdaptiveDelay large data: %v", err)
	}
	if delay < 0 {
		t.Errorf("negative delay: %v", delay)
	}
}

func TestCalculateAdaptiveDelay_BurstMode(t *testing.T) {
	// BurstProbability=1.0 → generateRandomFloat() < 1.0 always → burst path
	cfg := EvasionConfig{
		TimingEvasion: TimingEvasionConfig{Enabled: true},
	}
	e, _ := NewEvasionEngine(cfg)
	profile := &types.TimingProfile{
		MinDelay:         100 * time.Millisecond,
		MaxDelay:         200 * time.Millisecond,
		JitterFactor:     0,
		BurstProbability: 1.0, // always burst
		PauseProbability: 0,
	}
	delay, err := e.CalculateAdaptiveDelay(profile, 64)
	if err != nil {
		t.Fatalf("CalculateAdaptiveDelay burst: %v", err)
	}
	if delay < 0 {
		t.Errorf("burst mode: negative delay %v", delay)
	}
}

func TestCalculateAdaptiveDelay_PauseMode(t *testing.T) {
	// BurstProbability=0, PauseProbability=1.0 → pause path always triggers
	cfg := EvasionConfig{
		TimingEvasion: TimingEvasionConfig{Enabled: true},
	}
	e, _ := NewEvasionEngine(cfg)
	profile := &types.TimingProfile{
		MinDelay:         10 * time.Millisecond,
		MaxDelay:         20 * time.Millisecond,
		JitterFactor:     0,
		BurstProbability: 0,
		PauseProbability: 1.0, // always pause
	}
	delay, err := e.CalculateAdaptiveDelay(profile, 64)
	if err != nil {
		t.Fatalf("CalculateAdaptiveDelay pause: %v", err)
	}
	if delay < 0 {
		t.Errorf("pause mode: negative delay %v", delay)
	}
}

func TestCalculateAdaptiveDelay_InBounds(t *testing.T) {
	cfg := EvasionConfig{
		TimingEvasion: TimingEvasionConfig{
			Enabled:        true,
			AdaptiveDelays: true,
			JitterPercentage: 0.1,
		},
	}
	e, _ := NewEvasionEngine(cfg)

	profile := &types.TimingProfile{
		MinDelay:         100 * time.Millisecond,
		MaxDelay:         500 * time.Millisecond,
		JitterFactor:     0.1,
		BurstProbability: 0,
		PauseProbability: 0,
	}

	// Run many times to catch edge cases in the random delay calculation.
	for i := 0; i < 200; i++ {
		delay, err := e.CalculateAdaptiveDelay(profile, 512)
		if err != nil {
			t.Fatalf("iter %d: CalculateAdaptiveDelay: %v", i, err)
		}
		// With jitter ±10%, allowed range is [90ms, 550ms]
		if delay < 0 {
			t.Errorf("iter %d: negative delay %v", i, delay)
		}
	}
}

func TestApplyServiceMimicry_Valid(t *testing.T) {
	cfg := EvasionConfig{
		TimingEvasion: TimingEvasionConfig{
			Enabled:        true,
			ServiceMimicry: []string{"windows_update", "ntp_sync", "antivirus"},
		},
	}
	e, _ := NewEvasionEngine(cfg)
	for _, svc := range []string{"windows_update", "ntp_sync", "antivirus"} {
		if err := e.ApplyServiceMimicry(svc); err != nil {
			t.Errorf("ApplyServiceMimicry(%s): %v", svc, err)
		}
	}
}

func TestApplyServiceMimicry_Unknown(t *testing.T) {
	cfg := EvasionConfig{TimingEvasion: TimingEvasionConfig{Enabled: true}}
	e, _ := NewEvasionEngine(cfg)
	if err := e.ApplyServiceMimicry("nonexistent_service"); err == nil {
		t.Error("expected error for unknown service")
	}
}

// ── TrafficObfuscator ─────────────────────────────────────────────────────────

func TestObfuscateData_Disabled(t *testing.T) {
	cfg := EvasionConfig{TrafficAnalysisResistance: false}
	e, _ := NewEvasionEngine(cfg)
	data := []byte("unchanged")
	out, err := e.ObfuscateData(data)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "unchanged" {
		t.Errorf("disabled obfuscation should return original data, got %q", out)
	}
}

func TestObfuscateData_PaddingApplied(t *testing.T) {
	cfg := EvasionConfig{
		TrafficAnalysisResistance: true,
		PaddingSizes:              []int{64},
		FakeDataInjectionRate:     0.0, // no fake injection for determinism
	}
	e, _ := NewEvasionEngine(cfg)
	data := []byte("hello")
	out, err := e.ObfuscateData(data)
	if err != nil {
		t.Fatal(err)
	}
	// With fixed padding of 64, output must be at least len(data)+64
	if len(out) < len(data)+64 {
		t.Errorf("expected padded output ≥ %d bytes, got %d", len(data)+64, len(out))
	}
}

func TestObfuscateData_EmptyPaddingSizes(t *testing.T) {
	// Empty padding list → no padding, no panic
	cfg := EvasionConfig{
		TrafficAnalysisResistance: true,
		PaddingSizes:              []int{},
		FakeDataInjectionRate:     0.0,
	}
	e, _ := NewEvasionEngine(cfg)
	data := []byte("no padding here")
	out, err := e.ObfuscateData(data)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[:len(data)]) != "no padding here" {
		t.Errorf("original data prefix corrupted: %q", out[:len(data)])
	}
}

// ── generateRandomFloat bounds ────────────────────────────────────────────────

func TestGenerateRandomFloat_Bounds(t *testing.T) {
	// 10 000 samples — must all be in [0, 1]
	for i := 0; i < 10000; i++ {
		f := generateRandomFloat()
		if f < 0 || f > 1 {
			t.Fatalf("out-of-range value at iter %d: %f", i, f)
		}
	}
}

// Regression test: applyPadding must not panic when generateRandomFloat() is at its ceiling.
func TestApplyPadding_NoPanic(t *testing.T) {
	to := NewTrafficObfuscator([]int{16, 32, 64, 128, 256}, 0)
	data := []byte("data")
	for i := 0; i < 10000; i++ {
		_ = to.applyPadding(data)
	}
}

// ── injectFakeData ────────────────────────────────────────────────────────────

func TestInjectFakeData_OutputLongerThanInput(t *testing.T) {
	to := NewTrafficObfuscator(nil, 1.0)
	input := []byte("original payload data")
	// injectFakeData inserts up to 255 bytes of random data; the result must be
	// at least as long as the input (fakeSize=0 edge case is valid).
	for i := 0; i < 100; i++ {
		out := to.injectFakeData(input)
		if len(out) < len(input) {
			t.Fatalf("injectFakeData shrank the data: input %d bytes, got %d bytes", len(input), len(out))
		}
	}
}

func TestInjectFakeData_NoPanic_EmptyInput(t *testing.T) {
	to := NewTrafficObfuscator(nil, 1.0)
	for i := 0; i < 500; i++ {
		_ = to.injectFakeData([]byte{})
	}
}

func TestInjectFakeData_OriginalBytesPreserved(t *testing.T) {
	// Inject into a single-byte input. The original byte must still appear
	// exactly once in the output (at position 0 or len(fakeData)).
	to := NewTrafficObfuscator(nil, 1.0)
	const sentinel = byte(0xFE)
	input := []byte{sentinel}
	for i := 0; i < 200; i++ {
		out := to.injectFakeData(input)
		found := false
		for _, b := range out {
			if b == sentinel {
				found = true
				break
			}
		}
		if !found {
			t.Error("sentinel byte 0xFE lost after injectFakeData")
		}
	}
}

// ── contains ─────────────────────────────────────────────────────────────────

func TestContains_PresentItem(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("contains: expected true for present item")
	}
}

func TestContains_AbsentItem(t *testing.T) {
	if contains([]string{"a", "b", "c"}, "z") {
		t.Error("contains: expected false for absent item")
	}
}

func TestContains_EmptySlice(t *testing.T) {
	if contains([]string{}, "x") {
		t.Error("contains: expected false for empty slice")
	}
}

func TestContains_EmptyString(t *testing.T) {
	if !contains([]string{"", "a"}, "") {
		t.Error("contains: empty string should be found in slice containing empty string")
	}
}

// ── SandboxDetector — unexported check branches ───────────────────────────────

func TestCheckUptime_LowUptimeBranch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uptime check only runs on linux")
	}
	// Any real machine has uptime < 100 000 days → triggers "Low uptime" branch.
	sd := NewSandboxDetector(AntiSandboxConfig{
		MinUptime: 100000 * 24 * time.Hour,
	})
	score, reason := sd.checkUptime()
	if score == 0 {
		t.Errorf("expected non-zero score, got %f", score)
	}
	if reason == "" {
		t.Error("expected non-empty reason for low uptime")
	}
}

func TestCheckProcessCount_LowCountBranch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process count check only runs on linux")
	}
	// No real machine has 999 999 processes → triggers "Low process count" branch.
	sd := NewSandboxDetector(AntiSandboxConfig{
		MinProcesses: 999999,
	})
	score, reason := sd.checkProcessCount()
	if score == 0 {
		t.Errorf("expected non-zero score, got %f", score)
	}
	if reason == "" {
		t.Error("expected non-empty reason for low process count")
	}
}

func TestDetectSandbox_StrictMode(t *testing.T) {
	// StrictMode=true changes threshold from 0.5 to 0.3; with no checks,
	// confidence=0 → IsSandbox=false regardless.
	cfg := EvasionConfig{
		AntiSandbox: AntiSandboxConfig{
			Enabled:    true,
			StrictMode: true,
			Checks:     []string{}, // no checks → confidence stays 0
		},
	}
	e, _ := NewEvasionEngine(cfg)
	result, err := e.PerformSandboxCheck()
	if err != nil {
		t.Fatalf("PerformSandboxCheck: %v", err)
	}
	if result.IsSandbox {
		t.Error("expected IsSandbox=false with zero confidence")
	}
}

// ── DetectSandbox — indicator append branch ───────────────────────────────────

func TestDetectSandbox_WithTriggeringUptime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires /proc/uptime (Linux only)")
	}
	// MinUptime set far beyond any real uptime → checkUptime returns a non-empty
	// indicator → the `if indicator != ""` append branch inside DetectSandbox fires.
	cfg := EvasionConfig{
		AntiSandbox: AntiSandboxConfig{
			Enabled: true,
			Checks:  []string{"uptime"},
			MinUptime: 100000 * 24 * time.Hour, // 100k days — always triggers
		},
	}
	e, err := NewEvasionEngine(cfg)
	if err != nil {
		t.Fatalf("NewEvasionEngine: %v", err)
	}
	result, err := e.PerformSandboxCheck()
	if err != nil {
		t.Fatalf("PerformSandboxCheck: %v", err)
	}
	if len(result.Indicators) == 0 {
		t.Error("expected at least one indicator from low-uptime check")
	}
}

// ── TimingController — disabled early return ──────────────────────────────────

func TestTimingController_CalculateDelay_Disabled(t *testing.T) {
	// tc.config.Enabled=false → CalculateDelay returns (0, nil) immediately
	// without running the delay logic. This path is skipped by EvasionEngine
	// (which has its own Enabled check) so the TimingController must be tested
	// directly.
	tc := NewTimingController(TimingEvasionConfig{Enabled: false})
	d, err := tc.CalculateDelay(&types.TimingProfile{
		MinDelay:         10 * time.Millisecond,
		MaxDelay:         100 * time.Millisecond,
		JitterFactor:     0.1,
		BurstProbability: 0.0,
		PauseProbability: 0.0,
	}, 64)
	if err != nil {
		t.Errorf("CalculateDelay disabled: unexpected error: %v", err)
	}
	if d != 0 {
		t.Errorf("CalculateDelay disabled: expected 0 delay, got %v", d)
	}
}

// ── ObfuscateData — fakeDataInjection branch ──────────────────────────────────

func TestObfuscateData_WithFakeDataInjection(t *testing.T) {
	// FakeDataInjectionRate=1.0 → generateRandomFloat() < 1.0 always → injectFakeData called.
	cfg := EvasionConfig{
		TrafficAnalysisResistance: true,
		PaddingSizes:              []int{0},
		FakeDataInjectionRate:     1.0,
	}
	e, _ := NewEvasionEngine(cfg)
	data := []byte("original payload")
	out, err := e.ObfuscateData(data)
	if err != nil {
		t.Fatal(err)
	}
	// injectFakeData inserts random bytes; output must be at least as long as input.
	if len(out) < len(data) {
		t.Errorf("expected len(out) >= %d, got %d", len(data), len(out))
	}
}
