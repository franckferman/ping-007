package config

import (
	"os"
	"testing"

	"ping007/pkg/types"
)

// ── ValidateTarget ───────────────────────────────────────────────────────────

func testConfig() *Config {
	return &Config{
		Network: NetworkConfig{
			AuthorizedTargets: []string{
				"192.168.0.0/16",
				"10.0.0.0/8",
				"172.16.0.0/12",
			},
			ForbiddenTargets: []string{
				"127.0.0.0/8",
				"0.0.0.0/8",
				"169.254.0.0/16",
			},
		},
	}
}

func TestValidateTarget_Authorized(t *testing.T) {
	cfg := testConfig()
	cases := []string{"10.0.0.1", "10.255.255.254", "192.168.1.100", "172.16.0.1"}
	for _, ip := range cases {
		if err := cfg.ValidateTarget(ip); err != nil {
			t.Errorf("expected %s to be authorized, got: %v", ip, err)
		}
	}
}

func TestValidateTarget_Forbidden(t *testing.T) {
	cfg := testConfig()
	cases := []string{"127.0.0.1", "127.0.0.2", "169.254.1.1"}
	for _, ip := range cases {
		if err := cfg.ValidateTarget(ip); err == nil {
			t.Errorf("expected %s to be rejected (forbidden range)", ip)
		}
	}
}

func TestValidateTarget_NotInAnyRange(t *testing.T) {
	cfg := testConfig()
	// 8.8.8.8 is public, not in any authorized range
	if err := cfg.ValidateTarget("8.8.8.8"); err == nil {
		t.Error("expected 8.8.8.8 to be rejected (not in authorized range)")
	}
}

func TestValidateTarget_InvalidIP(t *testing.T) {
	cfg := testConfig()
	cases := []string{"not-an-ip", "999.999.999.999", ""}
	for _, s := range cases {
		if err := cfg.ValidateTarget(s); err == nil {
			t.Errorf("expected %q to be rejected (invalid IP)", s)
		}
	}
}

// ── validateConfig ───────────────────────────────────────────────────────────

func baseValidConfig() *Config {
	return &Config{
		Network: NetworkConfig{
			AuthorizedTargets: []string{"10.0.0.0/8"},
			ForbiddenTargets:  []string{"127.0.0.0/8"},
		},
		Evasion: EvasionConfig{
			CryptoAgility: CryptoAgilityConfig{
				RotationInterval: 300,
			},
			AntiSandbox: AntiSandboxConfig{
				MinUptime: 0,
			},
		},
		APTProfiles: map[string]APTProfileConfig{},
	}
}

func TestValidateConfig_Valid(t *testing.T) {
	if err := validateConfig(baseValidConfig()); err != nil {
		t.Errorf("expected valid config to pass, got: %v", err)
	}
}

func TestValidateConfig_InvalidAuthorizedCIDR(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Network.AuthorizedTargets = []string{"not-a-cidr"}
	if err := validateConfig(cfg); err == nil {
		t.Error("expected invalid authorized CIDR to fail")
	}
}

func TestValidateConfig_InvalidForbiddenCIDR(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Network.ForbiddenTargets = []string{"300.300.300.300/8"}
	if err := validateConfig(cfg); err == nil {
		t.Error("expected invalid forbidden CIDR to fail")
	}
}

func TestValidateConfig_RotationIntervalTooShort(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Evasion.CryptoAgility.RotationInterval = 299
	if err := validateConfig(cfg); err == nil {
		t.Error("expected rotation interval < 300 to fail")
	}
}

func TestValidateConfig_NegativeUptime(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Evasion.AntiSandbox.MinUptime = -1
	if err := validateConfig(cfg); err == nil {
		t.Error("expected negative min_uptime to fail")
	}
}

func TestValidateConfig_InvalidAPTTimingRange(t *testing.T) {
	cfg := baseValidConfig()
	cfg.APTProfiles = map[string]APTProfileConfig{
		"bad": {
			TimingRange: [2]int{3600, 300}, // min > max
			SizeRange:   [2]int{0, 64},
		},
	}
	if err := validateConfig(cfg); err == nil {
		t.Error("expected invalid APT timing range to fail")
	}
}

func TestValidateConfig_InvalidAPTSizeRange(t *testing.T) {
	cfg := baseValidConfig()
	cfg.APTProfiles = map[string]APTProfileConfig{
		"bad": {
			TimingRange: [2]int{0, 60},
			SizeRange:   [2]int{512, 64}, // min > max
		},
	}
	if err := validateConfig(cfg); err == nil {
		t.Error("expected invalid APT size range to fail")
	}
}

// ── EnsureDirectories ────────────────────────────────────────────────────────

func TestEnsureDirectories_EmptyDir(t *testing.T) {
	// With an empty OutputDir, EnsureDirectories should skip without error.
	cfg := &Config{
		Reporting: ReportingConfig{OutputDir: ""},
	}
	if err := cfg.EnsureDirectories(); err != nil {
		t.Errorf("unexpected error with empty OutputDir: %v", err)
	}
}

func TestEnsureDirectories_TempDir(t *testing.T) {
	cfg := &Config{
		Reporting: ReportingConfig{OutputDir: t.TempDir() + "/ping007-test-output"},
	}
	if err := cfg.EnsureDirectories(); err != nil {
		t.Errorf("unexpected error creating temp dir: %v", err)
	}
}

func TestEnsureDirectories_ErrorWhenParentIsFile(t *testing.T) {
	// Create a regular file, then try to use it as a directory parent.
	// os.MkdirAll must fail because the path component is a file, not a dir.
	tmp := t.TempDir()
	// Create a plain file
	parentFile := tmp + "/notadir"
	f, err := os.Create(parentFile)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	f.Close()

	cfg := &Config{
		Reporting: ReportingConfig{OutputDir: parentFile + "/subdir"},
	}
	if err := cfg.EnsureDirectories(); err == nil {
		t.Error("expected error when OutputDir parent is a regular file")
	}
}

func TestValidateTarget_Hostname_ForbiddenAfterResolve(t *testing.T) {
	cfg := testConfig() // has 127.0.0.0/8 as forbidden
	// "localhost" resolves (via /etc/hosts) to 127.0.0.1 — should be rejected.
	err := cfg.ValidateTarget("localhost")
	if err == nil {
		t.Error("expected 'localhost' (127.0.0.1) to be rejected as forbidden")
	}
}

// ── GetAPTProfile ─────────────────────────────────────────────────────────────

func TestGetAPTProfile_Found(t *testing.T) {
	cfg := &Config{
		APTProfiles: map[string]APTProfileConfig{
			"lazarus": {
				Description:      "Lazarus Group (North Korea)",
				TimingRange:      [2]int{300, 3600},
				SizeRange:        [2]int{64, 1024},
				CryptoPreference: "aes256",
				Sophistication:   "high",
			},
		},
	}
	profile, err := cfg.GetAPTProfile(types.APTLazarus)
	if err != nil {
		t.Fatalf("GetAPTProfile(lazarus): %v", err)
	}
	if profile.Description != "Lazarus Group (North Korea)" {
		t.Errorf("Description: got %q, want \"Lazarus Group (North Korea)\"", profile.Description)
	}
	if profile.CryptoPreference != "aes256" {
		t.Errorf("CryptoPreference: got %q, want \"aes256\"", profile.CryptoPreference)
	}
}

func TestGetAPTProfile_NotFound(t *testing.T) {
	cfg := &Config{APTProfiles: map[string]APTProfileConfig{}}
	_, err := cfg.GetAPTProfile(types.APTProfile("unknown_apt"))
	if err == nil {
		t.Error("expected error for unknown APT profile")
	}
}

// ── Load ─────────────────────────────────────────────────────────────────────

func TestLoad_DefaultsWhenNoFile(t *testing.T) {
	// go test runs with cwd = package dir (internal/config).
	// No ping-007.yaml exists there → viper uses setDefaults() only.
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with no config file: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
	// Spot-check a few defaults to confirm setDefaults was applied.
	if cfg.Framework.Name == "" {
		t.Error("expected Framework.Name to be set from defaults")
	}
	if len(cfg.Network.AuthorizedTargets) == 0 {
		t.Error("expected non-empty AuthorizedTargets from defaults")
	}
}

func TestGetAPTProfile_AllFourProfiles(t *testing.T) {
	cfg := &Config{
		APTProfiles: map[string]APTProfileConfig{
			"lazarus":  {TimingRange: [2]int{300, 3600}},
			"apt29":    {TimingRange: [2]int{1800, 7200}},
			"apt28":    {TimingRange: [2]int{600, 1800}},
			"equation": {TimingRange: [2]int{86400, 259200}},
		},
	}
	for _, name := range []string{"lazarus", "apt29", "apt28", "equation"} {
		if _, err := cfg.GetAPTProfile(types.APTProfile(name)); err != nil {
			t.Errorf("GetAPTProfile(%q): unexpected error: %v", name, err)
		}
	}
}

// ── ValidateTarget — unresolvable hostname ────────────────────────────────────

func TestValidateTarget_NonResolvableHostname(t *testing.T) {
	cfg := testConfig()
	// ".invalid" is a reserved TLD (RFC 2606) guaranteed never to resolve.
	err := cfg.ValidateTarget("nonexistent.invalid")
	if err == nil {
		t.Error("expected error for hostname that cannot be resolved")
	}
}
