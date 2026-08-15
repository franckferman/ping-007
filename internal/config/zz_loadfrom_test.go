package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromExplicitPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "custom.yml")
	content := "network:\n  authorized_targets:\n    - \"159.89.104.175/32\"\n"
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFrom(p)
	if err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}
	if err := cfg.ValidateTarget("159.89.104.175"); err != nil {
		t.Fatalf("expected 159.89.104.175 authorized, got: %v", err)
	}
	if err := cfg.ValidateTarget("8.8.8.8"); err == nil {
		t.Fatal("expected 8.8.8.8 to be rejected")
	}
}

func TestAllowAllTargetsBypass(t *testing.T) {
	cfg := &Config{}
	cfg.Network.AllowAllTargets = true
	if err := cfg.ValidateTarget("203.0.113.99"); err != nil {
		t.Fatalf("AllowAllTargets should bypass validation: %v", err)
	}
	// forbidden ranges are also bypassed by design of the flag
	if err := cfg.ValidateTarget("127.0.0.1"); err != nil {
		t.Fatalf("AllowAllTargets should bypass forbidden too: %v", err)
	}
}
