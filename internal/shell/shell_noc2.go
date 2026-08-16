//go:build noc2

package shell

import (
	"fmt"
	"time"

	"ping007/internal/crypto"
	"ping007/internal/network"
)

// Stub types — present so the orchestrator compiles under -tags noc2.
// All methods return immediately; the shell command is excluded from the CLI.

type ShellConfig struct {
	MaxSessions       int
	SessionTimeout    time.Duration
	CommandTimeout    time.Duration
	MaxOutputSize     int
	EncryptionEnabled bool
	JitterMax         time.Duration
}

type ShellEngine struct{}

type ShellSession struct{}

func NewShellEngine(
	_ *network.NetworkService,
	_ *crypto.CryptoEngine,
	_ ShellConfig,
) *ShellEngine {
	return nil
}

func (s *ShellEngine) InteractiveShell(_, _ string, _ time.Duration) error {
	return fmt.Errorf("shell C2 not available in this build (compiled with -tags noc2)")
}

func (s *ShellEngine) GetSessionStats() map[string]any {
	return nil
}
