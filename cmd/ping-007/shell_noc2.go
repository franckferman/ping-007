//go:build noc2

package main

import (
	"ping007/internal/orchestrator"

	"github.com/spf13/cobra"
)

// addShellCommand is a no-op when built with -tags noc2.
// The interactive shell command is excluded from the binary.
func addShellCommand(_ *cobra.Command, _ *orchestrator.Orchestrator) {}
