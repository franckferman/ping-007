package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ping007/pkg/types"
)

type Logger struct {
	slogger    *slog.Logger
	config     LoggerConfig
	siemWriter *SIEMWriter
	file       *os.File
	mu         sync.RWMutex
}

type LoggerConfig struct {
	Level           string
	OutputFile      string
	Format          string // "json" or "text"
	SIEMEnabled     bool
	AuditEnabled    bool
	MaxFileSize     int64
	RotationCount   int
}

type SIEMConfig struct {
	Enabled          bool
	ConnectorType    string // "splunk", "elastic", "custom"
	Endpoint         string
	Index            string
	SourceType       string
	APIToken         string
	RealTimeAlerting bool
}

func New(level string) *Logger {
	config := LoggerConfig{
		Level:         level,
		OutputFile:    "logs/ping-007.log",
		Format:        "json",
		AuditEnabled:  true,
		MaxFileSize:   100 * 1024 * 1024, // 100MB
		RotationCount: 5,
	}

	logger := &Logger{
		config: config,
	}

	logger.initialize()
	return logger
}

func NewWithConfig(config LoggerConfig, siemConfig *SIEMConfig) *Logger {
	logger := &Logger{
		config: config,
	}

	if siemConfig != nil && siemConfig.Enabled {
		logger.siemWriter = NewSIEMWriter(*siemConfig)
	}

	logger.initialize()
	return logger
}

// initialize sets up the logger
func (l *Logger) initialize() {
	// Create logs directory
	logDir := filepath.Dir(l.config.OutputFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
	}

	// Open log file
	var err error
	l.file, err = os.OpenFile(l.config.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		l.file = nil
	}

	// Create writers
	var writers []io.Writer
	writers = append(writers, os.Stdout)

	if l.file != nil {
		writers = append(writers, l.file)
	}

	if l.siemWriter != nil {
		writers = append(writers, l.siemWriter)
	}

	multiWriter := io.MultiWriter(writers...)

	// Configure slog level
	var logLevel slog.Level
	switch strings.ToUpper(l.config.Level) {
	case "DEBUG":
		logLevel = slog.LevelDebug
	case "INFO":
		logLevel = slog.LevelInfo
	case "WARN", "WARNING":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	// Create handler based on format
	var handler slog.Handler
	if l.config.Format == "json" {
		handler = slog.NewJSONHandler(multiWriter, &slog.HandlerOptions{
			Level: logLevel,
			AddSource: true,
		})
	} else {
		handler = slog.NewTextHandler(multiWriter, &slog.HandlerOptions{
			Level: logLevel,
			AddSource: true,
		})
	}

	l.slogger = slog.New(handler)
}

// Info logs an info level message
func (l *Logger) Info(msg string, args ...any) {
	l.slogger.Info(msg, args...)
}

// Debug logs a debug level message
func (l *Logger) Debug(msg string, args ...any) {
	l.slogger.Debug(msg, args...)
}

// Warn logs a warning level message
func (l *Logger) Warn(msg string, args ...any) {
	l.slogger.Warn(msg, args...)
}

// Error logs an error level message
func (l *Logger) Error(msg string, args ...any) {
	l.slogger.Error(msg, args...)
}

// LogSecurityEvent logs a security event for SIEM integration
func (l *Logger) LogSecurityEvent(event *types.SecurityEvent) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Convert event to structured log
	eventData := map[string]any{
		"event_type":     event.EventType,
		"severity":       event.Severity,
		"message":        event.Message,
		"timestamp":      event.Timestamp,
		"security_level": event.SecurityLevel,
	}

	// Add optional fields
	if event.SessionID != "" {
		eventData["session_id"] = event.SessionID
	}
	if event.TargetIP != "" {
		eventData["target_ip"] = event.TargetIP
	}
	if event.Technique != "" {
		eventData["technique"] = event.Technique
	}
	if event.Component != "" {
		eventData["component"] = event.Component
	}

	// Add metadata
	for key, value := range event.Metadata {
		eventData[fmt.Sprintf("meta_%s", key)] = value
	}

	// Log based on severity
	switch strings.ToUpper(event.Severity) {
	case "DEBUG":
		l.slogger.Debug("Security Event", slog.Any("event", eventData))
	case "INFO":
		l.slogger.Info("Security Event", slog.Any("event", eventData))
	case "WARN", "WARNING":
		l.slogger.Warn("Security Event", slog.Any("event", eventData))
	case "ERROR", "CRITICAL":
		l.slogger.Error("Security Event", slog.Any("event", eventData))
	default:
		l.slogger.Info("Security Event", slog.Any("event", eventData))
	}
}

// LogExfiltrationEvent logs data exfiltration events
func (l *Logger) LogExfiltrationEvent(jobID, target, method string, bytesTransmitted int64, success bool) {
	event := &types.SecurityEvent{
		EventType:     "data_exfiltration",
		Severity:      "INFO",
		Message:       fmt.Sprintf("Data exfiltration job %s to %s via %s", jobID, target, method),
		Timestamp:     time.Now(),
		TargetIP:      target,
		Technique:     method,
		Component:     "exfiltration_engine",
		SecurityLevel: "operational",
		Metadata: map[string]any{
			"job_id":             jobID,
			"bytes_transmitted":  bytesTransmitted,
			"success":            success,
			"exfiltration_method": method,
		},
	}

	if !success {
		event.Severity = "ERROR"
	}

	l.LogSecurityEvent(event)
}

// LogShellActivity logs shell command activity
func (l *Logger) LogShellActivity(sessionID, target, command string, success bool, executionTime time.Duration) {
	event := &types.SecurityEvent{
		EventType:     "shell_command",
		Severity:      "INFO",
		Message:       fmt.Sprintf("Shell command executed in session %s", sessionID),
		Timestamp:     time.Now(),
		SessionID:     sessionID,
		TargetIP:      target,
		Component:     "shell_engine",
		SecurityLevel: "operational",
		Metadata: map[string]any{
			"command":        command,
			"success":        success,
			"execution_time": executionTime.String(),
		},
	}

	l.LogSecurityEvent(event)
}

// LogEvasionActivity logs evasion technique usage
func (l *Logger) LogEvasionActivity(technique string, success bool, confidence float64) {
	event := &types.SecurityEvent{
		EventType:     "evasion_technique",
		Severity:      "INFO",
		Message:       fmt.Sprintf("Evasion technique %s applied", technique),
		Timestamp:     time.Now(),
		Technique:     technique,
		Component:     "evasion_engine",
		SecurityLevel: "tactical",
		Metadata: map[string]any{
			"success":    success,
			"confidence": confidence,
		},
	}

	l.LogSecurityEvent(event)
}

// LogNetworkActivity logs network transmission activity
func (l *Logger) LogNetworkActivity(target string, packetsSent, bytesTransmitted int64, latency time.Duration) {
	event := &types.SecurityEvent{
		EventType:     "network_transmission",
		Severity:      "DEBUG",
		Message:       fmt.Sprintf("Network activity to %s", target),
		Timestamp:     time.Now(),
		TargetIP:      target,
		Component:     "network_service",
		SecurityLevel: "technical",
		Metadata: map[string]any{
			"packets_sent":      packetsSent,
			"bytes_transmitted": bytesTransmitted,
			"latency_ms":        float64(latency.Nanoseconds()) / 1e6,
		},
	}

	l.LogSecurityEvent(event)
}

// LogCryptoActivity logs cryptographic operations
func (l *Logger) LogCryptoActivity(operation string, algorithm string, success bool) {
	event := &types.SecurityEvent{
		EventType:     "crypto_operation",
		Severity:      "DEBUG",
		Message:       fmt.Sprintf("Cryptographic operation: %s with %s", operation, algorithm),
		Timestamp:     time.Now(),
		Component:     "crypto_engine",
		SecurityLevel: "technical",
		Metadata: map[string]any{
			"operation": operation,
			"algorithm": algorithm,
			"success":   success,
		},
	}

	l.LogSecurityEvent(event)
}

// Close closes the logger and its resources
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var err error
	if l.file != nil {
		err = l.file.Close()
		l.file = nil
	}

	if l.siemWriter != nil {
		if closeErr := l.siemWriter.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}

	return err
}

// RotateLog rotates the log file if it exceeds size limit
func (l *Logger) RotateLog() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return nil
	}

	// Check file size
	info, err := l.file.Stat()
	if err != nil {
		return err
	}

	if info.Size() < l.config.MaxFileSize {
		return nil // No rotation needed
	}

	// Close current file
	l.file.Close()

	// Rotate files
	baseName := l.config.OutputFile
	for i := l.config.RotationCount - 1; i >= 1; i-- {
		oldName := fmt.Sprintf("%s.%d", baseName, i)
		newName := fmt.Sprintf("%s.%d", baseName, i+1)
		os.Rename(oldName, newName)
	}

	// Move current file to .1
	os.Rename(baseName, baseName+".1")

	// Create new file
	l.file, err = os.OpenFile(baseName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %w", err)
	}

	return nil
}

// SIEMWriter handles SIEM integration
type SIEMWriter struct {
	config SIEMConfig
	buffer chan []byte
	done   chan struct{}
	mu     sync.RWMutex
}

func NewSIEMWriter(config SIEMConfig) *SIEMWriter {
	writer := &SIEMWriter{
		config: config,
		buffer: make(chan []byte, 1000),
		done:   make(chan struct{}),
	}

	// Start background worker
	go writer.worker()

	return writer
}

// Write implements io.Writer for SIEM integration
func (sw *SIEMWriter) Write(p []byte) (n int, err error) {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	select {
	case sw.buffer <- append([]byte(nil), p...): // Copy data
		return len(p), nil
	case <-sw.done:
		return 0, fmt.Errorf("SIEM writer is closed")
	default:
		// Buffer full, drop message (in production, might want to handle differently)
		return len(p), nil
	}
}

// worker processes SIEM messages in background
func (sw *SIEMWriter) worker() {
	for {
		select {
		case data := <-sw.buffer:
			sw.sendToSIEM(data)
		case <-sw.done:
			return
		}
	}
}

// sendToSIEM sends data to the configured SIEM system
func (sw *SIEMWriter) sendToSIEM(data []byte) {
	// In a real implementation, this would send to Splunk, Elastic, etc.
	// For now, we'll just format and potentially store it
	switch sw.config.ConnectorType {
	case "splunk":
		sw.sendToSplunk(data)
	case "elastic":
		sw.sendToElastic(data)
	default:
		// Default: just log to a separate SIEM file
		sw.sendToFile(data)
	}
}

// sendToSplunk sends data to Splunk HEC
func (sw *SIEMWriter) sendToSplunk(data []byte) {
	// TODO: Implement Splunk HEC integration
	// This would use HTTP POST to the Splunk HEC endpoint
	fmt.Printf("[SIEM-SPLUNK] %s\n", string(data))
}

// sendToElastic sends data to Elasticsearch
func (sw *SIEMWriter) sendToElastic(data []byte) {
	// TODO: Implement Elasticsearch integration
	// This would use the Elasticsearch client
	fmt.Printf("[SIEM-ELASTIC] %s\n", string(data))
}

// sendToFile writes to a SIEM-specific file
func (sw *SIEMWriter) sendToFile(data []byte) {
	// Create SIEM log file
	siemFile := "logs/ping-007-siem.log"

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(siemFile), 0755); err != nil {
		return
	}

	// Write to file
	file, err := os.OpenFile(siemFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	// Add SIEM metadata
	siemEntry := map[string]any{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"source":     "ping-007",
		"sourcetype": sw.config.SourceType,
		"index":      sw.config.Index,
		"event":      json.RawMessage(data),
	}

	siemData, err := json.Marshal(siemEntry)
	if err != nil {
		return
	}

	file.Write(siemData)
	file.Write([]byte("\n"))
}

// Close closes the SIEM writer
func (sw *SIEMWriter) Close() error {
	close(sw.done)
	return nil
}

type AuditLogger struct {
	logger *Logger
	file   *os.File
}

func NewAuditLogger(auditFile string) (*AuditLogger, error) {
	// Create audit directory
	auditDir := filepath.Dir(auditFile)
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %w", err)
	}

	// Open audit file
	file, err := os.OpenFile(auditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit file: %w", err)
	}

	return &AuditLogger{
		file: file,
	}, nil
}

// LogAuditEvent logs an audit event
func (al *AuditLogger) LogAuditEvent(eventType, user, action string, metadata map[string]any) {
	auditEntry := map[string]any{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"event_type": eventType,
		"user":       user,
		"action":     action,
		"metadata":   metadata,
	}

	data, err := json.Marshal(auditEntry)
	if err != nil {
		return
	}

	al.file.Write(data)
	al.file.Write([]byte("\n"))
}

// Close closes the audit logger
func (al *AuditLogger) Close() error {
	if al.file != nil {
		return al.file.Close()
	}
	return nil
}