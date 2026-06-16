package network

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"ping007/pkg/types"
)

// TestPacketBuilder tests packet building functionality
func TestPacketBuilder(t *testing.T) {
	sessionID := "test-session-123"
	builder := NewPacketBuilder(sessionID)

	t.Run("CreateDataPacket", func(t *testing.T) {
		data := []byte("test data")
		packet := builder.CreateDataPacket(data, "test")

		if string(packet.Payload) != "test data" {
			t.Errorf("Expected payload 'test data', got '%s'", string(packet.Payload))
		}

		if packet.Metadata.SessionID != sessionID {
			t.Errorf("Expected session ID '%s', got '%s'", sessionID, packet.Metadata.SessionID)
		}
	})

	t.Run("CreateStealthPacket", func(t *testing.T) {
		data := []byte("stealth test")
		packet := builder.CreateStealthPacket(data, true)

		// Stealth packet should be padded to 56 bytes
		if len(packet.Payload) != 56 {
			t.Errorf("Expected stealth payload size 56 bytes, got %d", len(packet.Payload))
		}

		// Should have stealth headers
		if !packet.Headers["stealth_mode"].(bool) {
			t.Error("Expected stealth_mode header to be true")
		}
	})

	t.Run("CreateStealthChunks", func(t *testing.T) {
		// Large data that needs chunking
		largeData := make([]byte, 100) // > 48 bytes, should be chunked
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		chunks := builder.CreateStealthChunks(largeData)

		if len(chunks) < 2 {
			t.Errorf("Expected multiple chunks for large data, got %d", len(chunks))
		}

		// Verify chunk metadata
		for i, chunk := range chunks {
			if chunk.Headers["chunk_index"] != i {
				t.Errorf("Chunk %d has wrong index: %v", i, chunk.Headers["chunk_index"])
			}

			if chunk.Headers["total_chunks"] != len(chunks) {
				t.Errorf("Chunk %d has wrong total_chunks: %v", i, chunk.Headers["total_chunks"])
			}
		}
	})
}

// TestNetworkConfig tests configuration validation
func TestNetworkConfig(t *testing.T) {
	config := NetworkConfig{
		DefaultInterface: "eth0",
		Timeout:          5 * time.Second,
		MaxPacketSize:    1500,
	}

	// Test timeout validation
	if config.Timeout <= 0 {
		t.Error("Expected positive timeout")
	}

	// Test packet size validation
	if config.MaxPacketSize <= 0 {
		t.Error("Expected positive max packet size")
	}
}

// TestLegitimatePayload tests ping mimicry
func TestLegitimatePayload(t *testing.T) {
	builder := NewPacketBuilder("test-session")

	testCases := []struct {
		name       string
		input      []byte
		expectSize int
		checkPattern bool // Only check ping pattern for empty data
	}{
		{"Empty data", []byte{}, 56, true},
		{"Small data", []byte("hello"), 56, false},
		{"Medium data", []byte("this is a longer test message"), 56, false},
		{"Exact fit", make([]byte, 48), 56, false}, // 48 + 8 ping pattern = 56
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := builder.createLegitimatePayload(tc.input, 56)

			if len(payload) != tc.expectSize {
				t.Errorf("Expected payload size %d, got %d", tc.expectSize, len(payload))
			}

			// Check ping pattern only for empty data (pattern gets XORed when data is present)
			if tc.checkPattern {
				// First 8 bytes are timestamp, next 8 bytes should be ping pattern
				// Linux ping pattern starts from byte 8 (after timestamp)
				expectedPattern := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
				for i, b := range expectedPattern {
					if payload[i+8] != b {
						t.Errorf("Ping pattern mismatch at byte %d: expected %02x, got %02x", i+8, b, payload[i+8])
					}
				}
			}
		})
	}
}

// BenchmarkPacketCreation benchmarks packet creation performance
func BenchmarkPacketCreation(b *testing.B) {
	builder := NewPacketBuilder("bench-session")
	data := []byte("benchmark test data")

	b.Run("CreateDataPacket", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			builder.CreateDataPacket(data, "benchmark")
		}
	})

	b.Run("CreateStealthPacket", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			builder.CreateStealthPacket(data, false)
		}
	})
}
// ── Fragment protocol (0xA7) tests ────────────────────────────────────────────

func TestFragDataCapacity(t *testing.T) {
	if got := FragDataCapacity("linux"); got != 42 {
		t.Errorf("linux capacity: want 42, got %d", got)
	}
	if got := FragDataCapacity("windows"); got != 18 {
		t.Errorf("windows capacity: want 18, got %d", got)
	}
	// Unknown signature falls back to linux default
	if got := FragDataCapacity("unknown"); got != 42 {
		t.Errorf("unknown capacity: want 42 (default), got %d", got)
	}
}

func TestCreateFragmentedPackets_SingleFrag(t *testing.T) {
	pb := NewPacketBuilder("frag-test")
	// Payload small enough to fit in one linux fragment (≤42 bytes)
	data := bytes.Repeat([]byte{0xAA}, 10)
	pkts, err := pb.CreateFragmentedPackets(data, 0xBB, "linux")
	if err != nil {
		t.Fatalf("CreateFragmentedPackets: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	// Verify headers
	if pkts[0].Headers["frag_id"].(byte) != 0 {
		t.Error("single fragment should have frag_id=0")
	}
	if pkts[0].Headers["total_frags"].(byte) != 1 {
		t.Error("single fragment should have total_frags=1")
	}
}

func TestCreateFragmentedPackets_MultipleFrags(t *testing.T) {
	pb := NewPacketBuilder("frag-test")
	// 90 bytes: ceil(90/42) = 3 fragments
	data := bytes.Repeat([]byte{0x42}, 90)
	pkts, err := pb.CreateFragmentedPackets(data, 0x01, "linux")
	if err != nil {
		t.Fatalf("CreateFragmentedPackets: %v", err)
	}
	if len(pkts) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(pkts))
	}
	for i, pkt := range pkts {
		if pkt.Headers["frag_id"].(byte) != byte(i) {
			t.Errorf("pkt[%d]: frag_id=%d, want %d", i, pkt.Headers["frag_id"].(byte), i)
		}
		if pkt.Headers["total_frags"].(byte) != 3 {
			t.Errorf("pkt[%d]: total_frags=%d, want 3", i, pkt.Headers["total_frags"].(byte))
		}
		if pkt.Headers["session_byte"].(byte) != 0x01 {
			t.Errorf("pkt[%d]: session_byte mismatch", i)
		}
	}
}

// extractLinuxEmbedded decodes the embedded payload from a linux stealth packet.
// Linux format: [0..7] timeval | [8..9] length XOR 0x08/0x09 | [10..] data XOR sequential(0x0a+i)
func extractLinuxEmbedded(payload []byte) ([]byte, error) {
	if len(payload) < 10 {
		return nil, fmt.Errorf("payload too short: %d bytes", len(payload))
	}
	dataLen := int(payload[8]^0x08)<<8 | int(payload[9]^0x09)
	if 10+dataLen > len(payload) {
		return nil, fmt.Errorf("declared length %d exceeds payload", dataLen)
	}
	embedded := make([]byte, dataLen)
	for i := 0; i < dataLen; i++ {
		embedded[i] = payload[10+i] ^ byte(0x0a+i)
	}
	return embedded, nil
}

func TestCreateFragmentedPackets_Reassembly(t *testing.T) {
	pb := NewPacketBuilder("reassembly-test")
	original := make([]byte, 200)
	for i := range original {
		original[i] = byte(i % 251)
	}

	pkts, err := pb.CreateFragmentedPackets(original, 0xCC, "linux")
	if err != nil {
		t.Fatalf("CreateFragmentedPackets: %v", err)
	}

	// Decode each fragment and reassemble: XOR back with linux sequential pattern,
	// verify magic byte, strip 4-byte frag header, collect payload bytes.
	var reassembled []byte
	for idx, pkt := range pkts {
		embedded, err := extractLinuxEmbedded(pkt.Payload)
		if err != nil {
			t.Fatalf("fragment %d: %v", idx, err)
		}
		if len(embedded) < 4 {
			t.Fatalf("fragment %d: embedded too short (%d bytes)", idx, len(embedded))
		}
		if embedded[0] != FragMagic {
			t.Fatalf("fragment %d: magic=0x%02X, want 0x%02X", idx, embedded[0], FragMagic)
		}
		// embedded[1]=session, [2]=frag_id, [3]=total_frags, [4..]=fragment payload
		reassembled = append(reassembled, embedded[4:]...)
	}

	if !bytes.Equal(original, reassembled) {
		t.Errorf("reassembly mismatch: got %d bytes, want %d bytes", len(reassembled), len(original))
	}
}

func TestCreateFragmentedPackets_WindowsCapacity(t *testing.T) {
	pb := NewPacketBuilder("win-frag")
	// 36 bytes: ceil(36/18) = 2 windows fragments
	data := bytes.Repeat([]byte{0xFF}, 36)
	pkts, err := pb.CreateFragmentedPackets(data, 0x05, "windows")
	if err != nil {
		t.Fatalf("CreateFragmentedPackets: %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("expected 2 windows packets, got %d", len(pkts))
	}
}

func TestCreateFragmentedPackets_TooLarge(t *testing.T) {
	pb := NewPacketBuilder("toolarge")
	// 256 fragments needed → exceeds 255 max
	data := bytes.Repeat([]byte{0x01}, 256*FragDataCapacity("linux")+1)
	_, err := pb.CreateFragmentedPackets(data, 0x00, "linux")
	if err == nil {
		t.Error("expected error for oversized payload (>255 fragments)")
	}
}

// TestCreateStealthPacketWithSignature verifies packet size and signature header for both OS profiles.
// TTL is applied at socket level (SetTTL), not stored in packet headers.
func TestCreateStealthPacketWithSignature(t *testing.T) {
	pb := NewPacketBuilder("sig-test")

	linuxPkt := pb.CreateStealthPacketWithSignature([]byte{}, false, "linux")
	if len(linuxPkt.Payload) != 56 {
		t.Errorf("linux payload: want 56 bytes, got %d", len(linuxPkt.Payload))
	}
	if sig, ok := linuxPkt.Headers["signature"].(string); !ok || sig != "linux" {
		t.Errorf("linux signature header: want \"linux\", got %v", linuxPkt.Headers["signature"])
	}

	winPkt := pb.CreateStealthPacketWithSignature([]byte{}, false, "windows")
	if len(winPkt.Payload) != 32 {
		t.Errorf("windows payload: want 32 bytes, got %d", len(winPkt.Payload))
	}
	if sig, ok := winPkt.Headers["signature"].(string); !ok || sig != "windows" {
		t.Errorf("windows signature header: want \"windows\", got %v", winPkt.Headers["signature"])
	}
}

// minNetworkService returns a NetworkService with no socket, suitable for
// testing pure computation methods (calculateChecksum, parseICMPPacket,
// buildICMPPacket, GetMetrics, UpdateLatency, UpdateThroughput).
func minNetworkService() *NetworkService {
	return &NetworkService{
		conn:      nil,
		sessionID: "test-session",
		metrics:   &types.NetworkMetrics{},
	}
}

// ── calculateChecksum ─────────────────────────────────────────────────────────

func TestCalculateChecksum_AllZeros(t *testing.T) {
	// All-zero 8-byte header → sum=0 → one's complement = 0xFFFF
	ns := minNetworkService()
	data := make([]byte, 8)
	got := ns.calculateChecksum(data)
	if got != 0xFFFF {
		t.Errorf("all-zeros checksum: want 0xFFFF, got 0x%04X", got)
	}
}

func TestCalculateChecksum_ICMPEchoNoPayload(t *testing.T) {
	// ICMP type=8 code=0 id=0 seq=0, no payload
	// Sum of 16-bit words: 0x0800 + 0x0000 + 0x0000 + 0x0000 = 0x0800
	// One's complement of 0x0800 = 0xF7FF
	ns := minNetworkService()
	data := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	got := ns.calculateChecksum(data)
	if got != 0xF7FF {
		t.Errorf("ICMP echo no-payload: want 0xF7FF, got 0x%04X", got)
	}
}

func TestCalculateChecksum_ZeroesChecksumField(t *testing.T) {
	// calculateChecksum zeroes bytes 2+3 before summing (RFC 792 requirement).
	// The result must be the same regardless of what was in bytes 2+3 before.
	ns := minNetworkService()
	base := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	dirty := []byte{0x08, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}
	if ns.calculateChecksum(base) != ns.calculateChecksum(dirty) {
		t.Error("checksum must be identical regardless of pre-existing checksum field bytes")
	}
}

func TestCalculateChecksum_OddLength(t *testing.T) {
	// Odd-length data: the trailing byte is left-padded with 0x00 (RFC 792).
	// [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAB]
	// Sum: 0x0800 + 0x0000 + 0x0000 + 0x0000 + 0xAB00 = 0xB300
	// One's complement: 0x4CFF
	ns := minNetworkService()
	data := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAB}
	got := ns.calculateChecksum(data)
	if got != 0x4CFF {
		t.Errorf("odd-length: want 0x4CFF, got 0x%04X", got)
	}
}

// ── parseICMPPacket ───────────────────────────────────────────────────────────

func TestParseICMPPacket_TooShort(t *testing.T) {
	ns := minNetworkService()
	_, err := ns.parseICMPPacket([]byte{0x00, 0x01, 0x02}, "10.0.0.1")
	if err == nil {
		t.Error("expected error for < 8-byte input")
	}
}

func TestParseICMPPacket_HeaderFields(t *testing.T) {
	ns := minNetworkService()
	// type=8, code=0, checksum=0x1234, id=0x5678, seq=0x9ABC
	raw := []byte{0x08, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
	pkt, err := ns.parseICMPPacket(raw, "192.168.1.1")
	if err != nil {
		t.Fatalf("parseICMPPacket: %v", err)
	}
	if pkt.Headers["icmp_type"].(byte) != 0x08 {
		t.Errorf("icmp_type: got %v, want 0x08", pkt.Headers["icmp_type"])
	}
	if pkt.Headers["icmp_code"].(byte) != 0x00 {
		t.Errorf("icmp_code: got %v, want 0x00", pkt.Headers["icmp_code"])
	}
	if pkt.Checksum != 0x1234 {
		t.Errorf("checksum: got 0x%04X, want 0x1234", pkt.Checksum)
	}
	if pkt.Metadata.SourceIP != "192.168.1.1" {
		t.Errorf("source IP: got %q, want \"192.168.1.1\"", pkt.Metadata.SourceIP)
	}
}

func TestParseICMPPacket_PayloadExtracted(t *testing.T) {
	ns := minNetworkService()
	payload := []byte("ping-007 data")
	raw := append([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, payload...)
	pkt, err := ns.parseICMPPacket(raw, "10.0.0.1")
	if err != nil {
		t.Fatalf("parseICMPPacket: %v", err)
	}
	if !bytes.Equal(pkt.Payload, payload) {
		t.Errorf("payload: got %q, want %q", pkt.Payload, payload)
	}
}

// ── buildICMPPacket ───────────────────────────────────────────────────────────

func TestBuildICMPPacket_StructureAndChecksum(t *testing.T) {
	ns := minNetworkService()
	pkt := &types.NetworkPacket{
		Payload: []byte("hello"),
		Headers: map[string]any{},
	}

	raw, err := ns.buildICMPPacket(pkt)
	if err != nil {
		t.Fatalf("buildICMPPacket: %v", err)
	}
	// ICMP header (8 bytes) + payload
	if len(raw) != 8+5 {
		t.Errorf("packet length: want 13, got %d", len(raw))
	}
	// Type field must be ICMPEcho (8)
	if raw[0] != ICMPEcho {
		t.Errorf("ICMP type: want %d (ICMPEcho), got %d", ICMPEcho, raw[0])
	}
	// Checksum must be non-zero (empty checksum is 0x0000 only for all-zeros data)
	checksum := uint16(raw[2])<<8 | uint16(raw[3])
	if checksum == 0 {
		t.Error("ICMP checksum must not be zero for non-zero payload")
	}
}

func TestBuildICMPPacket_SequenceIncrement(t *testing.T) {
	ns := minNetworkService()
	pkt := func() *types.NetworkPacket {
		return &types.NetworkPacket{Payload: []byte("x"), Headers: map[string]any{}}
	}
	r1, _ := ns.buildICMPPacket(pkt())
	r2, _ := ns.buildICMPPacket(pkt())
	seq1 := uint16(r1[6])<<8 | uint16(r1[7])
	seq2 := uint16(r2[6])<<8 | uint16(r2[7])
	if seq2 != seq1+1 {
		t.Errorf("sequence should increment: seq1=%d seq2=%d", seq1, seq2)
	}
}

// ── GetMetrics / UpdateLatency / UpdateThroughput ─────────────────────────────

func TestGetMetrics_ReturnsCopy(t *testing.T) {
	ns := minNetworkService()
	m := ns.GetMetrics()
	m.PacketsSent = 9999 // mutate the returned copy
	if ns.metrics.PacketsSent == 9999 {
		t.Error("GetMetrics must return a copy, not a pointer to the internal struct")
	}
}

func TestUpdateLatency(t *testing.T) {
	ns := minNetworkService()
	ns.UpdateLatency(5 * time.Millisecond)
	if ns.metrics.LatencyMs != 5.0 {
		t.Errorf("LatencyMs: want 5.0, got %f", ns.metrics.LatencyMs)
	}
}

func TestUpdateThroughput(t *testing.T) {
	ns := minNetworkService()
	ns.UpdateThroughput(1024.5)
	if ns.metrics.ThroughputBps != 1024.5 {
		t.Errorf("ThroughputBps: want 1024.5, got %f", ns.metrics.ThroughputBps)
	}
}

// ── CreateStealthChunksWithSignature ─────────────────────────────────────────

func TestCreateStealthChunksWithSignature_Linux_MultiPacket(t *testing.T) {
	pb := NewPacketBuilder("sess-linux")
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	// linux: maxDataPerPacket = 48 → ceil(100/48) = 3 packets
	packets := pb.CreateStealthChunksWithSignature(data, "linux")
	if len(packets) != 3 {
		t.Fatalf("linux 100 bytes: expected 3 packets, got %d", len(packets))
	}
	// Verify total_chunks header on each packet
	for i, pkt := range packets {
		if tc := pkt.Headers["total_chunks"].(int); tc != 3 {
			t.Errorf("packet %d: total_chunks=%d, want 3", i, tc)
		}
		if ci := pkt.Headers["chunk_index"].(int); ci != i {
			t.Errorf("packet %d: chunk_index=%d, want %d", i, ci, i)
		}
	}
}

func TestCreateStealthChunksWithSignature_Windows_MultiPacket(t *testing.T) {
	pb := NewPacketBuilder("sess-win")
	data := make([]byte, 50)
	// windows: maxDataPerPacket = 24 → ceil(50/24) = 3 packets
	packets := pb.CreateStealthChunksWithSignature(data, "windows")
	if len(packets) != 3 {
		t.Fatalf("windows 50 bytes: expected 3 packets, got %d", len(packets))
	}
}

func TestCreateStealthChunksWithSignature_None_SinglePacket(t *testing.T) {
	pb := NewPacketBuilder("sess-none")
	data := make([]byte, 50)
	// none: maxDataPerPacket = 1400 → 50 fits in 1 packet
	packets := pb.CreateStealthChunksWithSignature(data, "none")
	if len(packets) != 1 {
		t.Fatalf("none 50 bytes: expected 1 packet, got %d", len(packets))
	}
}

func TestCreateStealthChunksWithSignature_Empty(t *testing.T) {
	pb := NewPacketBuilder("sess-empty")
	packets := pb.CreateStealthChunksWithSignature([]byte{}, "linux")
	if len(packets) != 0 {
		t.Errorf("empty data: expected 0 packets, got %d", len(packets))
	}
}

func TestCreateStealthChunksWithSignature_ChunkSizeHeader(t *testing.T) {
	pb := NewPacketBuilder("sess-hdr")
	data := make([]byte, 10)
	// linux: 10 bytes fits in 1 chunk (< 48)
	packets := pb.CreateStealthChunksWithSignature(data, "linux")
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if sz := packets[0].Headers["chunk_size"].(int); sz != 10 {
		t.Errorf("chunk_size: got %d, want 10", sz)
	}
}

// ── CreateChunkPacket ─────────────────────────────────────────────────────────

func TestCreateChunkPacket_Headers(t *testing.T) {
	pb := NewPacketBuilder("sess-chunk")
	chunk := &types.DataChunk{
		ID:          7,
		Data:        []byte("chunk payload"),
		TotalChunks: 15,
		Checksum:    "deadbeef",
	}
	pkt := pb.CreateChunkPacket(chunk)
	if pkt == nil {
		t.Fatal("CreateChunkPacket returned nil")
	}
	if id := pkt.Headers["chunk_id"].(int); id != 7 {
		t.Errorf("chunk_id: got %d, want 7", id)
	}
	if tc := pkt.Headers["total_chunks"].(int); tc != 15 {
		t.Errorf("total_chunks: got %d, want 15", tc)
	}
	if cs := pkt.Headers["checksum"].(string); cs != "deadbeef" {
		t.Errorf("checksum: got %q, want %q", cs, "deadbeef")
	}
}

// ── GetLocalInterface ─────────────────────────────────────────────────────────

func TestGetLocalInterface_DoesNotPanic(t *testing.T) {
	nu := &NetworkUtils{}
	// May return an error on minimal environments — just verify no panic.
	iface, err := nu.GetLocalInterface()
	if err != nil {
		t.Logf("GetLocalInterface: %v (acceptable in test environment)", err)
		return
	}
	if iface == nil {
		t.Error("expected non-nil interface when error is nil")
	}
}

// ── ValidateIP ────────────────────────────────────────────────────────────────

func TestValidateIP_InvalidFormat(t *testing.T) {
	// net.ParseIP returns nil for these → ValidateIP errors before any dial.
	nu := &NetworkUtils{}
	for _, ip := range []string{"not-an-ip", "", "300.0.0.1"} {
		if err := nu.ValidateIP(ip); err == nil {
			t.Errorf("ValidateIP(%q): expected error for invalid format", ip)
		}
	}
}

func TestValidateIP_ValidFormat_Unreachable(t *testing.T) {
	// Passes ParseIP, then DialTimeout("ip4:icmp") fails without CAP_NET_RAW.
	// Covers the "IP not reachable" error path; on privileged runners just logs.
	nu := &NetworkUtils{}
	err := nu.ValidateIP("127.0.0.1")
	if err != nil {
		t.Logf("ValidateIP(127.0.0.1): %v (expected without CAP_NET_RAW)", err)
	} else {
		t.Log("ValidateIP(127.0.0.1): succeeded (privileged environment)")
	}
}
