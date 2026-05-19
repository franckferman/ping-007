package network

import (
	"testing"
	"time"
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