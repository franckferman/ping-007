//go:build !windows

package network

import (
	"fmt"
	"os"
	"syscall"
)

// icmpIDFromOS returns the ICMP identifier matching Linux iputils ping behaviour:
// getpid() & 0xFFFF — the kernel exposes the raw socket's PID as the identifier.
func icmpIDFromOS() uint16 {
	return uint16(os.Getpid() & 0xFFFF)
}

// SetTTL sets the IP TTL on the raw socket via setsockopt(IP_TTL).
func (n *NetworkService) SetTTL(ttl int) error {
	rawConn, err := n.conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscallconn: %w", err)
	}
	var innerErr error
	if err := rawConn.Control(func(fd uintptr) {
		innerErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	}); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	return innerErr
}
