//go:build !windows

package network

import (
	"fmt"
	"syscall"
)

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
