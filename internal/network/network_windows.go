//go:build windows

package network

import (
	"fmt"
	"syscall"
)

// icmpIDFromOS returns the ICMP identifier matching Windows Vista+ ping.exe behaviour:
// the kernel assigns a fixed value of 1 via IcmpSendEcho2; user-space cannot override it.
func icmpIDFromOS() uint16 {
	return 0x0001
}

// SetTTL sets the IP TTL on the raw socket via setsockopt(IP_TTL).
// On Windows, SysRawConn passes a SOCKET handle (uintptr), and
// syscall.SetsockoptInt expects syscall.Handle (uintptr) — not int.
func (n *NetworkService) SetTTL(ttl int) error {
	rawConn, err := n.conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscallconn: %w", err)
	}
	var innerErr error
	if err := rawConn.Control(func(fd uintptr) {
		innerErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	}); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	return innerErr
}
