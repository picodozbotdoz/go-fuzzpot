//go:build unix

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenControl enlarges the socket receive buffer to absorb payload bursts.
var listenControl = func(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 256*1024)
	})
}

// healthSignals returns the signals that trigger an on-demand stats dump
// (SIGUSR1 on Unix).
func healthSignals() []os.Signal {
	return []os.Signal{syscall.SIGUSR1}
}

// maxConnections derives the concurrency cap from the soft file-descriptor
// limit: half of the limit, clamped to [100, 4096].
func maxConnections() int {
	var rlimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rlimit); err == nil && rlimit.Cur > 0 {
		n := int(rlimit.Cur / 2) // Use half of available FDs
		if n < 100 {
			return 100 // Minimum safe value
		}
		if n > 4096 {
			return 4096 // Cap at reasonable default
		}
		return n
	}
	return 256 // Conservative default if we can't determine limit
}
