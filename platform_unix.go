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

// fallbackConnections is the handler cap when the fd limit cannot be read.
const fallbackConnections = 256

// fdSoftLimit reports the soft RLIMIT_NOFILE, if it can be read.
func fdSoftLimit() (uint64, bool) {
	var rlimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rlimit); err != nil {
		return 0, false
	}
	// Cur is uint64 on Linux and int64 on the BSDs.
	cur := uint64(rlimit.Cur)
	if cur == 0 {
		return 0, false
	}
	return cur, true
}
