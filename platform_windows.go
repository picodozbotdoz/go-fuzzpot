//go:build windows

package main

import (
	"os"
	"syscall"
)

// listenControl is a no-op on Windows: the SO_RCVBUF control path is
// Unix-only (x/sys/unix on Windows has no SetsockoptInt).
var listenControl = func(network, address string, c syscall.RawConn) error {
	return nil
}

// healthSignals returns no signals on Windows: there is no SIGUSR1, and the
// other definable signals are reserved for shutdown.
func healthSignals() []os.Signal {
	return nil
}

// fallbackConnections is the handler cap on Windows, where the soft
// file-descriptor limit is not queryable via Getrlimit. 4096 matches the
// upper clamp applied on Unix platforms.
const fallbackConnections = 4096

// fdSoftLimit reports no limit on Windows (see fallbackConnections).
func fdSoftLimit() (uint64, bool) {
	return 0, false
}
