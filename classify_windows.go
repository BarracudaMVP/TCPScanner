package portscan

import (
	"errors"
	"syscall"
)

// Winsock reports these Errno values from ConnectEx. The POSIX-named
// syscall constants on Windows use different values.
const (
	wsaeNetDown     syscall.Errno = 10050
	wsaeNetUnreach  syscall.Errno = 10051
	wsaeTimedOut    syscall.Errno = 10060
	wsaeConnRefused syscall.Errno = 10061
	wsaeHostDown    syscall.Errno = 10064
	wsaeHostUnreach syscall.Errno = 10065
)

func classifySystemError(err error) (State, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return StateError, false
	}
	switch errno {
	case wsaeConnRefused:
		return StateClosed, true
	case wsaeNetDown, wsaeNetUnreach, wsaeHostDown, wsaeHostUnreach:
		return StateUnreachable, true
	case wsaeTimedOut:
		return StateTimeout, true
	default:
		return StateError, true
	}
}
