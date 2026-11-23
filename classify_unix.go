//go:build unix

package portscan

import (
	"errors"
	"syscall"
)

func classifySystemError(err error) (State, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return StateError, false
	}
	switch errno {
	case syscall.ECONNREFUSED:
		return StateClosed, true
	case syscall.ENETDOWN, syscall.ENETUNREACH, syscall.EHOSTDOWN, syscall.EHOSTUNREACH:
		return StateUnreachable, true
	case syscall.ETIMEDOUT:
		return StateTimeout, true
	default:
		// Errno.Timeout also returns true for EAGAIN, a temporary resource error.
		return StateError, true
	}
}
