//go:build unix

package socketerr

import (
	"errors"
	"syscall"
)

// Classify interprets the system error in err's chain.
func Classify(err error) Kind {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return Unknown
	}
	switch errno {
	case syscall.ECONNREFUSED:
		return Refused
	case syscall.ENETDOWN, syscall.ENETUNREACH, syscall.EHOSTDOWN, syscall.EHOSTUNREACH:
		return Unreachable
	case syscall.ETIMEDOUT:
		return Timeout
	default:
		// Errno.Timeout also returns true for EAGAIN, a temporary resource error.
		return Other
	}
}
