package socketerr

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

// Classify interprets the system error in err's chain.
func Classify(err error) Kind {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return Unknown
	}
	switch errno {
	case wsaeConnRefused:
		return Refused
	case wsaeNetDown, wsaeNetUnreach, wsaeHostDown, wsaeHostUnreach:
		return Unreachable
	case wsaeTimedOut:
		return Timeout
	default:
		return Other
	}
}
