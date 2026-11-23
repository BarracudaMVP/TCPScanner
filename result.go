package tcpscanner

import (
	"net/netip"
	"time"
)

// State describes the outcome of a port check.
type State string

const (
	// StateOpen reports that the TCP connection succeeded.
	StateOpen State = "open"
	// StateClosed reports that the connection was refused.
	StateClosed State = "closed"
	// StateTimeout reports that the connection attempt timed out.
	StateTimeout State = "timeout"
	// StateUnreachable reports that the host or network was unreachable.
	StateUnreachable State = "unreachable"
	// StateCanceled reports that the scan context canceled the attempt.
	StateCanceled State = "canceled"
	// StateError reports a DNS failure or another connection error.
	StateError State = "error"
)

// Result reports one TCP attempt or a DNS failure for a requested port.
type Result struct {
	// Host retains the target's original spelling in the input.
	Host string
	// IP is the address checked. It is invalid for DNS failures.
	IP    netip.Addr
	Port  uint16
	State State
	// Duration measures the TCP connection attempt. It is zero for DNS failures.
	Duration time.Duration
	// Err preserves the connection or DNS error and is nil for [StateOpen].
	Err error
}
