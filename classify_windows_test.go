package portscan

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifyWinsockError(t *testing.T) {
	tests := []struct {
		errno syscall.Errno
		state State
	}{
		{10050, StateUnreachable}, // WSAENETDOWN
		{10051, StateUnreachable}, // WSAENETUNREACH
		{10060, StateTimeout},     // WSAETIMEDOUT
		{10061, StateClosed},      // WSAECONNREFUSED
		{10064, StateUnreachable}, // WSAEHOSTDOWN
		{10065, StateUnreachable}, // WSAEHOSTUNREACH
		{10013, StateError},       // WSAEACCES
		{syscall.ECONNREFUSED, StateError},
	}
	for _, tt := range tests {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", tt.errno)}
		if got := classifyDialError(err, context.Canceled); got != tt.state {
			t.Errorf("classifyDialError errno %d = %q, want %q", tt.errno, got, tt.state)
		}
	}
}
