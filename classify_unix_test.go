//go:build unix

package portscan

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifyUnixError(t *testing.T) {
	tests := []struct {
		errno syscall.Errno
		state State
	}{
		{syscall.ECONNREFUSED, StateClosed},
		{syscall.ENETDOWN, StateUnreachable},
		{syscall.ENETUNREACH, StateUnreachable},
		{syscall.EHOSTDOWN, StateUnreachable},
		{syscall.EHOSTUNREACH, StateUnreachable},
		{syscall.ETIMEDOUT, StateTimeout},
		{syscall.EAGAIN, StateError},
		{syscall.EADDRNOTAVAIL, StateError},
	}
	for _, tt := range tests {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", tt.errno)}
		if got := classifyDialError(err, context.Canceled); got != tt.state {
			t.Errorf("classifyDialError errno %d = %q, want %q", tt.errno, got, tt.state)
		}
	}
}
