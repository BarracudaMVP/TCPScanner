//go:build unix

package socketerr

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifyUnixError(t *testing.T) {
	tests := []struct {
		errno syscall.Errno
		kind  Kind
	}{
		{syscall.ECONNREFUSED, Refused},
		{syscall.ENETDOWN, Unreachable},
		{syscall.ENETUNREACH, Unreachable},
		{syscall.EHOSTDOWN, Unreachable},
		{syscall.EHOSTUNREACH, Unreachable},
		{syscall.ETIMEDOUT, Timeout},
		{syscall.EAGAIN, Other},
		{syscall.EADDRNOTAVAIL, Other},
	}
	for _, tt := range tests {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", tt.errno)}
		if got := Classify(err); got != tt.kind {
			t.Errorf("Classify errno %d = %v, want %v", tt.errno, got, tt.kind)
		}
	}
}
