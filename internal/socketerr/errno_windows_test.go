package socketerr

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifyWinsockError(t *testing.T) {
	tests := []struct {
		errno syscall.Errno
		kind  Kind
	}{
		{10050, Unreachable}, // WSAENETDOWN
		{10051, Unreachable}, // WSAENETUNREACH
		{10060, Timeout},     // WSAETIMEDOUT
		{10061, Refused},     // WSAECONNREFUSED
		{10064, Unreachable}, // WSAEHOSTDOWN
		{10065, Unreachable}, // WSAEHOSTUNREACH
		{10013, Other},       // WSAEACCES
		{syscall.ECONNREFUSED, Other},
	}
	for _, tt := range tests {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", tt.errno)}
		if got := Classify(err); got != tt.kind {
			t.Errorf("Classify errno %d = %v, want %v", tt.errno, got, tt.kind)
		}
	}
}
