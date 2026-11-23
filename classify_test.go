package tcpscanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
)

func TestClassifyDialError(t *testing.T) {
	callerCause := errors.New("caller stopped scan")
	tests := []struct {
		name  string
		err   error
		cause error
		state State
	}{
		{name: "success even after cancellation", cause: callerCause, state: StateOpen},
		{name: "caller canceled", err: context.Canceled, cause: callerCause, state: StateCanceled},
		{name: "caller deadline", err: context.DeadlineExceeded, cause: callerCause, state: StateCanceled},
		{name: "connect deadline", err: context.DeadlineExceeded, cause: errConnectTimeout, state: StateTimeout},
		{name: "poller deadline", err: os.ErrDeadlineExceeded, state: StateTimeout},
		{name: "poller caller deadline", err: os.ErrDeadlineExceeded, cause: callerCause, state: StateCanceled},
		{name: "network timeout", err: &net.DNSError{IsTimeout: true}, state: StateTimeout},
		{name: "closed descriptor", err: net.ErrClosed, state: StateError},
		{name: "plain error with refusal text", err: errors.New("connection refused"), state: StateError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.err
			if err != nil {
				err = fmt.Errorf("dial: %w", err)
			}
			if got := classifyDialError(err, tt.cause); got != tt.state {
				t.Errorf("classifyDialError(%v, %v) = %q, want %q", err, tt.cause, got, tt.state)
			}
		})
	}
}
