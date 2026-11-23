package portscan

import (
	"context"
	"errors"
	"net"
	"os"
)

var errConnectTimeout = errors.New("TCP connect timeout")

func classifyDialError(err, cause error) State {
	switch {
	case err == nil:
		return StateOpen
	case errors.Is(err, context.Canceled):
		return StateCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		if cause != nil && cause != errConnectTimeout {
			return StateCanceled
		}
		return StateTimeout
	}

	if state, ok := classifySystemError(err); ok {
		return state
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}
	return StateError
}
