package tcpscanner

import (
	"context"
	"errors"
	"net"
	"os"

	"github.com/BarracudaMVP/TCPScanner/internal/socketerr"
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

	switch socketerr.Classify(err) {
	case socketerr.Refused:
		return StateClosed
	case socketerr.Timeout:
		return StateTimeout
	case socketerr.Unreachable:
		return StateUnreachable
	case socketerr.Other:
		return StateError
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}
	return StateError
}
