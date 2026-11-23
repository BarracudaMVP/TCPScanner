//go:build !unix && !windows

package portscan

func classifySystemError(error) (State, bool) {
	return StateError, false
}
