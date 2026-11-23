//go:build !unix && !windows

package socketerr

// Classify returns Unknown on platforms without an error code mapping.
func Classify(error) Kind {
	return Unknown
}
