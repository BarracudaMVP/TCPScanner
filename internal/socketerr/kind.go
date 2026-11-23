// Package socketerr interprets the system errors returned by TCP connects.
package socketerr

// Kind is the result of classifying a system socket error.
type Kind uint8

const (
	Unknown     Kind = iota // The error has no supported system code.
	Refused                 // The remote endpoint refused the connection.
	Timeout                 // The connection attempt timed out.
	Unreachable             // The host or network could not be reached.
	Other                   // A system code was found outside these categories.
)
