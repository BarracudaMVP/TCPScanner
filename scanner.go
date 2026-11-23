// Package portscan checks TCP port availability with bounded concurrency.
// The scanner closes each connection as soon as the attempt succeeds.
//
// Use [New] to configure a [Scanner] and [Scanner.Scan] to check IP literals or
// DNS names. Read the results until the channel closes or cancel the scan context
// if you stop reading early.
package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Config controls the limits for a Scanner. Both fields must be positive.
type Config struct {
	// Concurrency limits active TCP attempts across all scans on the Scanner.
	Concurrency int
	// ConnectTimeout starts when a TCP attempt obtains a concurrency slot.
	ConnectTimeout time.Duration
}

// Scanner performs TCP connects. Construct it with New. Its Scan method can
// be called concurrently, with one shared limit for active TCP attempts.
type Scanner struct {
	connectTimeout time.Duration
	slots          chan struct{}
	lookupNetIP    func(context.Context, string, string) ([]netip.Addr, error)
	dialContext    func(context.Context, string, string) (net.Conn, error)
}

// New constructs a Scanner with the given connection limits.
func New(cfg Config) (*Scanner, error) {
	if cfg.Concurrency <= 0 {
		return nil, fmt.Errorf("portscan: concurrency must be positive, got %d", cfg.Concurrency)
	}
	if cfg.ConnectTimeout <= 0 {
		return nil, fmt.Errorf("portscan: connect timeout must be positive, got %s", cfg.ConnectTimeout)
	}
	var resolver net.Resolver
	var dialer net.Dialer
	return &Scanner{
		connectTimeout: cfg.ConnectTimeout,
		slots:          make(chan struct{}, cfg.Concurrency),
		lookupNetIP:    resolver.LookupNetIP,
		dialContext:    dialer.DialContext,
	}, nil
}
