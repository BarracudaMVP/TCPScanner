// Package portscan checks TCP port availability with bounded concurrency.
package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Config controls the limits for a Scanner. Both fields must be positive.
type Config struct {
	// Concurrency limits active TCP attempts across all scans on the Scanner.
	Concurrency int
	// ConnectTimeout starts when a TCP attempt obtains a concurrency slot.
	ConnectTimeout time.Duration
}

// PortRange is an inclusive range of TCP port numbers.
type PortRange struct {
	From int
	To   int
}

// Ports is the union of individual ports and inclusive ranges.
type Ports struct {
	List   []int
	Ranges []PortRange
}

// State describes the outcome of a port check.
type State string

const (
	StateOpen        State = "open"
	StateClosed      State = "closed"
	StateTimeout     State = "timeout"
	StateUnreachable State = "unreachable"
	StateCanceled    State = "canceled"
	StateError       State = "error"
)

// Result reports one TCP attempt, or a DNS failure for a requested port.
// Host retains the first input spelling. IP is invalid and Duration is zero
// for DNS failures. Otherwise Duration measures the TCP dial, and Err is nil
// only if the connection was established.
type Result struct {
	Host     string
	IP       netip.Addr
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
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

// Scan validates and normalizes its inputs before starting an asynchronous scan.
// Each unique target contributes one result per IP and port. Unresolvable
// targets contribute one error result per port. Results have no fixed order.
// The caller must read until the channel closes or cancel ctx when stopping
// early. A canceled scan can deliver a partial set of results.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports Ports) (<-chan Result, error) {
	if s == nil || s.slots == nil {
		return nil, errors.New("portscan: initialize the scanner with New")
	}
	if ctx == nil {
		return nil, errors.New("portscan: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	targets, err := normalizeTargets(hosts)
	if err != nil {
		return nil, err
	}
	portNumbers, err := normalizePorts(ports)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	workers := cap(s.slots)
	jobs := make(chan job)
	results := make(chan Result, workers)
	var senders sync.WaitGroup
	senders.Go(func() {
		defer close(jobs)
		s.schedule(ctx, targets, portNumbers, jobs, results)
	})
	for range workers {
		senders.Go(func() {
			for job := range jobs {
				result, attempted := s.checkPort(ctx, job)
				if !attempted {
					return
				}
				publishResult(ctx, results, result)
			}
		})
	}
	go func() {
		senders.Wait()
		close(results)
	}()
	return results, nil
}

type job struct {
	host     string
	endpoint netip.AddrPort
}

func (s *Scanner) schedule(ctx context.Context, targets []target, ports []uint16, jobs chan<- job, results chan<- Result) {
	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}
		addresses, err := s.resolve(ctx, target)
		if err != nil {
			for _, port := range ports {
				if ctx.Err() != nil {
					return
				}
				publishResult(ctx, results, Result{Host: target.host, Port: port, State: StateError, Err: err})
			}
			continue
		}
		for _, ip := range addresses {
			for _, port := range ports {
				if ctx.Err() != nil {
					return
				}
				select {
				case jobs <- job{host: target.host, endpoint: netip.AddrPortFrom(ip, port)}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (s *Scanner) resolve(ctx context.Context, target target) ([]netip.Addr, error) {
	if target.ip.IsValid() {
		return []netip.Addr{target.ip}, nil
	}
	addresses, err := s.lookupNetIP(ctx, "ip", target.host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", target.host, err)
	}
	seen := make(map[netip.Addr]struct{}, len(addresses))
	unique := make([]netip.Addr, 0, len(addresses))
	for _, ip := range addresses {
		ip = normalizeIP(ip)
		if !ip.IsValid() {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("resolve %q: no usable IP addresses", target.host)
	}
	return unique, nil
}

func (s *Scanner) checkPort(ctx context.Context, job job) (Result, bool) {
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return Result{}, false
	}
	defer func() { <-s.slots }()
	if ctx.Err() != nil {
		return Result{}, false
	}

	attempt, cancel := context.WithTimeoutCause(ctx, s.connectTimeout, errConnectTimeout)
	defer cancel()
	address := job.endpoint.String()
	started := time.Now()
	conn, err := s.dialContext(attempt, "tcp", address)
	finished := time.Now()
	cause := context.Cause(attempt)
	if err == nil {
		_ = conn.Close()
	} else if deadline, ok := ctx.Deadline(); cause == nil && ok && !finished.Before(deadline) {
		// The network poller can observe the deadline before the context timer fires.
		if attemptDeadline, _ := attempt.Deadline(); attemptDeadline.Equal(deadline) {
			cause = context.DeadlineExceeded
		}
	}
	return Result{
		Host:     job.host,
		IP:       job.endpoint.Addr(),
		Port:     job.endpoint.Port(),
		State:    classifyDialError(err, cause),
		Duration: finished.Sub(started),
		Err:      err,
	}, true
}

func publishResult(ctx context.Context, results chan<- Result, result Result) {
	select {
	case results <- result:
	case <-ctx.Done():
		// Keep the result if there is room, even during cancellation.
		select {
		case results <- result:
		default:
		}
	}
}
