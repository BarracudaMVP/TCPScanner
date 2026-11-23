package tcpscanner

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/BarracudaMVP/TCPScanner/internal/target"
)

// Scan validates and normalizes its inputs before starting an asynchronous scan.
// Each unique target contributes one result per IP and port. Unresolvable
// targets contribute one error result per port. Results have no fixed order.
// The caller must read until the channel closes or cancel ctx when stopping
// early. A canceled scan can deliver a partial set of results.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports Ports) (<-chan Result, error) {
	if s == nil || s.slots == nil {
		return nil, errors.New("tcpscanner: initialize the scanner with New")
	}
	if ctx == nil {
		return nil, errors.New("tcpscanner: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	targets, err := target.Parse(hosts)
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

func (s *Scanner) schedule(ctx context.Context, targets []target.Host, ports []uint16, jobs chan<- job, results chan<- Result) {
	for _, host := range targets {
		if ctx.Err() != nil {
			return
		}
		addresses, err := host.Resolve(ctx, s.lookupNetIP)
		if err != nil {
			for _, port := range ports {
				if ctx.Err() != nil {
					return
				}
				publishResult(ctx, results, Result{Host: host.Name, Port: port, State: StateError, Err: err})
			}
			continue
		}
		for _, ip := range addresses {
			for _, port := range ports {
				if ctx.Err() != nil {
					return
				}
				select {
				case jobs <- job{host: host.Name, endpoint: netip.AddrPortFrom(ip, port)}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
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
