package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func TestScannerValidation(t *testing.T) {
	for _, cfg := range []Config{
		{Concurrency: 0, ConnectTimeout: time.Second},
		{Concurrency: -1, ConnectTimeout: time.Second},
		{Concurrency: 1, ConnectTimeout: 0},
		{Concurrency: 1, ConnectTimeout: -time.Second},
	} {
		if scanner, err := New(cfg); scanner != nil || err == nil {
			t.Errorf("New(%+v) = %v, %v; want nil scanner and error", cfg, scanner, err)
		}
	}

	scanner := newTestScanner(t, 1, time.Second)
	hosts := []string{"127.0.0.1"}
	ports := Ports{List: []int{80}}
	if results, err := scanner.Scan(nil, hosts, ports); results != nil || err == nil {
		t.Errorf("Scan with nil context = %v, %v; want nil channel and error", results, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if results, err := scanner.Scan(ctx, hosts, ports); results != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("Scan with canceled context = %v, %v; want nil channel and context.Canceled", results, err)
	}
	if results, err := scanner.Scan(t.Context(), []string{""}, ports); results != nil || err == nil {
		t.Errorf("Scan with empty host = %v, %v; want nil channel and error", results, err)
	}
	if results, err := scanner.Scan(t.Context(), hosts, Ports{List: []int{0}}); results != nil || err == nil {
		t.Errorf("Scan with port zero = %v, %v; want nil channel and error", results, err)
	}
}

func TestScanLoopback(t *testing.T) {
	for _, tc := range []struct {
		network string
		ip      netip.Addr
	}{
		{"tcp4", netip.MustParseAddr("127.0.0.1")},
		{"tcp6", netip.IPv6Loopback()},
	} {
		t.Run(tc.network, func(t *testing.T) {
			listener, err := net.ListenTCP(tc.network, net.TCPAddrFromAddrPort(netip.AddrPortFrom(tc.ip, 0)))
			if tc.network == "tcp6" && ipv6Unavailable(err) {
				t.Skipf("IPv6 loopback unavailable: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			scanner := newTestScanner(t, 1, 5*time.Second)
			port := listener.Addr().(*net.TCPAddr).Port
			host := tc.ip.String()
			ports := Ports{List: []int{port}}
			results, err := scanner.Scan(ctx, []string{host}, ports)
			if err != nil {
				t.Fatal(err)
			}
			result := singleResult(t, ctx, results)
			if result.Host != host || result.IP != tc.ip || result.Port != uint16(port) || result.State != StateOpen || result.Err != nil {
				t.Fatalf("unexpected open result: %+v", result)
			}

			deadline, _ := ctx.Deadline()
			if err := listener.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			peer, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err := peer.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			var data [1]byte
			if n, err := peer.Read(data[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("peer.Read = %d, %v; want EOF from closed scan connection", n, err)
			}

			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			results, err = scanner.Scan(ctx, []string{host}, ports)
			if err != nil {
				t.Fatal(err)
			}
			result = singleResult(t, ctx, results)
			if result.State != StateClosed || result.Err == nil {
				t.Fatalf("unexpected closed result: %+v", result)
			}
			if state := classifyDialError(result.Err, context.Canceled); state != StateClosed {
				t.Errorf("completed refusal with a canceled caller = %q; want closed", state)
			}
		})
	}
}

func TestScanDNS(t *testing.T) {
	scanner := newTestScanner(t, 2, time.Second)
	ipv4 := netip.MustParseAddr("127.0.0.1")
	ipv6 := netip.IPv6Loopback()
	dnsErr := &net.DNSError{Err: "test name not found", Name: "missing.example", IsNotFound: true}
	dialErr := errors.New("test dial error")
	var names []string
	scanner.lookupNetIP = func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" {
			t.Errorf("lookup network = %q; want ip", network)
		}
		host = strings.ToLower(host)
		names = append(names, host)
		if host == dnsErr.Name {
			return nil, dnsErr
		}
		return []netip.Addr{ipv4, ipv6, netip.MustParseAddr("::ffff:127.0.0.1"), ipv6}, nil
	}
	var dialCount atomic.Int32
	scanner.dialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		dialCount.Add(1)
		endpoint, err := netip.ParseAddrPort(address)
		if network != "tcp" || err != nil || (endpoint.Addr() != ipv4 && endpoint.Addr() != ipv6) || (endpoint.Port() != 80 && endpoint.Port() != 81) {
			t.Errorf("unexpected dial: %s %q", network, address)
		}
		return nil, dialErr
	}

	const firstHost = "Lab.example"
	hosts := []string{firstHost, "lab.EXAMPLE", dnsErr.Name, ipv4.String(), "::ffff:127.0.0.1"}
	ports := Ports{List: []int{80, 81}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}
	hosts[0] = "changed.example"
	ports.List[0] = 1234
	type resultKey struct {
		host string
		ip   netip.Addr
		port uint16
	}
	seen := make(map[resultKey]bool)
	for result := range results {
		key := resultKey{result.Host, result.IP, result.Port}
		if seen[key] {
			t.Errorf("duplicate result: %+v", result)
		}
		seen[key] = true
		wantErr := dialErr
		switch result.Host {
		case dnsErr.Name:
			wantErr = dnsErr
			if result.IP.IsValid() || result.Duration != 0 {
				t.Errorf("DNS failure includes a TCP attempt: %+v", result)
			}
		case firstHost:
			if result.IP != ipv4 && result.IP != ipv6 {
				t.Errorf("unexpected resolved IP: %+v", result)
			}
		case ipv4.String():
			if result.IP != ipv4 {
				t.Errorf("unexpected literal IP: %+v", result)
			}
		default:
			t.Errorf("unexpected target: %+v", result)
		}
		if result.State != StateError || !errors.Is(result.Err, wantErr) || (result.Port != 80 && result.Port != 81) {
			t.Errorf("unexpected result: %+v; want error %v", result, wantErr)
		}
	}
	if len(seen) != 8 || dialCount.Load() != 6 || len(names) != 2 || names[0] != "lab.example" || names[1] != dnsErr.Name {
		t.Fatalf("got %d results, %d dials and DNS lookups %v; want 8 results, 6 dials and two unique DNS lookups", len(seen), dialCount.Load(), names)
	}
}

func TestScanSharedConcurrency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		scanner := newTestScanner(t, 2, time.Minute)
		release := make(chan struct{})
		var started atomic.Int32
		scanner.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			started.Add(1)
			select {
			case <-release:
				return nil, errors.New("test dial error")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		scan := func() <-chan Result {
			t.Helper()
			results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Ports{List: []int{80, 81}})
			if err != nil {
				t.Fatal(err)
			}
			return results
		}

		first := scan()
		synctest.Wait()
		if got := started.Load(); got != 2 {
			t.Fatalf("first Scan started %d dials; want 2", got)
		}
		second := scan()
		synctest.Wait()
		if got := started.Load(); got != 2 {
			t.Fatalf("overlapping scans started %d dials; want 2", got)
		}
		close(release)
		for _, stream := range []<-chan Result{first, second, scan()} {
			count := 0
			for result := range stream {
				count++
				if result.State != StateError {
					t.Errorf("unexpected result: %+v", result)
				}
			}
			if count != 2 {
				t.Errorf("stream produced %d results; want 2", count)
			}
		}
	})
}

func TestScanDeadlineAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		parentTimeout time.Duration
		cancelDial    bool
		wantState     State
		wantErr       error
		wantDuration  time.Duration
	}{
		{"connect timeout", 2 * time.Second, false, StateTimeout, context.DeadlineExceeded, time.Second},
		{"caller deadline", 500 * time.Millisecond, false, StateCanceled, context.DeadlineExceeded, 500 * time.Millisecond},
		{"caller cancellation", 2 * time.Second, true, StateCanceled, context.Canceled, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), tc.parentTimeout)
				defer cancel()
				scanner := newTestScanner(t, 1, time.Second)
				started := make(chan struct{})
				scanner.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
					close(started)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Ports{List: []int{80}})
				if err != nil {
					t.Fatal(err)
				}
				<-started
				if tc.cancelDial {
					cancel()
				}
				result := singleResult(t, t.Context(), results)
				if result.State != tc.wantState || !errors.Is(result.Err, tc.wantErr) || result.Duration != tc.wantDuration {
					t.Errorf("got %+v; want state %s, error %v and duration %s", result, tc.wantState, tc.wantErr, tc.wantDuration)
				}
			})
		})
	}
}

func TestScanCancelWhileReaderIsBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		scanner := newTestScanner(t, 1, time.Minute)
		var opened, closed atomic.Int32
		scanner.dialContext = func(context.Context, string, string) (net.Conn, error) {
			opened.Add(1)
			return &trackedConn{closed: &closed}, nil
		}
		results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Ports{Ranges: []PortRange{{From: 1, To: 65535}}})
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		pending := opened.Load()
		if pending != int32(cap(results)+1) || closed.Load() != pending {
			t.Fatalf("full stream buffer %d, opened %d and closed %d; want one result held by worker and all connections closed", cap(results), pending, closed.Load())
		}
		probeCtx, stopProbe := context.WithTimeout(ctx, time.Second)
		defer stopProbe()
		probeResults, err := scanner.Scan(probeCtx, []string{"127.0.0.1"}, Ports{List: []int{80}})
		if err != nil {
			t.Fatal(err)
		}
		if result := singleResult(t, probeCtx, probeResults); result.State != StateOpen {
			t.Errorf("second scan returned %+v while first reader was blocked", result)
		}
		pending++
		if n := closed.Load(); n != pending {
			t.Errorf("closed %d connections; want %d", n, pending)
		}
		cancel()
		synctest.Wait()
		for range len(results) {
			<-results
		}
		select {
		case _, ok := <-results:
			if ok {
				t.Error("unexpected extra result after cancellation")
			}
		default:
			t.Fatal("results channel is still open after cancellation")
		}
		if calls := opened.Load(); calls != pending {
			t.Errorf("started %d additional dials after cancellation", calls-pending)
		}
	})
}

func newTestScanner(t *testing.T, concurrency int, timeout time.Duration) *Scanner {
	t.Helper()
	scanner, err := New(Config{Concurrency: concurrency, ConnectTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return scanner
}

func singleResult(t *testing.T, ctx context.Context, results <-chan Result) Result {
	t.Helper()
	var result Result
	select {
	case item, ok := <-results:
		if !ok {
			t.Fatal("results channel closed before delivering result")
		}
		result = item
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case item, ok := <-results:
		if ok {
			t.Fatalf("unexpected extra result: %+v", item)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return result
}

func ipv6Unavailable(err error) bool {
	if runtime.GOOS == "windows" {
		const (
			wsaAFNotSupported = syscall.Errno(10047)
			wsaAddrNotAvail   = syscall.Errno(10049)
		)
		return errors.Is(err, wsaAFNotSupported) || errors.Is(err, wsaAddrNotAvail)
	}
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)
}

type trackedConn struct {
	net.Conn
	closed *atomic.Int32
}

func (c *trackedConn) Close() error {
	c.closed.Add(1)
	return nil
}
