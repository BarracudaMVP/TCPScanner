// Package target validates scan targets and resolves them to IP addresses.
package target

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Host is a validated IP literal or DNS name. Name preserves its input spelling.
type Host struct {
	Name string
	ip   netip.Addr
}

// Parse validates hosts and keeps the first spelling of each distinct target.
func Parse(hosts []string) ([]Host, error) {
	if len(hosts) == 0 {
		return nil, errors.New("at least one host is required")
	}

	targets := make([]Host, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		ip, err := netip.ParseAddr(host)
		var key string
		if err == nil {
			ip = normalizeIP(ip)
			if !ip.IsValid() {
				return nil, fmt.Errorf("unspecified IP address %q", host)
			}
			key = ip.String()
		} else {
			if !validDNSHost(host) {
				return nil, fmt.Errorf("invalid TCP target %q", host)
			}
			key = strings.ToLower(host)
		}

		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, Host{Name: host, ip: ip})
	}
	return targets, nil
}

// Resolve returns the literal IP or the unique usable IPs returned by DNS.
func (h Host) Resolve(ctx context.Context, lookupNetIP func(context.Context, string, string) ([]netip.Addr, error)) ([]netip.Addr, error) {
	if h.ip.IsValid() {
		return []netip.Addr{h.ip}, nil
	}
	addresses, err := lookupNetIP(ctx, "ip", h.Name)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", h.Name, err)
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
		return nil, fmt.Errorf("resolve %q: no usable IP addresses", h.Name)
	}
	return unique, nil
}

func normalizeIP(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.WithZone("").IsUnspecified() {
		return netip.Addr{}
	}
	return ip
}

func validDNSHost(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if len(name) > 253 {
		return false
	}

	numeric := true
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			switch {
			case '0' <= char && char <= '9':
			case 'a' <= char && char <= 'z', 'A' <= char && char <= 'Z', char == '-':
				numeric = false
			default:
				return false
			}
		}
	}
	// A system resolver may interpret a purely numeric name as an IPv4 address.
	return !numeric
}
