package portscan

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

type target struct {
	host string
	ip   netip.Addr
}

func normalizeTargets(hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, errors.New("at least one host is required")
	}

	targets := make([]target, 0, len(hosts))
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
		targets = append(targets, target{host: host, ip: ip})
	}
	return targets, nil
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

func normalizePorts(ports Ports) ([]uint16, error) {
	const maxPort = 65535
	if len(ports.List) == 0 && len(ports.Ranges) == 0 {
		return nil, errors.New("at least one port is required")
	}

	ranges := make([]PortRange, 0, len(ports.List)+len(ports.Ranges))
	for _, port := range ports.List {
		if port < 1 || port > maxPort {
			return nil, fmt.Errorf("port %d is outside 1..65535", port)
		}
		ranges = append(ranges, PortRange{From: port, To: port})
	}
	for _, interval := range ports.Ranges {
		if interval.From < 1 || interval.From > interval.To || interval.To > maxPort {
			return nil, fmt.Errorf("invalid port range %d..%d", interval.From, interval.To)
		}
		ranges = append(ranges, interval)
	}

	slices.SortFunc(ranges, func(a, b PortRange) int {
		return cmp.Compare(a.From, b.From)
	})
	var unique []uint16
	last := 0
	for _, interval := range ranges {
		for port := max(interval.From, last+1); port <= interval.To; port++ {
			unique = append(unique, uint16(port))
		}
		last = max(last, interval.To)
	}
	return unique, nil
}
