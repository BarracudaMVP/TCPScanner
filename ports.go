package tcpscanner

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
)

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
