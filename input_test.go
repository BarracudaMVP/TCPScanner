package portscan

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeTargets(t *testing.T) {
	hosts := []string{
		"EXAMPLE.org", "example.ORG", "example.org.",
		"localhost", "3com.example", "node-1.example", "xn--mnich-kva.example",
		"::ffff:127.0.0.1", "127.0.0.1",
		"2001:0db8::1", "2001:db8:0:0::1",
		"fe80::1%zone1", "fe80::1%zone2", "FE80:0::1%zone1",
	}
	want := []target{
		{host: "EXAMPLE.org"},
		{host: "example.org."},
		{host: "localhost"},
		{host: "3com.example"},
		{host: "node-1.example"},
		{host: "xn--mnich-kva.example"},
		{host: "::ffff:127.0.0.1", ip: netip.MustParseAddr("127.0.0.1")},
		{host: "2001:0db8::1", ip: netip.MustParseAddr("2001:db8::1")},
		{host: "fe80::1%zone1", ip: netip.MustParseAddr("fe80::1%zone1")},
		{host: "fe80::1%zone2", ip: netip.MustParseAddr("fe80::1%zone2")},
	}
	got, err := normalizeTargets(hosts)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("normalizeTargets = %v, %v; want %v", got, err, want)
	}
}

func TestNormalizeTargetsRejectsInvalidInput(t *testing.T) {
	if got, err := normalizeTargets(nil); got != nil || err == nil {
		t.Fatalf("normalizeTargets(nil) = %v, %v; want nil and an error", got, err)
	}
	for _, host := range []string{
		"", " localhost", "https://example.org", "example.org:80", "[::1]", "[::1]:80",
		"2001::db8::1", "999.0.0.1", "127.1", "0.0.0.0", "::", "::%zone", "::ffff:0.0.0.0",
		".", "example..org", "-example.org", "example-.org", "münich.example", strings.Repeat("x", 64) + ".org",
	} {
		t.Run(host, func(t *testing.T) {
			got, err := normalizeTargets([]string{"localhost", host})
			if got != nil || err == nil {
				t.Errorf("normalizeTargets = %v, %v; want nil and an error", got, err)
			}
		})
	}
}

func TestNormalizePorts(t *testing.T) {
	ports := Ports{
		List:   []int{65534, 22, 3, 22},
		Ranges: []PortRange{{From: 65534, To: 65535}, {From: 2, To: 3}, {From: 1, To: 4}, {From: 2, To: 2}},
	}
	want := []uint16{1, 2, 3, 4, 22, 65534, 65535}
	got, err := normalizePorts(ports)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("normalizePorts = %v, %v; want %v", got, err, want)
	}
	if ports.List[0] != 65534 || ports.Ranges[0].From != 65534 {
		t.Fatal("normalizePorts modified the input slices")
	}
}

func TestNormalizePortsRejectsInvalidInput(t *testing.T) {
	for _, ports := range []Ports{
		{},
		{List: []int{1, 0}},
		{List: []int{-1}},
		{List: []int{65536}},
		{Ranges: []PortRange{{From: 0, To: 1}}},
		{Ranges: []PortRange{{From: 1, To: 65536}}},
		{Ranges: []PortRange{{From: 1000, To: 1}}},
	} {
		got, err := normalizePorts(ports)
		if got != nil || err == nil {
			t.Errorf("normalizePorts(%+v) = %v, %v; want nil and an error", ports, got, err)
		}
	}
}
