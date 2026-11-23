package portscan

import (
	"slices"
	"testing"
)

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
