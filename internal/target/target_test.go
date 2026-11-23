package target

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	hosts := []string{
		"EXAMPLE.org", "example.ORG", "example.org.",
		"localhost", "3com.example", "node-1.example", "xn--mnich-kva.example",
		"::ffff:127.0.0.1", "127.0.0.1",
		"2001:0db8::1", "2001:db8:0:0::1",
		"fe80::1%zone1", "fe80::1%zone2", "FE80:0::1%zone1",
	}
	want := []Host{
		{Name: "EXAMPLE.org"},
		{Name: "example.org."},
		{Name: "localhost"},
		{Name: "3com.example"},
		{Name: "node-1.example"},
		{Name: "xn--mnich-kva.example"},
		{Name: "::ffff:127.0.0.1", ip: netip.MustParseAddr("127.0.0.1")},
		{Name: "2001:0db8::1", ip: netip.MustParseAddr("2001:db8::1")},
		{Name: "fe80::1%zone1", ip: netip.MustParseAddr("fe80::1%zone1")},
		{Name: "fe80::1%zone2", ip: netip.MustParseAddr("fe80::1%zone2")},
	}
	got, err := Parse(hosts)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("Parse = %v, %v; want %v", got, err, want)
	}
}

func TestParseRejectsInvalidInput(t *testing.T) {
	if got, err := Parse(nil); got != nil || err == nil {
		t.Fatalf("Parse(nil) = %v, %v; want nil and an error", got, err)
	}
	for _, host := range []string{
		"", " localhost", "https://example.org", "example.org:80", "[::1]", "[::1]:80",
		"2001::db8::1", "999.0.0.1", "127.1", "0.0.0.0", "::", "::%zone", "::ffff:0.0.0.0",
		".", "example..org", "-example.org", "example-.org", "münich.example", strings.Repeat("x", 64) + ".org",
	} {
		t.Run(host, func(t *testing.T) {
			got, err := Parse([]string{"localhost", host})
			if got != nil || err == nil {
				t.Errorf("Parse = %v, %v; want nil and an error", got, err)
			}
		})
	}
}
