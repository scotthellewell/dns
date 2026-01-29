package resolver

import (
	"net"
	"testing"

	"github.com/scott/dns/config"
)

func TestIPv6ToDashedExpanded(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
	}{
		{
			ip:       "2602:ff29::1",
			expected: "2602-ff29-0000-0000-0000-0000-0000-0001",
		},
		{
			ip:       "2602:ff29:0001:0002:0003:0004:0005:0006",
			expected: "2602-ff29-0001-0002-0003-0004-0005-0006",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IPv6ToDashedExpanded(ip)
			if result != tt.expected {
				t.Errorf("IPv6ToDashedExpanded(%s) = %s, want %s", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIPv6ToDashedStripped(t *testing.T) {
	tests := []struct {
		ip        string
		prefixLen int
		expected  string
	}{
		{
			ip:        "2602:ff29:0001:0002:0003:0004:0005:0006",
			prefixLen: 40,
			expected:  "01-0002-0003-0004-0005-0006",
		},
		{
			ip:        "2602:ff29:ab00::1",
			prefixLen: 40,
			expected:  "00-0000-0000-0000-0000-0001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IPv6ToDashedStripped(ip, tt.prefixLen)
			if result != tt.expected {
				t.Errorf("IPv6ToDashedStripped(%s, %d) = %s, want %s", tt.ip, tt.prefixLen, result, tt.expected)
			}
		})
	}
}

func TestIPv4ToHostPart(t *testing.T) {
	tests := []struct {
		ip        string
		prefixLen int
		expected  string
	}{
		{
			ip:        "23.148.184.5",
			prefixLen: 24,
			expected:  "5",
		},
		{
			ip:        "23.148.184.100",
			prefixLen: 24,
			expected:  "100",
		},
		{
			ip:        "192.168.1.100",
			prefixLen: 16,
			expected:  "1-100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IPv4ToHostPart(ip, tt.prefixLen)
			if result != tt.expected {
				t.Errorf("IPv4ToHostPart(%s, %d) = %s, want %s", tt.ip, tt.prefixLen, result, tt.expected)
			}
		})
	}
}

func TestResolverLookupPTR_IPv6(t *testing.T) {
	_, network, _ := net.ParseCIDR("2602:ff29::/40")

	cfg := &config.ParsedConfig{
		Zones: []config.ParsedZone{
			{
				Network:     network,
				Domain:      "ip6.quicktechresults.com",
				StripPrefix: true,
				PrefixLen:   40,
				TTL:         3600,
				IsIPv6:      true,
			},
		},
	}

	r := New(cfg)

	// Test pattern-based resolution for 2602:ff29:0001::1
	// Full: 2602:ff29:0001:0000:0000:0000:0000:0001
	// After stripping 40 bits (10 nibbles = 2602ff2900): 01-0000-0000-0000-0000-0001
	reverseName := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.9.2.f.f.2.0.6.2.ip6.arpa."
	hostname, ttl, found := r.LookupPTR(reverseName)
	if !found {
		t.Fatal("Expected to find PTR for subnet IP")
	}
	expectedHostname := "01-0000-0000-0000-0000-0001.ip6.quicktechresults.com"
	if hostname != expectedHostname {
		t.Errorf("Expected %s, got %s", expectedHostname, hostname)
	}
	if ttl != 3600 {
		t.Errorf("Expected TTL 3600, got %d", ttl)
	}
}

func TestResolverLookupPTR_IPv4(t *testing.T) {
	_, network, _ := net.ParseCIDR("23.148.184.0/24")

	cfg := &config.ParsedConfig{
		Zones: []config.ParsedZone{
			{
				Network:     network,
				Domain:      "ip4.quicktechresults.com",
				StripPrefix: true,
				PrefixLen:   24,
				TTL:         3600,
				IsIPv6:      false,
			},
		},
	}

	r := New(cfg)

	// Test 23.148.184.5
	hostname, ttl, found := r.LookupPTR("5.184.148.23.in-addr.arpa.")
	if !found {
		t.Fatal("Expected to find PTR for subnet IP")
	}
	if hostname != "5.ip4.quicktechresults.com" {
		t.Errorf("Expected 5.ip4.quicktechresults.com, got %s", hostname)
	}
	if ttl != 3600 {
		t.Errorf("Expected TTL 3600, got %d", ttl)
	}
}

func TestResolverLookupAAAA(t *testing.T) {
	_, network, _ := net.ParseCIDR("2602:ff29::/40")

	cfg := &config.ParsedConfig{
		Zones: []config.ParsedZone{
			{
				Network:     network,
				Domain:      "ip6.quicktechresults.com",
				StripPrefix: true,
				PrefixLen:   40,
				TTL:         3600,
				IsIPv6:      true,
			},
		},
	}

	r := New(cfg)

	// Test pattern-based lookup
	ip, ttl, found := r.LookupAAAA("01-0000-0000-0000-0000-0001.ip6.quicktechresults.com.")
	if !found {
		t.Fatal("Expected to find AAAA for pattern hostname")
	}
	expectedIP := net.ParseIP("2602:ff29:0001::1")
	if !ip.Equal(expectedIP) {
		t.Errorf("Expected %s, got %s", expectedIP, ip)
	}
	if ttl != 3600 {
		t.Errorf("Expected TTL 3600, got %d", ttl)
	}
}

func TestResolverLookupA(t *testing.T) {
	_, network, _ := net.ParseCIDR("23.148.184.0/24")

	cfg := &config.ParsedConfig{
		Zones: []config.ParsedZone{
			{
				Network:     network,
				Domain:      "ip4.quicktechresults.com",
				StripPrefix: true,
				PrefixLen:   24,
				TTL:         3600,
				IsIPv6:      false,
			},
		},
	}

	r := New(cfg)

	// Test pattern-based lookup
	ip, ttl, found := r.LookupA("5.ip4.quicktechresults.com.")
	if !found {
		t.Fatal("Expected to find A for pattern hostname")
	}
	expectedIP := net.ParseIP("23.148.184.5").To4()
	if !ip.Equal(expectedIP) {
		t.Errorf("Expected %s, got %s", expectedIP, ip)
	}
	if ttl != 3600 {
		t.Errorf("Expected TTL 3600, got %d", ttl)
	}
}
