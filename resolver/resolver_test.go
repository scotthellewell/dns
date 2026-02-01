package resolver

import (
	"net"
	"testing"
)

func TestIPv4ToReverseName(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"simple", "192.168.1.100", "100.1.168.192.in-addr.arpa."},
		{"loopback", "127.0.0.1", "1.0.0.127.in-addr.arpa."},
		{"zeros", "0.0.0.0", "0.0.0.0.in-addr.arpa."},
		{"broadcast", "255.255.255.255", "255.255.255.255.in-addr.arpa."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IPv4ToReverseName(ip)
			if result != tt.expected {
				t.Errorf("IPv4ToReverseName(%s) = %s, want %s", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIPv4ToReverseName_Invalid(t *testing.T) {
	result := IPv4ToReverseName(nil)
	if result != "" {
		t.Errorf("IPv4ToReverseName(nil) = %s, want empty", result)
	}
}

func TestIPv6ToReverseName(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{
			"loopback",
			"::1",
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		},
		{
			"full",
			"2001:db8::1",
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IPv6ToReverseName(ip)
			if result != tt.expected {
				t.Errorf("IPv6ToReverseName(%s) = %s, want %s", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIPv6ToReverseName_Invalid(t *testing.T) {
	result := IPv6ToReverseName(nil)
	if result != "" {
		t.Errorf("IPv6ToReverseName(nil) = %s, want empty", result)
	}
}

func TestReverseNameToIPv4(t *testing.T) {
	tests := []struct {
		name     string
		reverse  string
		expected string
	}{
		{"simple", "100.1.168.192.in-addr.arpa.", "192.168.1.100"},
		{"loopback", "1.0.0.127.in-addr.arpa.", "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReverseNameToIPv4(tt.reverse)
			if result == nil {
				t.Fatalf("ReverseNameToIPv4(%s) returned nil", tt.reverse)
			}
			if result.String() != tt.expected {
				t.Errorf("ReverseNameToIPv4(%s) = %s, want %s", tt.reverse, result.String(), tt.expected)
			}
		})
	}
}

func TestReverseNameToIPv4_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		reverse string
	}{
		{"empty", ""},
		{"wrong-parts", "1.2.3.in-addr.arpa."},
		{"invalid-value", "256.1.168.192.in-addr.arpa."},
		{"non-numeric", "abc.1.168.192.in-addr.arpa."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReverseNameToIPv4(tt.reverse)
			if result != nil {
				t.Errorf("ReverseNameToIPv4(%s) = %s, want nil", tt.reverse, result.String())
			}
		})
	}
}

func TestReverseNameToIPv6(t *testing.T) {
	tests := []struct {
		name     string
		reverse  string
		expected string
	}{
		{
			"loopback",
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
			"::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReverseNameToIPv6(tt.reverse)
			if result == nil {
				t.Fatalf("ReverseNameToIPv6(%s) returned nil", tt.reverse)
			}
			expected := net.ParseIP(tt.expected)
			if !result.Equal(expected) {
				t.Errorf("ReverseNameToIPv6(%s) = %s, want %s", tt.reverse, result.String(), tt.expected)
			}
		})
	}
}

func TestReverseNameToIPv6_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		reverse string
	}{
		{"empty", ""},
		{"wrong-length", "1.2.3.ip6.arpa."},
		{"invalid-hex", "g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReverseNameToIPv6(tt.reverse)
			if result != nil {
				t.Errorf("ReverseNameToIPv6(%s) = %s, want nil", tt.reverse, result.String())
			}
		})
	}
}

func TestNew(t *testing.T) {
	resolver := New(nil)
	if resolver == nil {
		t.Error("New(nil) returned nil")
	}
}

// Test round-trip conversions
func TestIPv4RoundTrip(t *testing.T) {
	ips := []string{"192.168.1.1", "10.0.0.1", "172.16.0.100", "8.8.8.8"}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		reverse := IPv4ToReverseName(ip)
		recovered := ReverseNameToIPv4(reverse)
		if !ip.Equal(recovered) {
			t.Errorf("Round trip failed for %s: got %s", ipStr, recovered)
		}
	}
}

func TestIPv6RoundTrip(t *testing.T) {
	ips := []string{"::1", "2001:db8::1", "fe80::1"}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		reverse := IPv6ToReverseName(ip)
		recovered := ReverseNameToIPv6(reverse)
		if !ip.Equal(recovered) {
			t.Errorf("Round trip failed for %s: got %s", ipStr, recovered)
		}
	}
}
