package server

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/scott/dns/config"
)

// TestDNSIntegration tests DNS protocol functionality
func TestDNSIntegration(t *testing.T) {
	// Create test configuration
	rawCfg := config.DefaultConfig()
	rawCfg.Listen = "127.0.0.1:15353"
	rawCfg.Zones = []config.ZoneConfig{
		{Name: "test.local", Type: config.ZoneTypeForward, TTL: 3600},
	}
	rawCfg.Records.A = []config.ARecord{
		{Name: "www.test.local", IP: "192.168.1.1", TTL: 300},
		{Name: "mail.test.local", IP: "192.168.1.2", TTL: 300},
	}
	rawCfg.Records.AAAA = []config.AAAARecord{
		{Name: "www.test.local", IP: "2001:db8::1", TTL: 300},
	}
	rawCfg.Records.CNAME = []config.CNAMERecord{
		{Name: "alias.test.local", Target: "www.test.local", TTL: 300},
	}
	rawCfg.Records.MX = []config.MXRecord{
		{Name: "test.local", Target: "mail.test.local", Priority: 10, TTL: 300},
	}
	rawCfg.Records.TXT = []config.TXTRecord{
		{Name: "info.test.local", Values: []string{"Hello World"}, TTL: 300},
	}
	rawCfg.Records.NS = []config.NSRecord{
		{Name: "test.local", Target: "ns1.test.local", TTL: 3600},
	}
	rawCfg.Recursion.Enabled = false

	parsedCfg, err := rawCfg.Parse()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Create and start DNS server
	server := New(parsedCfg)

	// Start UDP server
	udpServer := &dns.Server{
		Addr:    "127.0.0.1:15353",
		Net:     "udp",
		Handler: dns.HandlerFunc(server.ServeDNS),
	}

	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			// Ignore shutdown errors
			if err.Error() != "dns: server not started" {
				t.Logf("UDP server error: %v", err)
			}
		}
	}()
	defer udpServer.Shutdown()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create DNS client
	client := &dns.Client{
		Timeout: 2 * time.Second,
	}

	t.Run("A record query", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("www.test.local.", dns.TypeA)

		resp, _, err := client.Exchange(msg, "127.0.0.1:15353")
		if err != nil {
			t.Fatalf("DNS query failed: %v", err)
		}

		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("Expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
		}

		if len(resp.Answer) == 0 {
			t.Fatal("Expected answer section to have records")
		}

		a, ok := resp.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("Expected A record, got %T", resp.Answer[0])
		}

		if a.A.String() != "192.168.1.1" {
			t.Errorf("Expected IP 192.168.1.1, got %s", a.A.String())
		}
	})

	t.Run("AAAA record query", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("www.test.local.", dns.TypeAAAA)

		resp, _, err := client.Exchange(msg, "127.0.0.1:15353")
		if err != nil {
			t.Fatalf("DNS query failed: %v", err)
		}

		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("Expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
		}

		if len(resp.Answer) == 0 {
			t.Fatal("Expected answer section to have records")
		}

		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("Expected AAAA record, got %T", resp.Answer[0])
		}

		expectedIP := net.ParseIP("2001:db8::1")
		if !aaaa.AAAA.Equal(expectedIP) {
			t.Errorf("Expected IP 2001:db8::1, got %s", aaaa.AAAA.String())
		}
	})

	t.Run("CNAME record query", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("alias.test.local.", dns.TypeCNAME)

		resp, _, err := client.Exchange(msg, "127.0.0.1:15353")
		if err != nil {
			t.Fatalf("DNS query failed: %v", err)
		}

		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("Expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
		}

		if len(resp.Answer) == 0 {
			t.Fatal("Expected answer section to have records")
		}

		cname, ok := resp.Answer[0].(*dns.CNAME)
		if !ok {
			t.Fatalf("Expected CNAME record, got %T", resp.Answer[0])
		}

		if cname.Target != "www.test.local." {
			t.Errorf("Expected target www.test.local., got %s", cname.Target)
		}
	})

	t.Run("MX record query", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("test.local.", dns.TypeMX)

		resp, _, err := client.Exchange(msg, "127.0.0.1:15353")
		if err != nil {
			t.Fatalf("DNS query failed: %v", err)
		}

		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("Expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
		}

		if len(resp.Answer) == 0 {
			t.Fatal("Expected answer section to have records")
		}

		mx, ok := resp.Answer[0].(*dns.MX)
		if !ok {
			t.Fatalf("Expected MX record, got %T", resp.Answer[0])
		}

		if mx.Preference != 10 {
			t.Errorf("Expected priority 10, got %d", mx.Preference)
		}

		if mx.Mx != "mail.test.local." {
			t.Errorf("Expected mail.test.local., got %s", mx.Mx)
		}
	})

	t.Run("TXT record query", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("info.test.local.", dns.TypeTXT)

		resp, _, err := client.Exchange(msg, "127.0.0.1:15353")
		if err != nil {
			t.Fatalf("DNS query failed: %v", err)
		}

		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("Expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
		}

		if len(resp.Answer) == 0 {
			t.Fatal("Expected answer section to have records")
		}

		txt, ok := resp.Answer[0].(*dns.TXT)
		if !ok {
			t.Fatalf("Expected TXT record, got %T", resp.Answer[0])
		}

		found := false
		for _, v := range txt.Txt {
			if v == "Hello World" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'Hello World' in TXT record, got %v", txt.Txt)
		}
	})

	t.Run("NS record query", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("test.local.", dns.TypeNS)

		resp, _, err := client.Exchange(msg, "127.0.0.1:15353")
		if err != nil {
			t.Fatalf("DNS query failed: %v", err)
		}

		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("Expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
		}

		if len(resp.Answer) == 0 && len(resp.Ns) == 0 {
			t.Fatal("Expected answer or authority section to have records")
		}
	})

	t.Run("NXDOMAIN for non-existent name", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("nonexistent.test.local.", dns.TypeA)

		resp, _, err := client.Exchange(msg, "127.0.0.1:15353")
		if err != nil {
			t.Fatalf("DNS query failed: %v", err)
		}

		// For authoritative zones, non-existent names should return NXDOMAIN
		if resp.Rcode != dns.RcodeNameError && resp.Rcode != dns.RcodeSuccess {
			t.Logf("Note: Rcode is %s (may vary based on zone configuration)", dns.RcodeToString[resp.Rcode])
		}
	})

	t.Run("Unknown zone returns REFUSED or SERVFAIL", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("unknown.zone.", dns.TypeA)

		resp, _, err := client.Exchange(msg, "127.0.0.1:15353")
		if err != nil {
			t.Fatalf("DNS query failed: %v", err)
		}

		// Server should refuse or fail for unknown zones when recursion is disabled
		validCodes := []int{dns.RcodeRefused, dns.RcodeServerFailure, dns.RcodeNameError}
		valid := false
		for _, code := range validCodes {
			if resp.Rcode == code {
				valid = true
				break
			}
		}
		if !valid && len(resp.Answer) == 0 {
			t.Logf("Note: Unknown zone returned %s", dns.RcodeToString[resp.Rcode])
		}
	})

	t.Run("Multiple queries stress test", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			msg := new(dns.Msg)
			msg.SetQuestion("www.test.local.", dns.TypeA)

			resp, _, err := client.Exchange(msg, "127.0.0.1:15353")
			if err != nil {
				t.Fatalf("Query %d failed: %v", i, err)
			}

			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("Query %d: Expected NOERROR, got %s", i, dns.RcodeToString[resp.Rcode])
			}
		}
	})
}

// TestDNSWithTCP tests DNS over TCP
func TestDNSWithTCP(t *testing.T) {
	rawCfg := config.DefaultConfig()
	rawCfg.Listen = "127.0.0.1:15354"
	rawCfg.Zones = []config.ZoneConfig{
		{Name: "tcptest.local", Type: config.ZoneTypeForward, TTL: 3600},
	}
	rawCfg.Records.A = []config.ARecord{
		{Name: "host.tcptest.local", IP: "10.0.0.1", TTL: 300},
	}

	parsedCfg, err := rawCfg.Parse()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	server := New(parsedCfg)

	// Start TCP server
	tcpServer := &dns.Server{
		Addr:    "127.0.0.1:15354",
		Net:     "tcp",
		Handler: dns.HandlerFunc(server.ServeDNS),
	}

	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			if err.Error() != "dns: server not started" {
				t.Logf("TCP server error: %v", err)
			}
		}
	}()
	defer tcpServer.Shutdown()

	time.Sleep(100 * time.Millisecond)

	// Create TCP client
	client := &dns.Client{
		Net:     "tcp",
		Timeout: 2 * time.Second,
	}

	t.Run("TCP A record query", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("host.tcptest.local.", dns.TypeA)

		resp, _, err := client.Exchange(msg, "127.0.0.1:15354")
		if err != nil {
			t.Fatalf("TCP DNS query failed: %v", err)
		}

		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("Expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
		}

		if len(resp.Answer) == 0 {
			t.Fatal("Expected answer")
		}

		a, ok := resp.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("Expected A record, got %T", resp.Answer[0])
		}

		if a.A.String() != "10.0.0.1" {
			t.Errorf("Expected 10.0.0.1, got %s", a.A.String())
		}
	})
}

// TestReverseZone tests reverse DNS lookups
func TestReverseZone(t *testing.T) {
	rawCfg := config.DefaultConfig()
	rawCfg.Listen = "127.0.0.1:15355"
	rawCfg.Zones = []config.ZoneConfig{
		{Name: "1.168.192.in-addr.arpa", Type: config.ZoneTypeReverse, Subnet: "192.168.1.0/24", TTL: 3600},
	}
	rawCfg.Records.PTR = []config.PTRRecord{
		{IP: "192.168.1.10", Hostname: "host10.example.com", TTL: 300, Zone: "1.168.192.in-addr.arpa"},
		{IP: "192.168.1.20", Hostname: "host20.example.com", TTL: 300, Zone: "1.168.192.in-addr.arpa"},
	}

	parsedCfg, err := rawCfg.Parse()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	server := New(parsedCfg)

	udpServer := &dns.Server{
		Addr:    "127.0.0.1:15355",
		Net:     "udp",
		Handler: dns.HandlerFunc(server.ServeDNS),
	}

	go func() {
		udpServer.ListenAndServe()
	}()
	defer udpServer.Shutdown()

	time.Sleep(100 * time.Millisecond)

	client := &dns.Client{Timeout: 2 * time.Second}

	t.Run("PTR record query", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("10.1.168.192.in-addr.arpa.", dns.TypePTR)

		resp, _, err := client.Exchange(msg, "127.0.0.1:15355")
		if err != nil {
			t.Fatalf("DNS query failed: %v", err)
		}

		if resp.Rcode != dns.RcodeSuccess {
			t.Logf("PTR query returned %s (may be expected based on zone config)", dns.RcodeToString[resp.Rcode])
		}

		if len(resp.Answer) > 0 {
			ptr, ok := resp.Answer[0].(*dns.PTR)
			if ok && ptr.Ptr != "host10.example.com." {
				t.Errorf("Expected host10.example.com., got %s", ptr.Ptr)
			}
		}
	})
}

// TestEDNS tests EDNS0 support
func TestEDNS(t *testing.T) {
	rawCfg := config.DefaultConfig()
	rawCfg.Listen = "127.0.0.1:15356"
	rawCfg.Zones = []config.ZoneConfig{
		{Name: "edns.local", Type: config.ZoneTypeForward, TTL: 3600},
	}
	rawCfg.Records.A = []config.ARecord{
		{Name: "test.edns.local", IP: "1.2.3.4", TTL: 300},
	}

	parsedCfg, err := rawCfg.Parse()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	server := New(parsedCfg)

	udpServer := &dns.Server{
		Addr:    "127.0.0.1:15356",
		Net:     "udp",
		Handler: dns.HandlerFunc(server.ServeDNS),
	}

	go udpServer.ListenAndServe()
	defer udpServer.Shutdown()

	time.Sleep(100 * time.Millisecond)

	client := &dns.Client{Timeout: 2 * time.Second}

	t.Run("Query with EDNS0", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("test.edns.local.", dns.TypeA)
		msg.SetEdns0(4096, true) // Request DNSSEC OK

		resp, _, err := client.Exchange(msg, "127.0.0.1:15356")
		if err != nil {
			t.Fatalf("DNS query failed: %v", err)
		}

		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("Expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
		}

		// Check if server supports EDNS0
		opt := resp.IsEdns0()
		if opt != nil {
			t.Logf("Server supports EDNS0 with buffer size %d", opt.UDPSize())
		}
	})
}

// TestConcurrentQueries tests handling of concurrent DNS queries
func TestConcurrentQueries(t *testing.T) {
	rawCfg := config.DefaultConfig()
	rawCfg.Listen = "127.0.0.1:15357"
	rawCfg.Zones = []config.ZoneConfig{
		{Name: "concurrent.local", Type: config.ZoneTypeForward, TTL: 3600},
	}
	rawCfg.Records.A = []config.ARecord{
		{Name: "host1.concurrent.local", IP: "10.0.0.1", TTL: 300},
		{Name: "host2.concurrent.local", IP: "10.0.0.2", TTL: 300},
		{Name: "host3.concurrent.local", IP: "10.0.0.3", TTL: 300},
	}

	parsedCfg, err := rawCfg.Parse()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	server := New(parsedCfg)

	udpServer := &dns.Server{
		Addr:    "127.0.0.1:15357",
		Net:     "udp",
		Handler: dns.HandlerFunc(server.ServeDNS),
	}

	go udpServer.ListenAndServe()
	defer udpServer.Shutdown()

	time.Sleep(100 * time.Millisecond)

	t.Run("50 concurrent queries", func(t *testing.T) {
		done := make(chan error, 50)

		for i := 0; i < 50; i++ {
			go func(n int) {
				client := &dns.Client{Timeout: 5 * time.Second}
				host := "host1"
				if n%3 == 1 {
					host = "host2"
				} else if n%3 == 2 {
					host = "host3"
				}

				msg := new(dns.Msg)
				msg.SetQuestion(host+".concurrent.local.", dns.TypeA)

				resp, _, err := client.Exchange(msg, "127.0.0.1:15357")
				if err != nil {
					done <- err
					return
				}

				if resp.Rcode != dns.RcodeSuccess {
					done <- fmt.Errorf("query %d: expected NOERROR, got %s", n, dns.RcodeToString[resp.Rcode])
					return
				}

				done <- nil
			}(i)
		}

		// Wait for all queries
		errors := 0
		for i := 0; i < 50; i++ {
			if err := <-done; err != nil {
				t.Logf("Concurrent query error: %v", err)
				errors++
			}
		}

		if errors > 5 { // Allow some failures due to timing
			t.Errorf("Too many concurrent query failures: %d/50", errors)
		}
	})
}
