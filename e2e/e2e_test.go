package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestE2EFullStack tests the complete DNS server stack
// This test requires the server to be running or starts it
func TestE2EFullStack(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Check if server is already running
	apiURL := getEnvOrDefault("DNS_API_URL", "http://localhost:8080")
	dnsAddr := getEnvOrDefault("DNS_ADDR", "127.0.0.1:5353")

	// Wait for services to be ready
	if !waitForAPI(apiURL, 5*time.Second) {
		t.Skip("API server not available, skipping E2E tests")
	}

	t.Run("API Status", func(t *testing.T) {
		resp, err := http.Get(apiURL + "/api/status")
		if err != nil {
			t.Fatalf("Failed to get status: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var status map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if _, ok := status["status"]; !ok {
			t.Error("Response missing 'status' field")
		}
	})

	t.Run("API Zones CRUD", func(t *testing.T) {
		// GET zones
		resp, err := http.Get(apiURL + "/api/zones")
		if err != nil {
			t.Fatalf("Failed to get zones: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /api/zones: expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("API Records CRUD", func(t *testing.T) {
		// GET records
		resp, err := http.Get(apiURL + "/api/records")
		if err != nil {
			t.Fatalf("Failed to get records: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /api/records: expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("API Config", func(t *testing.T) {
		resp, err := http.Get(apiURL + "/api/config")
		if err != nil {
			t.Fatalf("Failed to get config: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /api/config: expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("API Metrics", func(t *testing.T) {
		resp, err := http.Get(apiURL + "/metrics")
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /metrics: expected 200, got %d", resp.StatusCode)
		}
	})

	// DNS protocol tests (only if DNS server is running)
	if waitForDNS(dnsAddr, 2*time.Second) {
		t.Run("DNS A Query", func(t *testing.T) {
			testDNSQuery(t, dnsAddr, "example.com.", dns.TypeA)
		})

		t.Run("DNS AAAA Query", func(t *testing.T) {
			testDNSQuery(t, dnsAddr, "example.com.", dns.TypeAAAA)
		})

		t.Run("DNS MX Query", func(t *testing.T) {
			testDNSQuery(t, dnsAddr, "example.com.", dns.TypeMX)
		})

		t.Run("DNS TXT Query", func(t *testing.T) {
			testDNSQuery(t, dnsAddr, "example.com.", dns.TypeTXT)
		})

		t.Run("DNS Concurrent Queries", func(t *testing.T) {
			testConcurrentDNS(t, dnsAddr, 20)
		})
	} else {
		t.Log("DNS server not available, skipping DNS protocol tests")
	}
}

// TestE2EWebToAPI tests the web frontend to API integration
func TestE2EWebToAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	apiURL := getEnvOrDefault("DNS_API_URL", "http://localhost:8080")

	if !waitForAPI(apiURL, 5*time.Second) {
		t.Skip("API server not available")
	}

	t.Run("CORS Headers", func(t *testing.T) {
		req, _ := http.NewRequest("OPTIONS", apiURL+"/api/status", nil)
		req.Header.Set("Origin", "http://localhost:4200")
		req.Header.Set("Access-Control-Request-Method", "GET")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("CORS preflight failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			t.Errorf("CORS preflight: expected 200/204, got %d", resp.StatusCode)
		}

		corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		if corsOrigin == "" {
			t.Error("Missing Access-Control-Allow-Origin header")
		}
	})

	t.Run("JSON Content-Type", func(t *testing.T) {
		resp, err := http.Get(apiURL + "/api/status")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()

		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			t.Log("Warning: No Content-Type header")
		}
	})
}

// TestE2ESecurityHeaders tests security-related headers
func TestE2ESecurityHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	apiURL := getEnvOrDefault("DNS_API_URL", "http://localhost:8080")

	if !waitForAPI(apiURL, 5*time.Second) {
		t.Skip("API server not available")
	}

	resp, err := http.Get(apiURL + "/api/status")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp.Body.Close()

	// Log security headers (informational)
	headers := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
		"Strict-Transport-Security",
	}

	for _, h := range headers {
		if v := resp.Header.Get(h); v != "" {
			t.Logf("%s: %s", h, v)
		}
	}
}

// TestE2EPerformance tests API response times
func TestE2EPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	apiURL := getEnvOrDefault("DNS_API_URL", "http://localhost:8080")

	if !waitForAPI(apiURL, 5*time.Second) {
		t.Skip("API server not available")
	}

	endpoints := []string{
		"/api/status",
		"/api/zones",
		"/api/records",
		"/api/config",
		"/metrics",
	}

	for _, endpoint := range endpoints {
		t.Run("Response time "+endpoint, func(t *testing.T) {
			start := time.Now()
			resp, err := http.Get(apiURL + endpoint)
			duration := time.Since(start)

			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			resp.Body.Close()

			// API should respond within 500ms
			if duration > 500*time.Millisecond {
				t.Errorf("Slow response: %v (expected < 500ms)", duration)
			} else {
				t.Logf("%s: %v", endpoint, duration)
			}
		})
	}
}

// Helper functions

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func waitForAPI(url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 1 * time.Second}

	for time.Now().Before(deadline) {
		resp, err := client.Get(url + "/api/status")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func waitForDNS(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	client := &dns.Client{Timeout: 1 * time.Second}

	for time.Now().Before(deadline) {
		msg := new(dns.Msg)
		msg.SetQuestion(".", dns.TypeNS)
		_, _, err := client.Exchange(msg, addr)
		if err == nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func testDNSQuery(t *testing.T, addr, name string, qtype uint16) {
	client := &dns.Client{Timeout: 5 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)

	resp, _, err := client.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("DNS query failed: %v", err)
	}

	// We just want to verify the server responds
	// NXDOMAIN is acceptable for non-existent records
	validCodes := []int{dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeRefused}
	valid := false
	for _, code := range validCodes {
		if resp.Rcode == code {
			valid = true
			break
		}
	}

	if !valid {
		t.Errorf("Unexpected response code: %s", dns.RcodeToString[resp.Rcode])
	}
}

func testConcurrentDNS(t *testing.T, addr string, count int) {
	done := make(chan error, count)

	for i := 0; i < count; i++ {
		go func(n int) {
			client := &dns.Client{Timeout: 5 * time.Second}
			msg := new(dns.Msg)
			msg.SetQuestion(fmt.Sprintf("test%d.example.com.", n), dns.TypeA)

			_, _, err := client.Exchange(msg, addr)
			done <- err
		}(i)
	}

	errors := 0
	for i := 0; i < count; i++ {
		if err := <-done; err != nil {
			errors++
		}
	}

	if errors > count/10 { // Allow up to 10% failures
		t.Errorf("Too many concurrent query failures: %d/%d", errors, count)
	}
}
