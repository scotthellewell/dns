package querylog

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("Expected Enabled=false")
	}
	if !cfg.LogSuccess {
		t.Error("Expected LogSuccess=true")
	}
}

func TestNew_NilConfig(t *testing.T) {
	logger := New(nil)
	if logger.config == nil {
		t.Fatal("Expected default config")
	}
}

func createQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func createResponse(rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.Rcode = rcode
	return m
}

func TestLog_Disabled(t *testing.T) {
	logger := New(&Config{Enabled: false})
	logger.Log("1.2.3.4", createQuery("example.com", dns.TypeA), createResponse(dns.RcodeSuccess), time.Millisecond)
	if len(logger.GetEntries(100, "", "")) != 0 {
		t.Error("Should not log when disabled")
	}
}

func TestLog_Enabled(t *testing.T) {
	logger := New(&Config{Enabled: true, LogSuccess: true})
	logger.Log("1.2.3.4", createQuery("example.com", dns.TypeA), createResponse(dns.RcodeSuccess), 10*time.Millisecond)
	entries := logger.GetEntries(100, "", "")
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}
	if entries[0].ClientIP != "1.2.3.4" {
		t.Errorf("Expected ClientIP=1.2.3.4")
	}
	if entries[0].QType != "A" {
		t.Errorf("Expected QType=A")
	}
}

func TestLog_FilterByRcode(t *testing.T) {
	tests := []struct {
		name   string
		rcode  int
		logIt  bool
		config *Config
	}{
		{"success logged", dns.RcodeSuccess, true, &Config{Enabled: true, LogSuccess: true}},
		{"success not logged", dns.RcodeSuccess, false, &Config{Enabled: true, LogSuccess: false}},
		{"nxdomain logged", dns.RcodeNameError, true, &Config{Enabled: true, LogNXDomain: true}},
		{"nxdomain not logged", dns.RcodeNameError, false, &Config{Enabled: true, LogNXDomain: false}},
		{"error logged", dns.RcodeServerFailure, true, &Config{Enabled: true, LogErrors: true}},
		{"error not logged", dns.RcodeServerFailure, false, &Config{Enabled: true, LogErrors: false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := New(tt.config)
			logger.Log("1.2.3.4", createQuery("example.com", dns.TypeA), createResponse(tt.rcode), time.Millisecond)
			entries := logger.GetEntries(100, "", "")
			if tt.logIt && len(entries) == 0 {
				t.Error("Expected entry to be logged")
			}
			if !tt.logIt && len(entries) > 0 {
				t.Error("Expected entry not to be logged")
			}
		})
	}
}

func TestLog_NilQuery(t *testing.T) {
	logger := New(&Config{Enabled: true, LogSuccess: true})
	logger.Log("1.2.3.4", nil, createResponse(dns.RcodeSuccess), time.Millisecond)
	if len(logger.GetEntries(100, "", "")) != 0 {
		t.Error("Should not log nil query")
	}
}

func TestGetEntries_Filter(t *testing.T) {
	logger := New(&Config{Enabled: true, LogSuccess: true, LogNXDomain: true})
	logger.Log("1.1.1.1", createQuery("a.com", dns.TypeA), createResponse(dns.RcodeSuccess), time.Millisecond)
	logger.Log("2.2.2.2", createQuery("b.com", dns.TypeAAAA), createResponse(dns.RcodeSuccess), time.Millisecond)
	logger.Log("3.3.3.3", createQuery("c.com", dns.TypeA), createResponse(dns.RcodeNameError), time.Millisecond)

	if len(logger.GetEntries(100, "", "")) != 3 {
		t.Error("Expected 3 total entries")
	}
	if len(logger.GetEntries(100, "A", "")) != 2 {
		t.Error("Expected 2 A entries")
	}
	if len(logger.GetEntries(100, "", "NXDOMAIN")) != 1 {
		t.Error("Expected 1 NXDOMAIN entry")
	}
	if len(logger.GetEntries(2, "", "")) != 2 {
		t.Error("Expected 2 entries with limit")
	}
}

func TestGetStats(t *testing.T) {
	logger := New(&Config{Enabled: true, LogSuccess: true})
	logger.Log("1.1.1.1", createQuery("a.com", dns.TypeA), createResponse(dns.RcodeSuccess), 10*time.Millisecond)
	logger.Log("2.2.2.2", createQuery("b.com", dns.TypeA), createResponse(dns.RcodeSuccess), 20*time.Millisecond)
	stats := logger.GetStats()
	if stats.TotalQueries != 2 {
		t.Errorf("Expected TotalQueries=2, got %d", stats.TotalQueries)
	}
	if stats.ByQType["A"] != 2 {
		t.Errorf("Expected ByQType[A]=2")
	}
	if stats.AvgResponseMS == 0 {
		t.Error("Expected AvgResponseMS > 0")
	}
}

func TestClear(t *testing.T) {
	logger := New(&Config{Enabled: true, LogSuccess: true})
	logger.Log("1.1.1.1", createQuery("a.com", dns.TypeA), createResponse(dns.RcodeSuccess), time.Millisecond)
	logger.Clear()
	if len(logger.GetEntries(100, "", "")) != 0 {
		t.Error("Expected 0 entries after clear")
	}
}

func TestUpdateConfig(t *testing.T) {
	logger := New(&Config{Enabled: false})
	logger.UpdateConfig(&Config{Enabled: true})
	if !logger.GetConfig().Enabled {
		t.Error("Config should be updated")
	}
}
