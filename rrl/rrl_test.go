package rrl

import (
	"net"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("Expected Enabled to be false")
	}
	if cfg.ResponsesPerSec != 5 {
		t.Errorf("Expected ResponsesPerSec=5, got %d", cfg.ResponsesPerSec)
	}
}

func TestNew_NilConfig(t *testing.T) {
	limiter := New(nil)
	defer limiter.Stop()
	if limiter.config == nil {
		t.Fatal("Expected default config")
	}
}

func TestNew_CustomConfig(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		ResponsesPerSec: 10,
		WhitelistCIDRs:  []string{"10.0.0.0/8"},
	}
	limiter := New(cfg)
	defer limiter.Stop()
	if limiter.config.ResponsesPerSec != 10 {
		t.Errorf("Expected ResponsesPerSec=10")
	}
	if len(limiter.whitelistNets) != 1 {
		t.Errorf("Expected 1 whitelist network")
	}
}

func TestCheck_Disabled(t *testing.T) {
	limiter := New(&Config{Enabled: false})
	defer limiter.Stop()
	ip := net.ParseIP("1.2.3.4")
	if limiter.Check(ip) != Allow {
		t.Error("Expected Allow when disabled")
	}
}

func TestCheck_Whitelist(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		ResponsesPerSec: 1,
		WhitelistCIDRs:  []string{"10.0.0.0/8"},
	}
	limiter := New(cfg)
	defer limiter.Stop()
	ip := net.ParseIP("10.1.2.3")
	for i := 0; i < 100; i++ {
		if limiter.Check(ip) != Allow {
			t.Error("Whitelisted IP should always be allowed")
		}
	}
}

func TestCheck_RateLimiting(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		ResponsesPerSec: 3,
		SlipRatio:       0,
		WindowSeconds:   1,
	}
	limiter := New(cfg)
	defer limiter.Stop()
	ip := net.ParseIP("1.2.3.4")
	for i := 0; i < 3; i++ {
		if limiter.Check(ip) != Allow {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}
	if limiter.Check(ip) != Refuse {
		t.Error("4th request should be refused")
	}
}

func TestCheck_SlipRatio(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		ResponsesPerSec: 1,
		SlipRatio:       2,
		WindowSeconds:   1,
	}
	limiter := New(cfg)
	defer limiter.Stop()
	ip := net.ParseIP("1.2.3.4")
	limiter.Check(ip)
	slips := 0
	refuses := 0
	for i := 0; i < 10; i++ {
		action := limiter.Check(ip)
		if action == Slip {
			slips++
		} else if action == Refuse {
			refuses++
		}
	}
	if slips == 0 {
		t.Error("Expected some slip responses")
	}
}

func TestCheck_WindowExpiry(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		ResponsesPerSec: 1,
		SlipRatio:       0,
		WindowSeconds:   1,
	}
	limiter := New(cfg)
	defer limiter.Stop()
	ip := net.ParseIP("1.2.3.4")
	limiter.Check(ip)
	if limiter.Check(ip) != Refuse {
		t.Error("Should be refused")
	}
	time.Sleep(1100 * time.Millisecond)
	if limiter.Check(ip) != Allow {
		t.Error("Should be allowed after window expiry")
	}
}

func TestGetStats(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		ResponsesPerSec: 100,
		WindowSeconds:   5,
	}
	limiter := New(cfg)
	defer limiter.Stop()
	limiter.Check(net.ParseIP("1.1.1.1"))
	limiter.Check(net.ParseIP("2.2.2.2"))
	stats := limiter.GetStats()
	if stats.ActiveClients != 2 {
		t.Errorf("Expected 2 clients, got %d", stats.ActiveClients)
	}
	if stats.TotalQueries != 2 {
		t.Errorf("Expected 2 queries, got %d", stats.TotalQueries)
	}
}

func TestUpdateConfig(t *testing.T) {
	limiter := New(&Config{ResponsesPerSec: 5})
	defer limiter.Stop()
	limiter.UpdateConfig(&Config{ResponsesPerSec: 10})
	if limiter.GetConfig().ResponsesPerSec != 10 {
		t.Error("Config should be updated")
	}
}
