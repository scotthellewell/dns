// Package rrl implements Response Rate Limiting (RRL) for DNS servers.
// RRL is a technique to mitigate DNS amplification attacks and reflection-based DDoS.
package rrl

import (
	"net"
	"sync"
	"time"
)

// Config holds rate limiting configuration.
type Config struct {
	Enabled         bool     // Whether rate limiting is enabled
	ResponsesPerSec int      // Max responses per second per client
	SlipRatio       int      // 1-in-N responses sent when rate limited (0 = refuse all)
	WindowSeconds   int      // Time window for rate tracking
	WhitelistCIDRs  []string // CIDRs exempt from rate limiting
}

// DefaultConfig returns sensible defaults for RRL.
func DefaultConfig() *Config {
	return &Config{
		Enabled:         false,
		ResponsesPerSec: 5,
		SlipRatio:       2,
		WindowSeconds:   1,
		WhitelistCIDRs:  []string{"127.0.0.0/8", "::1/128"},
	}
}

// Action represents the action to take for a query.
type Action int

const (
	// Allow means the query should be processed normally.
	Allow Action = iota
	// Slip means send a truncated response (forces TCP retry).
	Slip
	// Refuse means drop or refuse the query entirely.
	Refuse
)

// clientState tracks query rate for a single client.
type clientState struct {
	count     int       // Queries in current window
	windowEnd time.Time // When current window expires
	slipCount int       // Counter for slip ratio
}

// Limiter implements per-client rate limiting.
type Limiter struct {
	config        *Config
	clients       map[string]*clientState
	whitelistNets []*net.IPNet
	mu            sync.Mutex
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// New creates a new rate limiter with the given configuration.
func New(cfg *Config) *Limiter {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	l := &Limiter{
		config:  cfg,
		clients: make(map[string]*clientState),
	}

	// Parse whitelist CIDRs
	for _, cidr := range cfg.WhitelistCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			l.whitelistNets = append(l.whitelistNets, network)
		}
	}

	// Start cleanup goroutine to prevent memory leaks
	l.stopCleanup = make(chan struct{})
	l.cleanupTicker = time.NewTicker(time.Minute)
	go l.cleanupLoop()

	return l
}

// Check determines if a query from the given IP should be allowed.
func (l *Limiter) Check(clientIP net.IP) Action {
	if !l.config.Enabled {
		return Allow
	}

	// Check whitelist
	for _, network := range l.whitelistNets {
		if network.Contains(clientIP) {
			return Allow
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	key := clientIP.String()
	now := time.Now()

	state, exists := l.clients[key]
	if !exists || now.After(state.windowEnd) {
		// New window
		state = &clientState{
			count:     1,
			windowEnd: now.Add(time.Duration(l.config.WindowSeconds) * time.Second),
			slipCount: 0,
		}
		l.clients[key] = state
		return Allow
	}

	state.count++

	// Within rate limit?
	if state.count <= l.config.ResponsesPerSec {
		return Allow
	}

	// Rate limited - determine slip or refuse
	if l.config.SlipRatio > 0 {
		state.slipCount++
		if state.slipCount >= l.config.SlipRatio {
			state.slipCount = 0
			return Slip
		}
	}

	return Refuse
}

// UpdateConfig updates the rate limiter configuration.
func (l *Limiter) UpdateConfig(cfg *Config) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.config = cfg

	// Re-parse whitelist
	l.whitelistNets = nil
	for _, cidr := range cfg.WhitelistCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			l.whitelistNets = append(l.whitelistNets, network)
		}
	}
}

// GetConfig returns the current configuration.
func (l *Limiter) GetConfig() *Config {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config
}

// Stats returns current rate limiter statistics.
type Stats struct {
	ActiveClients int // Number of clients being tracked
	TotalQueries  int // Total queries in current windows
}

// GetStats returns current statistics.
func (l *Limiter) GetStats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()

	stats := Stats{
		ActiveClients: len(l.clients),
	}
	for _, state := range l.clients {
		stats.TotalQueries += state.count
	}
	return stats
}

// cleanupLoop periodically removes expired client states.
func (l *Limiter) cleanupLoop() {
	for {
		select {
		case <-l.cleanupTicker.C:
			l.cleanup()
		case <-l.stopCleanup:
			l.cleanupTicker.Stop()
			return
		}
	}
}

// cleanup removes expired client states.
func (l *Limiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for key, state := range l.clients {
		if now.After(state.windowEnd) {
			delete(l.clients, key)
		}
	}
}

// Stop stops the rate limiter cleanup goroutine.
func (l *Limiter) Stop() {
	close(l.stopCleanup)
}
