// Package querylog implements DNS query logging with configurable filtering.
package querylog

import (
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Config holds query logging configuration.
type Config struct {
	Enabled     bool // Whether query logging is enabled
	LogSuccess  bool // Log successful queries (NOERROR)
	LogNXDomain bool // Log NXDOMAIN responses
	LogErrors   bool // Log other error responses
}

// DefaultConfig returns sensible defaults for query logging.
func DefaultConfig() *Config {
	return &Config{
		Enabled:     false,
		LogSuccess:  true,
		LogNXDomain: true,
		LogErrors:   true,
	}
}

// Entry represents a single query log entry.
type Entry struct {
	Time       time.Time `json:"time"`
	ClientIP   string    `json:"client_ip"`
	QName      string    `json:"qname"`
	QType      string    `json:"qtype"`
	Rcode      string    `json:"rcode"`
	ResponseMS float64   `json:"response_ms"`
	Answers    int       `json:"answers"`
}

// Logger handles DNS query logging.
type Logger struct {
	config  *Config
	entries []Entry
	maxSize int // Maximum entries to keep in memory
	mu      sync.RWMutex
}

// New creates a new query logger with the given configuration.
func New(cfg *Config) *Logger {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &Logger{
		config:  cfg,
		entries: make([]Entry, 0, 1000),
		maxSize: 10000, // Keep last 10k entries
	}
}

// Log logs a DNS query if it matches the configured filters.
func (l *Logger) Log(clientIP string, r *dns.Msg, response *dns.Msg, duration time.Duration) {
	if !l.config.Enabled || r == nil || len(r.Question) == 0 {
		return
	}

	rcode := dns.RcodeToString[response.Rcode]

	// Check if we should log this response type
	switch response.Rcode {
	case dns.RcodeSuccess:
		if !l.config.LogSuccess {
			return
		}
	case dns.RcodeNameError:
		if !l.config.LogNXDomain {
			return
		}
	default:
		if !l.config.LogErrors {
			return
		}
	}

	q := r.Question[0]
	entry := Entry{
		Time:       time.Now(),
		ClientIP:   clientIP,
		QName:      q.Name,
		QType:      dns.TypeToString[q.Qtype],
		Rcode:      rcode,
		ResponseMS: float64(duration.Microseconds()) / 1000.0,
		Answers:    len(response.Answer),
	}

	// Log to stdout
	log.Printf("[QUERY] %s %s %s -> %s (%d answers, %.2fms)",
		clientIP, entry.QType, entry.QName, rcode, entry.Answers, entry.ResponseMS)

	// Store in memory buffer
	l.mu.Lock()
	l.entries = append(l.entries, entry)
	if len(l.entries) > l.maxSize {
		// Remove oldest entries
		l.entries = l.entries[len(l.entries)-l.maxSize:]
	}
	l.mu.Unlock()
}

// UpdateConfig updates the logger configuration.
func (l *Logger) UpdateConfig(cfg *Config) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config = cfg
}

// GetConfig returns the current configuration.
func (l *Logger) GetConfig() *Config {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

// GetEntries returns recent log entries, optionally filtered.
func (l *Logger) GetEntries(limit int, qtype string, rcode string) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []Entry

	// Iterate backwards (newest first)
	for i := len(l.entries) - 1; i >= 0 && len(result) < limit; i-- {
		entry := l.entries[i]

		// Apply filters
		if qtype != "" && entry.QType != qtype {
			continue
		}
		if rcode != "" && entry.Rcode != rcode {
			continue
		}

		result = append(result, entry)
	}

	return result
}

// Stats returns query statistics.
type Stats struct {
	TotalQueries  int            `json:"total_queries"`
	ByQType       map[string]int `json:"by_qtype"`
	ByRcode       map[string]int `json:"by_rcode"`
	AvgResponseMS float64        `json:"avg_response_ms"`
}

// GetStats returns aggregated statistics from logged queries.
func (l *Logger) GetStats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	stats := Stats{
		TotalQueries: len(l.entries),
		ByQType:      make(map[string]int),
		ByRcode:      make(map[string]int),
	}

	var totalMS float64
	for _, entry := range l.entries {
		stats.ByQType[entry.QType]++
		stats.ByRcode[entry.Rcode]++
		totalMS += entry.ResponseMS
	}

	if stats.TotalQueries > 0 {
		stats.AvgResponseMS = totalMS / float64(stats.TotalQueries)
	}

	return stats
}

// Clear removes all log entries.
func (l *Logger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = make([]Entry, 0, 1000)
}
