package cache

import (
	"net"
	"sync"
	"time"
)

// Entry represents a cached DNS response
type Entry struct {
	IPs       []net.IP
	CNAMEs    []string
	TTL       uint32
	ExpiresAt time.Time
	Negative  bool // True if this is a negative cache entry (NXDOMAIN/NODATA)
}

// Cache provides TTL-based caching for DNS responses
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*Entry
	maxSize int
}

// New creates a new cache with the specified maximum size
func New(maxSize int) *Cache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	c := &Cache{
		entries: make(map[string]*Entry),
		maxSize: maxSize,
	}
	// Start background cleanup goroutine
	go c.cleanup()
	return c
}

// Key generates a cache key from name and query type
func Key(name string, qtype uint16) string {
	return name + ":" + string(rune(qtype))
}

// Get retrieves an entry from the cache if it exists and hasn't expired
func (c *Cache) Get(key string) (*Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	// Calculate remaining TTL
	remaining := uint32(time.Until(entry.ExpiresAt).Seconds())
	if remaining == 0 {
		remaining = 1
	}

	// Return a copy with adjusted TTL
	return &Entry{
		IPs:       entry.IPs,
		CNAMEs:    entry.CNAMEs,
		TTL:       remaining,
		ExpiresAt: entry.ExpiresAt,
	}, true
}

// Set stores an entry in the cache
func (c *Cache) Set(key string, ips []net.IP, cnames []string, ttl uint32) {
	c.SetWithNegative(key, ips, cnames, ttl, false)
}

// SetNegative stores a negative cache entry (NXDOMAIN/NODATA)
func (c *Cache) SetNegative(key string, ttl uint32) {
	c.SetWithNegative(key, nil, nil, ttl, true)
}

// SetWithNegative stores an entry in the cache with optional negative flag
func (c *Cache) SetWithNegative(key string, ips []net.IP, cnames []string, ttl uint32, negative bool) {
	if ttl == 0 {
		ttl = 60 // Default negative cache TTL of 60 seconds
	}

	// Cap TTL at 1 hour to prevent stale entries
	// For negative entries, cap at 5 minutes to allow faster recovery
	maxTTL := uint32(3600)
	if negative && ttl > 300 {
		maxTTL = 300
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: if at max size, remove oldest entries
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &Entry{
		IPs:       ips,
		CNAMEs:    cnames,
		TTL:       ttl,
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
		Negative:  negative,
	}
}

// evictOldest removes expired entries and oldest entries if still over limit
func (c *Cache) evictOldest() {
	now := time.Now()
	
	// First pass: remove expired entries
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}

	// If still over limit, remove entries closest to expiration
	if len(c.entries) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time
		first := true

		for key, entry := range c.entries {
			if first || entry.ExpiresAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.ExpiresAt
				first = false
			}
		}

		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
}

// cleanup periodically removes expired entries
func (c *Cache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.ExpiresAt) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// Size returns the current number of entries
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Clear removes all entries from the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*Entry)
}
