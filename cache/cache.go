package cache

import (
	"net"
	"sync"
	"time"
)

// Entry represents a cached DNS response
type Entry struct {
	IPs        []net.IP
	CNAMEs     []string
	TTL        uint32
	ExpiresAt  time.Time
	Negative   bool      // True if this is a negative cache entry (NXDOMAIN/NODATA)
	HitCount   int       // Number of times this entry has been accessed
	LastAccess time.Time // When this entry was last accessed
	Fetching   bool      // True if this entry is being refreshed in background
}

// Cache provides TTL-based caching for DNS responses
type Cache struct {
	mu       sync.RWMutex
	entries  map[string]*Entry
	maxSize  int
	staleAge time.Duration // How long to serve stale entries (0 = disabled)
}

// New creates a new cache with the specified maximum size
func New(maxSize int) *Cache {
	return NewWithStale(maxSize, 0)
}

// NewWithStale creates a new cache with stale serving enabled
func NewWithStale(maxSize int, staleAge time.Duration) *Cache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	c := &Cache{
		entries:  make(map[string]*Entry),
		maxSize:  maxSize,
		staleAge: staleAge,
	}
	// Start background cleanup goroutine
	go c.cleanup()
	return c
}

// Key generates a cache key from name and query type
func Key(name string, qtype uint16) string {
	return name + ":" + string(rune(qtype))
}

// Get retrieves an entry from the cache if it exists and hasn't expired.
// Returns (entry, isStale, found)
// If isStale is true, the entry is expired but within the stale window.
func (c *Cache) Get(key string) (*Entry, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false, false
	}

	now := time.Now()
	
	// Update access tracking
	entry.HitCount++
	entry.LastAccess = now

	// Check if expired
	expired := now.After(entry.ExpiresAt)
	
	if expired {
		// Check if within stale window
		if c.staleAge > 0 && now.Before(entry.ExpiresAt.Add(c.staleAge)) {
			// Return stale entry with TTL of 1 (indicates stale)
			return &Entry{
				IPs:        entry.IPs,
				CNAMEs:     entry.CNAMEs,
				TTL:        1, // Stale
				ExpiresAt:  entry.ExpiresAt,
				Negative:   entry.Negative,
				HitCount:   entry.HitCount,
				LastAccess: entry.LastAccess,
				Fetching:   entry.Fetching,
			}, true, true
		}
		return nil, false, false
	}

	// Calculate remaining TTL
	remaining := uint32(time.Until(entry.ExpiresAt).Seconds())
	if remaining == 0 {
		remaining = 1
	}

	// Return a copy with adjusted TTL
	return &Entry{
		IPs:        entry.IPs,
		CNAMEs:     entry.CNAMEs,
		TTL:        remaining,
		ExpiresAt:  entry.ExpiresAt,
		Negative:   entry.Negative,
		HitCount:   entry.HitCount,
		LastAccess: entry.LastAccess,
		Fetching:   entry.Fetching,
	}, false, true
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

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: if at max size, remove oldest entries
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &Entry{
		IPs:        ips,
		CNAMEs:     cnames,
		TTL:        ttl,
		ExpiresAt:  now.Add(time.Duration(ttl) * time.Second),
		Negative:   negative,
		HitCount:   0,
		LastAccess: now,
		Fetching:   false,
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

// PrefetchCandidate represents an entry that should be prefetched
type PrefetchCandidate struct {
	Key       string
	HitCount  int
	TTLPct    float64 // Percentage of TTL remaining (0.0 - 1.0)
	ExpiresAt time.Time
}

// GetPrefetchCandidates returns entries that are close to expiring and have been accessed enough
// minHits: minimum hit count required
// ttlThreshold: refresh when TTL remaining is below this percentage (e.g., 0.2 = 20%)
func (c *Cache) GetPrefetchCandidates(minHits int, ttlThreshold float64) []PrefetchCandidate {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var candidates []PrefetchCandidate

	for key, entry := range c.entries {
		// Skip negative cache entries and entries already being fetched
		if entry.Negative || entry.Fetching {
			continue
		}

		// Skip entries that haven't been accessed enough
		if entry.HitCount < minHits {
			continue
		}

		// Calculate TTL percentage remaining
		totalTTL := float64(entry.TTL)
		if totalTTL == 0 {
			continue
		}
		remaining := time.Until(entry.ExpiresAt).Seconds()
		if remaining < 0 {
			remaining = 0
		}
		pctRemaining := remaining / float64(entry.TTL)

		// Skip if not close enough to expiring
		if pctRemaining > ttlThreshold {
			continue
		}

		candidates = append(candidates, PrefetchCandidate{
			Key:       key,
			HitCount:  entry.HitCount,
			TTLPct:    pctRemaining,
			ExpiresAt: entry.ExpiresAt,
		})
	}

	return candidates
}

// MarkFetching marks an entry as currently being fetched
// Returns true if the entry exists and was marked, false otherwise
func (c *Cache) MarkFetching(key string, fetching bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return false
	}
	entry.Fetching = fetching
	return true
}

// Stats returns cache statistics
type CacheStats struct {
	Size       int
	MaxSize    int
	StaleAge   time.Duration
	HotEntries int // Entries with >0 hits
}

func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hotCount := 0
	for _, entry := range c.entries {
		if entry.HitCount > 0 {
			hotCount++
		}
	}

	return CacheStats{
		Size:       len(c.entries),
		MaxSize:    c.maxSize,
		StaleAge:   c.staleAge,
		HotEntries: hotCount,
	}
}
