// Package blocklist provides DNS-level blocking for ads, malware, and unwanted content.
package blocklist

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Manager handles blocklist operations including lookups and updates.
type Manager struct {
	mu           sync.RWMutex
	config       *Config
	sources      map[string]*Source
	bloom        *BloomFilter
	store        Store
	scheduler    *Scheduler
	whitelist    map[string]bool
	whitelistNet []*net.IPNet

	// Stats
	totalBlocked   uint64
	totalAllowed   uint64
	lastUpdateTime time.Time

	// Initialization state
	ready    bool
	initDone chan struct{}
}

// Config holds blocklist configuration.
type Config struct {
	Enabled    bool   `json:"enabled"`
	Response   string `json:"response"`    // "nxdomain", "zero", "redirect"
	RedirectIP string `json:"redirect_ip"` // Only for redirect mode
	LogBlocked bool   `json:"log_blocked"`
}

// Source represents a blocklist source (URL to fetch).
type Source struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Format        string    `json:"format"` // "hosts", "domains"
	Enabled       bool      `json:"enabled"`
	UpdateMinutes int       `json:"update_minutes"`
	LastUpdate    time.Time `json:"last_update"`
	LastETag      string    `json:"last_etag,omitempty"`
	EntryCount    int       `json:"entry_count"`
	LastError     string    `json:"last_error,omitempty"`
	ErrorCount    int       `json:"error_count"`
}

// Store interface for persistent blocklist storage.
type Store interface {
	// Config
	GetBlocklistConfig() (*Config, error)
	SaveBlocklistConfig(config *Config) error

	// Sources
	GetBlocklistSources() ([]*Source, error)
	SaveBlocklistSource(source *Source) error
	DeleteBlocklistSource(id string) error

	// Whitelist
	GetBlocklistWhitelist() ([]string, error)
	SaveBlocklistWhitelist(entries []string) error

	// Domain entries (the actual block data)
	AddBlockedDomains(sourceID string, domains []string) error
	RemoveBlockedDomainsForSource(sourceID string) error
	IsBlocked(domain string) (bool, error)
	GetAllBlockedDomains() ([]string, error)
	GetBlockedDomainCount() (int, error)
}

// New creates a new blocklist manager.
func New(store Store) *Manager {
	m := &Manager{
		sources:   make(map[string]*Source),
		whitelist: make(map[string]bool),
		store:     store,
		config: &Config{
			Enabled:    false,
			Response:   "nxdomain",
			LogBlocked: true,
		},
		initDone: make(chan struct{}),
	}

	return m
}

// Start initializes the manager and starts the update scheduler.
// This returns immediately and does initialization in the background.
func (m *Manager) Start() error {
	// Load config from storage (fast operation, do synchronously)
	if cfg, err := m.store.GetBlocklistConfig(); err == nil && cfg != nil {
		m.mu.Lock()
		m.config = cfg
		m.mu.Unlock()
	}

	// Load sources from storage (fast operation, do synchronously)
	sources, err := m.store.GetBlocklistSources()
	if err != nil {
		log.Printf("[blocklist] Failed to load sources: %v", err)
	} else {
		m.mu.Lock()
		for _, s := range sources {
			m.sources[s.ID] = s
		}
		m.mu.Unlock()
	}

	// Load whitelist (fast operation, do synchronously)
	if entries, err := m.store.GetBlocklistWhitelist(); err == nil {
		m.mu.Lock()
		for _, e := range entries {
			m.addToWhitelist(e)
		}
		m.mu.Unlock()
	}

	log.Printf("[blocklist] Starting initialization in background (sources: %d)", len(m.sources))

	// Do heavy lifting in background goroutine
	go m.initializeInBackground()

	return nil
}

// initializeInBackground performs slow initialization tasks without blocking server startup.
func (m *Manager) initializeInBackground() {
	defer close(m.initDone)

	// Build bloom filter from stored domains (can be slow with large lists)
	if err := m.rebuildBloomFilter(); err != nil {
		log.Printf("[blocklist] Failed to build bloom filter: %v", err)
	}

	// Start scheduler
	m.scheduler = NewScheduler(m)
	m.scheduler.Start()

	m.mu.Lock()
	m.ready = true
	var count uint64
	if m.bloom != nil {
		count = m.bloom.Count()
	}
	m.mu.Unlock()

	log.Printf("[blocklist] Initialization complete (bloom filter: %d entries)", count)
}

// Stop stops the blocklist manager.
func (m *Manager) Stop() {
	if m.scheduler != nil {
		m.scheduler.Stop()
	}
}

// IsReady returns true if the blocklist manager has finished initialization.
func (m *Manager) IsReady() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ready
}

// WaitReady blocks until the blocklist manager is fully initialized.
func (m *Manager) WaitReady() {
	<-m.initDone
}

// Check returns true if the domain should be blocked.
func (m *Manager) Check(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.config.Enabled {
		return false
	}

	// If not yet initialized, allow all traffic (fail open)
	if !m.ready {
		return false
	}

	// Normalize domain
	domain = normalizeDomain(domain)

	// Check whitelist first
	if m.isWhitelisted(domain) {
		m.totalAllowed++
		return false
	}

	// Check bloom filter (fast path)
	if m.bloom == nil || !m.bloom.MayContain(domain) {
		// Also check parent domains for wildcard blocking
		if !m.checkParentDomains(domain) {
			m.totalAllowed++
			return false
		}
	}

	// Bloom filter says maybe blocked - verify in storage
	blocked, err := m.store.IsBlocked(domain)
	if err != nil {
		log.Printf("[blocklist] Storage check error for %s: %v", domain, err)
		return false
	}

	if blocked {
		m.totalBlocked++
		if m.config.LogBlocked {
			log.Printf("[blocklist] BLOCKED: %s", domain)
		}
		return true
	}

	// Check parent domains (for wildcard-style blocking)
	if m.checkParentDomainsStorage(domain) {
		m.totalBlocked++
		if m.config.LogBlocked {
			log.Printf("[blocklist] BLOCKED (parent): %s", domain)
		}
		return true
	}

	m.totalAllowed++
	return false
}

// checkParentDomains checks if any parent domain is in the bloom filter.
func (m *Manager) checkParentDomains(domain string) bool {
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if m.bloom != nil && m.bloom.MayContain(parent) {
			return true
		}
	}
	return false
}

// checkParentDomainsStorage verifies parent domains in storage.
func (m *Manager) checkParentDomainsStorage(domain string) bool {
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if blocked, _ := m.store.IsBlocked(parent); blocked {
			return true
		}
	}
	return false
}

// isWhitelisted checks if domain matches whitelist.
func (m *Manager) isWhitelisted(domain string) bool {
	// Exact match
	if m.whitelist[domain] {
		return true
	}

	// Wildcard match (check parent domains)
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := "*." + strings.Join(parts[i:], ".")
		if m.whitelist[parent] {
			return true
		}
	}

	return false
}

// addToWhitelist adds a domain to the whitelist.
func (m *Manager) addToWhitelist(entry string) {
	entry = normalizeDomain(entry)
	m.whitelist[entry] = true
}

// GetConfig returns the current configuration.
func (m *Manager) GetConfig() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// SetConfig updates the configuration.
func (m *Manager) SetConfig(cfg *Config) error {
	m.mu.Lock()
	m.config = cfg
	m.mu.Unlock()

	return m.store.SaveBlocklistConfig(cfg)
}

// GetSources returns all configured sources.
func (m *Manager) GetSources() []*Source {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Source, 0, len(m.sources))
	for _, s := range m.sources {
		result = append(result, s)
	}
	return result
}

// GetSource returns a source by ID.
func (m *Manager) GetSource(id string) *Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sources[id]
}

// UpdateSource updates an existing blocklist source.
func (m *Manager) UpdateSource(source *Source) error {
	m.mu.Lock()
	m.sources[source.ID] = source
	m.mu.Unlock()

	return m.store.SaveBlocklistSource(source)
}

// AddSource adds a new blocklist source.
func (m *Manager) AddSource(source *Source) error {
	m.mu.Lock()
	m.sources[source.ID] = source
	m.mu.Unlock()

	if err := m.store.SaveBlocklistSource(source); err != nil {
		return err
	}

	// Trigger immediate update if enabled
	if source.Enabled && m.scheduler != nil {
		go m.scheduler.UpdateSource(source.ID)
	}

	return nil
}

// RemoveSource removes a blocklist source.
func (m *Manager) RemoveSource(id string) error {
	m.mu.Lock()
	delete(m.sources, id)
	m.mu.Unlock()

	// Remove stored domains for this source
	if err := m.store.RemoveBlockedDomainsForSource(id); err != nil {
		log.Printf("[blocklist] Failed to remove domains for source %s: %v", id, err)
	}

	// Rebuild bloom filter
	if err := m.rebuildBloomFilter(); err != nil {
		log.Printf("[blocklist] Failed to rebuild bloom filter: %v", err)
	}

	return m.store.DeleteBlocklistSource(id)
}

// GetWhitelist returns the current whitelist.
func (m *Manager) GetWhitelist() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0, len(m.whitelist))
	for domain := range m.whitelist {
		result = append(result, domain)
	}
	return result
}

// SetWhitelist replaces the whitelist.
func (m *Manager) SetWhitelist(entries []string) error {
	m.mu.Lock()
	m.whitelist = make(map[string]bool)
	for _, e := range entries {
		m.addToWhitelist(e)
	}
	m.mu.Unlock()

	return m.store.SaveBlocklistWhitelist(entries)
}

// AddToWhitelist adds domains to the whitelist.
func (m *Manager) AddToWhitelist(domains ...string) error {
	m.mu.Lock()
	for _, d := range domains {
		m.addToWhitelist(d)
	}
	whitelist := make([]string, 0, len(m.whitelist))
	for d := range m.whitelist {
		whitelist = append(whitelist, d)
	}
	m.mu.Unlock()

	return m.store.SaveBlocklistWhitelist(whitelist)
}

// RemoveFromWhitelist removes domains from the whitelist.
func (m *Manager) RemoveFromWhitelist(domains ...string) error {
	m.mu.Lock()
	for _, d := range domains {
		d = normalizeDomain(d)
		delete(m.whitelist, d)
	}
	whitelist := make([]string, 0, len(m.whitelist))
	for d := range m.whitelist {
		whitelist = append(whitelist, d)
	}
	m.mu.Unlock()

	return m.store.SaveBlocklistWhitelist(whitelist)
}

// GetStats returns blocklist statistics.
func (m *Manager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sourceStats := make([]map[string]interface{}, 0, len(m.sources))
	for _, s := range m.sources {
		sourceStats = append(sourceStats, map[string]interface{}{
			"id":             s.ID,
			"name":           s.Name,
			"enabled":        s.Enabled,
			"entry_count":    s.EntryCount,
			"last_update":    s.LastUpdate,
			"last_error":     s.LastError,
			"update_minutes": s.UpdateMinutes,
		})
	}

	count, _ := m.store.GetBlockedDomainCount()

	return map[string]interface{}{
		"enabled":         m.config.Enabled,
		"total_domains":   count,
		"bloom_count":     m.bloom.Count(),
		"total_blocked":   m.totalBlocked,
		"total_allowed":   m.totalAllowed,
		"whitelist_count": len(m.whitelist),
		"sources":         sourceStats,
	}
}

// ForceUpdate triggers an immediate update of all sources.
func (m *Manager) ForceUpdate() {
	if m.scheduler != nil {
		m.scheduler.UpdateAll()
	}
}

// ForceUpdateSource triggers an immediate update of a specific source.
func (m *Manager) ForceUpdateSource(sourceID string) error {
	m.mu.RLock()
	_, exists := m.sources[sourceID]
	m.mu.RUnlock()

	if !exists {
		return ErrSourceNotFound
	}

	if m.scheduler != nil {
		go m.scheduler.UpdateSource(sourceID)
	}
	return nil
}

// rebuildBloomFilter rebuilds the bloom filter from storage.
func (m *Manager) rebuildBloomFilter() error {
	domains, err := m.store.GetAllBlockedDomains()
	if err != nil {
		return err
	}

	// Create bloom filter sized for the domain count (with 1% false positive rate)
	size := len(domains)
	if size < 10000 {
		size = 10000 // Minimum size
	}

	m.bloom = NewBloomFilter(size, 0.01)
	for _, d := range domains {
		m.bloom.Add(d)
	}

	m.lastUpdateTime = time.Now()
	return nil
}

// UpdateSourceDomains updates the domains for a source after download.
func (m *Manager) UpdateSourceDomains(sourceID string, domains []string) error {
	// Remove old domains for this source
	if err := m.store.RemoveBlockedDomainsForSource(sourceID); err != nil {
		return err
	}

	// Add new domains
	if err := m.store.AddBlockedDomains(sourceID, domains); err != nil {
		return err
	}

	// Update source stats
	m.mu.Lock()
	if source, ok := m.sources[sourceID]; ok {
		source.EntryCount = len(domains)
		source.LastUpdate = time.Now()
		source.LastError = ""
		source.ErrorCount = 0
		m.store.SaveBlocklistSource(source)
	}
	m.mu.Unlock()

	// Rebuild bloom filter
	return m.rebuildBloomFilter()
}

// SetSourceError records an error for a source.
func (m *Manager) SetSourceError(sourceID string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if source, ok := m.sources[sourceID]; ok {
		source.LastError = err.Error()
		source.ErrorCount++
		m.store.SaveBlocklistSource(source)
	}
}

// GetResponse returns the configured block response type.
func (m *Manager) GetResponse() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.Response
}

// GetRedirectIP returns the redirect IP if configured.
func (m *Manager) GetRedirectIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.RedirectIP
}

// normalizeDomain normalizes a domain name for comparison.
func normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

// Errors
var (
	ErrSourceNotFound = &BlocklistError{Message: "source not found"}
	ErrSourceExists   = &BlocklistError{Message: "source already exists"}
)

// BlocklistError represents a blocklist-specific error.
type BlocklistError struct {
	Message string
}

func (e *BlocklistError) Error() string {
	return e.Message
}
