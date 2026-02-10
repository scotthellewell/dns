package blocklist

import (
	"time"
)

// CompositeStore combines main storage (for synced config/sources/whitelist)
// with blocklist storage (for domain entries only).
type CompositeStore struct {
	// Main storage for config, sources, whitelist (synced across cluster)
	main MainStorage
	// Blocklist storage for domain entries only (local, not synced)
	domains DomainStorage
}

// MainStorage interface for the main database operations (synced)
type MainStorage interface {
	GetBlocklistConfig() (*MainConfig, error)
	SaveBlocklistConfig(config *MainConfig) error
	GetBlocklistSources() ([]*MainSource, error)
	GetBlocklistSource(id string) (*MainSource, error)
	SaveBlocklistSource(source *MainSource) error
	DeleteBlocklistSource(id string) error
	GetBlocklistWhitelist() ([]string, error)
	SaveBlocklistWhitelist(entries []string) error
}

// DomainStorage interface for domain entries only (not synced)
type DomainStorage interface {
	AddBlockedDomains(sourceID string, domains []string) error
	RemoveBlockedDomainsForSource(sourceID string) error
	IsBlocked(domain string) (bool, error)
	GetAllBlockedDomains() ([]string, error)
	GetBlockedDomainCount() (int, error)
}

// MainConfig mirrors storage.BlocklistConfig - must have same JSON tags
type MainConfig struct {
	Enabled    bool   `json:"enabled"`
	Response   string `json:"response"`
	RedirectIP string `json:"redirect_ip,omitempty"`
	LogBlocked bool   `json:"log_blocked"`
}

// MainSource mirrors storage.BlocklistSource - must have same JSON tags
type MainSource struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Format        string    `json:"format"`
	Enabled       bool      `json:"enabled"`
	UpdateMinutes int       `json:"update_minutes"`
	LastUpdate    time.Time `json:"last_update"`
	LastETag      string    `json:"last_etag,omitempty"`
	EntryCount    int       `json:"entry_count"`
	LastError     string    `json:"last_error,omitempty"`
	ErrorCount    int       `json:"error_count"`
}

// NewCompositeStore creates a composite store that uses main storage for
// config/sources/whitelist and domain storage for blocked domains.
func NewCompositeStore(main MainStorage, domains DomainStorage) *CompositeStore {
	return &CompositeStore{
		main:    main,
		domains: domains,
	}
}

// GetBlocklistConfig retrieves config from main storage (synced).
func (c *CompositeStore) GetBlocklistConfig() (*Config, error) {
	cfg, err := c.main.GetBlocklistConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &Config{
		Enabled:    cfg.Enabled,
		Response:   cfg.Response,
		RedirectIP: cfg.RedirectIP,
		LogBlocked: cfg.LogBlocked,
	}, nil
}

// SaveBlocklistConfig saves config to main storage (synced).
func (c *CompositeStore) SaveBlocklistConfig(config *Config) error {
	return c.main.SaveBlocklistConfig(&MainConfig{
		Enabled:    config.Enabled,
		Response:   config.Response,
		RedirectIP: config.RedirectIP,
		LogBlocked: config.LogBlocked,
	})
}

// GetBlocklistSources retrieves sources from main storage (synced).
func (c *CompositeStore) GetBlocklistSources() ([]*Source, error) {
	sources, err := c.main.GetBlocklistSources()
	if err != nil {
		return nil, err
	}
	result := make([]*Source, 0, len(sources))
	for _, s := range sources {
		result = append(result, &Source{
			ID:            s.ID,
			Name:          s.Name,
			URL:           s.URL,
			Format:        s.Format,
			Enabled:       s.Enabled,
			UpdateMinutes: s.UpdateMinutes,
			LastUpdate:    s.LastUpdate,
			LastETag:      s.LastETag,
			EntryCount:    s.EntryCount,
			LastError:     s.LastError,
			ErrorCount:    s.ErrorCount,
		})
	}
	return result, nil
}

// SaveBlocklistSource saves source to main storage (synced).
func (c *CompositeStore) SaveBlocklistSource(source *Source) error {
	return c.main.SaveBlocklistSource(&MainSource{
		ID:            source.ID,
		Name:          source.Name,
		URL:           source.URL,
		Format:        source.Format,
		Enabled:       source.Enabled,
		UpdateMinutes: source.UpdateMinutes,
		LastUpdate:    source.LastUpdate,
		LastETag:      source.LastETag,
		EntryCount:    source.EntryCount,
		LastError:     source.LastError,
		ErrorCount:    source.ErrorCount,
	})
}

// DeleteBlocklistSource deletes source from main storage (synced).
func (c *CompositeStore) DeleteBlocklistSource(id string) error {
	return c.main.DeleteBlocklistSource(id)
}

// GetBlocklistWhitelist retrieves whitelist from main storage (synced).
func (c *CompositeStore) GetBlocklistWhitelist() ([]string, error) {
	return c.main.GetBlocklistWhitelist()
}

// SaveBlocklistWhitelist saves whitelist to main storage (synced).
func (c *CompositeStore) SaveBlocklistWhitelist(entries []string) error {
	return c.main.SaveBlocklistWhitelist(entries)
}

// AddBlockedDomains adds domains to domain storage (local only, not synced).
func (c *CompositeStore) AddBlockedDomains(sourceID string, domains []string) error {
	return c.domains.AddBlockedDomains(sourceID, domains)
}

// RemoveBlockedDomainsForSource removes domains from domain storage (local only).
func (c *CompositeStore) RemoveBlockedDomainsForSource(sourceID string) error {
	return c.domains.RemoveBlockedDomainsForSource(sourceID)
}

// IsBlocked checks if domain is blocked in domain storage.
func (c *CompositeStore) IsBlocked(domain string) (bool, error) {
	return c.domains.IsBlocked(domain)
}

// GetAllBlockedDomains returns all blocked domains from domain storage.
func (c *CompositeStore) GetAllBlockedDomains() ([]string, error) {
	return c.domains.GetAllBlockedDomains()
}

// GetBlockedDomainCount returns count from domain storage.
func (c *CompositeStore) GetBlockedDomainCount() (int, error) {
	return c.domains.GetBlockedDomainCount()
}
