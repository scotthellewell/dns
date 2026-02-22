package blocklist

import (
	"time"
)


// StorageStore is the interface for the actual storage package.
type StorageStore interface {
	GetBlocklistConfig() (*StorageConfig, error)
	SaveBlocklistConfig(config *StorageConfig) error
	GetBlocklistSources() ([]*StorageSource, error)
	SaveBlocklistSource(source *StorageSource) error
	DeleteBlocklistSource(id string) error
	GetBlocklistWhitelist() ([]string, error)
	SaveBlocklistWhitelist(entries []string) error
	AddBlockedDomains(sourceID string, domains []string) error
	RemoveBlockedDomainsForSource(sourceID string) error
	IsBlocked(domain string) (bool, error)
	GetAllBlockedDomains() ([]string, error)
	GetBlockedDomainCount() (int, error)
}

// StorageConfig mirrors storage.BlocklistConfig
type StorageConfig struct {
	Enabled    bool   `json:"enabled"`
	Response   string `json:"response"`
	RedirectIP string `json:"redirect_ip,omitempty"`
	LogBlocked bool   `json:"log_blocked"`
}

// StorageSource mirrors storage.BlocklistSource
type StorageSource struct {
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

// NewStoreAdapter creates a new adapter for the storage package.
func NewStoreAdapter(store StorageStore) *StoreAdapterImpl {
	return &StoreAdapterImpl{store: store}
}

// StoreAdapterImpl implements the Store interface using storage.Store.
type StoreAdapterImpl struct {
	store StorageStore
}

// GetBlocklistConfig retrieves the blocklist configuration.
func (a *StoreAdapterImpl) GetBlocklistConfig() (*Config, error) {
	cfg, err := a.store.GetBlocklistConfig()
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

// SaveBlocklistConfig saves the blocklist configuration.
func (a *StoreAdapterImpl) SaveBlocklistConfig(config *Config) error {
	return a.store.SaveBlocklistConfig(&StorageConfig{
		Enabled:    config.Enabled,
		Response:   config.Response,
		RedirectIP: config.RedirectIP,
		LogBlocked: config.LogBlocked,
	})
}

// GetBlocklistSources retrieves all blocklist sources.
func (a *StoreAdapterImpl) GetBlocklistSources() ([]*Source, error) {
	sources, err := a.store.GetBlocklistSources()
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

// SaveBlocklistSource saves a blocklist source.
func (a *StoreAdapterImpl) SaveBlocklistSource(source *Source) error {
	return a.store.SaveBlocklistSource(&StorageSource{
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

// DeleteBlocklistSource deletes a blocklist source.
func (a *StoreAdapterImpl) DeleteBlocklistSource(id string) error {
	return a.store.DeleteBlocklistSource(id)
}

// GetBlocklistWhitelist retrieves the blocklist whitelist.
func (a *StoreAdapterImpl) GetBlocklistWhitelist() ([]string, error) {
	return a.store.GetBlocklistWhitelist()
}

// SaveBlocklistWhitelist saves the blocklist whitelist.
func (a *StoreAdapterImpl) SaveBlocklistWhitelist(entries []string) error {
	return a.store.SaveBlocklistWhitelist(entries)
}

// AddBlockedDomains adds blocked domains for a source.
func (a *StoreAdapterImpl) AddBlockedDomains(sourceID string, domains []string) error {
	return a.store.AddBlockedDomains(sourceID, domains)
}

// RemoveBlockedDomainsForSource removes all blocked domains for a specific source.
func (a *StoreAdapterImpl) RemoveBlockedDomainsForSource(sourceID string) error {
	return a.store.RemoveBlockedDomainsForSource(sourceID)
}

// IsBlocked checks if a domain is blocked.
func (a *StoreAdapterImpl) IsBlocked(domain string) (bool, error) {
	return a.store.IsBlocked(domain)
}

// GetAllBlockedDomains returns all blocked domains.
func (a *StoreAdapterImpl) GetAllBlockedDomains() ([]string, error) {
	return a.store.GetAllBlockedDomains()
}

// GetBlockedDomainCount returns the count of blocked domains.
func (a *StoreAdapterImpl) GetBlockedDomainCount() (int, error) {
	return a.store.GetBlockedDomainCount()
}
