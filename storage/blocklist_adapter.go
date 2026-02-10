package storage

import (
	"github.com/scott/dns/blocklist"
)

// BlocklistMainStorageAdapter adapts storage.Store to blocklist.MainStorage interface
type BlocklistMainStorageAdapter struct {
	store *Store
}

// NewBlocklistMainStorageAdapter creates an adapter for blocklist main storage
func NewBlocklistMainStorageAdapter(store *Store) *BlocklistMainStorageAdapter {
	return &BlocklistMainStorageAdapter{store: store}
}

// GetBlocklistConfig adapts storage.BlocklistConfig to blocklist.MainConfig
func (a *BlocklistMainStorageAdapter) GetBlocklistConfig() (*blocklist.MainConfig, error) {
	cfg, err := a.store.GetBlocklistConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &blocklist.MainConfig{
		Enabled:    cfg.Enabled,
		Response:   cfg.Response,
		RedirectIP: cfg.RedirectIP,
		LogBlocked: cfg.LogBlocked,
	}, nil
}

// SaveBlocklistConfig adapts blocklist.MainConfig to storage.BlocklistConfig
func (a *BlocklistMainStorageAdapter) SaveBlocklistConfig(config *blocklist.MainConfig) error {
	return a.store.SaveBlocklistConfig(&BlocklistConfig{
		Enabled:    config.Enabled,
		Response:   config.Response,
		RedirectIP: config.RedirectIP,
		LogBlocked: config.LogBlocked,
	})
}

// GetBlocklistSources adapts storage.BlocklistSource to blocklist.MainSource
func (a *BlocklistMainStorageAdapter) GetBlocklistSources() ([]*blocklist.MainSource, error) {
	sources, err := a.store.GetBlocklistSources()
	if err != nil {
		return nil, err
	}
	result := make([]*blocklist.MainSource, 0, len(sources))
	for _, s := range sources {
		result = append(result, &blocklist.MainSource{
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

// GetBlocklistSource adapts storage.BlocklistSource to blocklist.MainSource
func (a *BlocklistMainStorageAdapter) GetBlocklistSource(id string) (*blocklist.MainSource, error) {
	s, err := a.store.GetBlocklistSource(id)
	if err != nil {
		return nil, err
	}
	return &blocklist.MainSource{
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
	}, nil
}

// SaveBlocklistSource adapts blocklist.MainSource to storage.BlocklistSource
func (a *BlocklistMainStorageAdapter) SaveBlocklistSource(source *blocklist.MainSource) error {
	return a.store.SaveBlocklistSource(&BlocklistSource{
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

// DeleteBlocklistSource delegates to storage
func (a *BlocklistMainStorageAdapter) DeleteBlocklistSource(id string) error {
	return a.store.DeleteBlocklistSource(id)
}

// GetBlocklistWhitelist delegates to storage
func (a *BlocklistMainStorageAdapter) GetBlocklistWhitelist() ([]string, error) {
	return a.store.GetBlocklistWhitelist()
}

// SaveBlocklistWhitelist delegates to storage
func (a *BlocklistMainStorageAdapter) SaveBlocklistWhitelist(entries []string) error {
	return a.store.SaveBlocklistWhitelist(entries)
}
