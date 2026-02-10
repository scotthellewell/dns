package storage

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ============================================================================
// Blocklist Storage - implements blocklist.Store interface
// ============================================================================

// BlocklistConfig holds blocklist configuration.
type BlocklistConfig struct {
	Enabled    bool   `json:"enabled"`
	Response   string `json:"response"`
	RedirectIP string `json:"redirect_ip,omitempty"`
	LogBlocked bool   `json:"log_blocked"`
}

// BlocklistSource represents a blocklist source.
type BlocklistSource struct {
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

// GetBlocklistConfig retrieves the blocklist configuration.
func (s *Store) GetBlocklistConfig() (*BlocklistConfig, error) {
	var config BlocklistConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistConfig)
		if bucket == nil {
			return nil
		}
		data := bucket.Get([]byte("config"))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &config)
	})
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// SaveBlocklistConfig saves the blocklist configuration.
func (s *Store) SaveBlocklistConfig(config *BlocklistConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistConfig)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return bucket.Put([]byte("config"), data)
	})
}

// GetBlocklistSources retrieves all blocklist sources.
func (s *Store) GetBlocklistSources() ([]*BlocklistSource, error) {
	var sources []*BlocklistSource
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistSources)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			var source BlocklistSource
			if err := json.Unmarshal(v, &source); err != nil {
				return nil // Skip invalid entries
			}
			sources = append(sources, &source)
			return nil
		})
	})
	return sources, err
}

// GetBlocklistSource retrieves a specific blocklist source.
func (s *Store) GetBlocklistSource(id string) (*BlocklistSource, error) {
	var source BlocklistSource
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistSources)
		if bucket == nil {
			return ErrNotFound
		}
		data := bucket.Get([]byte(id))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &source)
	})
	if err != nil {
		return nil, err
	}
	return &source, nil
}

// SaveBlocklistSource saves a blocklist source.
func (s *Store) SaveBlocklistSource(source *BlocklistSource) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistSources)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		data, err := json.Marshal(source)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(source.ID), data)
	})
}

// DeleteBlocklistSource deletes a blocklist source.
func (s *Store) DeleteBlocklistSource(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistSources)
		if bucket == nil {
			return ErrNotFound
		}
		if bucket.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return bucket.Delete([]byte(id))
	})
}

// GetBlocklistWhitelist retrieves the blocklist whitelist.
func (s *Store) GetBlocklistWhitelist() ([]string, error) {
	var whitelist []string
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistWhitelist)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, _ []byte) error {
			whitelist = append(whitelist, string(k))
			return nil
		})
	})
	return whitelist, err
}

// SaveBlocklistWhitelist saves the blocklist whitelist.
func (s *Store) SaveBlocklistWhitelist(entries []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistWhitelist)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		// Clear existing entries
		c := bucket.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}

		// Add new entries
		for _, entry := range entries {
			if err := bucket.Put([]byte(entry), []byte("1")); err != nil {
				return err
			}
		}
		return nil
	})
}

// AddBlockedDomains adds blocked domains for a source.
// Domains are stored with the source ID prefix for easy removal.
func (s *Store) AddBlockedDomains(sourceID string, domains []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistDomains)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		for _, domain := range domains {
			// Key format: domain -> sourceID (allows multiple sources to reference same domain)
			key := []byte(domain)
			existing := bucket.Get(key)
			if existing != nil {
				// Domain already exists from another source, update source list
				var sources []string
				if err := json.Unmarshal(existing, &sources); err != nil {
					sources = []string{}
				}
				// Check if source already in list
				found := false
				for _, s := range sources {
					if s == sourceID {
						found = true
						break
					}
				}
				if !found {
					sources = append(sources, sourceID)
					data, _ := json.Marshal(sources)
					if err := bucket.Put(key, data); err != nil {
						return err
					}
				}
			} else {
				// New domain
				data, _ := json.Marshal([]string{sourceID})
				if err := bucket.Put(key, data); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// RemoveBlockedDomainsForSource removes all blocked domains for a specific source.
func (s *Store) RemoveBlockedDomainsForSource(sourceID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistDomains)
		if bucket == nil {
			return nil
		}

		var toDelete [][]byte
		var toUpdate []struct {
			key     []byte
			sources []string
		}

		err := bucket.ForEach(func(k, v []byte) error {
			var sources []string
			if err := json.Unmarshal(v, &sources); err != nil {
				return nil
			}

			// Filter out this source
			newSources := make([]string, 0)
			for _, s := range sources {
				if s != sourceID {
					newSources = append(newSources, s)
				}
			}

			if len(newSources) == 0 {
				// No more sources reference this domain
				toDelete = append(toDelete, append([]byte{}, k...))
			} else if len(newSources) != len(sources) {
				// Sources changed
				toUpdate = append(toUpdate, struct {
					key     []byte
					sources []string
				}{
					key:     append([]byte{}, k...),
					sources: newSources,
				})
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Delete domains with no more sources
		for _, k := range toDelete {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}

		// Update domains with remaining sources
		for _, item := range toUpdate {
			data, _ := json.Marshal(item.sources)
			if err := bucket.Put(item.key, data); err != nil {
				return err
			}
		}

		return nil
	})
}

// IsBlocked checks if a domain is blocked.
func (s *Store) IsBlocked(domain string) (bool, error) {
	var blocked bool
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistDomains)
		if bucket == nil {
			return nil
		}
		data := bucket.Get([]byte(domain))
		blocked = data != nil
		return nil
	})
	return blocked, err
}

// GetAllBlockedDomains returns all blocked domains.
func (s *Store) GetAllBlockedDomains() ([]string, error) {
	var domains []string
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistDomains)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, _ []byte) error {
			domains = append(domains, string(k))
			return nil
		})
	})
	return domains, err
}

// GetBlockedDomainCount returns the count of blocked domains.
func (s *Store) GetBlockedDomainCount() (int, error) {
	var count int
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklistDomains)
		if bucket == nil {
			return nil
		}
		count = bucket.Stats().KeyN
		return nil
	})
	return count, err
}
