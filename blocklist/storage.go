package blocklist

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

// Bucket names for blocklist database
var (
	bucketConfig    = []byte("blocklist_config")
	bucketSources   = []byte("blocklist_sources")
	bucketDomains   = []byte("blocklist_domains")
	bucketWhitelist = []byte("blocklist_whitelist")
)

// BlocklistStore is a dedicated storage for blocklist data using a separate bbolt database.
// This prevents blocklist operations from blocking the main DNS server database.
type BlocklistStore struct {
	db     *bolt.DB
	dbPath string
}

// NewBlocklistStore creates a new blocklist store with its own database file.
func NewBlocklistStore(dataDir string) (*BlocklistStore, error) {
	dbPath := filepath.Join(dataDir, "blocklist.db")
	
	// Ensure directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Open database with options optimized for blocklist operations
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{
		Timeout:      0, // Don't timeout on open
		NoGrowSync:   false,
		FreelistType: bolt.FreelistArrayType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open blocklist database: %w", err)
	}

	// Create buckets
	err = db.Update(func(tx *bolt.Tx) error {
		buckets := [][]byte{bucketConfig, bucketSources, bucketDomains, bucketWhitelist}
		for _, b := range buckets {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return fmt.Errorf("failed to create bucket %s: %w", string(b), err)
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	log.Printf("[blocklist-store] Opened database: %s", dbPath)
	return &BlocklistStore{db: db, dbPath: dbPath}, nil
}

// Close closes the blocklist database.
func (s *BlocklistStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetBlocklistConfig retrieves the blocklist configuration.
func (s *BlocklistStore) GetBlocklistConfig() (*Config, error) {
	var config Config
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketConfig)
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
	if config.Response == "" {
		return nil, nil // No config stored yet
	}
	return &config, nil
}

// SaveBlocklistConfig saves the blocklist configuration.
func (s *BlocklistStore) SaveBlocklistConfig(config *Config) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketConfig)
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
func (s *BlocklistStore) GetBlocklistSources() ([]*Source, error) {
	var sources []*Source
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketSources)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			var source Source
			if err := json.Unmarshal(v, &source); err != nil {
				return nil // Skip invalid entries
			}
			sources = append(sources, &source)
			return nil
		})
	})
	return sources, err
}

// SaveBlocklistSource saves a blocklist source.
func (s *BlocklistStore) SaveBlocklistSource(source *Source) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketSources)
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
func (s *BlocklistStore) DeleteBlocklistSource(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketSources)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		return bucket.Delete([]byte(id))
	})
}

// GetBlocklistWhitelist retrieves the blocklist whitelist.
func (s *BlocklistStore) GetBlocklistWhitelist() ([]string, error) {
	var whitelist []string
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketWhitelist)
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
func (s *BlocklistStore) SaveBlocklistWhitelist(entries []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketWhitelist)
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
func (s *BlocklistStore) AddBlockedDomains(sourceID string, domains []string) error {
	// Use batched writes for better performance with large lists
	batchSize := 10000
	for i := 0; i < len(domains); i += batchSize {
		end := i + batchSize
		if end > len(domains) {
			end = len(domains)
		}
		batch := domains[i:end]

		err := s.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(bucketDomains)
			if bucket == nil {
				return fmt.Errorf("bucket not found")
			}

			for _, domain := range batch {
				key := []byte(domain)
				existing := bucket.Get(key)
				if existing != nil {
					// Domain already exists, add source to list
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
		if err != nil {
			return err
		}
	}
	return nil
}

// RemoveBlockedDomainsForSource removes all domains associated with a source.
func (s *BlocklistStore) RemoveBlockedDomainsForSource(sourceID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketDomains)
		if bucket == nil {
			return nil
		}

		var toDelete [][]byte
		var toUpdate []struct {
			key  []byte
			data []byte
		}

		err := bucket.ForEach(func(k, v []byte) error {
			var sources []string
			if err := json.Unmarshal(v, &sources); err != nil {
				return nil
			}

			// Remove this source from the list
			newSources := make([]string, 0, len(sources))
			for _, s := range sources {
				if s != sourceID {
					newSources = append(newSources, s)
				}
			}

			if len(newSources) == 0 {
				// No more sources reference this domain, delete it
				toDelete = append(toDelete, append([]byte{}, k...))
			} else if len(newSources) != len(sources) {
				// Update the sources list
				data, _ := json.Marshal(newSources)
				toUpdate = append(toUpdate, struct {
					key  []byte
					data []byte
				}{append([]byte{}, k...), data})
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Apply deletes
		for _, k := range toDelete {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}

		// Apply updates
		for _, u := range toUpdate {
			if err := bucket.Put(u.key, u.data); err != nil {
				return err
			}
		}

		return nil
	})
}

// IsBlocked checks if a domain is in the blocklist.
func (s *BlocklistStore) IsBlocked(domain string) (bool, error) {
	var blocked bool
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketDomains)
		if bucket == nil {
			return nil
		}
		data := bucket.Get([]byte(domain))
		blocked = data != nil
		return nil
	})
	return blocked, err
}

// GetAllBlockedDomains retrieves all blocked domains.
func (s *BlocklistStore) GetAllBlockedDomains() ([]string, error) {
	var domains []string
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketDomains)
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

// GetBlockedDomainCount returns the number of blocked domains.
func (s *BlocklistStore) GetBlockedDomainCount() (int, error) {
	var count int
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketDomains)
		if bucket == nil {
			return nil
		}
		count = bucket.Stats().KeyN
		return nil
	})
	return count, err
}
