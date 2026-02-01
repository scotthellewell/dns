package storage

import (
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// CreateAPIKey creates a new API key.
func (s *Store) CreateAPIKey(apiKey *APIKey) error {
	if apiKey.ID == "" {
		apiKey.ID = GenerateID()
	}
	if apiKey.Name == "" {
		return fmt.Errorf("API key name required")
	}
	if apiKey.KeyHash == "" {
		return fmt.Errorf("API key hash required")
	}
	if apiKey.TenantID == "" {
		return fmt.Errorf("tenant ID required")
	}

	apiKey.CreatedAt = time.Now().UTC()

	err := s.db.Update(func(tx *bolt.Tx) error {
		// Check tenant exists
		if tx.Bucket(BucketTenants).Get([]byte(apiKey.TenantID)) == nil {
			return fmt.Errorf("tenant not found")
		}

		return putJSON(tx, BucketAPIKeys, apiKey.ID, apiKey)
	})

	if err == nil {
		// Record change for sync (exclude key hash from sync data)
		syncKey := *apiKey
		syncKey.KeyHash = ""
		recordChange(EntityTypeAPIKey, apiKey.ID, apiKey.TenantID, OpCreate, &syncKey)
	}

	return err
}

// GetAPIKey retrieves an API key by ID.
func (s *Store) GetAPIKey(id string) (*APIKey, error) {
	var apiKey APIKey
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx, BucketAPIKeys, id, &apiKey)
	})
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

// GetAPIKeyByHash retrieves an API key by its hash.
func (s *Store) GetAPIKeyByHash(hash string) (*APIKey, error) {
	var found *APIKey

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAPIKeys)
		if b == nil {
			return ErrNotFound
		}

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var apiKey APIKey
			if err := unmarshalJSON(v, &apiKey); err == nil {
				if apiKey.KeyHash == hash {
					// Check expiry
					if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
						return ErrNotFound
					}
					found = &apiKey
					return nil
				}
			}
		}
		return ErrNotFound
	})

	if err != nil {
		return nil, err
	}
	return found, nil
}

// UpdateAPIKey updates an existing API key.
func (s *Store) UpdateAPIKey(apiKey *APIKey) error {
	if apiKey.ID == "" {
		return fmt.Errorf("API key ID required")
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAPIKeys)
		if b.Get([]byte(apiKey.ID)) == nil {
			return ErrNotFound
		}

		return putJSON(tx, BucketAPIKeys, apiKey.ID, apiKey)
	})

	if err == nil {
		syncKey := *apiKey
		syncKey.KeyHash = ""
		recordChange(EntityTypeAPIKey, apiKey.ID, apiKey.TenantID, OpUpdate, &syncKey)
	}

	return err
}

// UpdateAPIKeyLastUsed updates the last used timestamp for an API key.
func (s *Store) UpdateAPIKeyLastUsed(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var apiKey APIKey
		if err := getJSON(tx, BucketAPIKeys, id, &apiKey); err != nil {
			return err
		}

		now := time.Now().UTC()
		apiKey.LastUsed = &now
		return putJSON(tx, BucketAPIKeys, id, &apiKey)
	})
}

// DeleteAPIKey deletes an API key.
func (s *Store) DeleteAPIKey(id string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAPIKeys)
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}

		return delete(tx, BucketAPIKeys, id)
	})

	if err == nil {
		recordChange(EntityTypeAPIKey, id, "", OpDelete, nil)
	}

	return err
}

// ListAPIKeys returns all API keys, optionally filtered by tenant.
func (s *Store) ListAPIKeys(tenantID string) ([]*APIKey, error) {
	var apiKeys []*APIKey

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAPIKeys)
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var apiKey APIKey
			if err := unmarshalJSON(v, &apiKey); err != nil {
				return err
			}
			if tenantID == "" || apiKey.TenantID == tenantID {
				// Don't return the hash
				apiKey.KeyHash = ""
				apiKeys = append(apiKeys, &apiKey)
			}
			return nil
		})
	})

	return apiKeys, err
}

// ValidateAPIKey validates an API key and returns the key info if valid.
func (s *Store) ValidateAPIKey(key string) (*APIKey, error) {
	hash := HashAPIKey(key)
	apiKey, err := s.GetAPIKeyByHash(hash)
	if err != nil {
		return nil, ErrUnauthorized
	}

	// Update last used
	s.UpdateAPIKeyLastUsed(apiKey.ID)

	return apiKey, nil
}

// CleanupExpiredAPIKeys removes expired API keys.
func (s *Store) CleanupExpiredAPIKeys() (int, error) {
	count := 0

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAPIKeys)
		if b == nil {
			return nil
		}

		now := time.Now()
		c := b.Cursor()
		var toDelete [][]byte

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var apiKey APIKey
			if err := unmarshalJSON(v, &apiKey); err == nil {
				if apiKey.ExpiresAt != nil && now.After(*apiKey.ExpiresAt) {
					toDelete = append(toDelete, k)
				}
			}
		}

		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
			count++
		}

		return nil
	})

	return count, err
}

// HasPermission checks if an API key has a specific permission.
func (apiKey *APIKey) HasPermission(perm string) bool {
	for _, p := range apiKey.Permissions {
		if p == perm || p == "admin" {
			return true
		}
	}
	return false
}
