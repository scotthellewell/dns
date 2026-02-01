package storage

import (
	bolt "go.etcd.io/bbolt"
)

// GetSetting retrieves a setting value by key
func (s *Store) GetSetting(key string) (string, error) {
	var value string

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketSettings)
		if b == nil {
			return ErrNotFound
		}

		data := b.Get([]byte(key))
		if data == nil {
			return ErrNotFound
		}

		value = string(data)
		return nil
	})

	return value, err
}

// SetSetting stores a setting value by key
func (s *Store) SetSetting(key, value string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketSettings)
		if b == nil {
			return ErrNotFound
		}

		return b.Put([]byte(key), []byte(value))
	})

	if err == nil {
		recordChange(EntityTypeSettings, key, "", OpUpdate, map[string]string{"key": key, "value": value})
	}

	return err
}

// DeleteSetting removes a setting by key
func (s *Store) DeleteSetting(key string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketSettings)
		if b == nil {
			return nil
		}

		return b.Delete([]byte(key))
	})

	if err == nil {
		recordChange(EntityTypeSettings, key, "", OpDelete, nil)
	}

	return err
}

// ListSettings returns all settings as a map
func (s *Store) ListSettings() (map[string]string, error) {
	settings := make(map[string]string)

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketSettings)
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			settings[string(k)] = string(v)
			return nil
		})
	})

	return settings, err
}
