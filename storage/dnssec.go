package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// GetDNSSECKeys retrieves DNSSEC keys for a zone.
func (s *Store) GetDNSSECKeys(zoneName string) (*DNSSECKeys, error) {
	var keys DNSSECKeys

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("dnssec_keys"))
		data := bucket.Get([]byte(zoneName))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &keys)
	})

	return &keys, err
}

// SaveDNSSECKeys saves DNSSEC keys for a zone.
func (s *Store) SaveDNSSECKeys(keys *DNSSECKeys) error {
	if keys.ZoneName == "" {
		return fmt.Errorf("zone name required")
	}

	keys.UpdatedAt = time.Now()
	if keys.CreatedAt.IsZero() {
		keys.CreatedAt = keys.UpdatedAt
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("dnssec_keys"))
		data, err := json.Marshal(keys)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(keys.ZoneName), data)
	})

	if err == nil {
		// Record change for sync
		recordChange(EntityTypeDNSSECKeys, keys.ZoneName, "", OpUpdate, keys)
	}

	return err
}

// DeleteDNSSECKeys deletes DNSSEC keys for a zone.
func (s *Store) DeleteDNSSECKeys(zoneName string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("dnssec_keys"))
		return bucket.Delete([]byte(zoneName))
	})

	if err == nil {
		// Record change for sync
		recordChange(EntityTypeDNSSECKeys, zoneName, "", OpDelete, nil)
	}

	return err
}

// ListZonesWithDNSSEC lists all zones that have DNSSEC enabled.
func (s *Store) ListZonesWithDNSSEC() ([]string, error) {
	var zones []string

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("dnssec_keys"))

		return bucket.ForEach(func(k, v []byte) error {
			var keys DNSSECKeys
			if err := json.Unmarshal(v, &keys); err != nil {
				return err
			}
			if keys.Enabled {
				zones = append(zones, string(k))
			}
			return nil
		})
	})

	return zones, err
}

// EnableDNSSEC enables DNSSEC for a zone with the given algorithm.
// If keys don't exist, creates new ones.
func (s *Store) EnableDNSSEC(zoneName string, algorithm string, kskBits, zskBits int) (*DNSSECKeys, error) {
	// Check if zone exists
	zone, err := s.GetZone(zoneName)
	if err != nil {
		return nil, fmt.Errorf("zone not found: %w", err)
	}
	if zone == nil {
		return nil, fmt.Errorf("zone %s not found", zoneName)
	}

	keys, err := s.GetDNSSECKeys(zoneName)
	if err == ErrNotFound {
		// Create new keys structure
		keys = &DNSSECKeys{
			ZoneName:  zoneName,
			Algorithm: algorithm,
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	} else if err != nil {
		return nil, err
	}

	keys.Enabled = true
	keys.Algorithm = algorithm
	keys.UpdatedAt = time.Now()

	// Note: Actual key generation would happen at a higher layer
	// This just sets up the configuration

	if err := s.SaveDNSSECKeys(keys); err != nil {
		return nil, err
	}

	return keys, nil
}

// DisableDNSSEC disables DNSSEC for a zone (keeps keys for potential re-enable).
func (s *Store) DisableDNSSEC(zoneName string) error {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return err
	}

	keys.Enabled = false
	keys.UpdatedAt = time.Now()

	return s.SaveDNSSECKeys(keys)
}

// UpdateKSK updates the Key Signing Key for a zone.
func (s *Store) UpdateKSK(zoneName string, privateKey, publicKey string, keyTag uint16) error {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return err
	}

	keys.KSKPrivate = privateKey
	keys.KSKPublic = publicKey
	keys.KSKKeyTag = keyTag
	keys.KSKCreated = time.Now()
	keys.UpdatedAt = time.Now()

	return s.SaveDNSSECKeys(keys)
}

// UpdateZSK updates the Zone Signing Key for a zone.
func (s *Store) UpdateZSK(zoneName string, privateKey, publicKey string, keyTag uint16) error {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return err
	}

	keys.ZSKPrivate = privateKey
	keys.ZSKPublic = publicKey
	keys.ZSKKeyTag = keyTag
	keys.ZSKCreated = time.Now()
	keys.UpdatedAt = time.Now()

	return s.SaveDNSSECKeys(keys)
}

// GetDSRecord returns the DS record data for a zone.
func (s *Store) GetDSRecord(zoneName string) (*DSRecordData, error) {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return nil, err
	}

	if keys.DSRecord == "" {
		return nil, ErrNotFound
	}

	// Parse the stored DS record
	// Format: "keyTag algorithm digestType digest"
	var ds DSRecordData
	_, err = fmt.Sscanf(keys.DSRecord, "%d %d %d %s",
		&ds.KeyTag, &ds.Algorithm, &ds.DigestType, &ds.Digest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DS record: %w", err)
	}

	return &ds, nil
}

// UpdateDSRecord updates the DS record for a zone.
func (s *Store) UpdateDSRecord(zoneName string, ds *DSRecordData) error {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return err
	}

	keys.DSRecord = fmt.Sprintf("%d %d %d %s",
		ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
	keys.UpdatedAt = time.Now()

	return s.SaveDNSSECKeys(keys)
}

// RotateZSK marks the current ZSK for rotation.
// The actual rotation process would be handled by a higher-level service.
func (s *Store) RotateZSK(zoneName string) error {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return err
	}

	// Store current ZSK as previous for rollover period
	keys.PreviousZSKPrivate = keys.ZSKPrivate
	keys.PreviousZSKPublic = keys.ZSKPublic
	keys.PreviousZSKKeyTag = keys.ZSKKeyTag
	keys.UpdatedAt = time.Now()

	return s.SaveDNSSECKeys(keys)
}

// ClearPreviousZSK removes the previous ZSK after rollover is complete.
func (s *Store) ClearPreviousZSK(zoneName string) error {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return err
	}

	keys.PreviousZSKPrivate = ""
	keys.PreviousZSKPublic = ""
	keys.PreviousZSKKeyTag = 0
	keys.UpdatedAt = time.Now()

	return s.SaveDNSSECKeys(keys)
}

// GetAllDNSSECKeys retrieves all DNSSEC keys for backup purposes.
func (s *Store) GetAllDNSSECKeys() ([]DNSSECKeys, error) {
	var allKeys []DNSSECKeys

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("dnssec_keys"))

		return bucket.ForEach(func(k, v []byte) error {
			var keys DNSSECKeys
			if err := json.Unmarshal(v, &keys); err != nil {
				return err
			}
			allKeys = append(allKeys, keys)
			return nil
		})
	})

	return allKeys, err
}

// ImportDNSSECKeys imports DNSSEC keys (for restore from backup).
func (s *Store) ImportDNSSECKeys(keys *DNSSECKeys) error {
	return s.SaveDNSSECKeys(keys)
}

// GenerateKeyToken creates a new random token for DNSSEC key sharing.
func (s *Store) GenerateKeyToken(zoneName string) (string, error) {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return "", err
	}

	// Generate a 32-byte random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	keys.KeyToken = token
	keys.UpdatedAt = time.Now()

	if err := s.SaveDNSSECKeys(keys); err != nil {
		return "", err
	}

	return token, nil
}

// ValidateKeyToken checks if a token is valid for the given zone.
func (s *Store) ValidateKeyToken(zoneName, token string) (bool, error) {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return false, err
	}

	if keys.KeyToken == "" || token == "" {
		return false, nil
	}

	return keys.KeyToken == token, nil
}

// RevokeKeyToken removes the key token for a zone.
func (s *Store) RevokeKeyToken(zoneName string) error {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return err
	}

	keys.KeyToken = ""
	keys.UpdatedAt = time.Now()

	return s.SaveDNSSECKeys(keys)
}

// CheckKSKRotationAdvisory checks if KSK rotation is recommended.
// Returns true if the KSK is older than the threshold (default 1 year).
func (s *Store) CheckKSKRotationAdvisory(zoneName string, threshold time.Duration) (bool, error) {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return false, err
	}

	if keys.KSKCreated.IsZero() {
		return false, nil
	}

	isDue := time.Since(keys.KSKCreated) > threshold

	// Update the advisory flag if it changed
	if keys.KSKRotationDue != isDue {
		keys.KSKRotationDue = isDue
		keys.UpdatedAt = time.Now()
		_ = s.SaveDNSSECKeys(keys) // Best effort update
	}

	return isDue, nil
}

// SetKSKRotationDue manually sets/clears the KSK rotation advisory.
func (s *Store) SetKSKRotationDue(zoneName string, due bool) error {
	keys, err := s.GetDNSSECKeys(zoneName)
	if err != nil {
		return err
	}

	keys.KSKRotationDue = due
	keys.UpdatedAt = time.Now()

	return s.SaveDNSSECKeys(keys)
}
