package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// CreateAuditEntry creates a new audit log entry.
func (s *Store) CreateAuditEntry(entry *AuditEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketAudit)
		if bucket == nil {
			return fmt.Errorf("audit bucket not found")
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}

		// Use timestamp + id as key for chronological ordering
		key := fmt.Sprintf("%s:%s", entry.Timestamp.Format(time.RFC3339Nano), entry.ID)
		return bucket.Put([]byte(key), data)
	})
}

// ListAuditEntries returns audit entries, optionally filtered by resource or user.
func (s *Store) ListAuditEntries(limit int, resource, userID string) ([]*AuditEntry, error) {
	var entries []*AuditEntry

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketAudit)
		if bucket == nil {
			return nil
		}

		// Iterate in reverse order (newest first)
		c := bucket.Cursor()
		for k, v := c.Last(); k != nil && len(entries) < limit; k, v = c.Prev() {
			var entry AuditEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				continue
			}

			// Apply filters
			if resource != "" && entry.Resource != resource {
				continue
			}
			if userID != "" && entry.UserID != userID {
				continue
			}

			entries = append(entries, &entry)
		}

		return nil
	})

	return entries, err
}

// GetAuditEntry returns a single audit entry by ID.
func (s *Store) GetAuditEntry(id string) (*AuditEntry, error) {
	var entry *AuditEntry

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketAudit)
		if bucket == nil {
			return ErrNotFound
		}

		// We need to scan since ID is part of the key but not the full key
		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var e AuditEntry
			if err := json.Unmarshal(v, &e); err != nil {
				continue
			}
			if e.ID == id {
				entry = &e
				return nil
			}
		}

		return ErrNotFound
	})

	return entry, err
}

// PruneAuditEntries removes audit entries older than the specified duration.
func (s *Store) PruneAuditEntries(olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)
	deleted := 0

	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketAudit)
		if bucket == nil {
			return nil
		}

		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var entry AuditEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				continue
			}

			if entry.Timestamp.Before(cutoff) {
				if err := bucket.Delete(k); err != nil {
					return err
				}
				deleted++
			}
		}

		return nil
	})

	return deleted, err
}

// AuditAction constants for common actions.
const (
	AuditActionCreate = "create"
	AuditActionUpdate = "update"
	AuditActionDelete = "delete"
)

// AuditResource constants for resource types.
const (
	AuditResourceZone          = "zone"
	AuditResourceRecord        = "record"
	AuditResourceSecondaryZone = "secondary_zone"
	AuditResourceUser          = "user"
	AuditResourceAPIKey        = "api_key"
	AuditResourceConfig        = "config"
)

// LogZoneChange logs an audit entry for zone changes.
func (s *Store) LogZoneChange(userID, username, tenantID, action, zoneName string, before, after *Zone, ipAddress string) error {
	entry := &AuditEntry{
		UserID:     userID,
		Username:   username,
		TenantID:   tenantID,
		Action:     action,
		Resource:   AuditResourceZone,
		ResourceID: zoneName,
		IPAddress:  ipAddress,
	}

	if before != nil {
		data, _ := json.Marshal(before)
		entry.Before = data
	}
	if after != nil {
		data, _ := json.Marshal(after)
		entry.After = data
	}

	return s.CreateAuditEntry(entry)
}

// LogRecordChange logs an audit entry for record changes.
func (s *Store) LogRecordChange(userID, username, tenantID, action, recordID string, before, after *Record, ipAddress string) error {
	entry := &AuditEntry{
		UserID:     userID,
		Username:   username,
		TenantID:   tenantID,
		Action:     action,
		Resource:   AuditResourceRecord,
		ResourceID: recordID,
		IPAddress:  ipAddress,
	}

	if before != nil {
		data, _ := json.Marshal(before)
		entry.Before = data
	}
	if after != nil {
		data, _ := json.Marshal(after)
		entry.After = data
	}

	return s.CreateAuditEntry(entry)
}

// LogConfigChange logs an audit entry for configuration changes.
func (s *Store) LogConfigChange(userID, username, action, configKey string, before, after interface{}, ipAddress string) error {
	entry := &AuditEntry{
		UserID:     userID,
		Username:   username,
		Action:     action,
		Resource:   AuditResourceConfig,
		ResourceID: configKey,
		IPAddress:  ipAddress,
	}

	if before != nil {
		data, _ := json.Marshal(before)
		entry.Before = data
	}
	if after != nil {
		data, _ := json.Marshal(after)
		entry.After = data
	}

	return s.CreateAuditEntry(entry)
}
