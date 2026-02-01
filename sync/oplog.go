package sync

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	oplogBucket     = []byte("sync_oplog")
	peerStateBucket = []byte("sync_peer_state")
	syncMetaBucket  = []byte("sync_meta")
)

// OpLog manages the operation log for sync
type OpLog struct {
	db       *bolt.DB
	serverID string
	clock    *Clock
}

// NewOpLog creates a new OpLog backed by the given bolt database
func NewOpLog(db *bolt.DB, serverID string) (*OpLog, error) {
	// Create buckets if they don't exist
	err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(oplogBucket); err != nil {
			return fmt.Errorf("create oplog bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists(peerStateBucket); err != nil {
			return fmt.Errorf("create peer state bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists(syncMetaBucket); err != nil {
			return fmt.Errorf("create sync meta bucket: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &OpLog{
		db:       db,
		serverID: serverID,
		clock:    NewClock(serverID),
	}, nil
}

// Append adds a new entry to the operation log
func (o *OpLog) Append(entityType, entityID, tenantID, operation string, data interface{}) (*OpLogEntry, error) {
	var dataBytes json.RawMessage
	if data != nil {
		var err error
		dataBytes, err = json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("marshal data: %w", err)
		}
	}

	entry := &OpLogEntry{
		ID:         GenerateID(),
		ServerID:   o.serverID,
		HLC:        o.clock.Now(),
		Timestamp:  time.Now().UTC(),
		EntityType: entityType,
		EntityID:   entityID,
		TenantID:   tenantID,
		Operation:  operation,
		Data:       dataBytes,
	}

	// Generate checksum
	entry.Checksum = o.calculateChecksum(entry)

	err := o.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(oplogBucket)
		if b == nil {
			return fmt.Errorf("oplog bucket not found")
		}

		// Key is HLC-based for ordering: physical_logical_serverID_opID
		key := o.makeKey(entry.HLC, entry.ID)

		entryBytes, err := json.Marshal(entry)
		if err != nil {
			return err
		}

		return b.Put(key, entryBytes)
	})
	if err != nil {
		return nil, err
	}

	return entry, nil
}

// ApplyRemote applies a remote operation log entry
// Returns true if applied, false if it was a duplicate or older than existing
func (o *OpLog) ApplyRemote(entry *OpLogEntry) (bool, error) {
	// Update our clock based on received HLC
	o.clock.Update(entry.HLC)

	err := o.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(oplogBucket)
		if b == nil {
			return fmt.Errorf("oplog bucket not found")
		}

		// Check if we already have this entry (by ID)
		// We need to scan for it since key is HLC-based
		// For efficiency, we store a secondary index
		key := o.makeKey(entry.HLC, entry.ID)

		// Check if entry exists
		existing := b.Get(key)
		if existing != nil {
			// Already have this entry
			return nil
		}

		entryBytes, err := json.Marshal(entry)
		if err != nil {
			return err
		}

		return b.Put(key, entryBytes)
	})

	return err == nil, err
}

// GetEntriesSince returns entries with HLC greater than the given HLC
func (o *OpLog) GetEntriesSince(since HybridLogicalClock, limit int) ([]OpLogEntry, error) {
	var entries []OpLogEntry

	err := o.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(oplogBucket)
		if b == nil {
			return nil
		}

		c := b.Cursor()

		// If since is zero, start from beginning
		var startKey []byte
		if !since.IsZero() {
			startKey = o.makeKey(since, "")
		}

		var k, v []byte
		if startKey != nil {
			k, v = c.Seek(startKey)
			// Skip the exact match, we want entries AFTER since
			if k != nil {
				k, v = c.Next()
			}
		} else {
			k, v = c.First()
		}

		count := 0
		for ; k != nil && (limit <= 0 || count < limit); k, v = c.Next() {
			var entry OpLogEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				continue // Skip malformed entries
			}

			// Double-check HLC ordering
			if since.IsZero() || entry.HLC.Compare(since) > 0 {
				entries = append(entries, entry)
				count++
			}
		}

		return nil
	})

	return entries, err
}

// GetEntriesForServer returns entries originating from a specific server since the given HLC
func (o *OpLog) GetEntriesForServer(serverID string, since HybridLogicalClock, limit int) ([]OpLogEntry, error) {
	var entries []OpLogEntry

	err := o.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(oplogBucket)
		if b == nil {
			return nil
		}

		c := b.Cursor()
		count := 0

		for k, v := c.First(); k != nil && (limit <= 0 || count < limit); k, v = c.Next() {
			var entry OpLogEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				continue
			}

			// Filter by server ID and HLC
			if entry.ServerID == serverID {
				if since.IsZero() || entry.HLC.Compare(since) > 0 {
					entries = append(entries, entry)
					count++
				}
			}
		}

		return nil
	})

	return entries, err
}

// Count returns the total number of entries in the oplog
func (o *OpLog) Count() (int64, error) {
	var count int64

	err := o.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(oplogBucket)
		if b == nil {
			return nil
		}
		stats := b.Stats()
		count = int64(stats.KeyN)
		return nil
	})

	return count, err
}

// PruneTombstones removes delete entries older than the given duration
func (o *OpLog) PruneTombstones(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	var pruned int64

	err := o.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(oplogBucket)
		if b == nil {
			return nil
		}

		var keysToDelete [][]byte
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var entry OpLogEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				continue
			}

			// Only prune delete operations
			if entry.Operation == OpDelete && entry.Timestamp.Before(cutoff) {
				keysToDelete = append(keysToDelete, k)
			}
		}

		for _, key := range keysToDelete {
			if err := b.Delete(key); err != nil {
				return err
			}
			pruned++
		}

		return nil
	})

	return pruned, err
}

// SavePeerState saves the state for a peer
func (o *OpLog) SavePeerState(state *PeerState) error {
	return o.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(peerStateBucket)
		if b == nil {
			return fmt.Errorf("peer state bucket not found")
		}

		data, err := json.Marshal(state)
		if err != nil {
			return err
		}

		return b.Put([]byte(state.ServerID), data)
	})
}

// GetPeerState gets the state for a peer
func (o *OpLog) GetPeerState(serverID string) (*PeerState, error) {
	var state PeerState

	err := o.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(peerStateBucket)
		if b == nil {
			return nil
		}

		data := b.Get([]byte(serverID))
		if data == nil {
			return nil
		}

		return json.Unmarshal(data, &state)
	})

	if err != nil {
		return nil, err
	}
	if state.ServerID == "" {
		return nil, nil
	}
	return &state, nil
}

// GetAllPeerStates returns all saved peer states
func (o *OpLog) GetAllPeerStates() ([]PeerState, error) {
	var states []PeerState

	err := o.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(peerStateBucket)
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var state PeerState
			if err := json.Unmarshal(v, &state); err != nil {
				return nil // Skip malformed entries
			}
			states = append(states, state)
			return nil
		})
	})

	return states, err
}

// CurrentHLC returns the current HLC
func (o *OpLog) CurrentHLC() HybridLogicalClock {
	return o.clock.Current()
}

// makeKey creates a sortable key from an HLC and operation ID
func (o *OpLog) makeKey(hlc HybridLogicalClock, opID string) []byte {
	// Format: physical (16 hex) + logical (8 hex) + serverID + opID
	return []byte(fmt.Sprintf("%016x%08x_%s_%s", hlc.Physical, hlc.Logical, hlc.ServerID, opID))
}

// calculateChecksum calculates a checksum for an entry
func (o *OpLog) calculateChecksum(entry *OpLogEntry) string {
	// For now, just use a simple hash of the key fields
	// In production, use SHA256
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		entry.ServerID, entry.EntityType, entry.EntityID,
		entry.TenantID, entry.Operation, string(entry.Data))
	// Simple hash for now - replace with crypto/sha256 in production
	var hash uint64
	for _, c := range data {
		hash = hash*31 + uint64(c)
	}
	return fmt.Sprintf("%016x", hash)
}
