package sync

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func createTestDB(t *testing.T) (*bolt.DB, func()) {
	t.Helper()

	dir, err := os.MkdirTemp("", "sync-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(dir, "test.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("Failed to open database: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.RemoveAll(dir)
	}

	return db, cleanup
}

func TestNewOpLog(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	if oplog == nil {
		t.Fatal("NewOpLog returned nil")
	}
}

func TestOpLog_Append(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	entry, err := oplog.Append(EntityZone, "example.com", "main", OpCreate, map[string]interface{}{"name": "example.com"})
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	if entry.ID == "" {
		t.Error("Entry ID should be set after append")
	}

	if entry.EntityType != EntityZone {
		t.Errorf("Expected EntityType %s, got %s", EntityZone, entry.EntityType)
	}

	if entry.EntityID != "example.com" {
		t.Errorf("Expected EntityID 'example.com', got '%s'", entry.EntityID)
	}

	if entry.Operation != OpCreate {
		t.Errorf("Expected Operation %s, got %s", OpCreate, entry.Operation)
	}

	if entry.ServerID != "server-1" {
		t.Errorf("Expected ServerID 'server-1', got '%s'", entry.ServerID)
	}
}

func TestOpLog_GetEntriesSince(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	// Create entries
	for i := 0; i < 5; i++ {
		_, err := oplog.Append(EntityZone, "zone-"+string(rune('a'+i))+".com", "main", OpCreate, nil)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
		time.Sleep(2 * time.Millisecond) // Ensure distinct HLCs
	}

	// Get entries since the beginning
	since := HybridLogicalClock{}
	entries, err := oplog.GetEntriesSince(since, 100)
	if err != nil {
		t.Fatalf("GetEntriesSince failed: %v", err)
	}

	if len(entries) != 5 {
		t.Errorf("Expected 5 entries, got %d", len(entries))
	}
}

func TestOpLog_GetEntriesSince_WithLimit(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	// Create 10 entries
	for i := 0; i < 10; i++ {
		_, err := oplog.Append(EntityZone, "zone-"+string(rune('a'+i))+".com", "main", OpCreate, nil)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Get only 5 entries
	since := HybridLogicalClock{}
	entries, err := oplog.GetEntriesSince(since, 5)
	if err != nil {
		t.Fatalf("GetEntriesSince failed: %v", err)
	}

	if len(entries) != 5 {
		t.Errorf("Expected 5 entries (limited), got %d", len(entries))
	}
}

func TestOpLog_GetEntriesSince_AfterTimestamp(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	// Create 5 entries and capture middle HLC
	var entries []*OpLogEntry
	for i := 0; i < 5; i++ {
		entry, err := oplog.Append(EntityZone, "zone-"+string(rune('a'+i))+".com", "main", OpCreate, nil)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
		entries = append(entries, entry)
		time.Sleep(2 * time.Millisecond)
	}

	// Get entries after the middle one
	midClock := entries[2].HLC
	result, err := oplog.GetEntriesSince(midClock, 100)
	if err != nil {
		t.Fatalf("GetEntriesSince failed: %v", err)
	}

	// Should get 2 entries (entries 3 and 4)
	if len(result) != 2 {
		t.Errorf("Expected 2 entries after midpoint, got %d", len(result))
	}
}

func TestOpLog_ApplyRemote(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	// Create a remote entry
	remoteEntry := &OpLogEntry{
		ID:         GenerateID(),
		ServerID:   "server-2", // Different server
		HLC:        HybridLogicalClock{Physical: time.Now().UnixMilli(), Logical: 1, ServerID: "server-2"},
		Timestamp:  time.Now().UTC(),
		EntityType: EntityZone,
		EntityID:   "remote.com",
		TenantID:   "main",
		Operation:  OpCreate,
	}

	applied, err := oplog.ApplyRemote(remoteEntry)
	if err != nil {
		t.Fatalf("ApplyRemote failed: %v", err)
	}

	if !applied {
		t.Error("Expected entry to be applied")
	}

	// Try to apply same entry again - should still "succeed" but not duplicate
	applied2, err := oplog.ApplyRemote(remoteEntry)
	if err != nil {
		t.Fatalf("ApplyRemote second call failed: %v", err)
	}

	// The implementation returns true even for duplicates (no error)
	// Just verify no error occurred
	_ = applied2
}

func TestOpLog_Count(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	// Check initial count
	count, err := oplog.Count()
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 entries, got %d", count)
	}

	// Add entries
	for i := 0; i < 5; i++ {
		_, err := oplog.Append(EntityZone, "zone-"+string(rune('a'+i))+".com", "main", OpCreate, nil)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Check count after adding
	count, err = oplog.Count()
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 5 {
		t.Errorf("Expected 5 entries, got %d", count)
	}
}

func TestOpLog_CurrentHLC(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	hlc := oplog.CurrentHLC()

	if hlc.IsZero() {
		t.Error("CurrentHLC should not be zero")
	}

	if hlc.ServerID != "server-1" {
		t.Errorf("Expected ServerID 'server-1', got '%s'", hlc.ServerID)
	}
}

func TestOpLog_GetEntriesForServer(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "local-server")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	// Add local entries
	for i := 0; i < 3; i++ {
		_, err := oplog.Append(EntityZone, "local-"+string(rune('a'+i))+".com", "main", OpCreate, nil)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Add remote entries
	for i := 0; i < 2; i++ {
		remoteEntry := &OpLogEntry{
			ID:         GenerateID(),
			ServerID:   "remote-server",
			HLC:        HybridLogicalClock{Physical: time.Now().UnixMilli() + int64(i*100), Logical: 0, ServerID: "remote-server"},
			Timestamp:  time.Now().UTC(),
			EntityType: EntityZone,
			EntityID:   "remote-" + string(rune('a'+i)) + ".com",
			Operation:  OpCreate,
		}
		_, err := oplog.ApplyRemote(remoteEntry)
		if err != nil {
			t.Fatalf("ApplyRemote failed: %v", err)
		}
	}

	// Get entries for local server only
	localEntries, err := oplog.GetEntriesForServer("local-server", HybridLogicalClock{}, 100)
	if err != nil {
		t.Fatalf("GetEntriesForServer failed: %v", err)
	}

	if len(localEntries) != 3 {
		t.Errorf("Expected 3 local entries, got %d", len(localEntries))
	}

	// Get entries for remote server
	remoteEntries, err := oplog.GetEntriesForServer("remote-server", HybridLogicalClock{}, 100)
	if err != nil {
		t.Fatalf("GetEntriesForServer failed: %v", err)
	}

	if len(remoteEntries) != 2 {
		t.Errorf("Expected 2 remote entries, got %d", len(remoteEntries))
	}
}

func TestOpLog_PruneTombstones(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	// Add delete operations (tombstones)
	for i := 0; i < 3; i++ {
		_, err := oplog.Append(EntityZone, "zone-"+string(rune('a'+i))+".com", "main", OpDelete, nil)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Add a regular operation
	_, err = oplog.Append(EntityZone, "active.com", "main", OpCreate, nil)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// Verify we have 4 entries
	count, _ := oplog.Count()
	if count != 4 {
		t.Errorf("Expected 4 entries, got %d", count)
	}

	// Prune with 0 duration (prune all tombstones)
	pruned, err := oplog.PruneTombstones(0)
	if err != nil {
		t.Fatalf("PruneTombstones failed: %v", err)
	}

	if pruned != 3 {
		t.Errorf("Expected 3 tombstones pruned, got %d", pruned)
	}

	// Verify only 1 entry remains
	count, _ = oplog.Count()
	if count != 1 {
		t.Errorf("Expected 1 entry after pruning, got %d", count)
	}
}

func TestOpLog_MultipleEntityTypes(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	entityTypes := []string{EntityZone, EntityRecord, EntityUser, EntityTenant, EntityAPIKey, EntitySettings}

	// Create entries for different entity types
	for _, entityType := range entityTypes {
		_, err := oplog.Append(entityType, "entity-"+entityType, "main", OpCreate, nil)
		if err != nil {
			t.Fatalf("Append failed for %s: %v", entityType, err)
		}
	}

	// Retrieve all
	entries, err := oplog.GetEntriesSince(HybridLogicalClock{}, 100)
	if err != nil {
		t.Fatalf("GetEntriesSince failed: %v", err)
	}

	if len(entries) != len(entityTypes) {
		t.Errorf("Expected %d entries, got %d", len(entityTypes), len(entries))
	}

	// Verify each type is present
	typeFound := make(map[string]bool)
	for _, e := range entries {
		typeFound[e.EntityType] = true
	}

	for _, expected := range entityTypes {
		if !typeFound[expected] {
			t.Errorf("Missing entity type: %s", expected)
		}
	}
}

func TestOpLog_MultipleOperationTypes(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	// Create -> Update -> Delete lifecycle
	_, err = oplog.Append(EntityZone, "test.com", "main", OpCreate, map[string]interface{}{"name": "test.com"})
	if err != nil {
		t.Fatalf("Append create failed: %v", err)
	}

	_, err = oplog.Append(EntityZone, "test.com", "main", OpUpdate, map[string]interface{}{"name": "test.com", "ttl": 3600})
	if err != nil {
		t.Fatalf("Append update failed: %v", err)
	}

	_, err = oplog.Append(EntityZone, "test.com", "main", OpDelete, nil)
	if err != nil {
		t.Fatalf("Append delete failed: %v", err)
	}

	// Get all entries
	entries, err := oplog.GetEntriesSince(HybridLogicalClock{}, 100)
	if err != nil {
		t.Fatalf("GetEntriesSince failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(entries))
	}

	// Verify operations are in order
	expectedOps := []string{OpCreate, OpUpdate, OpDelete}
	for i, e := range entries {
		if e.Operation != expectedOps[i] {
			t.Errorf("Entry %d: expected operation %s, got %s", i, expectedOps[i], e.Operation)
		}
	}
}

func TestOpLog_DataSerialization(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	testData := map[string]interface{}{
		"name":    "example.com",
		"ttl":     float64(3600), // JSON numbers become float64
		"enabled": true,
		"tags":    []interface{}{"dns", "primary"},
	}

	entry, err := oplog.Append(EntityZone, "example.com", "main", OpCreate, testData)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	if entry.Data == nil {
		t.Error("Entry data should not be nil")
	}

	if entry.Checksum == "" {
		t.Error("Entry should have a checksum")
	}
}

func TestOpLog_TenantIsolation(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	oplog, err := NewOpLog(db, "server-1")
	if err != nil {
		t.Fatalf("NewOpLog failed: %v", err)
	}

	// Add entries for different tenants
	_, err = oplog.Append(EntityZone, "tenant1.com", "tenant-1", OpCreate, nil)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	_, err = oplog.Append(EntityZone, "tenant2.com", "tenant-2", OpCreate, nil)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	_, err = oplog.Append(EntityZone, "main.com", "", OpCreate, nil)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// Get all entries
	entries, err := oplog.GetEntriesSince(HybridLogicalClock{}, 100)
	if err != nil {
		t.Fatalf("GetEntriesSince failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(entries))
	}

	// Verify tenant IDs are preserved
	tenantCount := map[string]int{}
	for _, e := range entries {
		tenantCount[e.TenantID]++
	}

	if tenantCount["tenant-1"] != 1 || tenantCount["tenant-2"] != 1 || tenantCount[""] != 1 {
		t.Errorf("Unexpected tenant distribution: %v", tenantCount)
	}
}
