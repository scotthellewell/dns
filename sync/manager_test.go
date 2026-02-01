package sync

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	config := &Config{
		Enabled:      true,
		ServerID:     "test-server-1",
		ServerName:   "Test Server",
		SharedSecret: "test-secret",
		Peers: []PeerConfig{
			{URL: "wss://peer.example.com:9443/sync"},
		},
	}

	manager, err := NewManager(db, config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if manager == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestManager_GetServerID(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	config := &Config{
		Enabled:      true,
		ServerID:     "my-unique-server",
		SharedSecret: "secret",
		Peers:        []PeerConfig{{URL: "wss://peer:9443/sync"}},
	}

	manager, err := NewManager(db, config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	status := manager.Status()
	if status.ServerID != "my-unique-server" {
		t.Errorf("Expected 'my-unique-server', got '%s'", status.ServerID)
	}
}

func TestManager_AutoGenerateServerID(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	config := &Config{
		Enabled:      true,
		ServerID:     "", // Empty, should be auto-generated
		SharedSecret: "secret",
		Peers:        []PeerConfig{{URL: "wss://peer:9443/sync"}},
	}

	manager, err := NewManager(db, config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	status := manager.Status()
	if status.ServerID == "" {
		t.Error("ServerID should be auto-generated when empty")
	}
}

func TestManager_RecordChange(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	config := &Config{
		Enabled:      true,
		ServerID:     "test-server",
		SharedSecret: "secret",
		Peers:        []PeerConfig{{URL: "wss://peer:9443/sync"}},
	}

	manager, err := NewManager(db, config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Record a change
	err = manager.RecordChange(EntityZone, "example.com", "tenant1", OpCreate, map[string]interface{}{
		"name": "example.com",
	})
	if err != nil {
		t.Fatalf("RecordChange failed: %v", err)
	}

	// Verify entry was created
	status := manager.Status()
	if status.OpLogEntries != 1 {
		t.Errorf("Expected 1 oplog entry, got %d", status.OpLogEntries)
	}
}

func TestManager_RecordChange_Disabled(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	config := &Config{
		Enabled:  false, // Sync disabled
		ServerID: "test-server",
	}

	manager, err := NewManager(db, config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Record a change - should be a no-op
	err = manager.RecordChange(EntityZone, "example.com", "tenant1", OpCreate, nil)
	if err != nil {
		t.Fatalf("RecordChange failed: %v", err)
	}

	// No entries should be recorded when disabled
	status := manager.Status()
	if status.OpLogEntries != 0 {
		t.Errorf("Expected 0 oplog entries when disabled, got %d", status.OpLogEntries)
	}
}

func TestManager_RecordChange_MultipleOperations(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	config := &Config{
		Enabled:      true,
		ServerID:     "test-server",
		SharedSecret: "secret",
		Peers:        []PeerConfig{{URL: "wss://peer:9443/sync"}},
	}

	manager, err := NewManager(db, config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Record multiple changes
	operations := []struct {
		entityType string
		entityID   string
		operation  string
	}{
		{EntityZone, "zone1.com", OpCreate},
		{EntityZone, "zone2.com", OpCreate},
		{EntityRecord, "record1", OpCreate},
		{EntityZone, "zone1.com", OpUpdate},
		{EntityRecord, "record1", OpDelete},
	}

	for _, op := range operations {
		err := manager.RecordChange(op.entityType, op.entityID, "tenant1", op.operation, nil)
		if err != nil {
			t.Fatalf("RecordChange failed for %s/%s: %v", op.entityType, op.entityID, err)
		}
	}

	status := manager.Status()
	if status.OpLogEntries != int64(len(operations)) {
		t.Errorf("Expected %d oplog entries, got %d", len(operations), status.OpLogEntries)
	}
}

func TestManager_Status(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	config := &Config{
		Enabled:      true,
		ServerID:     "status-test-server",
		ServerName:   "Status Test",
		SharedSecret: "secret",
		Peers:        []PeerConfig{{URL: "wss://peer:9443/sync"}},
	}

	manager, err := NewManager(db, config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	status := manager.Status()

	if status.ServerID != "status-test-server" {
		t.Errorf("Expected ServerID 'status-test-server', got '%s'", status.ServerID)
	}

	if status.ServerName != "Status Test" {
		t.Errorf("Expected ServerName 'Status Test', got '%s'", status.ServerName)
	}

	if !status.Enabled {
		t.Error("Expected Enabled to be true")
	}

	if status.CurrentHLC.IsZero() {
		t.Error("CurrentHLC should not be zero")
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
	}{
		{
			name: "valid enabled config",
			config: Config{
				Enabled:      true,
				ServerID:     "server-1",
				SharedSecret: "secret-key",
				Peers:        []PeerConfig{{URL: "wss://peer:9443/sync"}},
			},
			expectError: false,
		},
		{
			name: "disabled config - always valid",
			config: Config{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing shared secret",
			config: Config{
				Enabled:      true,
				ServerID:     "server-1",
				SharedSecret: "",
				Peers:        []PeerConfig{{URL: "wss://peer:9443/sync"}},
			},
			expectError: true,
		},
		{
			name: "missing peers",
			config: Config{
				Enabled:      true,
				ServerID:     "server-1",
				SharedSecret: "secret",
				Peers:        []PeerConfig{},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("Expected validation error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("Default config should have Enabled=false")
	}

	if cfg.TombstoneRetention != 7*24*time.Hour {
		t.Errorf("Expected 7 days tombstone retention, got %v", cfg.TombstoneRetention)
	}

	if cfg.BatchSize != 1000 {
		t.Errorf("Expected BatchSize 1000, got %d", cfg.BatchSize)
	}

	if cfg.ReconnectInterval != 5*time.Second {
		t.Errorf("Expected ReconnectInterval 5s, got %v", cfg.ReconnectInterval)
	}

	if cfg.PingInterval != 30*time.Second {
		t.Errorf("Expected PingInterval 30s, got %v", cfg.PingInterval)
	}
}

func TestMessage_Serialization(t *testing.T) {
	payload := HelloPayload{
		ServerID:        "server-1",
		ServerName:      "Test Server",
		CurrentHLC:      HybridLogicalClock{Physical: 123456789, Logical: 5, ServerID: "server-1"},
		IsNew:           true,
		ProtocolVersion: ProtocolVersion,
		AuthToken:       "test-token",
		AuthTimestamp:   time.Now().Unix(),
	}

	msg, err := NewMessage(MsgHello, payload)
	if err != nil {
		t.Fatalf("NewMessage failed: %v", err)
	}

	if msg.Type != MsgHello {
		t.Errorf("Expected type %s, got %s", MsgHello, msg.Type)
	}

	// Verify payload can be decoded
	var decoded HelloPayload
	if err := json.Unmarshal(msg.Payload, &decoded); err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	if decoded.ServerID != "server-1" {
		t.Errorf("Expected ServerID 'server-1', got '%s'", decoded.ServerID)
	}
}

func TestChangePayload_Serialization(t *testing.T) {
	entry := OpLogEntry{
		ID:         "entry-1",
		ServerID:   "server-1",
		HLC:        HybridLogicalClock{Physical: 123456789, Logical: 5, ServerID: "server-1"},
		Timestamp:  time.Now().UTC(),
		EntityType: EntityZone,
		EntityID:   "test.com",
		Operation:  OpCreate,
	}

	payload := ChangePayload{Entry: entry}

	msg, err := NewMessage(MsgChange, payload)
	if err != nil {
		t.Fatalf("NewMessage failed: %v", err)
	}

	if msg.Type != MsgChange {
		t.Errorf("Expected type %s, got %s", MsgChange, msg.Type)
	}

	// Verify payload can be decoded
	var decoded ChangePayload
	if err := json.Unmarshal(msg.Payload, &decoded); err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	if decoded.Entry.EntityID != "test.com" {
		t.Errorf("Expected EntityID 'test.com', got '%s'", decoded.Entry.EntityID)
	}
}

func TestSyncRequestPayload_Serialization(t *testing.T) {
	payload := SyncRequestPayload{
		LastKnownHLC: map[string]HybridLogicalClock{
			"server-1": {Physical: 100, Logical: 1, ServerID: "server-1"},
			"server-2": {Physical: 200, Logical: 2, ServerID: "server-2"},
		},
		Limit: 1000,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded SyncRequestPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(decoded.LastKnownHLC) != 2 {
		t.Errorf("Expected 2 HLCs, got %d", len(decoded.LastKnownHLC))
	}

	if decoded.Limit != 1000 {
		t.Errorf("Expected Limit 1000, got %d", decoded.Limit)
	}
}

func TestSyncResponsePayload_Serialization(t *testing.T) {
	payload := SyncResponsePayload{
		Entries: []OpLogEntry{
			{
				ID:         "entry-1",
				EntityType: EntityZone,
				EntityID:   "zone1.com",
				Operation:  OpCreate,
			},
			{
				ID:         "entry-2",
				EntityType: EntityRecord,
				EntityID:   "record-1",
				Operation:  OpUpdate,
			},
		},
		HasMore:    true,
		CurrentHLC: HybridLogicalClock{Physical: 999, Logical: 10, ServerID: "server-1"},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded SyncResponsePayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(decoded.Entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(decoded.Entries))
	}

	if !decoded.HasMore {
		t.Error("Expected HasMore to be true")
	}
}

func TestConfigError(t *testing.T) {
	err := &ConfigError{Message: "test error"}

	if err.Error() != "sync config error: test error" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestPeerConfig(t *testing.T) {
	peer := PeerConfig{
		URL:                "wss://peer.example.com:9443/sync",
		InsecureSkipVerify: true,
	}

	if peer.URL != "wss://peer.example.com:9443/sync" {
		t.Errorf("Unexpected URL: %s", peer.URL)
	}

	if !peer.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be true")
	}
}

func TestClusterStatus(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	config := &Config{
		Enabled:      true,
		ServerID:     "cluster-test",
		ServerName:   "Cluster Test Server",
		SharedSecret: "secret",
		Peers:        []PeerConfig{{URL: "wss://peer:9443/sync"}},
	}

	manager, err := NewManager(db, config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Add some entries
	for i := 0; i < 3; i++ {
		_ = manager.RecordChange(EntityZone, "zone"+string(rune('a'+i))+".com", "", OpCreate, nil)
	}

	status := manager.Status()

	if status.ServerID != "cluster-test" {
		t.Errorf("Expected ServerID 'cluster-test', got '%s'", status.ServerID)
	}

	if status.ServerName != "Cluster Test Server" {
		t.Errorf("Expected ServerName 'Cluster Test Server', got '%s'", status.ServerName)
	}

	if status.OpLogEntries != 3 {
		t.Errorf("Expected 3 oplog entries, got %d", status.OpLogEntries)
	}

	if status.CurrentHLC.IsZero() {
		t.Error("CurrentHLC should not be zero")
	}
}

func TestMessageTypes(t *testing.T) {
	messageTypes := []string{
		MsgHello,
		MsgHelloAck,
		MsgSyncRequest,
		MsgSyncResponse,
		MsgChange,
		MsgChangeAck,
		MsgSnapshotRequest,
		MsgSnapshotBegin,
		MsgSnapshotData,
		MsgSnapshotEnd,
		MsgPing,
		MsgPong,
		MsgError,
	}

	// Verify all message types are unique
	seen := make(map[string]bool)
	for _, mt := range messageTypes {
		if mt == "" {
			t.Error("Message type should not be empty")
		}
		if seen[mt] {
			t.Errorf("Duplicate message type: %s", mt)
		}
		seen[mt] = true
	}
}
