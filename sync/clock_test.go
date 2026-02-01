package sync

import (
	"testing"
	"time"
)

func TestHybridLogicalClock_Compare(t *testing.T) {
	tests := []struct {
		name     string
		a        HybridLogicalClock
		b        HybridLogicalClock
		expected int
	}{
		{
			name:     "equal clocks",
			a:        HybridLogicalClock{Physical: 100, Logical: 1, ServerID: "s1"},
			b:        HybridLogicalClock{Physical: 100, Logical: 1, ServerID: "s1"},
			expected: 0,
		},
		{
			name:     "a has higher physical time",
			a:        HybridLogicalClock{Physical: 200, Logical: 1, ServerID: "s1"},
			b:        HybridLogicalClock{Physical: 100, Logical: 1, ServerID: "s1"},
			expected: 1,
		},
		{
			name:     "b has higher physical time",
			a:        HybridLogicalClock{Physical: 100, Logical: 1, ServerID: "s1"},
			b:        HybridLogicalClock{Physical: 200, Logical: 1, ServerID: "s1"},
			expected: -1,
		},
		{
			name:     "same physical, a has higher logical",
			a:        HybridLogicalClock{Physical: 100, Logical: 5, ServerID: "s1"},
			b:        HybridLogicalClock{Physical: 100, Logical: 1, ServerID: "s1"},
			expected: 1,
		},
		{
			name:     "same physical, b has higher logical",
			a:        HybridLogicalClock{Physical: 100, Logical: 1, ServerID: "s1"},
			b:        HybridLogicalClock{Physical: 100, Logical: 5, ServerID: "s1"},
			expected: -1,
		},
		{
			name:     "same time, a has lesser serverID",
			a:        HybridLogicalClock{Physical: 100, Logical: 1, ServerID: "a"},
			b:        HybridLogicalClock{Physical: 100, Logical: 1, ServerID: "b"},
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.a.Compare(tt.b)
			if result != tt.expected {
				t.Errorf("Compare() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestHybridLogicalClock_IsZero(t *testing.T) {
	zero := HybridLogicalClock{}
	if !zero.IsZero() {
		t.Error("Zero HLC should return IsZero=true")
	}

	nonZero := HybridLogicalClock{Physical: 100, Logical: 1}
	if nonZero.IsZero() {
		t.Error("Non-zero HLC should return IsZero=false")
	}
}

func TestHybridLogicalClock_String(t *testing.T) {
	hlc := HybridLogicalClock{Physical: 1000000, Logical: 5, ServerID: "server-1"}
	str := hlc.String()

	if str == "" {
		t.Error("String() should not return empty string")
	}

	// Should contain the physical time, logical counter, and server ID
	expected := "1000000.5@server-1"
	if str != expected {
		t.Errorf("Expected '%s', got '%s'", expected, str)
	}
}

func TestNewClock(t *testing.T) {
	clock := NewClock("test-server")

	if clock == nil {
		t.Fatal("NewClock returned nil")
	}
}

func TestClock_Now(t *testing.T) {
	clock := NewClock("test-server")

	hlc1 := clock.Now()
	if hlc1.IsZero() {
		t.Error("Now() should not return zero HLC")
	}

	if hlc1.ServerID != "test-server" {
		t.Errorf("Expected ServerID 'test-server', got '%s'", hlc1.ServerID)
	}

	if hlc1.Physical == 0 {
		t.Error("Physical time should not be zero")
	}
}

func TestClock_Now_Ordering(t *testing.T) {
	clock := NewClock("test-server")

	hlc1 := clock.Now()
	hlc2 := clock.Now()

	// Second call should be greater or equal (same millisecond with higher logical)
	if hlc2.Compare(hlc1) < 0 {
		t.Errorf("Second Now() (%v) should not be before first (%v)", hlc2, hlc1)
	}
}

func TestClock_Now_Concurrent(t *testing.T) {
	clock := NewClock("test-server")

	// Generate many HLCs rapidly
	hlcs := make([]HybridLogicalClock, 100)
	for i := 0; i < 100; i++ {
		hlcs[i] = clock.Now()
	}

	// Each should be unique and in order
	for i := 1; i < len(hlcs); i++ {
		if hlcs[i].Compare(hlcs[i-1]) <= 0 {
			t.Errorf("HLC %d (%v) should be after HLC %d (%v)", i, hlcs[i], i-1, hlcs[i-1])
		}
	}
}

func TestClock_Update(t *testing.T) {
	clock := NewClock("local-server")

	local := clock.Now()

	// Create a remote clock that's ahead
	remote := HybridLogicalClock{
		Physical: local.Physical + 1000, // 1 second ahead
		Logical:  10,
		ServerID: "remote-server",
	}

	// Update with remote
	updated := clock.Update(remote)

	// Updated should be after both local and remote
	if updated.Compare(local) <= 0 {
		t.Error("Updated clock should be after local")
	}

	if updated.Compare(remote) <= 0 {
		t.Error("Updated clock should be after remote")
	}
}

func TestClock_Update_WithPastTime(t *testing.T) {
	clock := NewClock("local-server")

	local := clock.Now()

	// Create a remote clock that's behind
	remote := HybridLogicalClock{
		Physical: local.Physical - 1000, // 1 second behind
		Logical:  10,
		ServerID: "remote-server",
	}

	// Update with remote
	updated := clock.Update(remote)

	// Updated should still be after local (we don't go backwards)
	if updated.Compare(local) <= 0 {
		t.Error("Updated clock should be after local even when remote is behind")
	}
}

func TestEntityTypeConstants(t *testing.T) {
	types := []string{
		EntityZone,
		EntityRecord,
		EntityUser,
		EntityTenant,
		EntityDNSSECKeys,
		EntityDelegation,
		EntitySecondaryZone,
		EntityTransfer,
		EntityRecursion,
		EntityAPIKey,
		EntitySettings,
	}

	for _, typ := range types {
		if typ == "" {
			t.Error("Entity type constant should not be empty")
		}
	}

	// Verify uniqueness
	seen := make(map[string]bool)
	for _, typ := range types {
		if seen[typ] {
			t.Errorf("Duplicate entity type: %s", typ)
		}
		seen[typ] = true
	}
}

func TestOperationConstants(t *testing.T) {
	if OpCreate != "create" {
		t.Errorf("OpCreate should be 'create', got '%s'", OpCreate)
	}
	if OpUpdate != "update" {
		t.Errorf("OpUpdate should be 'update', got '%s'", OpUpdate)
	}
	if OpDelete != "delete" {
		t.Errorf("OpDelete should be 'delete', got '%s'", OpDelete)
	}
}

func TestOpLogEntry_Fields(t *testing.T) {
	now := time.Now().UTC()
	entry := OpLogEntry{
		ID:         "test-id",
		ServerID:   "server-1",
		HLC:        HybridLogicalClock{Physical: 100, Logical: 1, ServerID: "server-1"},
		Timestamp:  now,
		EntityType: EntityZone,
		EntityID:   "example.com",
		TenantID:   "tenant-1",
		Operation:  OpCreate,
	}

	if entry.ID != "test-id" {
		t.Errorf("Expected ID 'test-id', got '%s'", entry.ID)
	}
	if entry.ServerID != "server-1" {
		t.Errorf("Expected ServerID 'server-1', got '%s'", entry.ServerID)
	}
	if entry.EntityType != EntityZone {
		t.Errorf("Expected EntityType '%s', got '%s'", EntityZone, entry.EntityType)
	}
	if entry.EntityID != "example.com" {
		t.Errorf("Expected EntityID 'example.com', got '%s'", entry.EntityID)
	}
	if entry.Operation != OpCreate {
		t.Errorf("Expected Operation '%s', got '%s'", OpCreate, entry.Operation)
	}
}

func TestGenerateID(t *testing.T) {
	id1 := GenerateID()
	id2 := GenerateID()

	if id1 == "" {
		t.Error("GenerateID should not return empty string")
	}

	if id1 == id2 {
		t.Error("GenerateID should return unique IDs")
	}
}

func TestGenerateServerID(t *testing.T) {
	sid1 := GenerateServerID()
	sid2 := GenerateServerID()

	if sid1 == "" {
		t.Error("GenerateServerID should not return empty string")
	}

	if sid1 == sid2 {
		t.Error("GenerateServerID should return unique IDs")
	}
}
