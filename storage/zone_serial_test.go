package storage

import (
	"encoding/json"
	"testing"
	"time"
)

type capturedChange struct {
	entityType, entityID, operation string
	data                            interface{}
}

// captureChanges installs a sync hook that records changes for the test.
func captureChanges(t *testing.T) *[]capturedChange {
	t.Helper()
	var changes []capturedChange
	prev := syncHook
	SetSyncHook(func(entityType, entityID, tenantID, operation string, data interface{}) error {
		changes = append(changes, capturedChange{entityType, entityID, operation, data})
		return nil
	})
	t.Cleanup(func() { syncHook = prev })
	return &changes
}

func newSerialTestZone(t *testing.T, store *Store, serial uint32) *Zone {
	t.Helper()
	zone := &Zone{
		Name: "serial.example.com", TenantID: MainTenantID, Type: ZoneTypeForward,
		Status: ZoneStatusActive, TTL: 3600, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := store.CreateZone(zone); err != nil {
		t.Fatal(err)
	}
	zone.Serial = serial
	if err := store.UpdateZonePreserveSerial(zone); err != nil {
		t.Fatal(err)
	}
	return zone
}

func newSerialTestRecord(zone, id, ip string) *Record {
	data, _ := json.Marshal(ARecordData{IP: ip})
	return &Record{ID: id, Zone: zone, Name: "www", Type: "A", TTL: 300, Enabled: true, Data: data}
}

func TestLocalRecordChangeBroadcastsZoneSerial(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()
	zone := newSerialTestZone(t, store, 2026100901)
	changes := captureChanges(t)

	if err := store.CreateRecord(newSerialTestRecord(zone.Name, "r1", "192.0.2.1")); err != nil {
		t.Fatal(err)
	}

	serial, _ := store.GetZoneSerial(zone.Name)
	if serial != 2026100902 {
		t.Fatalf("serial = %d, want 2026100902", serial)
	}
	var broadcast *ZoneSerial
	for _, c := range *changes {
		if c.entityType == EntityTypeZoneSerial && c.entityID == zone.Name && c.operation == OpUpdate {
			broadcast = c.data.(*ZoneSerial)
		}
		if c.entityType == EntityTypeZone {
			t.Error("record change broadcast the whole zone; only the serial should be sent")
		}
	}
	if broadcast == nil {
		t.Fatal("local record change did not broadcast the zone serial")
	}
	if broadcast.Serial != serial {
		t.Fatalf("broadcast serial = %d, want %d", broadcast.Serial, serial)
	}
}

func TestRemoteRecordChangeKeepsSerial(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()
	zone := newSerialTestZone(t, store, 2026100901)
	changes := captureChanges(t)

	err := WithSyncHookDisabled(func() error {
		return store.CreateRecord(newSerialTestRecord(zone.Name, "r1", "192.0.2.1"))
	})
	if err != nil {
		t.Fatal(err)
	}

	if serial, _ := store.GetZoneSerial(zone.Name); serial != 2026100901 {
		t.Fatalf("serial = %d, want unchanged 2026100901 (the origin's serial broadcast sets it)", serial)
	}
	if len(*changes) != 0 {
		t.Fatalf("applying a peer's change broadcast %d changes", len(*changes))
	}
}

func TestRaiseZoneSerial(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()
	zone := newSerialTestZone(t, store, 2026100905)

	// Out-of-order and duplicate updates converge on the highest serial
	for _, s := range []uint32{2026100907, 2026100903, 2026100907, 2026100906} {
		if err := store.RaiseZoneSerial(zone.Name, s); err != nil {
			t.Fatal(err)
		}
	}
	if serial, _ := store.GetZoneSerial(zone.Name); serial != 2026100907 {
		t.Fatalf("serial = %d, want 2026100907", serial)
	}
	if err := store.RaiseZoneSerial("missing.example.com", 1); err != ErrNotFound {
		t.Fatalf("missing zone: err = %v, want ErrNotFound", err)
	}
}

func TestIncrementSerialNeverDecreases(t *testing.T) {
	now := time.Now().UTC()
	today := uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100)

	cases := map[uint32]uint32{
		2026021389:  today + 1,   // older date: jump to today
		today + 5:   today + 6,   // same day
		today + 150: today + 151, // already past today+99 from record bumps
	}
	for current, want := range cases {
		if got := incrementSerial(current); got != want {
			t.Errorf("incrementSerial(%d) = %d, want %d", current, got, want)
		}
	}
}

func TestAnnounceZoneSerials(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()
	zone := newSerialTestZone(t, store, 2026100917)
	changes := captureChanges(t)

	if err := store.AnnounceZoneSerials(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range *changes {
		if c.entityType != EntityTypeZoneSerial {
			t.Errorf("announce recorded a %s change", c.entityType)
			continue
		}
		if zs := c.data.(*ZoneSerial); zs.Zone == zone.Name && zs.Serial == 2026100917 {
			found = true
		}
	}
	if !found {
		t.Fatalf("serial for %s not announced: %+v", zone.Name, *changes)
	}
}
