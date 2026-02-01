package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/scott/dns/storage"
)

// TestStorageBackendHandlers tests that API handlers work correctly
// when using storage backend (no rawConfig).
//
// This test was created to prevent regression of nil pointer dereferences
// that occurred when handlers accessed h.rawConfig which is nil when
// using NewWithStorage().
func TestStorageBackendHandlers(t *testing.T) {
	// Create temporary data directory
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Initialize storage
	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// Create handler with storage backend (simulates NewWithStorage)
	handler := &Handler{
		store:     store,
		rawConfig: nil, // This is the key - rawConfig is nil in storage mode
	}

	tests := []struct {
		name     string
		method   string
		path     string
		handler  func(http.ResponseWriter, *http.Request)
		wantCode int
	}{
		{
			name:     "GET /api/zones - storage backend",
			method:   "GET",
			path:     "/api/zones",
			handler:  handler.handleZones,
			wantCode: http.StatusOK,
		},
		{
			name:     "GET /api/records - storage backend",
			method:   "GET",
			path:     "/api/records",
			handler:  handler.handleRecords,
			wantCode: http.StatusOK,
		},
		{
			name:     "GET /api/secondary-zones - storage backend",
			method:   "GET",
			path:     "/api/secondary-zones",
			handler:  handler.handleSecondaryZones,
			wantCode: http.StatusOK,
		},
		{
			name:     "GET /api/transfer - storage backend",
			method:   "GET",
			path:     "/api/transfer",
			handler:  handler.handleTransfer,
			wantCode: http.StatusOK,
		},
		{
			name:     "GET /api/recursion - storage backend",
			method:   "GET",
			path:     "/api/recursion",
			handler:  handler.handleRecursion,
			wantCode: http.StatusOK,
		},
		{
			name:     "GET /api/dnssec - storage backend",
			method:   "GET",
			path:     "/api/dnssec",
			handler:  handler.handleDNSSEC,
			wantCode: http.StatusOK,
		},
		{
			name:     "GET /api/settings - storage backend",
			method:   "GET",
			path:     "/api/settings",
			handler:  handler.handleSettings,
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			// This should NOT panic with nil pointer dereference
			tt.handler(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("got status %d, want %d. Body: %s", w.Code, tt.wantCode, w.Body.String())
			}

			// Verify response is valid JSON
			if tt.wantCode == http.StatusOK {
				var result interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Errorf("response is not valid JSON: %v", err)
				}
			}
		})
	}
}

// TestStorageBackendZonesReturnsEmptyArray verifies that GET /api/zones
// returns an empty array (not null) when no zones exist.
func TestStorageBackendZonesReturnsEmptyArray(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	req := httptest.NewRequest("GET", "/api/zones", nil)
	w := httptest.NewRecorder()

	handler.handleZones(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusOK)
	}

	// Should be an empty array, not null
	body := w.Body.String()
	if body != "[]" && body != "[]\n" {
		var result []interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Errorf("response is not a valid array: %v", err)
		}
		if result == nil {
			t.Error("response was null, expected empty array []")
		}
	}
}

// TestStorageBackendCreateZone tests that POST /api/zones works correctly
// when using storage backend (no rawConfig).
// This test was created to prevent regression of nil pointer dereference
// when creating a zone via POST.
func TestStorageBackendCreateZone(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	handler := &Handler{
		store:     store,
		rawConfig: nil, // This is the key - rawConfig is nil in storage mode
	}

	// Create a zone via POST
	zoneData := map[string]interface{}{
		"name": "example.com",
		"type": "forward",
		"ttl":  3600,
	}
	body, _ := json.Marshal(zoneData)

	req := httptest.NewRequest("POST", "/api/zones", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// This should NOT panic with nil pointer dereference
	handler.handleZones(w, req)

	// Should succeed (or at least not panic)
	if w.Code == http.StatusInternalServerError {
		t.Errorf("got internal server error: %s", w.Body.String())
	}

	// 200 or 201 are acceptable for create
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Errorf("got status %d, want 200 or 201. Body: %s", w.Code, w.Body.String())
	}

	// Verify zone was created by listing zones
	req2 := httptest.NewRequest("GET", "/api/zones", nil)
	w2 := httptest.NewRecorder()
	handler.handleZones(w2, req2)

	var zones []map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &zones); err != nil {
		t.Fatalf("Failed to parse zones response: %v", err)
	}

	if len(zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(zones))
	}

	if len(zones) > 0 && zones[0]["name"] != "example.com" {
		t.Errorf("expected zone name 'example.com', got '%v'", zones[0]["name"])
	}
}

// TestStorageBackendCreateReverseZone tests that POST /api/zones works correctly
// for reverse zones when using storage backend.
func TestStorageBackendCreateReverseZone(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Create a reverse zone via POST
	zoneData := map[string]interface{}{
		"name":   "1.168.192.in-addr.arpa",
		"type":   "reverse",
		"subnet": "192.168.1.0/24",
		"domain": "home.local",
		"ttl":    3600,
	}
	body, _ := json.Marshal(zoneData)

	req := httptest.NewRequest("POST", "/api/zones", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleZones(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Errorf("got status %d, want 200 or 201. Body: %s", w.Code, w.Body.String())
	}

	// Verify zone was created
	req2 := httptest.NewRequest("GET", "/api/zones", nil)
	w2 := httptest.NewRecorder()
	handler.handleZones(w2, req2)

	var zones []map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &zones); err != nil {
		t.Fatalf("Failed to parse zones response: %v", err)
	}

	if len(zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(zones))
	}

	if len(zones) > 0 {
		if zones[0]["type"] != "reverse" {
			t.Errorf("expected zone type 'reverse', got '%v'", zones[0]["type"])
		}
		if zones[0]["subnet"] != "192.168.1.0/24" {
			t.Errorf("expected subnet '192.168.1.0/24', got '%v'", zones[0]["subnet"])
		}
	}
}

// TestStorageBackendCreateReverseZoneWithoutName tests that POST /api/zones works
// for reverse zones when name is not provided - it should be auto-generated from subnet.
func TestStorageBackendCreateReverseZoneWithoutName(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Create a reverse zone WITHOUT a name - only with subnet
	// This is how the UI sends it
	zoneData := map[string]interface{}{
		"type":   "reverse",
		"subnet": "192.168.1.0/24",
		"domain": "home.local",
		"ttl":    3600,
	}
	body, _ := json.Marshal(zoneData)

	req := httptest.NewRequest("POST", "/api/zones", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleZones(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Errorf("got status %d, want 200 or 201. Body: %s", w.Code, w.Body.String())
	}

	// Verify zone was created with auto-generated name
	req2 := httptest.NewRequest("GET", "/api/zones", nil)
	w2 := httptest.NewRecorder()
	handler.handleZones(w2, req2)

	var zones []map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &zones); err != nil {
		t.Fatalf("Failed to parse zones response: %v", err)
	}

	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}

	// The name should be auto-generated in in-addr.arpa format
	name := zones[0]["name"].(string)
	if name == "" {
		t.Error("expected zone name to be auto-generated, got empty string")
	}
	if !strings.Contains(name, "in-addr.arpa") && !strings.Contains(name, "ip6.arpa") {
		t.Errorf("expected zone name to be in-addr.arpa format, got '%s'", name)
	}
}

// TestStorageBackendDeleteRecord tests that DELETE /api/records/{type}/{id} works
// when using storage backend.
func TestStorageBackendDeleteRecord(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Try to delete a record with numeric index - should not panic even with rawConfig nil
	req := httptest.NewRequest("DELETE", "/api/records/A/0", nil)
	w := httptest.NewRecorder()

	handler.handleRecord(w, req)

	// Should get an error (not found) rather than panic
	if w.Code == http.StatusInternalServerError && w.Body.String() == "" {
		t.Error("handler panicked or returned empty error")
	}
}

// TestStorageBackendUpdateRecord tests that PUT /api/records/{type}/{id} works
// when using storage backend.
func TestStorageBackendUpdateRecord(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Try to update a record with numeric index
	recordData := map[string]interface{}{
		"name": "test",
		"ip":   "192.168.1.1",
		"ttl":  3600,
	}
	body, _ := json.Marshal(recordData)

	req := httptest.NewRequest("PUT", "/api/records/A/0", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleRecord(w, req)

	// Should not panic - any status except empty 500 is acceptable
	if w.Code == http.StatusInternalServerError && w.Body.String() == "" {
		t.Error("handler panicked or returned empty error")
	}
}

// TestStorageBackendSettings tests that GET/PUT /api/settings works
// when using storage backend.
func TestStorageBackendSettings(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// GET settings
	req := httptest.NewRequest("GET", "/api/settings", nil)
	w := httptest.NewRecorder()

	handler.handleSettings(w, req)

	// Should not panic
	if w.Code == http.StatusInternalServerError && w.Body.String() == "" {
		t.Error("GET settings panicked or returned empty error")
	}

	// PUT settings
	settingsData := map[string]interface{}{
		"listen": ":8053",
	}
	body, _ := json.Marshal(settingsData)

	req2 := httptest.NewRequest("PUT", "/api/settings", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()

	handler.handleSettings(w2, req2)

	// Should not panic
	if w2.Code == http.StatusInternalServerError && w2.Body.String() == "" {
		t.Error("PUT settings panicked or returned empty error")
	}
}

// TestStorageBackendCreateRecord tests that POST /api/records works
// when using storage backend.
func TestStorageBackendCreateRecord(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// First create a zone
	err = store.CreateZone(&storage.Zone{
		Name:     "example.com",
		Type:     storage.ZoneTypeForward,
		TenantID: storage.MainTenantID,
		TTL:      3600,
	})
	if err != nil {
		t.Fatalf("Failed to create zone: %v", err)
	}

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Create a record
	recordData := map[string]interface{}{
		"type": "A",
		"zone": "example.com",
		"name": "www",
		"ip":   "192.168.1.1",
		"ttl":  3600,
	}
	body, _ := json.Marshal(recordData)

	req := httptest.NewRequest("POST", "/api/records", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleRecords(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Errorf("got status %d, want 200 or 201. Body: %s", w.Code, w.Body.String())
	}
}

// TestStorageBackendDeleteZone tests that DELETE /api/zones/{id} works
// when using storage backend.
func TestStorageBackendDeleteZone(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// First create a zone
	zoneName := "example.com"
	err = store.CreateZone(&storage.Zone{
		Name:     zoneName,
		Type:     storage.ZoneTypeForward,
		TenantID: storage.MainTenantID,
		TTL:      3600,
	})
	if err != nil {
		t.Fatalf("Failed to create zone: %v", err)
	}

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Delete the zone - the ID is the zone name in storage mode
	req := httptest.NewRequest("DELETE", "/api/zones/"+zoneName, nil)
	w := httptest.NewRecorder()

	handler.handleZone(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	// Verify zone was deleted
	req2 := httptest.NewRequest("GET", "/api/zones", nil)
	w2 := httptest.NewRecorder()
	handler.handleZones(w2, req2)

	var zones []map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &zones); err != nil {
		t.Fatalf("Failed to parse zones response: %v", err)
	}

	if len(zones) != 0 {
		t.Errorf("expected 0 zones after delete, got %d", len(zones))
	}
}

// TestStorageBackendDeleteReverseZone tests that DELETE /api/zones/{id} works
// for reverse zones when using storage backend.
func TestStorageBackendDeleteReverseZone(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// Create a reverse zone
	zoneName := "1.168.192.in-addr.arpa"
	err = store.CreateZone(&storage.Zone{
		Name:     zoneName,
		Type:     storage.ZoneTypeReverse,
		Subnet:   "192.168.1.0/24",
		Domain:   "home.local",
		TenantID: storage.MainTenantID,
		TTL:      3600,
	})
	if err != nil {
		t.Fatalf("Failed to create zone: %v", err)
	}

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Delete the zone
	req := httptest.NewRequest("DELETE", "/api/zones/"+zoneName, nil)
	w := httptest.NewRecorder()

	handler.handleZone(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	// Verify zone was deleted
	req2 := httptest.NewRequest("GET", "/api/zones", nil)
	w2 := httptest.NewRecorder()
	handler.handleZones(w2, req2)

	var zones []map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &zones); err != nil {
		t.Fatalf("Failed to parse zones response: %v", err)
	}

	if len(zones) != 0 {
		t.Errorf("expected 0 zones after delete, got %d", len(zones))
	}
}

// TestSecondaryZoneCannotDuplicatePrimaryZone tests that creating a secondary zone
// with the same name as an existing primary zone is rejected.
func TestSecondaryZoneCannotDuplicatePrimaryZone(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// First, create a primary zone
	err = store.CreateZone(&storage.Zone{
		Name:     "example.com",
		Type:     storage.ZoneTypeForward,
		TenantID: storage.MainTenantID,
		TTL:      3600,
	})
	if err != nil {
		t.Fatalf("Failed to create primary zone: %v", err)
	}

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Now try to create a secondary zone with the same name
	secondaryZone := map[string]interface{}{
		"zone":    "example.com",
		"primary": "192.168.1.1",
	}
	body, _ := json.Marshal(secondaryZone)

	req := httptest.NewRequest("POST", "/api/secondary-zones", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleSecondaryZones(w, req)

	// Should be rejected with 400 Bad Request
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the error message mentions the conflict
	if !strings.Contains(w.Body.String(), "already exists") && !strings.Contains(w.Body.String(), "primary") {
		t.Errorf("Expected error message about zone conflict, got: %s", w.Body.String())
	}
}

// TestPrimaryZoneCannotDuplicateSecondaryZone tests that creating a primary zone
// with the same name as an existing secondary zone is rejected.
func TestPrimaryZoneCannotDuplicateSecondaryZone(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// First, create a secondary zone
	err = store.CreateSecondaryZone(&storage.SecondaryZone{
		Zone:      "example.com",
		Primaries: []string{"192.168.1.1"},
	})
	if err != nil {
		t.Fatalf("Failed to create secondary zone: %v", err)
	}

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Now try to create a primary zone with the same name
	primaryZone := map[string]interface{}{
		"name": "example.com",
		"type": "forward",
		"ttl":  3600,
	}
	body, _ := json.Marshal(primaryZone)

	req := httptest.NewRequest("POST", "/api/zones", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleZones(w, req)

	// Should be rejected with 400 Bad Request
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the error message mentions the conflict
	if !strings.Contains(w.Body.String(), "already exists") && !strings.Contains(w.Body.String(), "secondary") {
		t.Errorf("Expected error message about zone conflict, got: %s", w.Body.String())
	}
}

// TestDuplicatePrimaryZoneRejected tests that creating a primary zone
// with the same name as an existing primary zone is rejected.
func TestDuplicatePrimaryZoneRejected(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Create a primary zone
	zone1 := map[string]interface{}{
		"name": "example.com",
		"type": "forward",
		"ttl":  3600,
	}
	body1, _ := json.Marshal(zone1)

	req1 := httptest.NewRequest("POST", "/api/zones", bytes.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	handler.handleZones(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("Failed to create first zone: %d: %s", w1.Code, w1.Body.String())
	}

	// Try to create another primary zone with the same name
	body2, _ := json.Marshal(zone1)
	req2 := httptest.NewRequest("POST", "/api/zones", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.handleZones(w2, req2)

	// Should be rejected with 400 Bad Request
	if w2.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w2.Code, w2.Body.String())
	}

	if !strings.Contains(w2.Body.String(), "already exists") {
		t.Errorf("Expected error message about zone already existing, got: %s", w2.Body.String())
	}
}

// TestDuplicateSecondaryZoneRejected tests that creating a secondary zone
// with the same name as an existing secondary zone is rejected.
func TestDuplicateSecondaryZoneRejected(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	handler := &Handler{
		store:     store,
		rawConfig: nil,
	}

	// Create a secondary zone
	zone1 := map[string]interface{}{
		"zone":      "example.com",
		"primaries": []string{"192.168.1.1"},
	}
	body1, _ := json.Marshal(zone1)

	req1 := httptest.NewRequest("POST", "/api/secondary-zones", bytes.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	handler.handleSecondaryZones(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("Failed to create first secondary zone: %d: %s", w1.Code, w1.Body.String())
	}

	// Try to create another secondary zone with the same name
	body2, _ := json.Marshal(zone1)
	req2 := httptest.NewRequest("POST", "/api/secondary-zones", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.handleSecondaryZones(w2, req2)

	// Should be rejected with 400 Bad Request
	if w2.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w2.Code, w2.Body.String())
	}

	if !strings.Contains(w2.Body.String(), "already exists") {
		t.Errorf("Expected error message about zone already existing, got: %s", w2.Body.String())
	}
}
