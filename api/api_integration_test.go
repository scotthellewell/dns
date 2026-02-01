package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/scott/dns/config"
	"github.com/scott/dns/storage"
)

// createTestHandler creates a handler with an isolated temp storage for testing.
// Each test gets its own storage directory for isolation and repeatability.
func createTestHandler(t *testing.T) (*Handler, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create storage: %v", err)
	}

	// Build initial config from empty storage
	cfg, err := store.BuildParsedConfig()
	if err != nil {
		store.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to build config: %v", err)
	}

	handler := NewWithStorage(cfg, store, nil)

	cleanup := func() {
		store.Close()
		os.RemoveAll(tmpDir)
	}

	return handler, cleanup
}

// createTestHandlerWithZone creates a handler with a pre-existing zone for testing.
func createTestHandlerWithZone(t *testing.T, zoneName string) (*Handler, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "dns-api-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create storage: %v", err)
	}

	// Create a zone
	err = store.CreateZone(&storage.Zone{
		Name:     zoneName,
		Type:     storage.ZoneTypeForward,
		TenantID: storage.MainTenantID,
		TTL:      3600,
	})
	if err != nil {
		store.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create zone: %v", err)
	}

	// Build config
	cfg, err := store.BuildParsedConfig()
	if err != nil {
		store.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to build config: %v", err)
	}

	handler := NewWithStorage(cfg, store, nil)

	cleanup := func() {
		store.Close()
		os.RemoveAll(tmpDir)
	}

	return handler, cleanup
}

// TestAPIIntegration tests the HTTP API endpoints using storage backend
func TestAPIIntegration(t *testing.T) {
	handler, cleanup := createTestHandler(t)
	defer cleanup()

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	t.Run("GET /api/status", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/status", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var resp StatusResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if resp.Status != "ok" && resp.Status != "running" {
			t.Errorf("Expected status 'ok' or 'running', got '%s'", resp.Status)
		}
	})

	t.Run("GET /api/zones empty", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/zones", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var zones []map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&zones); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(zones) != 0 {
			t.Errorf("Expected 0 zones, got %d", len(zones))
		}
	})

	t.Run("GET /api/records empty", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/records", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("OPTIONS CORS preflight", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/status", nil)
		req.Header.Set("Origin", "http://localhost:4200")
		req.Header.Set("Access-Control-Request-Method", "GET")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
			t.Errorf("Expected status 200/204 for CORS preflight, got %d", w.Code)
		}

		if w.Header().Get("Access-Control-Allow-Origin") == "" {
			t.Error("Expected Access-Control-Allow-Origin header")
		}
	})

	t.Run("GET /api/recursion", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/recursion", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("GET /api/secondary-zones", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/secondary-zones", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("GET /api/settings", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/settings", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("GET /api/dnssec", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/dnssec", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

// TestZoneCRUD tests zone create, read, update, delete operations
func TestZoneCRUD(t *testing.T) {
	handler, cleanup := createTestHandler(t)
	defer cleanup()

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	var createdZoneID string

	t.Run("POST /api/zones - create forward zone", func(t *testing.T) {
		zone := map[string]interface{}{
			"name": "example.com",
			"type": "forward",
			"ttl":  3600,
		}
		body, _ := json.Marshal(zone)

		req := httptest.NewRequest("POST", "/api/zones", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK && w.Code != http.StatusCreated {
			t.Errorf("Expected status 200/201, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err == nil {
			if id, ok := resp["id"].(string); ok {
				createdZoneID = id
			}
		}
	})

	t.Run("GET /api/zones - list zones", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/zones", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var zones []map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&zones); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(zones) != 1 {
			t.Errorf("Expected 1 zone, got %d", len(zones))
		}

		if len(zones) > 0 {
			if zones[0]["name"] != "example.com" {
				t.Errorf("Expected zone name 'example.com', got '%v'", zones[0]["name"])
			}
			// Store zone_id for later tests
			if zoneID, ok := zones[0]["zone_id"].(string); ok {
				createdZoneID = zoneID
			}
		}
	})

	t.Run("GET /api/zones/{id} - get zone", func(t *testing.T) {
		if createdZoneID == "" {
			t.Skip("No zone ID available")
		}

		req := httptest.NewRequest("GET", "/api/zones/"+createdZoneID, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("PUT /api/zones/{id} - update zone", func(t *testing.T) {
		if createdZoneID == "" {
			t.Skip("No zone ID available")
		}

		zone := map[string]interface{}{
			"name": "example.com",
			"type": "forward",
			"ttl":  7200,
		}
		body, _ := json.Marshal(zone)

		req := httptest.NewRequest("PUT", "/api/zones/"+createdZoneID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("PUT /api/zones/{id} - rename zone", func(t *testing.T) {
		if createdZoneID == "" {
			t.Skip("No zone ID available")
		}

		// Rename from example.com to renamed.com
		zone := map[string]interface{}{
			"name": "renamed.com",
			"type": "forward",
			"ttl":  7200,
		}
		body, _ := json.Marshal(zone)

		req := httptest.NewRequest("PUT", "/api/zones/"+createdZoneID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		// Verify zone was renamed
		req2 := httptest.NewRequest("GET", "/api/zones", nil)
		w2 := httptest.NewRecorder()
		mux.ServeHTTP(w2, req2)

		var zones []map[string]interface{}
		json.NewDecoder(w2.Body).Decode(&zones)

		if len(zones) != 1 {
			t.Fatalf("Expected 1 zone, got %d", len(zones))
		}

		if zones[0]["name"] != "renamed.com" {
			t.Errorf("Expected zone name 'renamed.com', got '%v'", zones[0]["name"])
		}

		// Update createdZoneID to the new name for subsequent tests
		createdZoneID = "renamed.com"
	})

	t.Run("DELETE /api/zones/{id} - delete zone", func(t *testing.T) {
		if createdZoneID == "" {
			t.Skip("No zone ID available")
		}

		req := httptest.NewRequest("DELETE", "/api/zones/"+createdZoneID, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		// Verify zone is gone
		req2 := httptest.NewRequest("GET", "/api/zones", nil)
		w2 := httptest.NewRecorder()
		mux.ServeHTTP(w2, req2)

		var zones []map[string]interface{}
		json.NewDecoder(w2.Body).Decode(&zones)
		if len(zones) != 0 {
			t.Errorf("Expected 0 zones after delete, got %d", len(zones))
		}
	})
}

// TestRecordCRUD tests record create, read, update, delete operations
func TestRecordCRUD(t *testing.T) {
	handler, cleanup := createTestHandlerWithZone(t, "example.com")
	defer cleanup()

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	t.Run("POST /api/records - create A record", func(t *testing.T) {
		record := map[string]interface{}{
			"type": "A",
			"zone": "example.com",
			"name": "www",
			"ip":   "192.168.1.1",
			"ttl":  300,
		}
		body, _ := json.Marshal(record)

		req := httptest.NewRequest("POST", "/api/records", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK && w.Code != http.StatusCreated {
			t.Errorf("Expected status 200/201, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("GET /api/records - list records", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/records", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var records []map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&records); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(records) != 1 {
			t.Fatalf("Expected 1 record, got %d", len(records))
		}

		// Verify the IP address is returned correctly
		if records[0]["ip"] != "192.168.1.1" {
			t.Errorf("Expected ip '192.168.1.1', got '%v'", records[0]["ip"])
		}
		if records[0]["name"] != "www" {
			t.Errorf("Expected name 'www', got '%v'", records[0]["name"])
		}
		if records[0]["type"] != "A" {
			t.Errorf("Expected type 'A', got '%v'", records[0]["type"])
		}
	})

	t.Run("GET /api/records?zone=example.com - filter by zone", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/records?zone=example.com", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("GET /api/records?type=A - filter by type", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/records?type=A", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

// TestReverseZone tests reverse zone operations
func TestReverseZone(t *testing.T) {
	handler, cleanup := createTestHandler(t)
	defer cleanup()

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	t.Run("POST /api/zones - create reverse zone without name", func(t *testing.T) {
		// UI sends without name - should auto-generate from subnet
		zone := map[string]interface{}{
			"type":   "reverse",
			"subnet": "192.168.1.0/24",
			"domain": "home.local",
			"ttl":    3600,
		}
		body, _ := json.Marshal(zone)

		req := httptest.NewRequest("POST", "/api/zones", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK && w.Code != http.StatusCreated {
			t.Errorf("Expected status 200/201, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("GET /api/zones - verify reverse zone created", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/zones", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		var zones []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&zones)

		if len(zones) != 1 {
			t.Fatalf("Expected 1 zone, got %d", len(zones))
		}

		name := zones[0]["name"].(string)
		if name == "" {
			t.Error("Expected zone name to be auto-generated")
		}
		// Should be in-addr.arpa format
		if name != "1.168.192.in-addr.arpa" && name != "1.168.192.in-addr.arpa." {
			t.Errorf("Expected zone name '1.168.192.in-addr.arpa', got '%s'", name)
		}
	})
}

// TestQueryCounting tests the query counter functionality
func TestQueryCounting(t *testing.T) {
	handler, cleanup := createTestHandler(t)
	defer cleanup()

	handler.IncrementQueryCount("A")
	handler.IncrementQueryCount("A")
	handler.IncrementQueryCount("AAAA")

	if handler.stats.TotalQueries != 3 {
		t.Errorf("Expected 3 total queries, got %d", handler.stats.TotalQueries)
	}

	handler.stats.mu.RLock()
	aCount := handler.stats.QueriesByType["A"]
	aaaaCount := handler.stats.QueriesByType["AAAA"]
	handler.stats.mu.RUnlock()

	if aCount != 2 {
		t.Errorf("Expected 2 A queries, got %d", aCount)
	}
	if aaaaCount != 1 {
		t.Errorf("Expected 1 AAAA query, got %d", aaaaCount)
	}
}

// TestMetricsEndpoint tests the Prometheus metrics endpoint
func TestMetricsEndpoint(t *testing.T) {
	handler, cleanup := createTestHandler(t)
	defer cleanup()

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestConcurrentRequests tests handling of concurrent API requests
func TestConcurrentRequests(t *testing.T) {
	handler, cleanup := createTestHandler(t)
	defer cleanup()

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	done := make(chan bool, 50)

	for i := 0; i < 50; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/api/status", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Concurrent request failed with status %d", w.Code)
			}
			done <- true
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}
}

// TestIsolation verifies that each test gets isolated storage
func TestIsolation(t *testing.T) {
	// Create first handler with a zone
	handler1, cleanup1 := createTestHandler(t)
	defer cleanup1()

	// Add a zone to handler1
	store1 := handler1.getStore()
	store1.CreateZone(&storage.Zone{
		Name: "test1.com",
		Type: storage.ZoneTypeForward,
		TTL:  3600,
	})

	// Create second handler - should have no zones
	handler2, cleanup2 := createTestHandler(t)
	defer cleanup2()

	store2 := handler2.getStore()
	zones, _ := store2.ListZones("")

	if len(zones) != 0 {
		t.Errorf("Expected handler2 to have 0 zones (isolated), got %d", len(zones))
	}
}

// TestRecursionConfigUpdate tests that updating recursion config triggers a config reload
func TestRecursionConfigUpdate(t *testing.T) {
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

	cfg, err := store.BuildParsedConfig()
	if err != nil {
		t.Fatalf("Failed to build config: %v", err)
	}

	// Track config updates
	var lastConfig *config.ParsedConfig
	updateCount := 0

	handler := NewWithStorage(cfg, store, func(newCfg *config.ParsedConfig) {
		lastConfig = newCfg
		updateCount++
	})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Initial config should have recursion disabled
	if cfg.Recursion.Enabled {
		t.Error("Expected recursion to be disabled initially")
	}

	// Update recursion config to full mode
	newCfg := map[string]interface{}{
		"enabled":   true,
		"mode":      "full",
		"upstream":  []string{"8.8.8.8:53"},
		"timeout":   5,
		"max_depth": 10,
	}
	body, _ := json.Marshal(newCfg)

	req := httptest.NewRequest("PUT", "/api/recursion", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify callback was invoked
	if updateCount == 0 {
		t.Error("Expected onConfigUpdate callback to be invoked")
	}

	// Verify the new config has recursion enabled
	if lastConfig == nil {
		t.Fatal("lastConfig is nil - callback was not invoked")
	}

	if !lastConfig.Recursion.Enabled {
		t.Error("Expected recursion to be enabled after update")
	}

	if lastConfig.Recursion.Mode != "full" {
		t.Errorf("Expected recursion mode 'full', got '%s'", lastConfig.Recursion.Mode)
	}

	if len(lastConfig.Recursion.Upstream) != 1 || lastConfig.Recursion.Upstream[0] != "8.8.8.8:53" {
		t.Errorf("Expected upstream ['8.8.8.8:53'], got %v", lastConfig.Recursion.Upstream)
	}

	// Now disable recursion
	disabledCfg := map[string]interface{}{
		"enabled":   false,
		"mode":      "disabled",
		"upstream":  []string{},
		"timeout":   5,
		"max_depth": 10,
	}
	body2, _ := json.Marshal(disabledCfg)

	req2 := httptest.NewRequest("PUT", "/api/recursion", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w2.Code, w2.Body.String())
	}

	// Verify recursion is now disabled
	if lastConfig.Recursion.Enabled {
		t.Error("Expected recursion to be disabled after second update")
	}

	if lastConfig.Recursion.Mode != "disabled" {
		t.Errorf("Expected recursion mode 'disabled', got '%s'", lastConfig.Recursion.Mode)
	}
}
