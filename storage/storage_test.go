package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Helper to create a temp store
func setupTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "dns-storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	store, err := Open(Options{DataDir: tmpDir})
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to open store: %v", err)
	}

	cleanup := func() {
		store.Close()
		os.RemoveAll(tmpDir)
	}
	return store, cleanup
}

func TestOpen(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dns-storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := Open(Options{DataDir: tmpDir})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	// Check that data.db was created
	dbPath := filepath.Join(tmpDir, "data.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database file was not created at %s", dbPath)
	}
}

func TestOpen_DefaultDir(t *testing.T) {
	// This test just verifies DefaultDataDir doesn't panic
	dir := DefaultDataDir()
	if dir == "" {
		t.Error("DefaultDataDir() returned empty string")
	}
}

func TestClose(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	err := store.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// Tenant CRUD tests
func TestTenant_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	tenant := &Tenant{
		ID:          "test-tenant-1",
		Name:        "Test Tenant",
		Description: "A test tenant",
		CreatedAt:   time.Now(),
	}

	// Create
	err := store.CreateTenant(tenant)
	if err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}

	// Read
	got, err := store.GetTenant(tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant() error = %v", err)
	}
	if got.Name != tenant.Name {
		t.Errorf("GetTenant() Name = %v, want %v", got.Name, tenant.Name)
	}

	// Update
	tenant.Description = "Updated description"
	err = store.UpdateTenant(tenant)
	if err != nil {
		t.Fatalf("UpdateTenant() error = %v", err)
	}
	got, _ = store.GetTenant(tenant.ID)
	if got.Description != "Updated description" {
		t.Errorf("UpdateTenant() Description = %v, want 'Updated description'", got.Description)
	}

	// List
	tenants, err := store.ListTenants()
	if err != nil {
		t.Fatalf("ListTenants() error = %v", err)
	}
	// Should have at least our tenant (may also have 'main' tenant from init)
	found := false
	for _, ten := range tenants {
		if ten.ID == tenant.ID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListTenants() did not include created tenant")
	}

	// Delete
	err = store.DeleteTenant(tenant.ID)
	if err != nil {
		t.Fatalf("DeleteTenant() error = %v", err)
	}
	_, err = store.GetTenant(tenant.ID)
	if err == nil {
		t.Error("GetTenant() should return error for deleted tenant")
	}
}

// User CRUD tests
func TestUser_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// First create a tenant
	tenant := &Tenant{
		ID:        "user-test-tenant",
		Name:      "User Test Tenant",
		CreatedAt: time.Now(),
	}
	store.CreateTenant(tenant)

	user := &User{
		ID:        "test-user-1",
		Username:  "testuser",
		Email:     "test@example.com",
		TenantID:  tenant.ID,
		Role:      RoleUser,
		CreatedAt: time.Now(),
	}

	// Create with password
	err := store.CreateUserWithPassword(user, "testpassword123")
	if err != nil {
		t.Fatalf("CreateUserWithPassword() error = %v", err)
	}

	// Get by ID
	got, err := store.GetUser(user.ID)
	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if got.Username != user.Username {
		t.Errorf("GetUser() Username = %v, want %v", got.Username, user.Username)
	}

	// Get by username
	got, err = store.GetUserByUsername(user.Username)
	if err != nil {
		t.Fatalf("GetUserByUsername() error = %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByUsername() ID = %v, want %v", got.ID, user.ID)
	}

	// Validate password
	validated, err := store.ValidatePassword(user.Username, "testpassword123")
	if err != nil {
		t.Fatalf("ValidatePassword() error = %v", err)
	}
	if validated.ID != user.ID {
		t.Errorf("ValidatePassword() returned wrong user")
	}

	// Wrong password
	_, err = store.ValidatePassword(user.Username, "wrongpassword")
	if err == nil {
		t.Error("ValidatePassword() should fail for wrong password")
	}

	// Update
	user.DisplayName = "Test User Display"
	err = store.UpdateUser(user)
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	// Update password
	err = store.UpdateUserPassword(user.ID, "newpassword123")
	if err != nil {
		t.Fatalf("UpdateUserPassword() error = %v", err)
	}
	_, err = store.ValidatePassword(user.Username, "newpassword123")
	if err != nil {
		t.Error("ValidatePassword() should succeed with new password")
	}

	// List users by tenant
	users, err := store.ListUsers(tenant.ID)
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) == 0 {
		t.Error("ListUsers() returned empty list")
	}

	// Count users
	count, err := store.CountUsers(tenant.ID)
	if err != nil {
		t.Fatalf("CountUsers() error = %v", err)
	}
	if count < 1 {
		t.Errorf("CountUsers() = %d, want >= 1", count)
	}

	// Delete
	err = store.DeleteUser(user.ID)
	if err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
}

// Zone CRUD tests
func TestZone_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	zone := &Zone{
		Name:      "example.com",
		TenantID:  MainTenantID,
		Type:      ZoneTypeForward,
		Status:    ZoneStatusActive,
		Serial:    1,
		TTL:       3600,
		PrimaryNS: "ns1.example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create
	err := store.CreateZone(zone)
	if err != nil {
		t.Fatalf("CreateZone() error = %v", err)
	}

	// Get
	got, err := store.GetZone(zone.Name)
	if err != nil {
		t.Fatalf("GetZone() error = %v", err)
	}
	if got.Name != zone.Name {
		t.Errorf("GetZone() Name = %v, want %v", got.Name, zone.Name)
	}

	// GetZoneForName - should find zone for subdomain
	got, err = store.GetZoneForName("sub.example.com")
	if err != nil {
		t.Fatalf("GetZoneForName() error = %v", err)
	}
	if got.Name != zone.Name {
		t.Errorf("GetZoneForName() Name = %v, want %v", got.Name, zone.Name)
	}

	// Update
	zone.TTL = 7200
	err = store.UpdateZone(zone)
	if err != nil {
		t.Fatalf("UpdateZone() error = %v", err)
	}
	got, _ = store.GetZone(zone.Name)
	if got.TTL != 7200 {
		t.Errorf("UpdateZone() TTL = %v, want 7200", got.TTL)
	}

	// List
	zones, err := store.ListZones(MainTenantID)
	if err != nil {
		t.Fatalf("ListZones() error = %v", err)
	}
	found := false
	for _, z := range zones {
		if z.Name == zone.Name {
			found = true
			break
		}
	}
	if !found {
		t.Error("ListZones() did not include created zone")
	}

	// Increment serial
	err = store.IncrementZoneSerial(zone.Name)
	if err != nil {
		t.Fatalf("IncrementZoneSerial() error = %v", err)
	}
	serial, err := store.GetZoneSerial(zone.Name)
	if err != nil {
		t.Fatalf("GetZoneSerial() error = %v", err)
	}
	if serial <= 1 {
		t.Errorf("GetZoneSerial() = %d, want > 1", serial)
	}

	// Delete
	err = store.DeleteZone(zone.Name)
	if err != nil {
		t.Fatalf("DeleteZone() error = %v", err)
	}
}

// Record CRUD tests
func TestRecord_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// First create a zone
	zone := &Zone{
		Name:      "records.example.com",
		TenantID:  MainTenantID,
		Type:      ZoneTypeForward,
		Status:    ZoneStatusActive,
		Serial:    1,
		TTL:       3600,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	store.CreateZone(zone)

	// Create A record data
	aData, _ := json.Marshal(ARecordData{IP: "192.168.1.100"})
	record := &Record{
		ID:        "test-record-1",
		Zone:      zone.Name,
		Name:      "www",
		Type:      "A",
		TTL:       300,
		Enabled:   true,
		Data:      aData,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create
	err := store.CreateRecord(record)
	if err != nil {
		t.Fatalf("CreateRecord() error = %v", err)
	}

	// Get records
	records, err := store.GetRecords(zone.Name, "www", "A")
	if err != nil {
		t.Fatalf("GetRecords() error = %v", err)
	}
	if len(records) == 0 {
		t.Fatal("GetRecords() returned empty")
	}
	if records[0].Name != "www" {
		t.Errorf("GetRecords() Name = %v, want 'www'", records[0].Name)
	}

	// Get records by name
	records, err = store.GetRecordsByName(zone.Name, "www")
	if err != nil {
		t.Fatalf("GetRecordsByName() error = %v", err)
	}
	if len(records) == 0 {
		t.Fatal("GetRecordsByName() returned empty")
	}

	// Get all zone records
	records, err = store.GetAllZoneRecords(zone.Name)
	if err != nil {
		t.Fatalf("GetAllZoneRecords() error = %v", err)
	}
	if len(records) == 0 {
		t.Fatal("GetAllZoneRecords() returned empty")
	}

	// Query records
	records, err = store.QueryRecords("www.records.example.com", "A")
	if err != nil {
		t.Fatalf("QueryRecords() error = %v", err)
	}
	if len(records) == 0 {
		t.Fatal("QueryRecords() returned empty")
	}

	// Update
	record.TTL = 600
	err = store.UpdateRecord(record)
	if err != nil {
		t.Fatalf("UpdateRecord() error = %v", err)
	}
	records, _ = store.GetRecords(zone.Name, "www", "A")
	if len(records) > 0 && records[0].TTL != 600 {
		t.Errorf("UpdateRecord() TTL = %v, want 600", records[0].TTL)
	}

	// Count records
	count, err := store.CountRecords(zone.Name)
	if err != nil {
		t.Fatalf("CountRecords() error = %v", err)
	}
	if count < 1 {
		t.Errorf("CountRecords() = %d, want >= 1", count)
	}

	// Delete
	err = store.DeleteRecord(zone.Name, "www", "A", record.ID)
	if err != nil {
		t.Fatalf("DeleteRecord() error = %v", err)
	}
}

// Session tests
func TestSession_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	session := &Session{
		ID:         "test-session-1",
		UserID:     "user-1",
		Username:   "testuser",
		TenantID:   MainTenantID,
		Role:       RoleUser,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		AuthMethod: "password",
	}

	// Create
	err := store.CreateSession(session)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Get
	got, err := store.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got.Username != session.Username {
		t.Errorf("GetSession() Username = %v, want %v", got.Username, session.Username)
	}

	// Extend session
	err = store.ExtendSession(session.ID, 48*time.Hour)
	if err != nil {
		t.Fatalf("ExtendSession() error = %v", err)
	}

	// List user sessions
	sessions, err := store.ListUserSessions(session.UserID)
	if err != nil {
		t.Fatalf("ListUserSessions() error = %v", err)
	}
	if len(sessions) == 0 {
		t.Error("ListUserSessions() returned empty")
	}

	// Delete
	err = store.DeleteSession(session.ID)
	if err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}

	// Delete user sessions
	store.CreateSession(session)
	err = store.DeleteUserSessions(session.UserID)
	if err != nil {
		t.Fatalf("DeleteUserSessions() error = %v", err)
	}
}

// API Key tests
func TestAPIKey_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	apiKey := &APIKey{
		ID:          "test-apikey-1",
		Name:        "Test API Key",
		KeyHash:     "somehash123",
		KeyPrefix:   "dns_",
		TenantID:    MainTenantID,
		Permissions: []string{"read", "write"},
		CreatedAt:   time.Now(),
		CreatedBy:   "admin",
	}

	// Create
	err := store.CreateAPIKey(apiKey)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	// Get by ID
	got, err := store.GetAPIKey(apiKey.ID)
	if err != nil {
		t.Fatalf("GetAPIKey() error = %v", err)
	}
	if got.Name != apiKey.Name {
		t.Errorf("GetAPIKey() Name = %v, want %v", got.Name, apiKey.Name)
	}

	// Get by hash
	got, err = store.GetAPIKeyByHash(apiKey.KeyHash)
	if err != nil {
		t.Fatalf("GetAPIKeyByHash() error = %v", err)
	}
	if got.ID != apiKey.ID {
		t.Errorf("GetAPIKeyByHash() ID = %v, want %v", got.ID, apiKey.ID)
	}

	// Update
	apiKey.Name = "Updated API Key"
	err = store.UpdateAPIKey(apiKey)
	if err != nil {
		t.Fatalf("UpdateAPIKey() error = %v", err)
	}

	// Update last used
	err = store.UpdateAPIKeyLastUsed(apiKey.ID)
	if err != nil {
		t.Fatalf("UpdateAPIKeyLastUsed() error = %v", err)
	}

	// List
	keys, err := store.ListAPIKeys(MainTenantID)
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) == 0 {
		t.Error("ListAPIKeys() returned empty")
	}

	// Delete
	err = store.DeleteAPIKey(apiKey.ID)
	if err != nil {
		t.Fatalf("DeleteAPIKey() error = %v", err)
	}
}

// Config tests
func TestConfig_ServerConfig(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Get default config (should exist from init)
	config, err := store.GetServerConfig()
	if err != nil {
		t.Fatalf("GetServerConfig() error = %v", err)
	}
	if config == nil {
		t.Fatal("GetServerConfig() returned nil")
	}

	// Update config
	config.DNS.Address = "0.0.0.0"
	config.DNS.UDPPort = 5353
	err = store.UpdateServerConfig(config)
	if err != nil {
		t.Fatalf("UpdateServerConfig() error = %v", err)
	}

	// Verify update
	config, _ = store.GetServerConfig()
	if config.DNS.Address != "0.0.0.0" {
		t.Errorf("UpdateServerConfig() DNS.Address = %v, want '0.0.0.0'", config.DNS.Address)
	}
}

func TestConfig_RecursionConfig(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	config, err := store.GetRecursionConfig()
	if err != nil {
		t.Fatalf("GetRecursionConfig() error = %v", err)
	}

	config.Enabled = true
	err = store.UpdateRecursionConfig(config)
	if err != nil {
		t.Fatalf("UpdateRecursionConfig() error = %v", err)
	}
}

func TestConfig_RateLimitConfig(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	config, err := store.GetRateLimitConfig()
	if err != nil {
		t.Fatalf("GetRateLimitConfig() error = %v", err)
	}

	config.Enabled = true
	config.ResponsesPerSec = 100
	err = store.UpdateRateLimitConfig(config)
	if err != nil {
		t.Fatalf("UpdateRateLimitConfig() error = %v", err)
	}
}

func TestConfig_QueryLogConfig(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	config, err := store.GetQueryLogConfig()
	if err != nil {
		t.Fatalf("GetQueryLogConfig() error = %v", err)
	}

	config.Enabled = true
	err = store.UpdateQueryLogConfig(config)
	if err != nil {
		t.Fatalf("UpdateQueryLogConfig() error = %v", err)
	}
}

func TestConfig_GenericValues(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Set a value
	testVal := map[string]string{"key": "value"}
	err := store.SetConfigValue("test-config", testVal)
	if err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	// Get the value
	var got map[string]string
	err = store.GetConfigValue("test-config", &got)
	if err != nil {
		t.Fatalf("GetConfigValue() error = %v", err)
	}
	if got["key"] != "value" {
		t.Errorf("GetConfigValue() = %v, want {key: value}", got)
	}

	// List keys
	keys, err := store.ListConfigKeys()
	if err != nil {
		t.Fatalf("ListConfigKeys() error = %v", err)
	}
	found := false
	for _, k := range keys {
		if k == "test-config" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ListConfigKeys() did not include 'test-config'")
	}

	// Delete
	err = store.DeleteConfigValue("test-config")
	if err != nil {
		t.Fatalf("DeleteConfigValue() error = %v", err)
	}
}

// Bulk operations test
func TestBulkCreateRecords(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create a zone first
	zone := &Zone{
		Name:      "bulk.example.com",
		TenantID:  MainTenantID,
		Type:      ZoneTypeForward,
		Status:    ZoneStatusActive,
		Serial:    1,
		TTL:       3600,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	store.CreateZone(zone)

	// Create multiple records
	records := []Record{}
	for i := 0; i < 5; i++ {
		aData, _ := json.Marshal(ARecordData{IP: "192.168.1." + string(rune('0'+i))})
		records = append(records, Record{
			ID:        "bulk-record-" + string(rune('0'+i)),
			Zone:      zone.Name,
			Name:      "host" + string(rune('0'+i)),
			Type:      "A",
			TTL:       300,
			Enabled:   true,
			Data:      aData,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}

	err := store.BulkCreateRecords(records)
	if err != nil {
		t.Fatalf("BulkCreateRecords() error = %v", err)
	}

	// Verify
	allRecords, _ := store.GetAllZoneRecords(zone.Name)
	if len(allRecords) < 5 {
		t.Errorf("BulkCreateRecords() created %d records, want >= 5", len(allRecords))
	}
}

// Cleanup tests
func TestCleanupExpiredSessions(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create an expired session
	session := &Session{
		ID:         "expired-session",
		UserID:     "user-1",
		Username:   "testuser",
		TenantID:   MainTenantID,
		Role:       RoleUser,
		CreatedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt:  time.Now().Add(-24 * time.Hour), // Expired
		AuthMethod: "password",
	}
	store.CreateSession(session)

	// Run cleanup
	deleted, err := store.CleanupExpiredSessions()
	if err != nil {
		t.Fatalf("CleanupExpiredSessions() error = %v", err)
	}
	if deleted < 1 {
		t.Errorf("CleanupExpiredSessions() deleted %d, want >= 1", deleted)
	}
}
