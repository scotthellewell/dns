package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/scott/dns/storage"
)

// setupTestManager creates a test auth manager with a super admin user and main tenant
func setupTestManager(t *testing.T) (*Manager, func()) {
	tempDir, err := os.MkdirTemp("", "auth-apikey-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	store, err := storage.Open(storage.Options{DataDir: tempDir})
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create storage: %v", err)
	}

	manager := NewManagerWithStorage(store)

	// Ensure main tenant exists (Setup creates it automatically)
	_, err = manager.Setup("admin", "adminpassword", "admin@test.com", "Admin User")
	if err != nil {
		store.Close()
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to setup admin: %v", err)
	}

	cleanup := func() {
		store.Close()
		os.RemoveAll(tempDir)
	}

	return manager, cleanup
}

// createAdminSession creates and returns a super admin session
func createAdminSession(t *testing.T, m *Manager) *Session {
	session, err := m.AuthenticatePassword("admin", "adminpassword")
	if err != nil {
		t.Fatalf("Failed to authenticate admin: %v", err)
	}
	return session
}

func TestAPIKeyCreation_AdminSuccess(t *testing.T) {
	manager, cleanup := setupTestManager(t)
	defer cleanup()

	session := createAdminSession(t, manager)

	req := httptest.NewRequest("POST", "/api/auth/apikeys", strings.NewReader(`{"name":"test-key","role":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(withSession(req.Context(), session))

	rr := httptest.NewRecorder()
	manager.handleAPIKeys(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("API key creation should return 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if _, ok := response["key"]; !ok {
		t.Error("Response should contain 'key' field")
	}
	if response["name"] != "test-key" {
		t.Errorf("Response name = %v, want 'test-key'", response["name"])
	}
	if response["role"] != "admin" {
		t.Errorf("Response role = %v, want 'admin'", response["role"])
	}
}

func TestAPIKeyCreation_RolePermissions(t *testing.T) {
	manager, cleanup := setupTestManager(t)
	defer cleanup()

	session := createAdminSession(t, manager)

	tests := []struct {
		name       string
		role       string
		wantStatus int
		wantPerm   []string
	}{
		{"readonly role", "readonly", http.StatusCreated, []string{"read"}},
		{"admin role", "admin", http.StatusCreated, []string{"admin"}},
		{"super_admin role", "super_admin", http.StatusCreated, []string{"*"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/auth/apikeys",
				strings.NewReader(`{"name":"test-`+tt.role+`","role":"`+tt.role+`"}`))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(withSession(req.Context(), session))

			rr := httptest.NewRecorder()
			manager.handleAPIKeys(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("Status = %d, want %d: %s", rr.Code, tt.wantStatus, rr.Body.String())
				return
			}

			if tt.wantStatus == http.StatusCreated {
				var response map[string]interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}

				perms, ok := response["permissions"].([]interface{})
				if !ok {
					t.Errorf("Response should contain permissions array")
					return
				}

				if len(perms) != len(tt.wantPerm) {
					t.Errorf("Permissions length = %d, want %d", len(perms), len(tt.wantPerm))
				}
				for i, p := range tt.wantPerm {
					if perms[i] != p {
						t.Errorf("Permission[%d] = %v, want %v", i, perms[i], p)
					}
				}
			}
		})
	}
}

func TestAPIKeyCreation_AdminRequired(t *testing.T) {
	manager, cleanup := setupTestManager(t)
	defer cleanup()

	// Create a regular user (note: role comes before tenantID)
	_, err := manager.CreateUser("regularuser", "password123", "user@test.com", "Regular User", RoleReadonly, "main")
	if err != nil {
		t.Fatalf("Failed to create regular user: %v", err)
	}

	// Authenticate as regular user
	session, err := manager.AuthenticatePassword("regularuser", "password123")
	if err != nil {
		t.Fatalf("Failed to authenticate regular user: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/auth/apikeys", strings.NewReader(`{"name":"test-key","role":"readonly"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(withSession(req.Context(), session))

	rr := httptest.NewRecorder()
	manager.handleAPIKeys(rr, req)

	// Should be forbidden for non-admins
	if rr.Code != http.StatusForbidden {
		t.Errorf("API key creation should return 403 for non-admin, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAPIKeyRoles_Endpoint(t *testing.T) {
	manager, cleanup := setupTestManager(t)
	defer cleanup()

	session := createAdminSession(t, manager)

	req := httptest.NewRequest("GET", "/api/auth/apikeys/roles", nil)
	req = req.WithContext(withSession(req.Context(), session))

	rr := httptest.NewRecorder()
	manager.handleAPIKeyRoles(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("API key roles should return 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var roles []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &roles); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Super admin session should see all 3 roles
	if len(roles) != 3 {
		t.Errorf("Super admin should see 3 roles, got %d", len(roles))
	}

	roleValues := make(map[string]bool)
	for _, r := range roles {
		roleValues[r["value"].(string)] = true
	}

	expectedRoles := []string{"readonly", "admin", "super_admin"}
	for _, er := range expectedRoles {
		if !roleValues[er] {
			t.Errorf("Missing expected role: %s", er)
		}
	}
}

func TestAPIKeyDeletion_AdminCanDeleteAny(t *testing.T) {
	manager, cleanup := setupTestManager(t)
	defer cleanup()

	session := createAdminSession(t, manager)

	// Create an API key
	apiKey, _, err := manager.CreateAPIKey("test-key", []string{"read"}, "main", nil, session.UserID)
	if err != nil {
		t.Fatalf("Failed to create API key: %v", err)
	}

	// Delete it
	req := httptest.NewRequest("DELETE", "/api/auth/apikeys/"+apiKey.ID, nil)
	req = req.WithContext(withSession(req.Context(), session))

	rr := httptest.NewRecorder()
	manager.handleAPIKey(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Admin API key deletion should return 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAPIKeyDeletion_NonAdminOnlyOwnKeys(t *testing.T) {
	manager, cleanup := setupTestManager(t)
	defer cleanup()

	adminSession := createAdminSession(t, manager)

	// Create API key as admin
	apiKey, _, err := manager.CreateAPIKey("admin-key", []string{"read"}, "main", nil, adminSession.UserID)
	if err != nil {
		t.Fatalf("Failed to create API key: %v", err)
	}

	// Create regular user (role comes before tenantID)
	_, err = manager.CreateUser("regularuser", "password123", "user@test.com", "Regular User", RoleReadonly, "main")
	if err != nil {
		t.Fatalf("Failed to create regular user: %v", err)
	}

	userSession, err := manager.AuthenticatePassword("regularuser", "password123")
	if err != nil {
		t.Fatalf("Failed to authenticate user: %v", err)
	}

	// Try to delete admin's key as regular user
	req := httptest.NewRequest("DELETE", "/api/auth/apikeys/"+apiKey.ID, nil)
	req = req.WithContext(withSession(req.Context(), userSession))

	rr := httptest.NewRecorder()
	manager.handleAPIKey(rr, req)

	// Should be forbidden
	if rr.Code != http.StatusForbidden {
		t.Errorf("Non-admin deleting other's key should return 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAPIKeyAuthentication(t *testing.T) {
	manager, cleanup := setupTestManager(t)
	defer cleanup()

	session := createAdminSession(t, manager)

	// Create API key with admin permission
	_, rawKey, err := manager.CreateAPIKey("test-key", []string{"admin"}, "main", nil, session.UserID)
	if err != nil {
		t.Fatalf("Failed to create API key: %v", err)
	}

	// Authenticate with API key
	apiSession, err := manager.AuthenticateAPIKey(rawKey)
	if err != nil {
		t.Fatalf("Failed to authenticate with API key: %v", err)
	}

	// "admin" permission maps to "admin" role (tenant admin)
	if apiSession.Role != "admin" {
		t.Errorf("API key session role = %s, want 'admin'", apiSession.Role)
	}
	if apiSession.TenantID != "main" {
		t.Errorf("API key session tenant = %s, want 'main'", apiSession.TenantID)
	}
}

func TestAPIKeyAuthentication_SuperAdmin(t *testing.T) {
	manager, cleanup := setupTestManager(t)
	defer cleanup()

	session := createAdminSession(t, manager)

	// Create super admin API key with "*" permission
	_, rawKey, err := manager.CreateAPIKey("super-key", []string{"*"}, "main", nil, session.UserID)
	if err != nil {
		t.Fatalf("Failed to create API key: %v", err)
	}

	// Authenticate with API key
	apiSession, err := manager.AuthenticateAPIKey(rawKey)
	if err != nil {
		t.Fatalf("Failed to authenticate with API key: %v", err)
	}

	if !apiSession.IsSuperAdmin {
		t.Error("Super admin API key should set IsSuperAdmin = true")
	}
	// "*" permission maps to "super_admin" role
	if apiSession.Role != "super_admin" {
		t.Errorf("API key session role = %s, want 'super_admin'", apiSession.Role)
	}
}

func TestAPIKeyTenantIsolation(t *testing.T) {
	manager, cleanup := setupTestManager(t)
	defer cleanup()

	session := createAdminSession(t, manager)

	// Create API key for main tenant
	apiKey, _, err := manager.CreateAPIKey("main-key", []string{"admin"}, "main", nil, session.UserID)
	if err != nil {
		t.Fatalf("Failed to create API key: %v", err)
	}

	// Verify tenant is set
	if apiKey.TenantID != "main" {
		t.Errorf("API key tenant = %s, want 'main'", apiKey.TenantID)
	}
}

func TestPermissionsToRole(t *testing.T) {
	manager, cleanup := setupTestManager(t)
	defer cleanup()

	tests := []struct {
		permissions []string
		wantRole    string
	}{
		{[]string{"*"}, "super_admin"},    // "*" = super_admin
		{[]string{"admin"}, "admin"},      // "admin" = admin (tenant admin)
		{[]string{"write"}, "user"},       // "write" = user
		{[]string{"read"}, "readonly"},    // "read" = readonly
		{[]string{}, "readonly"},          // empty = readonly
		{[]string{"unknown"}, "readonly"}, // unknown = readonly
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.permissions, ","), func(t *testing.T) {
			role := manager.permissionsToRole(tt.permissions)
			if role != tt.wantRole {
				t.Errorf("permissionsToRole(%v) = %s, want %s", tt.permissions, role, tt.wantRole)
			}
		})
	}
}
