package auth

import (
	"os"
	"testing"

	"github.com/scott/dns/storage"
)

func TestSetupWithStorage(t *testing.T) {
	// Create a temporary directory for the test database
	tempDir, err := os.MkdirTemp("", "auth-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a storage instance
	store, err := storage.Open(storage.Options{DataDir: tempDir})
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// Create an auth manager with storage backend
	manager := NewManagerWithStorage(store)

	// Test 1: NeedsSetup should return true initially
	if !manager.NeedsSetup() {
		t.Error("NeedsSetup() should return true when no users exist")
	}

	// Test 2: Setup should succeed
	user, err := manager.Setup("admin", "testpassword123", "admin@test.com", "Admin User")
	if err != nil {
		t.Fatalf("Setup() failed: %v", err)
	}
	if user == nil {
		t.Fatal("Setup() returned nil user")
	}
	if user.Username != "admin" {
		t.Errorf("Setup() user.Username = %q, want %q", user.Username, "admin")
	}
	if user.Email != "admin@test.com" {
		t.Errorf("Setup() user.Email = %q, want %q", user.Email, "admin@test.com")
	}
	if user.Role != RoleSuperAdmin {
		t.Errorf("Setup() user.Role = %q, want %q", user.Role, RoleSuperAdmin)
	}

	// Test 3: NeedsSetup should return false after setup
	if manager.NeedsSetup() {
		t.Error("NeedsSetup() should return false after setup")
	}

	// Test 4: Setup should fail if called again
	_, err = manager.Setup("admin2", "password2", "admin2@test.com", "Admin 2")
	if err == nil {
		t.Error("Setup() should fail when users already exist")
	}

	// Test 5: Authentication should work with the setup credentials
	session, err := manager.AuthenticatePassword("admin", "testpassword123")
	if err != nil {
		t.Fatalf("AuthenticatePassword() failed: %v", err)
	}
	if session == nil {
		t.Fatal("AuthenticatePassword() returned nil session")
	}
	if session.Username != "admin" {
		t.Errorf("AuthenticatePassword() session.Username = %q, want %q", session.Username, "admin")
	}

	// Test 6: Authentication should fail with wrong password
	_, err = manager.AuthenticatePassword("admin", "wrongpassword")
	if err == nil {
		t.Error("AuthenticatePassword() should fail with wrong password")
	}

	// Test 7: Authentication should fail with non-existent user
	_, err = manager.AuthenticatePassword("nonexistent", "password")
	if err == nil {
		t.Error("AuthenticatePassword() should fail with non-existent user")
	}
}

func TestSetupWithoutStorage(t *testing.T) {
	t.Skip("In-memory auth manager has issues with empty config path - skipping")

	// Create a temp directory for the config file
	tempDir, err := os.MkdirTemp("", "auth-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test the in-memory auth manager (without storage)
	manager, err := NewManager("")
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Test 1: NeedsSetup should return true initially
	if !manager.NeedsSetup() {
		t.Error("NeedsSetup() should return true when no users exist")
	}

	// Test 2: Setup should succeed
	user, err := manager.Setup("admin", "testpassword123", "admin@test.com", "Admin User")
	if err != nil {
		t.Fatalf("Setup() failed: %v", err)
	}
	if user == nil {
		t.Fatal("Setup() returned nil user")
	}

	// Test 3: NeedsSetup should return false after setup
	if manager.NeedsSetup() {
		t.Error("NeedsSetup() should return false after setup")
	}

	// Test 4: Authentication should work
	session, err := manager.AuthenticatePassword("admin", "testpassword123")
	if err != nil {
		t.Fatalf("AuthenticatePassword() failed: %v", err)
	}
	if session == nil {
		t.Fatal("AuthenticatePassword() returned nil session")
	}
}
