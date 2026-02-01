package auth

import (
	"errors"
	"sync"
	"time"

	"github.com/scott/dns/storage"
)

// StorageInterface defines the storage methods needed by auth manager
type StorageInterface interface {
	// User operations
	GetUserByUsername(username string) (*storage.User, error)
	UpdateUser(user *storage.User) error
	ValidatePassword(username, password string) (*storage.User, error)
	ListUsers(tenantID string) ([]*storage.User, error)
	CreateUserWithPassword(user *storage.User, password string) error
	UpdateUserPassword(userID, password string) error
	DeleteUser(id string) error
	AddWebAuthnCredential(userID string, cred *storage.WebAuthnCredential) error
	RemoveWebAuthnCredential(userID, credID string) error
	UpdateWebAuthnCredentialSignCount(userID string, credentialID []byte, signCount uint32) error
	GetUserByCredentialID(credentialID []byte) (*storage.User, error)
	CountUsers(tenantID string) (int, error)

	// Session operations
	CreateSession(session *storage.Session) error
	GetSession(id string) (*storage.Session, error)
	DeleteSession(id string) error

	// API Key operations
	GetAPIKeyByHash(hash string) (*storage.APIKey, error)
	UpdateAPIKeyLastUsed(id string) error
	ListAPIKeys(tenantID string) ([]*storage.APIKey, error)
	CreateAPIKey(apiKey *storage.APIKey) error
	DeleteAPIKey(id string) error

	// Tenant operations
	GetTenant(id string) (*storage.Tenant, error)
	ListTenants() ([]*storage.Tenant, error)
	CreateTenant(tenant *storage.Tenant) error
	UpdateTenant(tenant *storage.Tenant) error
	DeleteTenant(id string) error

	// Config operations
	GetConfigValue(key string, v interface{}) error
	SetConfigValue(key string, v interface{}) error
}

// StorageManager is an auth manager backed by storage
type StorageManager struct {
	store    StorageInterface
	config   *AuthConfig // Cached config for OIDC/WebAuthn settings
	configMu sync.RWMutex
}

// NewManagerWithStorage creates a new auth manager using storage backend
func NewManagerWithStorage(store StorageInterface) *Manager {
	sm := &StorageManager{
		store: store,
		config: &AuthConfig{
			Enabled:       true, // Always enabled with storage
			SessionMaxAge: 86400,
		},
	}

	// Load OIDC/WebAuthn config from storage if available
	sm.loadConfig()

	// Return a Manager that wraps the storage manager
	return &Manager{
		config:         sm.config,
		sessions:       make(map[string]*Session),
		storageManager: sm,
	}
}

func (sm *StorageManager) loadConfig() {
	// Try to load OIDC config from storage
	var oidcConfig OIDCConfig
	if err := sm.store.GetConfigValue("oidc", &oidcConfig); err == nil {
		sm.config.OIDC = &oidcConfig
	}

	// Try to load WebAuthn config from storage
	var webauthnConfig WebAuthnConfig
	if err := sm.store.GetConfigValue("webauthn", &webauthnConfig); err == nil {
		sm.config.WebAuthn = &webauthnConfig
	}
}

// AuthenticatePassword authenticates a user with username/password
func (sm *StorageManager) AuthenticatePassword(username, password string) (*Session, error) {
	user, err := sm.store.ValidatePassword(username, password)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, ErrUserNotFound
		}
		return nil, ErrInvalidCredentials
	}

	// Update last login
	user.LastLogin = time.Now()
	sm.store.UpdateUser(user)

	return sm.createSession(user, "password")
}

// AuthenticateAPIKey authenticates using an API key
func (sm *StorageManager) AuthenticateAPIKey(key string) (*Session, error) {
	keyHash := HashAPIKey(key)

	apiKey, err := sm.store.GetAPIKeyByHash(keyHash)
	if err != nil {
		return nil, ErrInvalidAPIKey
	}

	// Check expiration
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	// Update last used
	sm.store.UpdateAPIKeyLastUsed(apiKey.ID)

	// Create session from API key
	session := &Session{
		ID:         apiKey.ID,
		UserID:     "apikey:" + apiKey.ID,
		Username:   "API Key: " + apiKey.Name,
		TenantID:   apiKey.TenantID,
		Role:       sm.permissionsToRole(apiKey.Permissions),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
		AuthMethod: "apikey",
	}

	return session, nil
}

func (sm *StorageManager) permissionsToRole(permissions []string) string {
	for _, p := range permissions {
		if p == "admin" {
			return RoleSuperAdmin
		}
	}
	for _, p := range permissions {
		if p == "write" {
			return RoleUser
		}
	}
	return RoleReadonly
}

func (sm *StorageManager) createSession(user *storage.User, authMethod string) (*Session, error) {
	sessionID, err := GenerateSessionID()
	if err != nil {
		return nil, err
	}

	maxAge := 86400
	if sm.config.SessionMaxAge > 0 {
		maxAge = sm.config.SessionMaxAge
	}

	tenantID := user.TenantID
	if tenantID == "" {
		tenantID = MainTenantID
	}

	// Get tenant name
	tenantName := ""
	tenant, err := sm.store.GetTenant(tenantID)
	if err == nil && tenant != nil {
		tenantName = tenant.Name
	}
	if tenantName == "" && tenantID == MainTenantID {
		tenantName = "Main"
	}

	isSuperAdmin := user.Role == RoleSuperAdmin ||
		(user.Role == RoleTenantAdmin && tenantID == MainTenantID)

	session := &Session{
		ID:           sessionID,
		UserID:       user.ID,
		Username:     user.Username,
		TenantID:     tenantID,
		TenantName:   tenantName,
		Role:         user.Role,
		IsSuperAdmin: isSuperAdmin,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(maxAge) * time.Second),
		AuthMethod:   authMethod,
	}

	// Store session in storage
	storageSession := &storage.Session{
		ID:           session.ID,
		UserID:       session.UserID,
		Username:     session.Username,
		TenantID:     session.TenantID,
		TenantName:   session.TenantName,
		Role:         session.Role,
		IsSuperAdmin: session.IsSuperAdmin,
		CreatedAt:    session.CreatedAt,
		ExpiresAt:    session.ExpiresAt,
		AuthMethod:   session.AuthMethod,
	}
	sm.store.CreateSession(storageSession)

	return session, nil
}

// ValidateSession validates a session token
func (sm *StorageManager) ValidateSession(sessionID string) (*Session, error) {
	storageSession, err := sm.store.GetSession(sessionID)
	if err != nil {
		return nil, ErrUnauthorized
	}

	if time.Now().After(storageSession.ExpiresAt) {
		sm.store.DeleteSession(sessionID)
		return nil, ErrSessionExpired
	}

	return &Session{
		ID:           storageSession.ID,
		UserID:       storageSession.UserID,
		Username:     storageSession.Username,
		TenantID:     storageSession.TenantID,
		TenantName:   storageSession.TenantName,
		Role:         storageSession.Role,
		IsSuperAdmin: storageSession.IsSuperAdmin,
		CreatedAt:    storageSession.CreatedAt,
		ExpiresAt:    storageSession.ExpiresAt,
		AuthMethod:   storageSession.AuthMethod,
	}, nil
}

// InvalidateSession removes a session
func (sm *StorageManager) InvalidateSession(sessionID string) {
	sm.store.DeleteSession(sessionID)
}

// CreateUser creates a new user
func (sm *StorageManager) CreateUser(username, password, email, displayName, role, tenantID string) (*User, error) {
	// Check if user exists
	existing, _ := sm.store.GetUserByUsername(username)
	if existing != nil {
		return nil, ErrUserExists
	}

	// Verify tenant exists if specified
	if tenantID != "" && tenantID != MainTenantID {
		tenant, err := sm.store.GetTenant(tenantID)
		if err != nil || tenant == nil {
			return nil, ErrTenantNotFound
		}
	}

	id, _ := GenerateSessionID()
	user := &storage.User{
		ID:          id[:16],
		Username:    username,
		Email:       email,
		DisplayName: displayName,
		Role:        role,
		TenantID:    tenantID,
		CreatedAt:   time.Now(),
	}

	if err := sm.store.CreateUserWithPassword(user, password); err != nil {
		return nil, err
	}

	return &User{
		ID:          user.ID,
		Username:    user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Role:        user.Role,
		TenantID:    user.TenantID,
		CreatedAt:   user.CreatedAt,
	}, nil
}

// UpdateUserPassword updates a user's password
func (sm *StorageManager) UpdateUserPassword(userID, newPassword string) error {
	return sm.store.UpdateUserPassword(userID, newPassword)
}

// DeleteUser removes a user
func (sm *StorageManager) DeleteUser(userID string) error {
	return sm.store.DeleteUser(userID)
}

// CreateAPIKey creates a new API key
func (sm *StorageManager) CreateAPIKey(name string, permissions []string, tenantID string, expiresAt *time.Time, createdBy string) (*APIKey, string, error) {
	rawKey, err := GenerateAPIKey()
	if err != nil {
		return nil, "", err
	}

	id, _ := GenerateSessionID()
	apiKey := &storage.APIKey{
		ID:          id[:16],
		Name:        name,
		KeyHash:     HashAPIKey(rawKey),
		KeyPrefix:   rawKey[:12],
		TenantID:    tenantID,
		Permissions: permissions,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		CreatedBy:   createdBy,
	}

	if err := sm.store.CreateAPIKey(apiKey); err != nil {
		return nil, "", err
	}

	return &APIKey{
		ID:          apiKey.ID,
		Name:        apiKey.Name,
		KeyPrefix:   apiKey.KeyPrefix,
		TenantID:    apiKey.TenantID,
		Permissions: apiKey.Permissions,
		CreatedAt:   apiKey.CreatedAt,
		ExpiresAt:   apiKey.ExpiresAt,
		CreatedBy:   apiKey.CreatedBy,
	}, rawKey, nil
}

// DeleteAPIKey removes an API key
func (sm *StorageManager) DeleteAPIKey(keyID string) error {
	return sm.store.DeleteAPIKey(keyID)
}

// ListUsers returns all users
func (sm *StorageManager) ListUsers(tenantID string) []User {
	users, err := sm.store.ListUsers(tenantID)
	if err != nil {
		return nil
	}

	result := make([]User, len(users))
	for i, u := range users {
		result[i] = User{
			ID:          u.ID,
			Username:    u.Username,
			Email:       u.Email,
			DisplayName: u.DisplayName,
			Role:        u.Role,
			TenantID:    u.TenantID,
			CreatedAt:   u.CreatedAt,
			LastLogin:   u.LastLogin,
		}
	}
	return result
}

// ListAPIKeys returns all API keys
func (sm *StorageManager) ListAPIKeys(tenantID string) []APIKey {
	keys, err := sm.store.ListAPIKeys(tenantID)
	if err != nil {
		return nil
	}

	result := make([]APIKey, len(keys))
	for i, k := range keys {
		result[i] = APIKey{
			ID:          k.ID,
			Name:        k.Name,
			KeyPrefix:   k.KeyPrefix,
			TenantID:    k.TenantID,
			Permissions: k.Permissions,
			CreatedAt:   k.CreatedAt,
			ExpiresAt:   k.ExpiresAt,
			LastUsed:    k.LastUsed,
			CreatedBy:   k.CreatedBy,
		}
	}
	return result
}

// IsEnabled returns whether auth is enabled (always true with storage)
func (sm *StorageManager) IsEnabled() bool {
	return true
}

// GetConfig returns the auth config
func (sm *StorageManager) GetConfig() AuthConfig {
	sm.configMu.RLock()
	defer sm.configMu.RUnlock()
	return *sm.config
}

// NeedsSetup returns true if initial setup is required (no users exist)
func (sm *StorageManager) NeedsSetup() bool {
	count, err := sm.store.CountUsers("")
	if err != nil {
		return true // Assume setup needed if we can't count
	}
	return count == 0
}

// Setup performs initial setup creating the main tenant and super admin user
func (sm *StorageManager) Setup(adminUsername, adminPassword, adminEmail, adminDisplayName string) (*User, error) {
	// Verify no users exist
	count, err := sm.store.CountUsers("")
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, ErrUserExists
	}

	// Create user using the storage manager's CreateUser method
	user, err := sm.CreateUser(adminUsername, adminPassword, adminEmail, adminDisplayName, RoleSuperAdmin, MainTenantID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// ListTenants returns all tenants from storage
func (sm *StorageManager) ListTenants() []Tenant {
	tenants, err := sm.store.ListTenants()
	if err != nil {
		return []Tenant{}
	}

	result := make([]Tenant, 0, len(tenants))
	for _, t := range tenants {
		result = append(result, Tenant{
			ID:          t.ID,
			Name:        t.Name,
			Description: t.Description,
			IsMain:      t.IsMain,
			CreatedAt:   t.CreatedAt,
			CreatedBy:   t.CreatedBy,
		})
	}
	return result
}

// GetTenant returns a tenant by ID from storage
func (sm *StorageManager) GetTenant(tenantID string) (*Tenant, error) {
	t, err := sm.store.GetTenant(tenantID)
	if err != nil {
		return nil, ErrTenantNotFound
	}
	return &Tenant{
		ID:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		IsMain:      t.IsMain,
		CreatedAt:   t.CreatedAt,
		CreatedBy:   t.CreatedBy,
	}, nil
}

// CreateTenant creates a new tenant in storage
func (sm *StorageManager) CreateTenant(id, name, description, createdBy string) (*Tenant, error) {
	tenant := &storage.Tenant{
		ID:          id,
		Name:        name,
		Description: description,
		IsMain:      false,
		CreatedAt:   time.Now(),
		CreatedBy:   createdBy,
	}

	if err := sm.store.CreateTenant(tenant); err != nil {
		if err == storage.ErrAlreadyExists {
			return nil, ErrTenantExists
		}
		return nil, err
	}

	return &Tenant{
		ID:          tenant.ID,
		Name:        tenant.Name,
		Description: tenant.Description,
		IsMain:      tenant.IsMain,
		CreatedAt:   tenant.CreatedAt,
		CreatedBy:   tenant.CreatedBy,
	}, nil
}

// UpdateTenant updates a tenant in storage
func (sm *StorageManager) UpdateTenant(tenantID, name, description string) (*Tenant, error) {
	t, err := sm.store.GetTenant(tenantID)
	if err != nil {
		return nil, ErrTenantNotFound
	}

	t.Name = name
	t.Description = description

	if err := sm.store.UpdateTenant(t); err != nil {
		return nil, err
	}

	return &Tenant{
		ID:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		IsMain:      t.IsMain,
		CreatedAt:   t.CreatedAt,
		CreatedBy:   t.CreatedBy,
	}, nil
}

// DeleteTenant removes a tenant from storage
func (sm *StorageManager) DeleteTenant(tenantID string) error {
	t, err := sm.store.GetTenant(tenantID)
	if err != nil {
		return ErrTenantNotFound
	}

	if t.IsMain {
		return errors.New("cannot delete main tenant")
	}

	return sm.store.DeleteTenant(tenantID)
}
