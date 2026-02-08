package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrSessionExpired     = errors.New("session expired")
	ErrInvalidAPIKey      = errors.New("invalid API key")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrTenantNotFound     = errors.New("tenant not found")
	ErrTenantExists       = errors.New("tenant already exists")
	ErrNotSuperAdmin      = errors.New("super admin access required")
	ErrSetupRequired      = errors.New("initial setup required")
)

// Role constants
const (
	RoleSuperAdmin  = "super_admin"  // Can manage all tenants, users, zones
	RoleTenantAdmin = "tenant_admin" // Can manage users and zones in their tenant
	RoleUser        = "user"         // Can view/edit zones in their tenant
	RoleReadonly    = "readonly"     // Read-only access to tenant zones
)

// MainTenantID is the ID of the main/system tenant
const MainTenantID = "main"

// Tenant represents an organization/tenant in the multi-tenant system
type Tenant struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	IsMain      bool      `json:"is_main,omitempty"` // Main tenant has super-admin privileges
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Enabled       bool            `json:"enabled"`
	SessionSecret string          `json:"session_secret"`
	SessionMaxAge int             `json:"session_max_age"` // seconds, default 86400 (24h)
	Tenants       []Tenant        `json:"tenants"`
	Users         []User          `json:"users"`
	APIKeys       []APIKey        `json:"api_keys"`
	OIDC          *OIDCConfig     `json:"oidc,omitempty"`
	WebAuthn      *WebAuthnConfig `json:"webauthn,omitempty"`
}

// User represents a local user account
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Email        string    `json:"email,omitempty"`
	DisplayName  string    `json:"display_name,omitempty"`
	TenantID     string    `json:"tenant_id"` // Tenant this user belongs to
	Role         string    `json:"role"`      // super_admin, tenant_admin, user, readonly
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login,omitempty"`
	// WebAuthn credentials stored separately
	WebAuthnCredentials []WebAuthnCredential `json:"webauthn_credentials,omitempty"`
}

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	KeyHash     string     `json:"key_hash"`    // Only store hash
	KeyPrefix   string     `json:"key_prefix"`  // First 8 chars for display
	TenantID    string     `json:"tenant_id"`   // Tenant this key belongs to
	Permissions []string   `json:"permissions"` // read, write, admin
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
	CreatedBy   string     `json:"created_by"`
}

// OIDCConfig holds OpenID Connect configuration
type OIDCConfig struct {
	Enabled      bool     `json:"enabled"`
	ProviderURL  string   `json:"provider_url"`
	ProviderName string   `json:"provider_name"`
	ProviderIcon string   `json:"provider_icon,omitempty"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
	// Map OIDC claims to roles
	AdminGroups   []string `json:"admin_groups,omitempty"`
	AllowedGroups []string `json:"allowed_groups,omitempty"`
}

// WebAuthnConfig holds WebAuthn/Passkey configuration
type WebAuthnConfig struct {
	Enabled       bool     `json:"enabled"`
	RPDisplayName string   `json:"rp_display_name"`
	RPID          string   `json:"rp_id"`
	RPOrigins     []string `json:"rp_origins"`
}

// WebAuthnCredential represents a stored passkey credential
type WebAuthnCredential struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	CredentialID    []byte     `json:"credential_id"`
	PublicKey       []byte     `json:"public_key"`
	AttestationType string     `json:"attestation_type"`
	AAGUID          []byte     `json:"aaguid"`
	SignCount       uint32     `json:"sign_count"`
	BackupEligible  bool       `json:"backup_eligible"`
	BackupState     bool       `json:"backup_state"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsed        *time.Time `json:"last_used,omitempty"`
}

// Session represents an authenticated session
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	TenantID     string    `json:"tenant_id"`
	TenantName   string    `json:"tenant_name,omitempty"`
	Role         string    `json:"role"`
	IsSuperAdmin bool      `json:"is_super_admin"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	AuthMethod   string    `json:"auth_method"` // password, webauthn, oidc, apikey
}

// Manager handles authentication
type Manager struct {
	config         *AuthConfig
	configPath     string
	sessionsPath   string
	sessions       map[string]*Session
	mu             sync.RWMutex
	configMu       sync.RWMutex
	storageManager *StorageManager // Optional storage backend
}

// NewManager creates a new auth manager
func NewManager(configPath string) (*Manager, error) {
	// Sessions file is alongside config file
	sessionsPath := configPath[:len(configPath)-5] + "-sessions.json"

	m := &Manager{
		configPath:   configPath,
		sessionsPath: sessionsPath,
		sessions:     make(map[string]*Session),
	}

	if err := m.loadConfig(); err != nil {
		// If config doesn't exist, create default
		if os.IsNotExist(err) {
			m.config = &AuthConfig{
				Enabled:       false,
				SessionMaxAge: 86400,
				Users:         []User{},
				APIKeys:       []APIKey{},
			}
			// Save default config
			if saveErr := m.saveConfig(); saveErr != nil {
				log.Printf("Warning: Could not save default auth config: %v", saveErr)
			} else {
				log.Printf("Created default auth config at %s", configPath)
			}
			return m, nil
		}
		return nil, err
	}

	// Load persisted sessions
	m.loadSessions()

	return m, nil
}

func (m *Manager) loadConfig() error {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}

	var config AuthConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	m.config = &config
	return nil
}

func (m *Manager) loadSessions() {
	data, err := os.ReadFile(m.sessionsPath)
	if err != nil {
		// No sessions file is fine
		return
	}

	var sessions map[string]*Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		return
	}

	// Only load non-expired sessions
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for id, session := range sessions {
		if session.ExpiresAt.After(now) {
			m.sessions[id] = session
		}
	}
}

func (m *Manager) saveSessions() {
	m.mu.RLock()
	data, err := json.MarshalIndent(m.sessions, "", "  ")
	m.mu.RUnlock()

	if err != nil {
		return
	}

	os.WriteFile(m.sessionsPath, data, 0600)
}

func (m *Manager) saveConfig() error {
	m.configMu.Lock()
	defer m.configMu.Unlock()
	return m.saveConfigLocked()
}

// saveConfigLocked saves config without acquiring lock (caller must hold lock)
func (m *Manager) saveConfigLocked() error {
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.configPath, data, 0600)
}

// GetConfig returns the current auth config (without sensitive data)
func (m *Manager) GetConfig() AuthConfig {
	m.configMu.RLock()
	defer m.configMu.RUnlock()

	// Return copy without password hashes and secrets
	config := *m.config
	config.SessionSecret = ""

	if config.OIDC != nil {
		oidcCopy := *config.OIDC
		oidcCopy.ClientSecret = ""
		config.OIDC = &oidcCopy
	}

	// Remove password hashes from users
	users := make([]User, len(config.Users))
	for i, u := range config.Users {
		users[i] = u
		users[i].PasswordHash = ""
	}
	config.Users = users

	// Remove key hashes from API keys
	keys := make([]APIKey, len(config.APIKeys))
	for i, k := range config.APIKeys {
		keys[i] = k
		keys[i].KeyHash = ""
	}
	config.APIKeys = keys

	return config
}

// IsEnabled returns whether auth is enabled
func (m *Manager) IsEnabled() bool {
	// Storage manager is always enabled
	if m.storageManager != nil {
		return m.storageManager.IsEnabled()
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()
	return m.config != nil && m.config.Enabled
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword verifies a password against a hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateSessionID generates a secure random session ID
func GenerateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateAPIKey generates a new API key
func GenerateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "dns_" + base64.URLEncoding.EncodeToString(bytes), nil
}

// HashAPIKey creates a hash of an API key for storage
func HashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// AuthenticatePassword authenticates a user with username/password
func (m *Manager) AuthenticatePassword(username, password string) (*Session, error) {
	// Delegate to storage manager if available
	if m.storageManager != nil {
		return m.storageManager.AuthenticatePassword(username, password)
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()

	for i, user := range m.config.Users {
		if user.Username == username {
			if !CheckPassword(password, user.PasswordHash) {
				return nil, ErrInvalidCredentials
			}

			// Update last login
			m.config.Users[i].LastLogin = time.Now()
			go m.saveConfig()

			return m.createSession(&user, "password")
		}
	}

	return nil, ErrUserNotFound
}

// AuthenticateAPIKey authenticates using an API key
func (m *Manager) AuthenticateAPIKey(key string) (*Session, error) {
	// Delegate to storage manager if available
	if m.storageManager != nil {
		return m.storageManager.AuthenticateAPIKey(key)
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()

	keyHash := HashAPIKey(key)

	for i, apiKey := range m.config.APIKeys {
		if subtle.ConstantTimeCompare([]byte(apiKey.KeyHash), []byte(keyHash)) == 1 {
			// Check expiration
			if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
				return nil, ErrSessionExpired
			}

			// Update last used
			now := time.Now()
			m.config.APIKeys[i].LastUsed = &now
			go m.saveConfig()

			role := m.permissionsToRole(apiKey.Permissions)

			// Create session from API key
			session := &Session{
				ID:           apiKey.ID,
				UserID:       "apikey:" + apiKey.ID,
				Username:     "API Key: " + apiKey.Name,
				TenantID:     apiKey.TenantID,
				Role:         role,
				IsSuperAdmin: role == "admin",
				CreatedAt:    time.Now(),
				ExpiresAt:    time.Now().Add(time.Hour), // API key sessions are short-lived
				AuthMethod:   "apikey",
			}

			return session, nil
		}
	}

	return nil, ErrInvalidAPIKey
}

func (m *Manager) permissionsToRole(permissions []string) string {
	for _, p := range permissions {
		if p == "*" {
			return RoleSuperAdmin
		}
	}
	for _, p := range permissions {
		if p == "admin" {
			return "admin" // "admin" permission maps to "admin" role for API keys
		}
	}
	for _, p := range permissions {
		if p == "write" {
			return RoleUser
		}
	}
	return RoleReadonly
}

func (m *Manager) createSession(user *User, authMethod string) (*Session, error) {
	sessionID, err := GenerateSessionID()
	if err != nil {
		return nil, err
	}

	maxAge := 86400
	if m.config.SessionMaxAge > 0 {
		maxAge = m.config.SessionMaxAge
	}

	// Normalize tenant ID - empty means main tenant
	userTenantID := user.TenantID
	if userTenantID == "" {
		userTenantID = MainTenantID
	}

	// Get tenant name
	tenantName := ""
	for _, t := range m.config.Tenants {
		if t.ID == userTenantID {
			tenantName = t.Name
			break
		}
	}
	// Default name for main tenant if not found
	if tenantName == "" && userTenantID == MainTenantID {
		tenantName = "Main"
	}

	// Check if user should be super admin (admin role in main tenant)
	isSuperAdmin := user.Role == RoleSuperAdmin || (user.Role == RoleTenantAdmin && userTenantID == MainTenantID)

	session := &Session{
		ID:           sessionID,
		UserID:       user.ID,
		Username:     user.Username,
		TenantID:     userTenantID,
		TenantName:   tenantName,
		Role:         user.Role,
		IsSuperAdmin: isSuperAdmin,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(maxAge) * time.Second),
		AuthMethod:   authMethod,
	}

	m.mu.Lock()
	m.sessions[sessionID] = session
	m.mu.Unlock()

	// Persist sessions
	go m.saveSessions()

	return session, nil
}

// ValidateSession validates a session token
func (m *Manager) ValidateSession(sessionID string) (*Session, error) {
	// Delegate to storage manager if available
	if m.storageManager != nil {
		return m.storageManager.ValidateSession(sessionID)
	}

	m.mu.RLock()
	session, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrUnauthorized
	}

	if time.Now().After(session.ExpiresAt) {
		m.mu.Lock()
		delete(m.sessions, sessionID)
		m.mu.Unlock()
		go m.saveSessions()
		return nil, ErrSessionExpired
	}

	return session, nil
}

// InvalidateSession removes a session
func (m *Manager) InvalidateSession(sessionID string) {
	// Delegate to storage manager if available
	if m.storageManager != nil {
		m.storageManager.InvalidateSession(sessionID)
		return
	}

	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
	go m.saveSessions()
}

// CreateUser creates a new user
func (m *Manager) CreateUser(username, password, email, displayName, role, tenantID string) (*User, error) {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.CreateUser(username, password, email, displayName, role, tenantID)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	// Check if user exists
	for _, u := range m.config.Users {
		if u.Username == username {
			return nil, ErrUserExists
		}
	}

	// Verify tenant exists
	tenantExists := false
	for _, t := range m.config.Tenants {
		if t.ID == tenantID {
			tenantExists = true
			break
		}
	}
	if !tenantExists && tenantID != "" {
		return nil, ErrTenantNotFound
	}

	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	id, _ := GenerateSessionID()
	user := User{
		ID:           id[:16],
		Username:     username,
		PasswordHash: hash,
		Email:        email,
		DisplayName:  displayName,
		Role:         role,
		TenantID:     tenantID,
		CreatedAt:    time.Now(),
	}

	m.config.Users = append(m.config.Users, user)

	if err := m.saveConfig(); err != nil {
		return nil, err
	}

	return &user, nil
}

// UpdateUserPassword updates a user's password
func (m *Manager) UpdateUserPassword(userID, newPassword string) error {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.UpdateUserPassword(userID, newPassword)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	for i, u := range m.config.Users {
		if u.ID == userID {
			hash, err := HashPassword(newPassword)
			if err != nil {
				return err
			}
			m.config.Users[i].PasswordHash = hash
			return m.saveConfigLocked()
		}
	}

	return ErrUserNotFound
}

// DeleteUser removes a user
func (m *Manager) DeleteUser(userID string) error {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.DeleteUser(userID)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	for i, u := range m.config.Users {
		if u.ID == userID {
			m.config.Users = append(m.config.Users[:i], m.config.Users[i+1:]...)
			return m.saveConfigLocked()
		}
	}

	return ErrUserNotFound
}

// CreateAPIKey creates a new API key and returns the raw key (only shown once)
func (m *Manager) CreateAPIKey(name string, permissions []string, tenantID string, expiresAt *time.Time, createdBy string) (*APIKey, string, error) {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.CreateAPIKey(name, permissions, tenantID, expiresAt, createdBy)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	rawKey, err := GenerateAPIKey()
	if err != nil {
		return nil, "", err
	}

	id, _ := GenerateSessionID()
	apiKey := APIKey{
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

	m.config.APIKeys = append(m.config.APIKeys, apiKey)

	if err := m.saveConfigLocked(); err != nil {
		return nil, "", err
	}

	return &apiKey, rawKey, nil
}

// DeleteAPIKey removes an API key
func (m *Manager) DeleteAPIKey(keyID string) error {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.store.DeleteAPIKey(keyID)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	for i, k := range m.config.APIKeys {
		if k.ID == keyID {
			m.config.APIKeys = append(m.config.APIKeys[:i], m.config.APIKeys[i+1:]...)
			return m.saveConfigLocked()
		}
	}

	return ErrInvalidAPIKey
}

// ListUsers returns all users (without password hashes)
func (m *Manager) ListUsers() []User {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.ListUsers("")
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()

	users := make([]User, len(m.config.Users))
	for i, u := range m.config.Users {
		users[i] = u
		users[i].PasswordHash = ""
		users[i].WebAuthnCredentials = nil
	}

	return users
}

// ListAPIKeys returns all API keys (without key hashes)
func (m *Manager) ListAPIKeys() []APIKey {
	// Use storage manager if available
	if m.storageManager != nil {
		keys, err := m.storageManager.store.ListAPIKeys("") // Empty tenant = all tenants for admin
		if err != nil {
			return nil
		}
		result := make([]APIKey, len(keys))
		for i, k := range keys {
			result[i] = APIKey{
				ID:          k.ID,
				Name:        k.Name,
				KeyHash:     "", // Never expose hash
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

	m.configMu.RLock()
	defer m.configMu.RUnlock()

	keys := make([]APIKey, len(m.config.APIKeys))
	for i, k := range m.config.APIKeys {
		keys[i] = k
		keys[i].KeyHash = ""
	}

	return keys
}

// EnableAuth enables authentication with an initial admin user
func (m *Manager) EnableAuth(adminUsername, adminPassword string) error {
	m.configMu.Lock()
	defer m.configMu.Unlock()

	// Generate session secret if not set
	if m.config.SessionSecret == "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		m.config.SessionSecret = base64.StdEncoding.EncodeToString(secret)
	}

	// Create main tenant if no tenants exist
	if len(m.config.Tenants) == 0 {
		m.config.Tenants = []Tenant{{
			ID:        MainTenantID,
			Name:      "Main",
			IsMain:    true,
			CreatedAt: time.Now(),
		}}
	}

	// Create admin user if no users exist
	if len(m.config.Users) == 0 {
		hash, err := HashPassword(adminPassword)
		if err != nil {
			return err
		}

		id, _ := GenerateSessionID()
		m.config.Users = []User{{
			ID:           id[:16],
			Username:     adminUsername,
			PasswordHash: hash,
			Role:         RoleSuperAdmin,
			TenantID:     MainTenantID,
			CreatedAt:    time.Now(),
		}}
	}

	m.config.Enabled = true
	return m.saveConfigLocked()
}

// DisableAuth disables authentication
func (m *Manager) DisableAuth() error {
	m.configMu.Lock()
	defer m.configMu.Unlock()

	m.config.Enabled = false
	return m.saveConfigLocked()
}

// Middleware provides HTTP middleware for authentication
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if not enabled
		if !m.IsEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		// Try to authenticate
		session, err := m.authenticateRequest(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add session to request context
		ctx := withSession(r.Context(), session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MiddlewareFunc provides middleware for http.HandlerFunc
func (m *Manager) MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if not enabled
		if !m.IsEnabled() {
			next(w, r)
			return
		}

		// Try to authenticate
		session, err := m.authenticateRequest(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add session to request context
		ctx := withSession(r.Context(), session)
		next(w, r.WithContext(ctx))
	}
}

func (m *Manager) authenticateRequest(r *http.Request) (*Session, error) {
	// Check for API key in header
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return m.AuthenticateAPIKey(apiKey)
	}

	// Check for Bearer token (API key)
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			// Try as session token first
			if session, err := m.ValidateSession(token); err == nil {
				return session, nil
			}
			// Try as API key
			if session, err := m.AuthenticateAPIKey(token); err == nil {
				return session, nil
			}
		}
	}

	// Check for session cookie
	if cookie, err := r.Cookie("session"); err == nil {
		return m.ValidateSession(cookie.Value)
	}

	return nil, ErrUnauthorized
}

// RequireRole returns middleware that requires a specific role
func (m *Manager) RequireRole(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			session := GetSession(r.Context())
			if session == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			for _, role := range roles {
				if session.Role == role {
					next(w, r)
					return
				}
			}

			// Super admin role has access to everything
			if session.Role == RoleSuperAdmin || session.Role == "admin" {
				next(w, r)
				return
			}

			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}
}

// GetUserByID retrieves a user by ID
func (m *Manager) GetUserByID(userID string) (*User, error) {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.GetUserByID(userID)
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()

	for _, u := range m.config.Users {
		if u.ID == userID {
			userCopy := u
			userCopy.PasswordHash = ""
			return &userCopy, nil
		}
	}

	return nil, ErrUserNotFound
}

// GetUserByUsername retrieves a user by username
func (m *Manager) GetUserByUsername(username string) (*User, error) {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.GetUserByUsername(username)
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()

	for _, u := range m.config.Users {
		if u.Username == username {
			userCopy := u
			userCopy.PasswordHash = ""
			return &userCopy, nil
		}
	}

	return nil, ErrUserNotFound
}

// ChangeUserPassword changes a user's password (requires current password)
func (m *Manager) ChangeUserPassword(userID, currentPassword, newPassword string) error {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.ChangeUserPassword(userID, currentPassword, newPassword)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	for i, u := range m.config.Users {
		if u.ID == userID {
			// Verify current password
			if !CheckPassword(currentPassword, u.PasswordHash) {
				return ErrInvalidCredentials
			}

			hash, err := HashPassword(newPassword)
			if err != nil {
				return err
			}
			m.config.Users[i].PasswordHash = hash
			return m.saveConfigLocked()
		}
	}

	return ErrUserNotFound
}

// CreateSessionForOIDC creates a session for an OIDC-authenticated user
func (m *Manager) CreateSessionForOIDC(subject, email, displayName, role string) (*Session, error) {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.CreateSessionForOIDC(subject, email, displayName, role)
	}

	// Check if user exists by subject (stored as ID)
	m.configMu.Lock()
	defer m.configMu.Unlock()

	var user *User
	for i, u := range m.config.Users {
		if u.ID == subject || u.Email == email {
			user = &m.config.Users[i]
			// Update last login
			m.config.Users[i].LastLogin = time.Now()
			break
		}
	}

	// Create user if doesn't exist
	if user == nil {
		username := email
		if idx := strings.Index(email, "@"); idx > 0 {
			username = email[:idx]
		}

		newUser := User{
			ID:          subject,
			Username:    username,
			Email:       email,
			DisplayName: displayName,
			Role:        role,
			CreatedAt:   time.Now(),
			LastLogin:   time.Now(),
		}
		m.config.Users = append(m.config.Users, newUser)
		user = &newUser
		go m.saveConfig()
	}

	return m.createSession(user, "oidc")
}

// AddWebAuthnCredential adds a WebAuthn credential to a user
func (m *Manager) AddWebAuthnCredential(userID string, cred WebAuthnCredential) error {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.AddWebAuthnCredential(userID, cred)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	for i, u := range m.config.Users {
		if u.ID == userID {
			m.config.Users[i].WebAuthnCredentials = append(m.config.Users[i].WebAuthnCredentials, cred)
			return m.saveConfigLocked()
		}
	}

	return ErrUserNotFound
}

// GetWebAuthnCredentials returns a user's WebAuthn credentials
func (m *Manager) GetWebAuthnCredentials(userID string) ([]WebAuthnCredential, error) {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.GetWebAuthnCredentials(userID)
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()

	for _, u := range m.config.Users {
		if u.ID == userID {
			return u.WebAuthnCredentials, nil
		}
	}

	return nil, ErrUserNotFound
}

// NeedsSetup returns true if initial setup is required (no users exist)
func (m *Manager) NeedsSetup() bool {
	// Delegate to storage manager if available
	if m.storageManager != nil {
		return m.storageManager.NeedsSetup()
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()
	return len(m.config.Users) == 0
}

// Setup performs initial setup creating the main tenant and super admin user
func (m *Manager) Setup(adminUsername, adminPassword, adminEmail, adminDisplayName string) (*User, error) {
	// Delegate to storage manager if available
	if m.storageManager != nil {
		return m.storageManager.Setup(adminUsername, adminPassword, adminEmail, adminDisplayName)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	// Verify no users exist
	if len(m.config.Users) > 0 {
		return nil, ErrUserExists
	}

	// Generate session secret if not set
	if m.config.SessionSecret == "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		m.config.SessionSecret = base64.StdEncoding.EncodeToString(secret)
	}

	// Create main tenant
	m.config.Tenants = []Tenant{{
		ID:        MainTenantID,
		Name:      "Main",
		IsMain:    true,
		CreatedAt: time.Now(),
	}}

	// Create super admin user
	hash, err := HashPassword(adminPassword)
	if err != nil {
		return nil, err
	}

	id, _ := GenerateSessionID()
	user := User{
		ID:           id[:16],
		Username:     adminUsername,
		PasswordHash: hash,
		Email:        adminEmail,
		DisplayName:  adminDisplayName,
		Role:         RoleSuperAdmin,
		TenantID:     MainTenantID,
		CreatedAt:    time.Now(),
	}
	m.config.Users = []User{user}
	m.config.Enabled = true

	if err := m.saveConfigLocked(); err != nil {
		return nil, err
	}

	// Return user without password hash
	user.PasswordHash = ""
	return &user, nil
}

// ListTenants returns all tenants
func (m *Manager) ListTenants() []Tenant {
	if m.storageManager != nil {
		return m.storageManager.ListTenants()
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()

	tenants := make([]Tenant, len(m.config.Tenants))
	copy(tenants, m.config.Tenants)
	return tenants
}

// GetTenant returns a tenant by ID
func (m *Manager) GetTenant(tenantID string) (*Tenant, error) {
	if m.storageManager != nil {
		return m.storageManager.GetTenant(tenantID)
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()

	for _, t := range m.config.Tenants {
		if t.ID == tenantID {
			return &t, nil
		}
	}

	return nil, ErrTenantNotFound
}

// CreateTenant creates a new tenant
func (m *Manager) CreateTenant(id, name, description, createdBy string) (*Tenant, error) {
	if m.storageManager != nil {
		return m.storageManager.CreateTenant(id, name, description, createdBy)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	// Check if tenant exists
	for _, t := range m.config.Tenants {
		if t.ID == id {
			return nil, ErrTenantExists
		}
	}

	tenant := Tenant{
		ID:          id,
		Name:        name,
		Description: description,
		IsMain:      false,
		CreatedAt:   time.Now(),
		CreatedBy:   createdBy,
	}

	m.config.Tenants = append(m.config.Tenants, tenant)

	if err := m.saveConfigLocked(); err != nil {
		return nil, err
	}

	return &tenant, nil
}

// UpdateTenant updates a tenant's name and description
func (m *Manager) UpdateTenant(tenantID, name, description string) (*Tenant, error) {
	if m.storageManager != nil {
		return m.storageManager.UpdateTenant(tenantID, name, description)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	for i, t := range m.config.Tenants {
		if t.ID == tenantID {
			m.config.Tenants[i].Name = name
			m.config.Tenants[i].Description = description

			if err := m.saveConfigLocked(); err != nil {
				return nil, err
			}

			return &m.config.Tenants[i], nil
		}
	}

	return nil, ErrTenantNotFound
}

// DeleteTenant removes a tenant (cannot delete main tenant)
func (m *Manager) DeleteTenant(tenantID string) error {
	if m.storageManager != nil {
		return m.storageManager.DeleteTenant(tenantID)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	for i, t := range m.config.Tenants {
		if t.ID == tenantID {
			if t.IsMain {
				return errors.New("cannot delete main tenant")
			}
			m.config.Tenants = append(m.config.Tenants[:i], m.config.Tenants[i+1:]...)
			return m.saveConfigLocked()
		}
	}

	return ErrTenantNotFound
}

// ListUsersByTenant returns all users in a specific tenant
func (m *Manager) ListUsersByTenant(tenantID string) []User {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.ListUsersByTenant(tenantID)
	}

	m.configMu.RLock()
	defer m.configMu.RUnlock()

	var users []User
	for _, u := range m.config.Users {
		if u.TenantID == tenantID {
			userCopy := u
			userCopy.PasswordHash = ""
			userCopy.WebAuthnCredentials = nil
			users = append(users, userCopy)
		}
	}

	return users
}

// UpdateUser updates a user's email, display name, and role
func (m *Manager) UpdateUser(userID, email, displayName, role string) (*User, error) {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.UpdateUser(userID, email, displayName, role)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	for i, u := range m.config.Users {
		if u.ID == userID {
			m.config.Users[i].Email = email
			m.config.Users[i].DisplayName = displayName
			m.config.Users[i].Role = role

			if err := m.saveConfigLocked(); err != nil {
				return nil, err
			}

			userCopy := m.config.Users[i]
			userCopy.PasswordHash = ""
			return &userCopy, nil
		}
	}

	return nil, ErrUserNotFound
}

// ResetUserPassword resets a user's password (admin function, no current password required)
func (m *Manager) ResetUserPassword(userID, newPassword string) error {
	return m.UpdateUserPassword(userID, newPassword)
}

// IsSuperAdmin checks if a session belongs to a super admin
func (m *Manager) IsSuperAdmin(session *Session) bool {
	return session != nil && session.IsSuperAdmin
}

// CanManageTenant checks if a session can manage a specific tenant
func (m *Manager) CanManageTenant(session *Session, tenantID string) bool {
	if session == nil {
		return false
	}
	// Super admins can manage any tenant
	if session.IsSuperAdmin {
		return true
	}
	// Tenant admins can only manage their own tenant
	if session.Role == RoleTenantAdmin && session.TenantID == tenantID {
		return true
	}
	return false
}

// CanAccessZone checks if a session can access a zone with a given tenant ID
func (m *Manager) CanAccessZone(session *Session, zoneTenantID string) bool {
	if session == nil {
		return false
	}
	// Super admins can access any zone
	if session.IsSuperAdmin {
		return true
	}
	// Users can only access zones in their tenant
	return session.TenantID == zoneTenantID
}

// RemoveWebAuthnCredential removes a WebAuthn credential from a user
func (m *Manager) RemoveWebAuthnCredential(userID, credentialID string) error {
	// Use storage manager if available
	if m.storageManager != nil {
		return m.storageManager.RemoveWebAuthnCredential(userID, credentialID)
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	for i, u := range m.config.Users {
		if u.ID == userID {
			for j, c := range u.WebAuthnCredentials {
				if c.ID == credentialID {
					m.config.Users[i].WebAuthnCredentials = append(
						m.config.Users[i].WebAuthnCredentials[:j],
						m.config.Users[i].WebAuthnCredentials[j+1:]...,
					)
					return m.saveConfigLocked()
				}
			}
			return errors.New("credential not found")
		}
	}

	return ErrUserNotFound
}
