package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RegisterAuthRoutes registers authentication API routes
func (m *Manager) RegisterAuthRoutes(mux *http.ServeMux) {
	// Setup endpoints (accessible when no users exist)
	mux.HandleFunc("/api/auth/setup-status", m.corsHandler(m.handleSetupStatus))
	mux.HandleFunc("/api/auth/setup", m.corsHandler(m.handleSetup))
	mux.HandleFunc("/api/auth/join-cluster", m.corsHandler(m.handleJoinCluster))

	// Public auth endpoints (no auth required)
	mux.HandleFunc("/api/auth/login", m.corsHandler(m.handleLogin))
	mux.HandleFunc("/api/auth/logout", m.corsHandler(m.handleLogout))
	mux.HandleFunc("/api/auth/status", m.corsHandler(m.handleAuthStatus))

	// Protected auth management endpoints
	mux.HandleFunc("/api/auth/users", m.corsHandler(m.MiddlewareFunc(m.handleUsers)))
	mux.HandleFunc("/api/auth/users/", m.corsHandler(m.MiddlewareFunc(m.handleUser)))
	mux.HandleFunc("/api/auth/apikeys", m.corsHandler(m.MiddlewareFunc(m.handleAPIKeys)))
	mux.HandleFunc("/api/auth/apikeys/roles", m.corsHandler(m.MiddlewareFunc(m.handleAPIKeyRoles)))
	mux.HandleFunc("/api/auth/apikeys/", m.corsHandler(m.MiddlewareFunc(m.handleAPIKey)))
	mux.HandleFunc("/api/auth/config", m.corsHandler(m.MiddlewareFunc(m.handleAuthConfig)))
	mux.HandleFunc("/api/auth/me", m.corsHandler(m.MiddlewareFunc(m.handleMe)))
	mux.HandleFunc("/api/auth/change-password", m.corsHandler(m.MiddlewareFunc(m.handleChangePassword)))

	// Tenant management (super admin only)
	mux.HandleFunc("/api/auth/tenants", m.corsHandler(m.MiddlewareFunc(m.handleTenants)))
	mux.HandleFunc("/api/auth/tenants/", m.corsHandler(m.MiddlewareFunc(m.handleTenant)))
}

func (m *Manager) corsHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// handleSetupStatus returns whether initial setup is required
func (m *Manager) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"needs_setup": m.NeedsSetup(),
	})
}

// handleSetup performs initial setup creating super admin
func (m *Manager) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Only allow setup if no users exist
	if !m.NeedsSetup() {
		http.Error(w, "Setup already completed", http.StatusBadRequest)
		return
	}

	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	user, err := m.Setup(req.Username, req.Password, req.Email, req.DisplayName)
	if err != nil {
		http.Error(w, "Failed to complete setup: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a session for the new user
	session, err := m.AuthenticatePassword(req.Username, req.Password)
	if err != nil {
		http.Error(w, "Setup completed but login failed", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(time.Until(session.ExpiresAt).Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user":    user,
		"token":   session.ID,
	})
}

// JoinClusterCallback is called after successfully joining a cluster
// to configure the sync manager
type JoinClusterCallback func(clusterConfig *ClusterJoinConfig) error

// ClusterJoinConfig contains configuration obtained from joining a cluster
type ClusterJoinConfig struct {
	SharedSecret string       `json:"shared_secret"`
	Peers        []PeerConfig `json:"peers"`
	ThisServer   PeerConfig   `json:"this_server"`
}

// PeerConfig represents a peer server configuration
type PeerConfig struct {
	URL      string `json:"url"`
	Name     string `json:"name,omitempty"`
	ServerID string `json:"server_id,omitempty"`
}

// SetJoinClusterCallback sets the callback for cluster join operations
func (m *Manager) SetJoinClusterCallback(callback JoinClusterCallback) {
	m.joinClusterCallback = callback
}

// ACMECertRequest contains all parameters for requesting an ACME certificate
type ACMECertRequest struct {
	Email       string   `json:"email"`
	Domain      string   `json:"domain"`
	Staging     bool     `json:"staging"`
	Provider    string   `json:"provider"`     // letsencrypt, zerossl, buypass, google
	EABKeyID    string   `json:"eab_key_id"`   // For ZeroSSL, Google Trust Services
	EABHMACKey  string   `json:"eab_hmac_key"` // For ZeroSSL, Google Trust Services
	PeerURLs    []string `json:"peer_urls"`    // URLs of peers to check for existing certs
}

// ACMECertCallback is called to request an ACME certificate before cluster join
type ACMECertCallback func(req ACMECertRequest) error

// SetACMECertCallback sets the callback for ACME certificate requests
func (m *Manager) SetACMECertCallback(callback ACMECertCallback) {
	m.acmeCertCallback = callback
}

// handleJoinCluster handles joining an existing cluster during setup
func (m *Manager) handleJoinCluster(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Only allow if setup is needed (no users exist)
	if !m.NeedsSetup() {
		http.Error(w, "Setup already completed - cannot join cluster on existing server", http.StatusBadRequest)
		return
	}

	var req struct {
		ClusterURL     string `json:"cluster_url"`
		Username       string `json:"username"`
		Password       string `json:"password"`
		ServerURL      string `json:"server_url"` // This server's URL for peers to connect back
		ServerName     string `json:"server_name"`
		ACMEEmail      string `json:"acme_email"`
		ACMEDomain     string `json:"acme_domain"`
		ACMEStaging    bool   `json:"acme_staging"`
		ACMEProvider   string `json:"acme_provider"`     // letsencrypt, zerossl, buypass, google
		ACMEEABKeyID   string `json:"acme_eab_key_id"`   // For ZeroSSL, Google Trust Services
		ACMEEABHMACKey string `json:"acme_eab_hmac_key"` // For ZeroSSL, Google Trust Services
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.ClusterURL == "" || req.Username == "" || req.Password == "" {
		http.Error(w, "cluster_url, username, and password are required", http.StatusBadRequest)
		return
	}

	if req.ServerURL == "" {
		http.Error(w, "server_url is required (this server's URL for cluster peers)", http.StatusBadRequest)
		return
	}

	// ACME is optional - we'll use self-signed cert if not provided or if rate limited
	acmeOptional := req.ACMEEmail == "" || req.ACMEDomain == ""

	// Step 1: Request ACME certificate FIRST (before cluster join) - only if ACME details provided
	if !acmeOptional && m.acmeCertCallback != nil {
		// Extract peer URL from cluster URL for certificate lookup
		peerURLs := []string{req.ClusterURL}
		
		acmeReq := ACMECertRequest{
			Email:      req.ACMEEmail,
			Domain:     req.ACMEDomain,
			Staging:    req.ACMEStaging,
			Provider:   req.ACMEProvider,
			EABKeyID:   req.ACMEEABKeyID,
			EABHMACKey: req.ACMEEABHMACKey,
			PeerURLs:   peerURLs,
		}
		
		log.Printf("[cluster-join] Requesting TLS certificate for %s (provider: %s)", req.ACMEDomain, req.ACMEProvider)
		if err := m.acmeCertCallback(acmeReq); err != nil {
			// Check if it's a rate limit error - if so, continue with self-signed cert
			if strings.Contains(err.Error(), "rateLimited") || strings.Contains(err.Error(), "too many") {
				log.Printf("[cluster-join] ACME rate limited, continuing with existing/self-signed certificate: %v", err)
			} else {
				log.Printf("[cluster-join] Failed to obtain TLS certificate: %v", err)
				http.Error(w, "Failed to obtain TLS certificate: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			log.Printf("[cluster-join] TLS certificate obtained successfully")
		}
	} else if acmeOptional {
		log.Printf("[cluster-join] ACME not configured, using self-signed certificate")
	} else {
		log.Printf("[cluster-join] Warning: No ACME callback configured, skipping certificate request")
	}

	// Step 2: Join the cluster
	result, err := m.joinCluster(req.ClusterURL, req.Username, req.Password, req.ServerURL, req.ServerName)
	if err != nil {
		log.Printf("[cluster-join] Failed to join cluster: %v", err)
		http.Error(w, "Failed to join cluster: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a session for the synced admin user
	session, err := m.AuthenticatePassword(req.Username, req.Password)
	if err != nil {
		// Users should have been synced, but authentication might still work
		log.Printf("[cluster-join] Warning: Could not authenticate after join: %v", err)
	}

	// Set session cookie if we have one
	if session != nil {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    session.ID,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(time.Until(session.ExpiresAt).Seconds()),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Successfully joined cluster",
		"peers":   result.Peers,
	})
}

func (m *Manager) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}


	session, err := m.AuthenticatePassword(req.Username, req.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(time.Until(session.ExpiresAt).Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"token":   session.ID,
		"user": map[string]interface{}{
			"id":             session.UserID,
			"username":       session.Username,
			"role":           session.Role,
			"tenant_id":      session.TenantID,
			"tenant_name":    session.TenantName,
			"is_super_admin": session.IsSuperAdmin,
		},
		"expires_at": session.ExpiresAt,
	})
}

func (m *Manager) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session from cookie or header
	var sessionID string
	if cookie, err := r.Cookie("session"); err == nil {
		sessionID = cookie.Value
	} else if auth := r.Header.Get("Authorization"); auth != "" {
		if len(auth) > 7 && auth[:7] == "Bearer " {
			sessionID = auth[7:]
		}
	}

	if sessionID != "" {
		m.InvalidateSession(sessionID)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (m *Manager) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	log.Printf("[auth-status] ====== START handleAuthStatus ======")
	log.Printf("[auth-status] Called from %s, Method: %s", r.RemoteAddr, r.Method)
	
	if r.Method != "GET" {
		log.Printf("[auth-status] Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("[auth-status] Calling m.IsEnabled()...")
	isEnabled := m.IsEnabled()
	log.Printf("[auth-status] IsEnabled() returned: %v", isEnabled)
	
	log.Printf("[auth-status] Calling m.NeedsSetup()...")
	needsSetup := m.NeedsSetup()
	log.Printf("[auth-status] NeedsSetup() returned: %v", needsSetup)
	
	log.Printf("[auth-status] Building response map...")
	response := map[string]interface{}{
		"auth_enabled": isEnabled,
		"needs_setup":  needsSetup,
	}

	// Check if user is authenticated
	log.Printf("[auth-status] Calling authenticateRequest()...")
	session, err := m.authenticateRequest(r)
	log.Printf("[auth-status] authenticateRequest returned: session=%v, err=%v", session != nil, err)
	if err == nil && session != nil {
		log.Printf("[auth-status] User authenticated: %s (role: %s)", session.Username, session.Role)
		response["authenticated"] = true
		response["user"] = map[string]interface{}{
			"id":             session.UserID,
			"username":       session.Username,
			"role":           session.Role,
			"tenant_id":      session.TenantID,
			"tenant_name":    session.TenantName,
			"is_super_admin": session.IsSuperAdmin,
		}
		response["auth_method"] = session.AuthMethod
		response["expires_at"] = session.ExpiresAt
	} else {
		log.Printf("[auth-status] User not authenticated")
		response["authenticated"] = false
	}

	// Include available auth methods
	log.Printf("[auth-status] Calling m.GetConfig()...")
	config := m.GetConfig()
	log.Printf("[auth-status] GetConfig() returned successfully")
	
	methods := []string{"password"}
	if config.WebAuthn != nil && config.WebAuthn.Enabled {
		methods = append(methods, "webauthn")
	}
	if config.OIDC != nil && config.OIDC.Enabled {
		methods = append(methods, "oidc")
	}
	response["auth_methods"] = methods

	log.Printf("[auth-status] Setting Content-Type header...")
	w.Header().Set("Content-Type", "application/json")
	
	log.Printf("[auth-status] Encoding JSON response...")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[auth-status] ERROR encoding response: %v", err)
	} else {
		log.Printf("[auth-status] Response sent successfully: authenticated=%v", response["authenticated"])
	}
	log.Printf("[auth-status] ====== END handleAuthStatus ======")
}

func (m *Manager) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          session.UserID,
		"username":    session.Username,
		"role":        session.Role,
		"auth_method": session.AuthMethod,
		"expires_at":  session.ExpiresAt,
	})
}

func (m *Manager) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify current password
	_, err := m.AuthenticatePassword(session.Username, req.CurrentPassword)
	if err != nil {
		http.Error(w, "Current password is incorrect", http.StatusBadRequest)
		return
	}

	// Update password
	if err := m.UpdateUserPassword(session.UserID, req.NewPassword); err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (m *Manager) handleUsers(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check permission - must be super_admin or tenant_admin
	canManageUsers := session.IsSuperAdmin || session.Role == RoleTenantAdmin || session.Role == "admin"
	if !canManageUsers {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	switch r.Method {
	case "GET":
		var users []User
		if session.IsSuperAdmin {
			// Super admins see all users
			users = m.ListUsers()
		} else {
			// Tenant admins only see users in their tenant
			users = m.ListUsersByTenant(session.TenantID)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case "POST":
		var req struct {
			Username    string `json:"username"`
			Password    string `json:"password"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			Role        string `json:"role"`
			TenantID    string `json:"tenant_id"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Role == "" {
			req.Role = RoleReadonly
		}

		// Non-super-admins can only create users in their own tenant
		if !session.IsSuperAdmin {
			req.TenantID = session.TenantID
			// Prevent non-super-admins from creating super_admins
			if req.Role == RoleSuperAdmin {
				http.Error(w, "Cannot create super admin", http.StatusForbidden)
				return
			}
		}

		// Default to session's tenant if not specified
		if req.TenantID == "" {
			req.TenantID = session.TenantID
		}

		user, err := m.CreateUser(req.Username, req.Password, req.Email, req.DisplayName, req.Role, req.TenantID)
		if err != nil {
			if err == ErrUserExists {
				http.Error(w, "User already exists", http.StatusConflict)
				return
			}
			if err == ErrTenantNotFound {
				http.Error(w, "Tenant not found", http.StatusBadRequest)
				return
			}
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		user.PasswordHash = ""
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(user)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) handleUser(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check permission - must be super_admin or tenant_admin
	canManageUsers := session.IsSuperAdmin || session.Role == RoleTenantAdmin || session.Role == "admin"
	if !canManageUsers {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Extract user ID from path
	userID := r.URL.Path[len("/api/auth/users/"):]
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	// Check if target user is in the same tenant (unless super admin)
	if !session.IsSuperAdmin {
		targetUser, err := m.GetUserByID(userID)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		if targetUser.TenantID != session.TenantID {
			http.Error(w, "Forbidden - cannot manage users outside your tenant", http.StatusForbidden)
			return
		}
	}

	switch r.Method {
	case "GET":
		user, err := m.GetUserByID(userID)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)

	case "DELETE":
		// Prevent deleting yourself
		if userID == session.UserID {
			http.Error(w, "Cannot delete your own account", http.StatusBadRequest)
			return
		}

		if err := m.DeleteUser(userID); err != nil {
			if err == ErrUserNotFound {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to delete user", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	case "PUT":
		var req struct {
			Password    string `json:"password,omitempty"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			Role        string `json:"role"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Prevent non-super-admins from elevating to super_admin
		if !session.IsSuperAdmin && req.Role == RoleSuperAdmin {
			http.Error(w, "Cannot assign super admin role", http.StatusForbidden)
			return
		}

		// Update password if provided
		if req.Password != "" {
			if err := m.ResetUserPassword(userID, req.Password); err != nil {
				http.Error(w, "Failed to update password", http.StatusInternalServerError)
				return
			}
		}

		// Update other fields
		user, err := m.UpdateUser(userID, req.Email, req.DisplayName, req.Role)
		if err != nil {
			if err == ErrUserNotFound {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to update user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case "GET":
		// Any authenticated user can list their keys, admins can see all
		keys := m.ListAPIKeys()
		if session.Role != "admin" && !session.IsSuperAdmin {
			// Filter to only show keys created by this user AND same tenant
			var userKeys []APIKey
			for _, k := range keys {
				if k.CreatedBy == session.UserID && k.TenantID == session.TenantID {
					userKeys = append(userKeys, k)
				}
			}
			keys = userKeys
		} else if !session.IsSuperAdmin {
			// Admin (but not super admin) can only see keys from their tenant
			var tenantKeys []APIKey
			for _, k := range keys {
				if k.TenantID == session.TenantID {
					tenantKeys = append(tenantKeys, k)
				}
			}
			keys = tenantKeys
		}
		// Ensure we return an empty array, not null
		if keys == nil {
			keys = []APIKey{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keys)

	case "POST":
		// Only admins and super admins can create API keys
		if session.Role != "admin" && !session.IsSuperAdmin {
			http.Error(w, "Forbidden: only administrators can create API keys", http.StatusForbidden)
			return
		}

		var req struct {
			Name        string     `json:"name"`
			Role        string     `json:"role"` // "super_admin", "admin", "readonly"
			Permissions []string   `json:"permissions"`
			TenantID    string     `json:"tenant_id"` // Optional: create key for specific tenant (super admin only)
			ExpiresAt   *time.Time `json:"expires_at,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Determine target tenant
		targetTenant := session.TenantID
		if req.TenantID != "" && req.TenantID != session.TenantID {
			// Creating key for different tenant requires super admin
			if !session.IsSuperAdmin {
				http.Error(w, "Only super admins can create API keys for other tenants", http.StatusForbidden)
				return
			}
			targetTenant = req.TenantID
		}

		// Convert role to permissions array
		// Supported roles: "super_admin" (main tenant only), "admin", "readonly"
		var permissions []string
		switch req.Role {
		case "super_admin":
			// Super admin only allowed for main tenant
			if targetTenant != "main" {
				http.Error(w, "Super admin role only available for main tenant", http.StatusForbidden)
				return
			}
			// Only super admins can create super admin keys
			if !session.IsSuperAdmin {
				http.Error(w, "Only super admins can create super admin API keys", http.StatusForbidden)
				return
			}
			permissions = []string{"*"}
		case "admin":
			permissions = []string{"admin"}
		case "readonly":
			permissions = []string{"read"}
		default:
			// Fallback to permissions array if role not specified (legacy support)
			if len(req.Permissions) > 0 {
				permissions = req.Permissions
				// Validate that non-super-admin can't create super admin keys
				for _, p := range permissions {
					if (p == "*" || p == "admin") && !session.IsSuperAdmin {
						// Regular admins can create "admin" role but not "*" (super admin)
						if p == "*" {
							http.Error(w, "Only super admins can create super admin API keys", http.StatusForbidden)
							return
						}
					}
				}
			} else {
				// Default to admin permissions for admins
				permissions = []string{"admin"}
			}
		}

		apiKey, rawKey, err := m.CreateAPIKey(req.Name, permissions, targetTenant, req.ExpiresAt, session.UserID)
		if err != nil {
			http.Error(w, "Failed to create API key", http.StatusInternalServerError)
			return
		}

		// Map permissions back to role for response
		role := m.permissionsToRole(permissions)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"key":         rawKey, // Only returned once!
			"id":          apiKey.ID,
			"name":        apiKey.Name,
			"prefix":      apiKey.KeyPrefix,
			"role":        role,
			"permissions": apiKey.Permissions,
			"created_at":  apiKey.CreatedAt,
			"expires_at":  apiKey.ExpiresAt,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) handleAPIKey(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract key ID from path
	keyID := r.URL.Path[len("/api/auth/apikeys/"):]
	if keyID == "" {
		http.Error(w, "Key ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "DELETE":
		// Admins and super admins can delete any key; others can only delete their own
		if session.Role != "admin" && !session.IsSuperAdmin {
			keys := m.ListAPIKeys()
			var owned bool
			for _, k := range keys {
				if k.ID == keyID && k.CreatedBy == session.UserID {
					owned = true
					break
				}
			}
			if !owned {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		if err := m.DeleteAPIKey(keyID); err != nil {
			http.Error(w, "Failed to delete API key", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIKeyRoles returns the available roles for API key creation
func (m *Manager) handleAPIKeyRoles(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Only admins can see available roles
	if session.Role != "admin" && !session.IsSuperAdmin {
		http.Error(w, "Forbidden: only administrators can view API key roles", http.StatusForbidden)
		return
	}

	type RoleOption struct {
		Value       string `json:"value"`
		Label       string `json:"label"`
		Description string `json:"description"`
	}

	roles := []RoleOption{
		{Value: "readonly", Label: "Read Only", Description: "Can only read data, no modifications"},
		{Value: "admin", Label: "Admin", Description: "Full access to tenant resources"},
	}

	// Super admin role only available for main tenant and super admins
	if session.IsSuperAdmin && session.TenantID == "main" {
		roles = append(roles, RoleOption{
			Value:       "super_admin",
			Label:       "Super Admin",
			Description: "Full system access including tenant management",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roles)
}

func (m *Manager) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil || session.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	switch r.Method {
	case "GET":
		config := m.GetConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)

	case "POST":
		var req struct {
			Action   string `json:"action"` // enable, disable
			Username string `json:"username,omitempty"`
			Password string `json:"password,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		switch req.Action {
		case "enable":
			if err := m.EnableAuth(req.Username, req.Password); err != nil {
				http.Error(w, "Failed to enable auth", http.StatusInternalServerError)
				return
			}
		case "disable":
			if err := m.DisableAuth(); err != nil {
				http.Error(w, "Failed to disable auth", http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, "Invalid action", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTenants handles listing and creating tenants (super admin only)
func (m *Manager) handleTenants(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Only super admins can manage tenants
	if !m.IsSuperAdmin(session) {
		http.Error(w, "Forbidden - super admin required", http.StatusForbidden)
		return
	}

	switch r.Method {
	case "GET":
		tenants := m.ListTenants()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tenants)

	case "POST":
		var req struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			http.Error(w, "Name is required", http.StatusBadRequest)
			return
		}

		// Auto-generate tenant ID if not provided
		tenantID := req.ID
		if tenantID == "" {
			tenantID = uuid.New().String()
		}

		tenant, err := m.CreateTenant(tenantID, req.Name, req.Description, session.UserID)
		if err != nil {
			if err == ErrTenantExists {
				http.Error(w, "Tenant already exists", http.StatusConflict)
				return
			}
			log.Printf("[auth] Failed to create tenant: %v", err)
			http.Error(w, "Failed to create tenant: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(tenant)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTenant handles individual tenant operations (super admin only)
func (m *Manager) handleTenant(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Only super admins can manage tenants
	if !m.IsSuperAdmin(session) {
		http.Error(w, "Forbidden - super admin required", http.StatusForbidden)
		return
	}

	// Extract tenant ID from path
	tenantID := r.URL.Path[len("/api/auth/tenants/"):]
	if tenantID == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	// Check for /users suffix for tenant-specific user management
	if len(tenantID) > 6 && tenantID[len(tenantID)-6:] == "/users" {
		m.handleTenantUsers(w, r, tenantID[:len(tenantID)-6])
		return
	}

	switch r.Method {
	case "GET":
		tenant, err := m.GetTenant(tenantID)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tenant)

	case "PUT":
		var req struct {
			Name                 string   `json:"name"`
			Description          string   `json:"description"`
			DefaultNameservers   []string `json:"default_nameservers,omitempty"`
			DefaultNameserverTTL uint32   `json:"default_nameserver_ttl,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		tenant, err := m.UpdateTenant(tenantID, req.Name, req.Description, req.DefaultNameservers, req.DefaultNameserverTTL)
		if err != nil {
			if err == ErrTenantNotFound {
				http.Error(w, "Tenant not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to update tenant", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tenant)

	case "DELETE":
		if err := m.DeleteTenant(tenantID); err != nil {
			if err == ErrTenantNotFound {
				http.Error(w, "Tenant not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTenantUsers handles listing and creating users for a specific tenant
func (m *Manager) handleTenantUsers(w http.ResponseWriter, r *http.Request, tenantID string) {
	log.Printf("[DEBUG] handleTenantUsers called with tenantID='%s' method=%s", tenantID, r.Method)

	switch r.Method {
	case "GET":
		users := m.ListUsersByTenant(tenantID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case "POST":
		// Verify tenant exists
		_, err := m.GetTenant(tenantID)
		if err != nil {
			log.Printf("[DEBUG] GetTenant('%s') failed: %v", tenantID, err)
			http.Error(w, "Tenant not found", http.StatusNotFound)
			return
		}

		var req struct {
			Username    string `json:"username"`
			Password    string `json:"password"`
			Role        string `json:"role"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Username == "" || req.Password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		role := req.Role
		if role == "" {
			role = RoleUser
		}

		// Validate role - only main tenant can have super_admin users
		if role == RoleSuperAdmin && tenantID != MainTenantID {
			http.Error(w, "Super admin role is only available for main tenant", http.StatusBadRequest)
			return
		}

		// Validate role values
		validRoles := map[string]bool{RoleSuperAdmin: true, RoleTenantAdmin: true, RoleUser: true, RoleReadonly: true}
		if !validRoles[role] {
			http.Error(w, "Invalid role", http.StatusBadRequest)
			return
		}

		user, err := m.CreateUser(req.Username, req.Password, req.Email, req.DisplayName, role, tenantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Don't return password hash
		user.PasswordHash = ""

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(user)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// joinCluster authenticates with an existing cluster and joins it
func (m *Manager) joinCluster(clusterURL, username, password, serverURL, serverName string) (*ClusterJoinConfig, error) {
	// Step 1: Authenticate with the cluster server
	log.Printf("[cluster-join] Authenticating with cluster at %s", clusterURL)
	
	loginReq := map[string]string{
		"username": username,
		"password": password,
	}
	loginBody, _ := json.Marshal(loginReq)
	
	resp, err := http.Post(clusterURL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to cluster: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("authentication failed: %s", string(body))
	}
	
	var loginResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return nil, fmt.Errorf("failed to parse login response: %w", err)
	}
	
	if loginResp.Token == "" {
		// Try to get session cookie
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "session" {
				loginResp.Token = cookie.Value
				break
			}
		}
	}
	
	if loginResp.Token == "" {
		return nil, fmt.Errorf("no authentication token received")
	}
	
	log.Printf("[cluster-join] Authentication successful")
	
	// Step 2: Get sync configuration from the cluster
	log.Printf("[cluster-join] Fetching cluster configuration")
	
	req, _ := http.NewRequest("GET", clusterURL+"/api/sync/config", nil)
	req.Header.Set("Cookie", "session="+loginResp.Token)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	
	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync config: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get sync config: %s", string(body))
	}
	
	var syncConfig struct {
		Enabled      bool   `json:"enabled"`
		ServerID     string `json:"server_id"`
		ServerName   string `json:"server_name"`
		SharedSecret string `json:"shared_secret"`
		Peers        []struct {
			URL      string `json:"url"`
			Name     string `json:"name"`
			ServerID string `json:"server_id"`
		} `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&syncConfig); err != nil {
		return nil, fmt.Errorf("failed to parse sync config: %w", err)
	}
	
	log.Printf("[cluster-join] Got sync config: %d existing peers", len(syncConfig.Peers))
	
	// Step 3: Get the actual shared secret (the config endpoint masks it)
	// We'll need a special endpoint or include it differently
	// For now, we need to get the unmasked secret
	req, _ = http.NewRequest("GET", clusterURL+"/api/sync/join-secret", nil)
	req.Header.Set("Cookie", "session="+loginResp.Token)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get join secret: %w", err)
	}
	defer resp.Body.Close()
	
	var secretResp struct {
		SharedSecret string `json:"shared_secret"`
	}
	if resp.StatusCode == http.StatusOK {
		json.NewDecoder(resp.Body).Decode(&secretResp)
	}
	
	if secretResp.SharedSecret == "" {
		return nil, fmt.Errorf("could not retrieve cluster shared secret - ensure you have super admin access")
	}
	
	// Step 4: Generate a server ID for this server
	newServerID := uuid.New().String()[:8]
	if serverName == "" {
		serverName = "server-" + newServerID
	}
	
	// Step 5: Register this server as a peer on all existing cluster servers
	thisServer := PeerConfig{
		URL:      serverURL,
		Name:     serverName,
		ServerID: newServerID,
	}
	
	// Add this server to the cluster server
	log.Printf("[cluster-join] Registering this server with cluster master at %s", clusterURL)
	peerBody, _ := json.Marshal(thisServer)
	req, _ = http.NewRequest("POST", clusterURL+"/api/sync/peers", bytes.NewReader(peerBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "session="+loginResp.Token)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("[cluster-join] Warning: Failed to register with %s: %v", clusterURL, err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("[cluster-join] Warning: Failed to register with %s: status %d", clusterURL, resp.StatusCode)
		} else {
			log.Printf("[cluster-join] Successfully registered with cluster master")
		}
	}
	
	// Also register with other peers in the cluster
	for _, peer := range syncConfig.Peers {
		log.Printf("[cluster-join] Registering this server with peer at %s", peer.URL)
		req, _ = http.NewRequest("POST", peer.URL+"/api/sync/peers", bytes.NewReader(peerBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", "session="+loginResp.Token)
		req.Header.Set("Authorization", "Bearer "+loginResp.Token)
		
		resp, err = client.Do(req)
		if err != nil {
			log.Printf("[cluster-join] Warning: Failed to register with peer %s: %v", peer.URL, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("[cluster-join] Warning: Failed to register with peer %s: status %d", peer.URL, resp.StatusCode)
		} else {
			log.Printf("[cluster-join] Successfully registered with peer %s", peer.URL)
		}
	}
	
	// Step 6: Build the list of peers for this server (cluster server + all other peers)
	peers := []PeerConfig{
		{
			URL:      clusterURL,
			Name:     syncConfig.ServerName,
			ServerID: syncConfig.ServerID,
		},
	}
	for _, peer := range syncConfig.Peers {
		peers = append(peers, PeerConfig{
			URL:      peer.URL,
			Name:     peer.Name,
			ServerID: peer.ServerID,
		})
	}
	
	result := &ClusterJoinConfig{
		SharedSecret: secretResp.SharedSecret,
		Peers:        peers,
		ThisServer:   thisServer,
	}
	
	// Step 7: Call the callback to configure sync
	if m.joinClusterCallback != nil {
		log.Printf("[cluster-join] Configuring local sync settings")
		if err := m.joinClusterCallback(result); err != nil {
			return nil, fmt.Errorf("failed to configure sync: %w", err)
		}
	}
	
	// Step 8: Trigger a full sync on the primary server to broadcast existing data
	log.Printf("[cluster-join] Requesting full sync from primary server")
	req, _ = http.NewRequest("POST", clusterURL+"/api/sync/full-sync", nil)
	req.Header.Set("Cookie", "session="+loginResp.Token)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("[cluster-join] Warning: Failed to trigger full sync: %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			log.Printf("[cluster-join] Full sync triggered on primary server")
		} else {
			log.Printf("[cluster-join] Warning: Full sync request returned status %d", resp.StatusCode)
		}
	}
	
	// Give sync a moment to complete before returning
	time.Sleep(2 * time.Second)
	
	log.Printf("[cluster-join] Successfully joined cluster with %d peers", len(peers))
	return result, nil
}
