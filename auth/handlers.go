package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// RegisterAuthRoutes registers authentication API routes
func (m *Manager) RegisterAuthRoutes(mux *http.ServeMux) {
	// Setup endpoints (accessible when no users exist)
	mux.HandleFunc("/api/auth/setup-status", m.corsHandler(m.handleSetupStatus))
	mux.HandleFunc("/api/auth/setup", m.corsHandler(m.handleSetup))

	// Public auth endpoints (no auth required)
	mux.HandleFunc("/api/auth/login", m.corsHandler(m.handleLogin))
	mux.HandleFunc("/api/auth/logout", m.corsHandler(m.handleLogout))
	mux.HandleFunc("/api/auth/status", m.corsHandler(m.handleAuthStatus))

	// Protected auth management endpoints
	mux.HandleFunc("/api/auth/users", m.corsHandler(m.MiddlewareFunc(m.handleUsers)))
	mux.HandleFunc("/api/auth/users/", m.corsHandler(m.MiddlewareFunc(m.handleUser)))
	mux.HandleFunc("/api/auth/apikeys", m.corsHandler(m.MiddlewareFunc(m.handleAPIKeys)))
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
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"auth_enabled": m.IsEnabled(),
		"needs_setup":  m.NeedsSetup(),
	}

	// Check if user is authenticated
	session, err := m.authenticateRequest(r)
	if err == nil && session != nil {
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
		response["authenticated"] = false
	}

	// Include available auth methods
	config := m.GetConfig()
	methods := []string{"password"}
	if config.WebAuthn != nil && config.WebAuthn.Enabled {
		methods = append(methods, "webauthn")
	}
	if config.OIDC != nil && config.OIDC.Enabled {
		methods = append(methods, "oidc")
	}
	response["auth_methods"] = methods

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
		if session.Role != "admin" {
			// Filter to only show keys created by this user
			var userKeys []APIKey
			for _, k := range keys {
				if k.CreatedBy == session.UserID {
					userKeys = append(userKeys, k)
				}
			}
			keys = userKeys
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keys)

	case "POST":
		var req struct {
			Name        string     `json:"name"`
			Permissions []string   `json:"permissions"`
			ExpiresAt   *time.Time `json:"expires_at,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Non-admin users can only create readonly keys
		if session.Role != "admin" && !session.IsSuperAdmin {
			req.Permissions = []string{"read"}
		}

		apiKey, rawKey, err := m.CreateAPIKey(req.Name, req.Permissions, session.TenantID, req.ExpiresAt, session.UserID)
		if err != nil {
			http.Error(w, "Failed to create API key", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"key":         rawKey, // Only returned once!
			"id":          apiKey.ID,
			"name":        apiKey.Name,
			"prefix":      apiKey.KeyPrefix,
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
		// Check ownership for non-admins
		if session.Role != "admin" {
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
			Name        string `json:"name"`
			Description string `json:"description"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		tenant, err := m.UpdateTenant(tenantID, req.Name, req.Description)
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
