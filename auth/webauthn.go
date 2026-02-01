package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnUser implements webauthn.User interface
type WebAuthnUser struct {
	user *User
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.user.Username
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.user.Username
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(u.user.WebAuthnCredentials))
	for i, c := range u.user.WebAuthnCredentials {
		creds[i] = webauthn.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Flags: webauthn.CredentialFlags{
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		}
	}
	return creds
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

// WebAuthn session data storage (in-memory for simplicity)
var webAuthnSessions = make(map[string]*webauthn.SessionData)

// RegisterWebAuthnRoutes registers WebAuthn-specific routes
func (m *Manager) RegisterWebAuthnRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/auth/webauthn/register/begin", m.corsHandler(m.MiddlewareFunc(m.handleWebAuthnRegisterBegin)))
	mux.HandleFunc("/api/auth/webauthn/register/finish", m.corsHandler(m.MiddlewareFunc(m.handleWebAuthnRegisterFinish)))
	mux.HandleFunc("/api/auth/webauthn/login/begin", m.corsHandler(m.handleWebAuthnLoginBegin))
	mux.HandleFunc("/api/auth/webauthn/login/finish", m.corsHandler(m.handleWebAuthnLoginFinish))
	mux.HandleFunc("/api/auth/webauthn/credentials", m.corsHandler(m.MiddlewareFunc(m.handleWebAuthnCredentials)))
}

func (m *Manager) getWebAuthn() (*webauthn.WebAuthn, error) {
	m.configMu.RLock()
	defer m.configMu.RUnlock()

	if m.config.WebAuthn == nil || !m.config.WebAuthn.Enabled {
		return nil, ErrUnauthorized
	}

	return webauthn.New(&webauthn.Config{
		RPDisplayName: m.config.WebAuthn.RPDisplayName,
		RPID:          m.config.WebAuthn.RPID,
		RPOrigins:     m.config.WebAuthn.RPOrigins,
	})
}

func (m *Manager) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	wn, err := m.getWebAuthn()
	if err != nil {
		http.Error(w, "WebAuthn not configured", http.StatusBadRequest)
		return
	}

	// Find user
	m.configMu.RLock()
	var user *User
	for i := range m.config.Users {
		if m.config.Users[i].ID == session.UserID {
			user = &m.config.Users[i]
			break
		}
	}
	m.configMu.RUnlock()

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	webauthnUser := &WebAuthnUser{user: user}

	// Begin registration
	options, sessionData, err := wn.BeginRegistration(webauthnUser,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		http.Error(w, "Failed to begin registration", http.StatusInternalServerError)
		return
	}

	// Store session data
	sessionID := generateWebAuthnSessionID()
	webAuthnSessions[sessionID] = sessionData

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "webauthn_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		MaxAge:   300,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (m *Manager) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	wn, err := m.getWebAuthn()
	if err != nil {
		http.Error(w, "WebAuthn not configured", http.StatusBadRequest)
		return
	}

	// Get session data
	cookie, err := r.Cookie("webauthn_session")
	if err != nil {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	sessionData, exists := webAuthnSessions[cookie.Value]
	if !exists {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}
	delete(webAuthnSessions, cookie.Value)

	// Get credential name from query param
	credentialName := r.URL.Query().Get("name")
	if credentialName == "" {
		credentialName = "Passkey"
	}

	// Find user
	m.configMu.Lock()
	defer m.configMu.Unlock()

	var userIndex int = -1
	for i := range m.config.Users {
		if m.config.Users[i].ID == session.UserID {
			userIndex = i
			break
		}
	}

	if userIndex < 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	webauthnUser := &WebAuthnUser{user: &m.config.Users[userIndex]}

	// Finish registration
	credential, err := wn.FinishRegistration(webauthnUser, *sessionData, r)
	if err != nil {
		http.Error(w, "Registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Store credential
	credID := generateWebAuthnSessionID()
	m.config.Users[userIndex].WebAuthnCredentials = append(
		m.config.Users[userIndex].WebAuthnCredentials,
		WebAuthnCredential{
			ID:              credID,
			Name:            credentialName,
			CredentialID:    credential.ID,
			PublicKey:       credential.PublicKey,
			AttestationType: credential.AttestationType,
			AAGUID:          credential.Authenticator.AAGUID,
			SignCount:       credential.Authenticator.SignCount,
			BackupEligible:  credential.Flags.BackupEligible,
			BackupState:     credential.Flags.BackupState,
			CreatedAt:       time.Now(),
		},
	)

	if err := m.saveConfigLocked(); err != nil {
		http.Error(w, "Failed to save credential", http.StatusInternalServerError)
		return
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "webauthn_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"credential": map[string]string{
			"id":   credID,
			"name": credentialName,
		},
	})
}

func (m *Manager) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	wn, err := m.getWebAuthn()
	if err != nil {
		http.Error(w, "WebAuthn not configured", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body for discoverable credentials
		req.Username = ""
	}

	if req.Username != "" {
		// Find user and begin authentication
		m.configMu.RLock()
		var user *User
		for i := range m.config.Users {
			if m.config.Users[i].Username == req.Username {
				user = &m.config.Users[i]
				break
			}
		}
		m.configMu.RUnlock()

		if user == nil || len(user.WebAuthnCredentials) == 0 {
			http.Error(w, "No passkeys found for user", http.StatusBadRequest)
			return
		}

		webauthnUser := &WebAuthnUser{user: user}
		options, sessionData, err := wn.BeginLogin(webauthnUser)
		if err != nil {
			http.Error(w, "Failed to begin login", http.StatusInternalServerError)
			return
		}

		sessionID := generateWebAuthnSessionID()
		webAuthnSessions[sessionID] = sessionData

		http.SetCookie(w, &http.Cookie{
			Name:     "webauthn_session",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			MaxAge:   300,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(options)
	} else {
		// Discoverable credentials flow
		options, sessionData, err := wn.BeginDiscoverableLogin()
		if err != nil {
			http.Error(w, "Failed to begin login", http.StatusInternalServerError)
			return
		}

		sessionID := generateWebAuthnSessionID()
		webAuthnSessions[sessionID] = sessionData

		http.SetCookie(w, &http.Cookie{
			Name:     "webauthn_session",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			MaxAge:   300,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(options)
	}
}

func (m *Manager) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	wn, err := m.getWebAuthn()
	if err != nil {
		http.Error(w, "WebAuthn not configured", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("webauthn_session")
	if err != nil {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	sessionData, exists := webAuthnSessions[cookie.Value]
	if !exists {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}
	delete(webAuthnSessions, cookie.Value)

	// Parse the credential response to get user handle for discoverable credentials
	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		http.Error(w, "Invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Find user by credential ID
	m.configMu.Lock()
	defer m.configMu.Unlock()

	var userIndex int = -1
	var credIndex int = -1

	for i := range m.config.Users {
		for j, cred := range m.config.Users[i].WebAuthnCredentials {
			if bytes.Equal(cred.CredentialID, parsedResponse.RawID) {
				userIndex = i
				credIndex = j
				break
			}
		}
		if userIndex >= 0 {
			break
		}
	}

	if userIndex < 0 {
		http.Error(w, "Credential not found", http.StatusUnauthorized)
		return
	}

	user := &m.config.Users[userIndex]
	webauthnUser := &WebAuthnUser{user: user}

	// Use ValidateDiscoverableLogin with a handler function that returns the user
	// This works for both discoverable and non-discoverable credentials
	userHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
		return webauthnUser, nil
	}

	credential, err := wn.ValidateDiscoverableLogin(userHandler, *sessionData, parsedResponse)
	if err != nil {
		// Log the actual error for debugging
		log.Printf("WebAuthn login validation failed: %v", err)
		http.Error(w, "Login failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Update sign count
	m.config.Users[userIndex].WebAuthnCredentials[credIndex].SignCount = credential.Authenticator.SignCount
	m.config.Users[userIndex].LastLogin = time.Now()
	m.saveConfigLocked() // Save sign count update

	// Create session
	session, err := m.createSession(user, "webauthn")
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Clear WebAuthn session cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "webauthn_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	// Set auth session cookie
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
		"user": map[string]string{
			"id":       session.UserID,
			"username": session.Username,
			"role":     session.Role,
		},
		"expires_at": session.ExpiresAt,
	})
}

func (m *Manager) handleWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case "GET":
		m.configMu.RLock()
		var credentials []map[string]interface{}
		for _, user := range m.config.Users {
			if user.ID == session.UserID {
				for _, cred := range user.WebAuthnCredentials {
					credentials = append(credentials, map[string]interface{}{
						"id":         cred.ID,
						"name":       cred.Name,
						"created_at": cred.CreatedAt,
					})
				}
				break
			}
		}
		m.configMu.RUnlock()

		if credentials == nil {
			credentials = []map[string]interface{}{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(credentials)

	case "DELETE":
		credID := r.URL.Query().Get("id")
		if credID == "" {
			http.Error(w, "Credential ID required", http.StatusBadRequest)
			return
		}

		m.configMu.Lock()
		for i := range m.config.Users {
			if m.config.Users[i].ID == session.UserID {
				for j, cred := range m.config.Users[i].WebAuthnCredentials {
					if cred.ID == credID {
						m.config.Users[i].WebAuthnCredentials = append(
							m.config.Users[i].WebAuthnCredentials[:j],
							m.config.Users[i].WebAuthnCredentials[j+1:]...,
						)
						break
					}
				}
				break
			}
		}
		m.configMu.Unlock()

		if err := m.saveConfig(); err != nil {
			http.Error(w, "Failed to delete credential", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func generateWebAuthnSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}
