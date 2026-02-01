package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCManager handles OpenID Connect authentication
type OIDCManager struct {
	config       *OIDCConfig
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	states       map[string]*oidcState
	mu           sync.RWMutex
}

type oidcState struct {
	State     string
	Nonce     string
	CreatedAt time.Time
	ReturnURL string
}

// OIDCClaims represents claims from an OIDC token
type OIDCClaims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	PreferredName string   `json:"preferred_username"`
	Groups        []string `json:"groups"`
}

// NewOIDCManager creates a new OIDC manager
func NewOIDCManager(ctx context.Context, config *OIDCConfig) (*OIDCManager, error) {
	if config == nil || !config.Enabled {
		return nil, errors.New("OIDC not enabled")
	}

	provider, err := oidc.NewProvider(ctx, config.ProviderURL)
	if err != nil {
		return nil, err
	}

	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return &OIDCManager{
		config:       config,
		provider:     provider,
		oauth2Config: oauth2Config,
		verifier:     verifier,
		states:       make(map[string]*oidcState),
	}, nil
}

// RegisterOIDCRoutes registers OIDC-specific routes
func (m *Manager) RegisterOIDCRoutes(mux *http.ServeMux, oidcMgr *OIDCManager) {
	if oidcMgr == nil {
		return
	}

	mux.HandleFunc("/api/auth/oidc/providers", m.corsHandler(oidcMgr.handleProviders))
	mux.HandleFunc("/api/auth/oidc/login", m.corsHandler(oidcMgr.handleLogin))
	mux.HandleFunc("/api/auth/oidc/callback", m.corsHandler(func(w http.ResponseWriter, r *http.Request) {
		oidcMgr.handleCallback(w, r, m)
	}))
}

func (om *OIDCManager) handleProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Return list of configured OIDC providers
	providers := []map[string]string{}
	if om.config != nil && om.config.Enabled {
		providers = append(providers, map[string]string{
			"id":   "default",
			"name": om.config.ProviderName,
			"icon": om.config.ProviderIcon,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(providers)
}

func (om *OIDCManager) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate state and nonce
	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	state := base64.URLEncoding.EncodeToString(stateBytes)

	nonceBytes := make([]byte, 16)
	rand.Read(nonceBytes)
	nonce := base64.URLEncoding.EncodeToString(nonceBytes)

	// Store state
	om.mu.Lock()
	om.states[state] = &oidcState{
		State:     state,
		Nonce:     nonce,
		CreatedAt: time.Now(),
		ReturnURL: r.URL.Query().Get("return_url"),
	}
	om.mu.Unlock()

	// Clean up old states
	go om.cleanupStates()

	// Redirect to OIDC provider
	authURL := om.oauth2Config.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "select_account"),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (om *OIDCManager) handleCallback(w http.ResponseWriter, r *http.Request, authMgr *Manager) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check for errors
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		http.Error(w, "OIDC error: "+errMsg+": "+errDesc, http.StatusBadRequest)
		return
	}

	// Verify state
	state := r.URL.Query().Get("state")
	om.mu.Lock()
	oidcState, exists := om.states[state]
	if exists {
		delete(om.states, state)
	}
	om.mu.Unlock()

	if !exists {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	code := r.URL.Query().Get("code")
	ctx := r.Context()
	token, err := om.oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Token exchange failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token in response", http.StatusBadRequest)
		return
	}

	// Verify ID token
	idToken, err := om.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Token verification failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Verify nonce
	if idToken.Nonce != oidcState.Nonce {
		http.Error(w, "Invalid nonce", http.StatusBadRequest)
		return
	}

	// Extract claims
	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check allowed groups
	if len(om.config.AllowedGroups) > 0 {
		allowed := false
		for _, allowedGroup := range om.config.AllowedGroups {
			for _, userGroup := range claims.Groups {
				if userGroup == allowedGroup {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			http.Error(w, "Access denied: not in allowed groups", http.StatusForbidden)
			return
		}
	}

	// Determine role based on groups
	role := "readonly"
	for _, adminGroup := range om.config.AdminGroups {
		for _, userGroup := range claims.Groups {
			if userGroup == adminGroup {
				role = "admin"
				break
			}
		}
		if role == "admin" {
			break
		}
	}

	// Find or create user
	username := claims.PreferredName
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Subject
	}

	authMgr.configMu.Lock()
	var user *User
	for i := range authMgr.config.Users {
		if authMgr.config.Users[i].ID == "oidc:"+claims.Subject {
			user = &authMgr.config.Users[i]
			user.LastLogin = time.Now()
			break
		}
	}

	if user == nil {
		// Create new OIDC user
		newUser := User{
			ID:          "oidc:" + claims.Subject,
			Username:    username,
			Email:       claims.Email,
			DisplayName: claims.Name,
			Role:        role,
			CreatedAt:   time.Now(),
			LastLogin:   time.Now(),
		}
		authMgr.config.Users = append(authMgr.config.Users, newUser)
		user = &authMgr.config.Users[len(authMgr.config.Users)-1]
	}
	authMgr.configMu.Unlock()

	go authMgr.saveConfig()

	// Create session
	session, err := authMgr.createSession(user, "oidc")
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
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

	// Redirect to return URL or dashboard
	returnURL := oidcState.ReturnURL
	if returnURL == "" {
		returnURL = "/dashboard"
	}

	// For SPA, we redirect with token in URL fragment (more secure) or to a page that sets it
	// Here we'll redirect to a simple success page that the Angular app can handle
	redirectURL := "/auth/callback?token=" + session.ID
	if returnURL != "" && !strings.HasPrefix(returnURL, "/auth") {
		redirectURL += "&return_url=" + returnURL
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (om *OIDCManager) cleanupStates() {
	om.mu.Lock()
	defer om.mu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	for state, data := range om.states {
		if data.CreatedAt.Before(cutoff) {
			delete(om.states, state)
		}
	}
}

// GetProviderInfo returns information about the OIDC provider
func (om *OIDCManager) GetProviderInfo() map[string]interface{} {
	return map[string]interface{}{
		"enabled":      om.config.Enabled,
		"provider_url": om.config.ProviderURL,
		"client_id":    om.config.ClientID,
	}
}

// UpdateConfig updates the OIDC configuration
func (m *Manager) UpdateOIDCConfig(config *OIDCConfig) error {
	m.configMu.Lock()
	m.config.OIDC = config
	m.configMu.Unlock()
	return m.saveConfig()
}

// UpdateWebAuthnConfig updates the WebAuthn configuration
func (m *Manager) UpdateWebAuthnConfig(config *WebAuthnConfig) error {
	m.configMu.Lock()
	m.config.WebAuthn = config
	m.configMu.Unlock()
	return m.saveConfig()
}
