package sync

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	bolt "go.etcd.io/bbolt"
)

// APIHandler provides HTTP handlers for sync management
type APIHandler struct {
	manager *Manager
	db      *bolt.DB
}

// NewAPIHandler creates a new API handler for sync
func NewAPIHandler(manager *Manager) *APIHandler {
	return &APIHandler{
		manager: manager,
		db:      manager.db,
	}
}

// SyncConfigDTO is the data transfer object for sync configuration
type SyncConfigDTO struct {
	Enabled                bool         `json:"enabled"`
	ServerID               string       `json:"server_id"`
	ServerName             string       `json:"server_name"`
	SharedSecret           string       `json:"shared_secret,omitempty"`
	Peers                  []PeerConfig `json:"peers"`
	TombstoneRetentionDays int          `json:"tombstone_retention_days"`
}

// HandleConfig handles GET/PUT for sync configuration
func (h *APIHandler) HandleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getConfig(w, r)
	case http.MethodPut:
		h.updateConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *APIHandler) getConfig(w http.ResponseWriter, r *http.Request) {
	// Return current config (without exposing full shared secret)
	cfg := h.manager.config
	dto := SyncConfigDTO{
		Enabled:                cfg.Enabled,
		ServerID:               cfg.ServerID,
		ServerName:             cfg.ServerName,
		Peers:                  cfg.Peers,
		TombstoneRetentionDays: int(cfg.TombstoneRetention / (24 * time.Hour)),
	}

	// Mask shared secret if set
	if cfg.SharedSecret != "" {
		dto.SharedSecret = "••••••••"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto)
}

func (h *APIHandler) updateConfig(w http.ResponseWriter, r *http.Request) {
	var dto SyncConfigDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Build new config
	newCfg := &Config{
		Enabled:            dto.Enabled,
		ServerID:           dto.ServerID,
		ServerName:         dto.ServerName,
		Peers:              dto.Peers,
		TombstoneRetention: time.Duration(dto.TombstoneRetentionDays) * 24 * time.Hour,
	}

	// Only update shared secret if a new one is provided (not the masked value)
	if dto.SharedSecret != "" && dto.SharedSecret != "••••••••" {
		newCfg.SharedSecret = dto.SharedSecret
	} else {
		// Keep existing secret
		newCfg.SharedSecret = h.manager.config.SharedSecret
	}

	// Set defaults
	if newCfg.TombstoneRetention == 0 {
		newCfg.TombstoneRetention = 7 * 24 * time.Hour
	}
	if newCfg.ServerID == "" {
		newCfg.ServerID = GenerateServerID()
	}

	// Validate if enabling
	if err := newCfg.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Save to database
	if err := h.saveConfigToDB(newCfg); err != nil {
		http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update manager config
	h.manager.UpdateConfig(newCfg)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": "Configuration saved. Restart may be required for some changes.",
	})
}

func (h *APIHandler) saveConfigToDB(cfg *Config) error {
	return h.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("config"))
		if err != nil {
			return err
		}

		// Convert to storage format
		storeCfg := map[string]interface{}{
			"enabled":                  cfg.Enabled,
			"node_id":                  cfg.ServerID,
			"server_name":              cfg.ServerName,
			"shared_secret":            cfg.SharedSecret,
			"tombstone_retention_days": int(cfg.TombstoneRetention / (24 * time.Hour)),
			"peers":                    make([]map[string]interface{}, len(cfg.Peers)),
		}

		for i, p := range cfg.Peers {
			storeCfg["peers"].([]map[string]interface{})[i] = map[string]interface{}{
				"id":                   p.ID,
				"address":              p.URL,
				"url":                  p.URL,
				"api_key":              p.APIKey,
				"insecure_skip_verify": p.InsecureSkipVerify,
			}
		}

		data, err := json.Marshal(storeCfg)
		if err != nil {
			return err
		}

		return bucket.Put([]byte("sync"), data)
	})
}

// HandleGenerateSecret generates a new random shared secret
func (h *APIHandler) HandleGenerateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate 32 random bytes and hex encode
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		http.Error(w, "Failed to generate secret", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"secret": hex.EncodeToString(secret),
	})
}

// HandleStatus returns the current sync status
func (h *APIHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := h.manager.Status()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// HandlePeers manages peer configuration
func (h *APIHandler) HandlePeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listPeers(w, r)
	case http.MethodPost:
		h.addPeer(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *APIHandler) listPeers(w http.ResponseWriter, r *http.Request) {
	peers := make([]PeerConfig, len(h.manager.config.Peers))
	copy(peers, h.manager.config.Peers)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

func (h *APIHandler) addPeer(w http.ResponseWriter, r *http.Request) {
	var peer PeerConfig
	if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if peer.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// Add to config
	h.manager.config.Peers = append(h.manager.config.Peers, peer)

	// Start connecting to new peer
	go h.manager.connectToPeer(peer)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleForceSync triggers a full resync with a peer
func (h *APIHandler) HandleForceSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServerID string `json:"server_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	h.manager.peersMu.RLock()
	peer, ok := h.manager.peers[req.ServerID]
	h.manager.peersMu.RUnlock()

	if !ok {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}

	// Trigger sync
	go h.manager.performSync(peer)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "sync_triggered"})
}

// HandleFullSync triggers a full sync that broadcasts all local data to connected peers
func (h *APIHandler) HandleFullSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	count, err := h.manager.FullSync()
	if err != nil {
		http.Error(w, "Full sync failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "full_sync_complete",
		"items_synced": count,
	})
}

// HandlePurge clears the entire oplog and peer state
func (h *APIHandler) HandlePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	purged, err := h.manager.oplog.Purge()
	if err != nil {
		http.Error(w, "Failed to purge oplog: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"purged":  purged,
		"message": "Oplog and peer state cleared",
	})
}

// RegisterRoutesWithAuth registers sync API routes with authentication on the given mux
func (h *APIHandler) RegisterRoutesWithAuth(mux *http.ServeMux, authMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/sync/status", authMiddleware(h.HandleStatus))
	mux.HandleFunc("/api/sync/config", authMiddleware(h.HandleConfig))
	mux.HandleFunc("/api/sync/config/generate-secret", authMiddleware(h.HandleGenerateSecret))
	mux.HandleFunc("/api/sync/peers", authMiddleware(h.HandlePeers))
	mux.HandleFunc("/api/sync/force", authMiddleware(h.HandleForceSync))
	mux.HandleFunc("/api/sync/full-sync", authMiddleware(h.HandleFullSync))
	mux.HandleFunc("/api/sync/purge", authMiddleware(h.HandlePurge))

	// WebSocket endpoint for peer sync (no auth middleware, uses shared secret)
	mux.HandleFunc("/sync", h.manager.HandleWebSocket)
}

// RegisterRoutes is a package-level function to register sync routes
func RegisterRoutes(mux *http.ServeMux, mgr *Manager, corsMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	handler := NewAPIHandler(mgr)
	// Without auth, just apply CORS
	mux.HandleFunc("/api/sync/status", corsMiddleware(handler.HandleStatus))
	mux.HandleFunc("/api/sync/config", corsMiddleware(handler.HandleConfig))
	mux.HandleFunc("/api/sync/config/generate-secret", corsMiddleware(handler.HandleGenerateSecret))
	mux.HandleFunc("/api/sync/peers", corsMiddleware(handler.HandlePeers))
	mux.HandleFunc("/api/sync/force", corsMiddleware(handler.HandleForceSync))
	mux.HandleFunc("/api/sync/full-sync", corsMiddleware(handler.HandleFullSync))
	mux.HandleFunc("/api/sync/purge", corsMiddleware(handler.HandlePurge))
	// WebSocket endpoint for peer sync
	mux.HandleFunc("/sync", mgr.HandleWebSocket)
}
