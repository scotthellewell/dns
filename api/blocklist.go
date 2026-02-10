package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/scott/dns/blocklist"
)

// BlocklistManager is the interface for blocklist operations in the API.
type BlocklistManager interface {
	GetConfig() *blocklist.Config
	SetConfig(cfg *blocklist.Config) error
	GetSources() []*blocklist.Source
	AddSource(source *blocklist.Source) error
	RemoveSource(id string) error
	GetWhitelist() []string
	SetWhitelist(entries []string) error
	AddToWhitelist(domains ...string) error
	RemoveFromWhitelist(domains ...string) error
	GetStats() map[string]interface{}
	ForceUpdate()
	ForceUpdateSource(sourceID string) error
	Check(domain string) bool
}

// SetBlocklistManager sets the blocklist manager for the API handler.
func (h *Handler) SetBlocklistManager(bl BlocklistManager) {
	h.configMu.Lock()
	defer h.configMu.Unlock()
	h.blocklistMgr = bl
}

// getBlocklistManager returns the blocklist manager if set.
func (h *Handler) getBlocklistManager() BlocklistManager {
	h.configMu.RLock()
	defer h.configMu.RUnlock()
	return h.blocklistMgr
}

// handleBlocklist handles blocklist configuration endpoints.
func (h *Handler) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	bl := h.getBlocklistManager()
	if bl == nil {
		http.Error(w, "Blocklist not enabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Return blocklist config and stats
		cfg := bl.GetConfig()
		stats := bl.GetStats()
		
		response := map[string]interface{}{
			"config": cfg,
			"stats":  stats,
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	case http.MethodPut:
		// Update blocklist config
		var cfg blocklist.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		
		if err := bl.SetConfig(&cfg); err != nil {
			http.Error(w, "Failed to update config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBlocklistSources handles blocklist source management.
func (h *Handler) handleBlocklistSources(w http.ResponseWriter, r *http.Request) {
	bl := h.getBlocklistManager()
	if bl == nil {
		http.Error(w, "Blocklist not enabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// List all sources
		sources := bl.GetSources()
		available := blocklist.AvailableSources()
		
		response := map[string]interface{}{
			"sources":   sources,
			"available": available,
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	case http.MethodPost:
		// Add a new source
		var source blocklist.Source
		if err := json.NewDecoder(r.Body).Decode(&source); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		
		// Validate required fields
		if source.ID == "" {
			http.Error(w, "Source ID is required", http.StatusBadRequest)
			return
		}
		if source.URL == "" {
			http.Error(w, "Source URL is required", http.StatusBadRequest)
			return
		}
		if source.Format == "" {
			source.Format = "domains" // Default format
		}
		if source.UpdateMinutes == 0 {
			source.UpdateMinutes = 720 // Default 12 hours
		}
		
		if err := bl.AddSource(&source); err != nil {
			http.Error(w, "Failed to add source: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(source)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBlocklistSource handles individual blocklist source operations.
func (h *Handler) handleBlocklistSource(w http.ResponseWriter, r *http.Request) {
	bl := h.getBlocklistManager()
	if bl == nil {
		http.Error(w, "Blocklist not enabled", http.StatusServiceUnavailable)
		return
	}

	// Extract source ID from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/blocklist/sources/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Source ID required", http.StatusBadRequest)
		return
	}
	sourceID := parts[0]
	
	// Check for action
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch r.Method {
	case http.MethodPost:
		// Handle actions like /api/blocklist/sources/{id}/refresh
		if action == "refresh" {
			if err := bl.ForceUpdateSource(sourceID); err != nil {
				http.Error(w, "Failed to refresh source: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "refreshing", "source_id": sourceID})
			return
		}
		http.Error(w, "Unknown action", http.StatusBadRequest)

	case http.MethodDelete:
		// Delete source
		if err := bl.RemoveSource(sourceID); err != nil {
			http.Error(w, "Failed to delete source: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "source_id": sourceID})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBlocklistWhitelist handles whitelist management.
func (h *Handler) handleBlocklistWhitelist(w http.ResponseWriter, r *http.Request) {
	bl := h.getBlocklistManager()
	if bl == nil {
		http.Error(w, "Blocklist not enabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// List whitelist entries
		entries := bl.GetWhitelist()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"whitelist": entries,
			"count":     len(entries),
		})

	case http.MethodPost:
		// Add to whitelist
		var req struct {
			Domains []string `json:"domains"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		
		if len(req.Domains) == 0 {
			http.Error(w, "At least one domain is required", http.StatusBadRequest)
			return
		}
		
		if err := bl.AddToWhitelist(req.Domains...); err != nil {
			http.Error(w, "Failed to add to whitelist: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "added",
			"count":  len(req.Domains),
		})

	case http.MethodPut:
		// Replace entire whitelist
		var req struct {
			Domains []string `json:"domains"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		
		if err := bl.SetWhitelist(req.Domains); err != nil {
			http.Error(w, "Failed to set whitelist: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "updated",
			"count":  len(req.Domains),
		})

	case http.MethodDelete:
		// Remove from whitelist
		var req struct {
			Domains []string `json:"domains"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		
		if len(req.Domains) == 0 {
			http.Error(w, "At least one domain is required", http.StatusBadRequest)
			return
		}
		
		if err := bl.RemoveFromWhitelist(req.Domains...); err != nil {
			http.Error(w, "Failed to remove from whitelist: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "removed",
			"count":   len(req.Domains),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBlocklistTest tests if a domain would be blocked.
func (h *Handler) handleBlocklistTest(w http.ResponseWriter, r *http.Request) {
	bl := h.getBlocklistManager()
	if bl == nil {
		http.Error(w, "Blocklist not enabled", http.StatusServiceUnavailable)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract domain from URL: /api/blocklist/test/{domain}
	domain := strings.TrimPrefix(r.URL.Path, "/api/blocklist/test/")
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}

	blocked := bl.Check(domain)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":  domain,
		"blocked": blocked,
	})
}

// handleBlocklistRefresh triggers an immediate update of all sources.
func (h *Handler) handleBlocklistRefresh(w http.ResponseWriter, r *http.Request) {
	bl := h.getBlocklistManager()
	if bl == nil {
		http.Error(w, "Blocklist not enabled", http.StatusServiceUnavailable)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	go bl.ForceUpdate()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "refreshing"})
}
