package api

import (
	"encoding/json"
	"net/http"

	"github.com/scott/dns/ports"
)

// PortManager interface for port management
type PortManager interface {
	GetConfig() ports.Config
	UpdateDNS(cfg ports.DNSPortConfig) error
	UpdateDoT(cfg ports.DoTPortConfig) error
	UpdateDoH(cfg ports.DoHPortConfig) error
	UpdateWeb(cfg ports.WebPortConfig) error
}

// portManager holds reference to the port manager
var portManager PortManager

// SetPortManager sets the port manager for API handlers
func SetPortManager(pm PortManager) {
	portManager = pm
}

// RegisterPortRoutes registers port management API routes
func RegisterPortRoutes(mux *http.ServeMux, corsMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/ports", corsMiddleware(handlePorts))
	mux.HandleFunc("/api/ports/dns", corsMiddleware(handlePortsDNS))
	mux.HandleFunc("/api/ports/dot", corsMiddleware(handlePortsDoT))
	mux.HandleFunc("/api/ports/doh", corsMiddleware(handlePortsDoH))
	mux.HandleFunc("/api/ports/web", corsMiddleware(handlePortsWeb))
}

// RegisterPortRoutesWithAuth registers port management routes with auth
func RegisterPortRoutesWithAuth(mux *http.ServeMux, corsMiddleware func(http.HandlerFunc) http.HandlerFunc, authMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return corsMiddleware(authMiddleware(h))
	}
	mux.HandleFunc("/api/ports", wrap(handlePorts))
	mux.HandleFunc("/api/ports/dns", wrap(handlePortsDNS))
	mux.HandleFunc("/api/ports/dot", wrap(handlePortsDoT))
	mux.HandleFunc("/api/ports/doh", wrap(handlePortsDoH))
	mux.HandleFunc("/api/ports/web", wrap(handlePortsWeb))
}

// handlePorts handles GET /api/ports - returns all port configuration
func handlePorts(w http.ResponseWriter, r *http.Request) {
	if portManager == nil {
		http.Error(w, "Port manager not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		config := portManager.GetConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)

	case http.MethodOptions:
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePortsDNS handles /api/ports/dns
func handlePortsDNS(w http.ResponseWriter, r *http.Request) {
	if portManager == nil {
		http.Error(w, "Port manager not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		config := portManager.GetConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config.DNS)

	case http.MethodPut, http.MethodPost:
		var cfg ports.DNSPortConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := portManager.UpdateDNS(cfg); err != nil {
			http.Error(w, "Failed to update DNS port: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"config":  cfg,
		})

	case http.MethodOptions:
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePortsDoT handles /api/ports/dot
func handlePortsDoT(w http.ResponseWriter, r *http.Request) {
	if portManager == nil {
		http.Error(w, "Port manager not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		config := portManager.GetConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config.DoT)

	case http.MethodPut, http.MethodPost:
		var cfg ports.DoTPortConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := portManager.UpdateDoT(cfg); err != nil {
			http.Error(w, "Failed to update DoT port: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"config":  cfg,
		})

	case http.MethodOptions:
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePortsDoH handles /api/ports/doh
func handlePortsDoH(w http.ResponseWriter, r *http.Request) {
	if portManager == nil {
		http.Error(w, "Port manager not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		config := portManager.GetConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config.DoH)

	case http.MethodPut, http.MethodPost:
		var cfg ports.DoHPortConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := portManager.UpdateDoH(cfg); err != nil {
			http.Error(w, "Failed to update DoH port: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"config":  cfg,
		})

	case http.MethodOptions:
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePortsWeb handles /api/ports/web
func handlePortsWeb(w http.ResponseWriter, r *http.Request) {
	if portManager == nil {
		http.Error(w, "Port manager not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		config := portManager.GetConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config.Web)

	case http.MethodPut, http.MethodPost:
		var cfg ports.WebPortConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := portManager.UpdateWeb(cfg); err != nil {
			http.Error(w, "Failed to update Web port: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"config":  cfg,
		})

	case http.MethodOptions:
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
