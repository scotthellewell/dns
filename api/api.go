package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scott/dns/auth"
	"github.com/scott/dns/config"
	"github.com/scott/dns/metrics"
	"github.com/scott/dns/storage"
)

// TODO: Add authentication middleware

// Stats holds server statistics
type Stats struct {
	StartTime     time.Time
	TotalQueries  uint64
	QueriesByType map[string]uint64
	mu            sync.RWMutex
}

// Handler provides the HTTP API for the DNS server
type Handler struct {
	config         *config.ParsedConfig
	rawConfig      *config.Config
	configPath     string
	stats          *Stats
	metrics        *metrics.Collector
	configMu       sync.RWMutex
	onConfigUpdate func(*config.ParsedConfig)
	store          interface{} // Optional storage backend (*storage.Store)
}

// New creates a new API handler with ephemeral storage.
// This ensures consistent API behavior between test and production modes.
// For production use, prefer NewWithStorage() with a persistent storage backend.
func New(cfg *config.ParsedConfig, rawCfg *config.Config, configPath string, onUpdate func(*config.ParsedConfig)) *Handler {
	// Create ephemeral in-memory storage for consistent behavior
	tmpDir, err := os.MkdirTemp("", "dns-ephemeral-*")
	if err != nil {
		log.Printf("Warning: failed to create ephemeral storage dir: %v", err)
		// Fall back to handler without storage (legacy behavior)
		return &Handler{
			config:         cfg,
			rawConfig:      rawCfg,
			configPath:     configPath,
			onConfigUpdate: onUpdate,
			metrics:        metrics.New(),
			stats: &Stats{
				StartTime:     time.Now(),
				QueriesByType: make(map[string]uint64),
			},
		}
	}

	store, err := storage.Open(storage.Options{DataDir: tmpDir})
	if err != nil {
		log.Printf("Warning: failed to create ephemeral storage: %v", err)
		os.RemoveAll(tmpDir)
		return &Handler{
			config:         cfg,
			rawConfig:      rawCfg,
			configPath:     configPath,
			onConfigUpdate: onUpdate,
			metrics:        metrics.New(),
			stats: &Stats{
				StartTime:     time.Now(),
				QueriesByType: make(map[string]uint64),
			},
		}
	}

	// Sync rawConfig zones to ephemeral storage
	if rawCfg != nil {
		for _, z := range rawCfg.Zones {
			zone := &storage.Zone{
				Name:     z.Name,
				Type:     storage.ZoneType(z.Type),
				Subnet:   z.Subnet,
				Domain:   z.Domain,
				TenantID: z.TenantID,
				TTL:      z.TTL,
			}
			if zone.TenantID == "" {
				zone.TenantID = storage.MainTenantID
			}
			store.CreateZone(zone)
		}
	}

	return &Handler{
		config:         cfg,
		rawConfig:      rawCfg,
		configPath:     configPath,
		onConfigUpdate: onUpdate,
		metrics:        metrics.New(),
		stats: &Stats{
			StartTime:     time.Now(),
			QueriesByType: make(map[string]uint64),
		},
		store: store,
	}
}

// UpdateConfig updates the handler's config reference
func (h *Handler) UpdateConfig(cfg *config.ParsedConfig, rawCfg *config.Config) {
	h.configMu.Lock()
	defer h.configMu.Unlock()
	h.config = cfg
	h.rawConfig = rawCfg
}

// IncrementQueryCount increments the query counter
func (h *Handler) IncrementQueryCount(qtype string) {
	atomic.AddUint64(&h.stats.TotalQueries, 1)
	h.stats.mu.Lock()
	h.stats.QueriesByType[qtype]++
	h.stats.mu.Unlock()
}

// GetMetrics returns the metrics collector for external use
func (h *Handler) GetMetrics() *metrics.Collector {
	return h.metrics
}

// AuthMiddleware is an interface for auth middleware
type AuthMiddleware interface {
	MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc
	IsEnabled() bool
}

// RegisterRoutes registers all API routes (no auth)
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Status and stats
	mux.HandleFunc("/api/status", h.corsMiddleware(h.handleStatus))

	// Prometheus metrics - public endpoint
	mux.HandleFunc("/metrics", h.handleMetrics)

	// Configuration
	mux.HandleFunc("/api/config", h.corsMiddleware(h.handleConfig))

	// Zones (reverse DNS patterns)
	mux.HandleFunc("/api/zones", h.corsMiddleware(h.handleZones))
	mux.HandleFunc("/api/zones/", h.corsMiddleware(h.handleZone))

	// DNS Records
	mux.HandleFunc("/api/records", h.corsMiddleware(h.handleRecords))
	mux.HandleFunc("/api/records/", h.corsMiddleware(h.handleRecord))

	// Secondary zones
	mux.HandleFunc("/api/secondary-zones", h.corsMiddleware(h.handleSecondaryZones))
	mux.HandleFunc("/api/secondary-zones/", h.corsMiddleware(h.handleSecondaryZone))

	// Transfer settings
	mux.HandleFunc("/api/transfer", h.corsMiddleware(h.handleTransfer))

	// Recursion settings
	mux.HandleFunc("/api/recursion", h.corsMiddleware(h.handleRecursion))

	// DNSSEC settings
	mux.HandleFunc("/api/dnssec", h.corsMiddleware(h.handleDNSSEC))

	// Server settings
	mux.HandleFunc("/api/settings", h.corsMiddleware(h.handleSettings))

	// Audit logs
	mux.HandleFunc("/api/audit", h.corsMiddleware(h.handleAudit))
}

// RegisterRoutesWithAuth registers all API routes with authentication middleware
func (h *Handler) RegisterRoutesWithAuth(mux *http.ServeMux, authMgr AuthMiddleware) {
	// Wrap handlers with auth middleware
	wrap := func(handler http.HandlerFunc) http.HandlerFunc {
		return h.corsMiddleware(authMgr.MiddlewareFunc(handler))
	}

	// Status is public (shows basic info even when not authenticated)
	mux.HandleFunc("/api/status", h.corsMiddleware(h.handleStatus))

	// Prometheus metrics - public endpoint
	mux.HandleFunc("/metrics", h.handleMetrics)

	// All other routes require authentication
	mux.HandleFunc("/api/config", wrap(h.handleConfig))
	mux.HandleFunc("/api/zones", wrap(h.handleZones))
	mux.HandleFunc("/api/zones/", wrap(h.handleZone))
	mux.HandleFunc("/api/records", wrap(h.handleRecords))
	mux.HandleFunc("/api/records/", wrap(h.handleRecord))
	mux.HandleFunc("/api/secondary-zones", wrap(h.handleSecondaryZones))
	mux.HandleFunc("/api/secondary-zones/", wrap(h.handleSecondaryZone))
	mux.HandleFunc("/api/delegations", wrap(h.handleDelegations))
	mux.HandleFunc("/api/delegations/", wrap(h.handleDelegation))
	mux.HandleFunc("/api/dnssec/keys/", wrap(h.handleDNSSECKeys))   // Export/import keys
	mux.HandleFunc("/api/dnssec/token/", wrap(h.handleDNSSECToken)) // Key token management
	mux.HandleFunc("/api/transfer", wrap(h.handleTransfer))
	mux.HandleFunc("/api/recursion", wrap(h.handleRecursion))
	mux.HandleFunc("/api/dnssec", wrap(h.handleDNSSEC))
	mux.HandleFunc("/api/settings", wrap(h.handleSettings))
	mux.HandleFunc("/api/audit", wrap(h.handleAudit))
}

// CORSMiddleware adds CORS headers - standalone version for use outside Handler
func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
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

// corsMiddleware adds CORS headers for development
func (h *Handler) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
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

// StatusResponse contains server status information
type StatusResponse struct {
	Status         string            `json:"status"`
	Uptime         string            `json:"uptime"`
	UptimeSeconds  float64           `json:"uptime_seconds"`
	TotalQueries   uint64            `json:"total_queries"`
	QueriesByType  map[string]uint64 `json:"queries_by_type"`
	Listen         string            `json:"listen"`
	ZoneCount      int               `json:"zone_count"`
	RecordCount    int               `json:"record_count"`
	SecondaryZones int               `json:"secondary_zones"`
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.configMu.RLock()
	cfg := h.config
	h.configMu.RUnlock()

	h.stats.mu.RLock()
	queryTypes := make(map[string]uint64)
	for k, v := range h.stats.QueriesByType {
		queryTypes[k] = v
	}
	h.stats.mu.RUnlock()

	uptime := time.Since(h.stats.StartTime)

	// Count records
	recordCount := len(cfg.ARecords) + len(cfg.AAAARecords) + len(cfg.MXRecords) +
		len(cfg.TXTRecords) + len(cfg.NSRecords) + len(cfg.SOARecords) +
		len(cfg.CNAMERecords) + len(cfg.SRVRecords) + len(cfg.CAARecords) +
		len(cfg.PTRRecords)

	resp := StatusResponse{
		Status:         "running",
		Uptime:         uptime.Round(time.Second).String(),
		UptimeSeconds:  uptime.Seconds(),
		TotalQueries:   atomic.LoadUint64(&h.stats.TotalQueries),
		QueriesByType:  queryTypes,
		Listen:         cfg.Listen,
		ZoneCount:      len(cfg.Zones),
		RecordCount:    recordCount,
		SecondaryZones: len(cfg.SecondaryZones),
	}

	h.jsonResponse(w, resp)
}

func (h *Handler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Update zone and record counts from current config
	h.configMu.RLock()
	cfg := h.config
	h.configMu.RUnlock()

	if h.metrics != nil {
		h.metrics.SetZonesTotal(uint64(len(cfg.Zones)))
		recordCount := len(cfg.ARecords) + len(cfg.AAAARecords) + len(cfg.MXRecords) +
			len(cfg.TXTRecords) + len(cfg.NSRecords) + len(cfg.SOARecords) +
			len(cfg.CNAMERecords) + len(cfg.SRVRecords) + len(cfg.CAARecords) +
			len(cfg.PTRRecords)
		h.metrics.SetRecordsTotal(uint64(recordCount))

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		h.metrics.WritePrometheus(w)
	} else {
		http.Error(w, "Metrics not available", http.StatusServiceUnavailable)
	}
}

func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.configMu.RLock()
		cfg := h.rawConfig
		h.configMu.RUnlock()
		h.jsonResponse(w, cfg)

	case "PUT":
		var newConfig config.Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Parse and validate the config
		parsed, err := newConfig.Parse()
		if err != nil {
			h.errorResponse(w, "Invalid configuration: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Save to file
		if err := config.SaveConfig(h.configPath, &newConfig); err != nil {
			h.errorResponse(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Update in-memory config
		h.configMu.Lock()
		h.config = parsed
		h.rawConfig = &newConfig
		h.configMu.Unlock()

		// Notify server of update
		if h.onConfigUpdate != nil {
			h.onConfigUpdate(parsed)
		}

		log.Printf("API: Configuration updated")
		h.jsonResponse(w, map[string]string{"status": "ok", "message": "Configuration updated"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ZoneResponse represents a zone in API responses
type ZoneResponse struct {
	ID          int             `json:"id"`
	ZoneID      string          `json:"zone_id,omitempty"` // Storage-based ID
	TenantID    string          `json:"tenant_id,omitempty"`
	Name        string          `json:"name"`             // Zone name (e.g., "example.com" or "168.192.in-addr.arpa")
	Type        config.ZoneType `json:"type"`             // "forward" or "reverse"
	Subnet      string          `json:"subnet,omitempty"` // For reverse zones
	Domain      string          `json:"domain,omitempty"` // For reverse zones (legacy)
	StripPrefix bool            `json:"strip_prefix"`
	TTL         uint32          `json:"ttl"`
}

// RecordResponse represents a DNS record in API responses
type RecordResponse struct {
	ID       string `json:"id"`
	ZoneID   string `json:"zone_id"`
	ZoneName string `json:"zone_name,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
	TTL      uint32 `json:"ttl"`
	// Type-specific fields
	IP       string   `json:"ip,omitempty"`       // A, AAAA
	Target   string   `json:"target,omitempty"`   // CNAME, MX, NS, PTR, SRV
	Priority int      `json:"priority,omitempty"` // MX, SRV
	Weight   int      `json:"weight,omitempty"`   // SRV
	Port     int      `json:"port,omitempty"`     // SRV
	Values   []string `json:"values,omitempty"`   // TXT
}

// getEffectiveZoneName returns the effective zone name from a ZoneConfig
// For forward zones, this is the Name field
// For reverse zones, this is generated from the Subnet
func getEffectiveZoneName(z config.ZoneConfig) string {
	if z.Name != "" {
		return z.Name
	}
	// Generate from subnet for reverse zones
	if z.Subnet != "" {
		// Parse CIDR and convert to in-addr.arpa format
		parts := strings.Split(strings.Split(z.Subnet, "/")[0], ".")
		if len(parts) == 4 {
			// Reverse the first 3 octets for typical /24 network
			return parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa"
		}
	}
	return z.Domain
}

// getEffectiveZoneType returns the zone type, inferring from fields if not set
func getEffectiveZoneType(z config.ZoneConfig) config.ZoneType {
	if z.Type != "" {
		return z.Type
	}
	// Infer from fields
	if z.Subnet != "" {
		return config.ZoneTypeReverse
	}
	return config.ZoneTypeForward
}

func (h *Handler) handleZones(w http.ResponseWriter, r *http.Request) {
	session := auth.GetSession(r.Context())

	// Use storage backend if available for all methods
	if h.hasStorage() {
		h.handleZonesStorage(w, r, session)
		return
	}

	switch r.Method {
	case "GET":
		h.configMu.RLock()
		zones := h.rawConfig.Zones
		h.configMu.RUnlock()

		var resp []ZoneResponse
		for i, z := range zones {
			// Filter by tenant - super admins see all, others only see their tenant
			// Empty TenantID means main tenant (backward compatibility)
			zoneTenant := z.TenantID
			if zoneTenant == "" {
				zoneTenant = auth.MainTenantID
			}

			// Normalize session tenant ID too (backward compatibility)
			sessionTenant := ""
			if session != nil {
				sessionTenant = session.TenantID
				if sessionTenant == "" {
					sessionTenant = auth.MainTenantID
				}
			}

			// If session exists and user is not super admin, filter by tenant
			// Also treat admin role in main tenant as super admin for backward compatibility
			isSuperAdmin := session != nil && (session.IsSuperAdmin || (session.Role == "admin" && sessionTenant == auth.MainTenantID))
			if session != nil && !isSuperAdmin {
				if sessionTenant != zoneTenant {
					continue
				}
			}

			resp = append(resp, ZoneResponse{
				ID:          i,
				TenantID:    z.TenantID,
				Name:        getEffectiveZoneName(z),
				Type:        getEffectiveZoneType(z),
				Subnet:      z.Subnet,
				Domain:      z.Domain,
				StripPrefix: z.StripPrefix,
				TTL:         z.TTL,
			})
		}
		h.jsonResponse(w, resp)

	case "POST":
		var zone config.ZoneConfig
		if err := json.NewDecoder(r.Body).Decode(&zone); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Set tenant ID from session if not super admin
		if session != nil && !session.IsSuperAdmin {
			zone.TenantID = session.TenantID
		}

		// If no tenant specified and user is super admin, default to main tenant
		if zone.TenantID == "" && session != nil && session.IsSuperAdmin {
			zone.TenantID = auth.MainTenantID
		}

		h.configMu.Lock()
		h.rawConfig.Zones = append(h.rawConfig.Zones, zone)
		h.configMu.Unlock()

		if err := h.saveAndReload(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok", "id": len(h.rawConfig.Zones) - 1})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleZone(w http.ResponseWriter, r *http.Request) {
	session := auth.GetSession(r.Context())

	// Extract ID from path: /api/zones/{id}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/zones/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		h.errorResponse(w, "Zone ID required", http.StatusBadRequest)
		return
	}

	// Use storage backend if available
	if h.hasStorage() {
		// With storage, the ID is a string (UUID)
		h.handleZoneStorage(w, r, session, parts[0])
		return
	}

	id, err := strconv.Atoi(parts[0])
	if err != nil {
		h.errorResponse(w, "Invalid zone ID", http.StatusBadRequest)
		return
	}

	h.configMu.Lock()
	defer h.configMu.Unlock()

	if id < 0 || id >= len(h.rawConfig.Zones) {
		h.errorResponse(w, "Zone not found", http.StatusNotFound)
		return
	}

	// Check tenant access
	zone := h.rawConfig.Zones[id]
	zoneTenant := zone.TenantID
	if zoneTenant == "" {
		zoneTenant = auth.MainTenantID
	}
	// Normalize session tenant and check super admin status
	sessionTenant := ""
	isSuperAdmin := false
	if session != nil {
		sessionTenant = session.TenantID
		if sessionTenant == "" {
			sessionTenant = auth.MainTenantID
		}
		isSuperAdmin = session.IsSuperAdmin || (session.Role == "admin" && sessionTenant == auth.MainTenantID)
	}
	if session != nil && !isSuperAdmin && sessionTenant != zoneTenant {
		h.errorResponse(w, "Forbidden - zone belongs to different tenant", http.StatusForbidden)
		return
	}

	switch r.Method {
	case "GET":
		h.jsonResponse(w, ZoneResponse{
			ID:          id,
			TenantID:    zone.TenantID,
			Name:        getEffectiveZoneName(zone),
			Type:        getEffectiveZoneType(zone),
			Subnet:      zone.Subnet,
			Domain:      zone.Domain,
			StripPrefix: zone.StripPrefix,
			TTL:         zone.TTL,
		})

	case "PUT":
		var updatedZone config.ZoneConfig
		if err := json.NewDecoder(r.Body).Decode(&updatedZone); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Preserve tenant ID - don't allow changing it unless super admin
		if session != nil && !session.IsSuperAdmin {
			updatedZone.TenantID = zone.TenantID
		}

		h.rawConfig.Zones[id] = updatedZone

		if err := h.saveAndReloadUnlocked(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	case "DELETE":
		h.rawConfig.Zones = append(h.rawConfig.Zones[:id], h.rawConfig.Zones[id+1:]...)

		if err := h.saveAndReloadUnlocked(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// RecordRequest represents a generic record for API operations
type RecordRequest struct {
	Type     string `json:"type"` // A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA, PTR, ALIAS, SSHFP, TLSA, NAPTR, SVCB, HTTPS, LOC
	TenantID string `json:"tenant_id,omitempty"`
	Zone     string `json:"zone,omitempty"` // Zone this record belongs to
	Name     string `json:"name"`
	TTL      uint32 `json:"ttl"`
	// A/AAAA
	IP string `json:"ip,omitempty"`
	// MX
	Priority uint16 `json:"priority,omitempty"`
	// MX, NS, CNAME, SRV, ALIAS
	Target string `json:"target,omitempty"`
	// TXT
	Values []string `json:"values,omitempty"`
	// SOA
	MName   string `json:"mname,omitempty"`
	RName   string `json:"rname,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Refresh uint32 `json:"refresh,omitempty"`
	Retry   uint32 `json:"retry,omitempty"`
	Expire  uint32 `json:"expire,omitempty"`
	Minimum uint32 `json:"minimum,omitempty"`
	// SRV
	Weight uint16 `json:"weight,omitempty"`
	Port   uint16 `json:"port,omitempty"`
	// CAA
	Flag  uint8  `json:"flag,omitempty"`
	Tag   string `json:"tag,omitempty"`
	Value string `json:"value,omitempty"`
	// PTR
	Hostname string `json:"hostname,omitempty"`
	// SSHFP
	Algorithm   uint8  `json:"algorithm,omitempty"`
	FPType      uint8  `json:"fp_type,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// TLSA
	Usage        uint8  `json:"usage,omitempty"`
	Selector     uint8  `json:"selector,omitempty"`
	MatchingType uint8  `json:"matching_type,omitempty"`
	Certificate  string `json:"certificate,omitempty"`
	// NAPTR
	Order       uint16 `json:"order,omitempty"`
	Preference  uint16 `json:"preference,omitempty"`
	Flags       string `json:"flags,omitempty"`
	Service     string `json:"service,omitempty"`
	Regexp      string `json:"regexp,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	// SVCB/HTTPS
	Params map[string]string `json:"params,omitempty"`
	// LOC
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
	Altitude  float64 `json:"altitude,omitempty"`
	Size      float64 `json:"size,omitempty"`
	HorizPre  float64 `json:"horiz_pre,omitempty"`
	VertPre   float64 `json:"vert_pre,omitempty"`
}

func (h *Handler) handleRecords(w http.ResponseWriter, r *http.Request) {
	session := auth.GetSession(r.Context())

	// Use storage backend if available
	if h.hasStorage() {
		h.handleRecordsStorage(w, r, session)
		return
	}

	switch r.Method {
	case "GET":
		// Get optional type and zone filters
		typeFilter := r.URL.Query().Get("type")
		zoneFilter := r.URL.Query().Get("zone")

		h.configMu.RLock()
		records := h.collectRecordsFiltered(typeFilter, zoneFilter, session)
		h.configMu.RUnlock()

		h.jsonResponse(w, records)

	case "POST":
		var req RecordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Set tenant ID from session if not super admin
		if session != nil && !session.IsSuperAdmin {
			req.TenantID = session.TenantID
		}

		// If no tenant specified and user is super admin, default to main tenant
		if req.TenantID == "" && session != nil && session.IsSuperAdmin {
			req.TenantID = auth.MainTenantID
		}

		h.configMu.Lock()
		if err := h.addRecord(req); err != nil {
			h.configMu.Unlock()
			h.errorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.configMu.Unlock()

		if err := h.saveAndReload(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleRecord(w http.ResponseWriter, r *http.Request) {
	// Path: /api/records/{type}/{index}
	path := strings.TrimPrefix(r.URL.Path, "/api/records/")
	parts := strings.Split(path, "/")

	if len(parts) < 2 {
		h.errorResponse(w, "Record type and index required", http.StatusBadRequest)
		return
	}

	recordType := strings.ToUpper(parts[0])
	recordID := parts[1]

	// Use storage backend if available
	if h.hasStorage() {
		h.handleRecordStorage(w, r, recordType, recordID)
		return
	}

	index, err := strconv.Atoi(recordID)
	if err != nil {
		h.errorResponse(w, "Invalid index", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "DELETE":
		h.configMu.Lock()
		if err := h.deleteRecord(recordType, index); err != nil {
			h.configMu.Unlock()
			h.errorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.configMu.Unlock()

		if err := h.saveAndReload(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	case "PUT":
		var req RecordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.Type = recordType

		h.configMu.Lock()
		if err := h.updateRecord(recordType, index, req); err != nil {
			h.configMu.Unlock()
			h.errorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.configMu.Unlock()

		if err := h.saveAndReload(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) collectRecords(typeFilter string) []RecordRequest {
	var records []RecordRequest

	if typeFilter == "" || typeFilter == "A" {
		for _, r := range h.rawConfig.Records.A {
			records = append(records, RecordRequest{Type: "A", Name: r.Name, IP: r.IP, TTL: r.TTL})
		}
	}
	if typeFilter == "" || typeFilter == "AAAA" {
		for _, r := range h.rawConfig.Records.AAAA {
			records = append(records, RecordRequest{Type: "AAAA", Name: r.Name, IP: r.IP, TTL: r.TTL})
		}
	}
	if typeFilter == "" || typeFilter == "MX" {
		for _, r := range h.rawConfig.Records.MX {
			records = append(records, RecordRequest{Type: "MX", Name: r.Name, Priority: r.Priority, Target: r.Target, TTL: r.TTL})
		}
	}
	if typeFilter == "" || typeFilter == "TXT" {
		for _, r := range h.rawConfig.Records.TXT {
			records = append(records, RecordRequest{Type: "TXT", Name: r.Name, Values: r.Values, TTL: r.TTL})
		}
	}
	if typeFilter == "" || typeFilter == "NS" {
		for _, r := range h.rawConfig.Records.NS {
			records = append(records, RecordRequest{Type: "NS", Name: r.Name, Target: r.Target, TTL: r.TTL})
		}
	}
	if typeFilter == "" || typeFilter == "SOA" {
		for _, r := range h.rawConfig.Records.SOA {
			records = append(records, RecordRequest{
				Type: "SOA", Name: r.Name, MName: r.MName, RName: r.RName,
				Serial: r.Serial, Refresh: r.Refresh, Retry: r.Retry,
				Expire: r.Expire, Minimum: r.Minimum, TTL: r.TTL,
			})
		}
	}
	if typeFilter == "" || typeFilter == "CNAME" {
		for _, r := range h.rawConfig.Records.CNAME {
			records = append(records, RecordRequest{Type: "CNAME", Name: r.Name, Target: r.Target, TTL: r.TTL})
		}
	}
	if typeFilter == "" || typeFilter == "SRV" {
		for _, r := range h.rawConfig.Records.SRV {
			records = append(records, RecordRequest{
				Type: "SRV", Name: r.Name, Priority: r.Priority, Weight: r.Weight,
				Port: r.Port, Target: r.Target, TTL: r.TTL,
			})
		}
	}
	if typeFilter == "" || typeFilter == "CAA" {
		for _, r := range h.rawConfig.Records.CAA {
			records = append(records, RecordRequest{Type: "CAA", Name: r.Name, Flag: r.Flag, Tag: r.Tag, Value: r.Value, TTL: r.TTL})
		}
	}
	if typeFilter == "" || typeFilter == "PTR" {
		for _, r := range h.rawConfig.Records.PTR {
			records = append(records, RecordRequest{Type: "PTR", IP: r.IP, Hostname: r.Hostname, TTL: r.TTL})
		}
	}
	if typeFilter == "" || typeFilter == "ALIAS" {
		for _, r := range h.rawConfig.Records.ALIAS {
			records = append(records, RecordRequest{Type: "ALIAS", Name: r.Name, Target: r.Target, TTL: r.TTL})
		}
	}
	if typeFilter == "" || typeFilter == "SSHFP" {
		for _, r := range h.rawConfig.Records.SSHFP {
			records = append(records, RecordRequest{
				Type: "SSHFP", Name: r.Name, Algorithm: r.Algorithm,
				FPType: r.Type, Fingerprint: r.Fingerprint, TTL: r.TTL,
			})
		}
	}
	if typeFilter == "" || typeFilter == "TLSA" {
		for _, r := range h.rawConfig.Records.TLSA {
			records = append(records, RecordRequest{
				Type: "TLSA", Name: r.Name, Usage: r.Usage, Selector: r.Selector,
				MatchingType: r.MatchingType, Certificate: r.Certificate, TTL: r.TTL,
			})
		}
	}
	if typeFilter == "" || typeFilter == "NAPTR" {
		for _, r := range h.rawConfig.Records.NAPTR {
			records = append(records, RecordRequest{
				Type: "NAPTR", Name: r.Name, Order: r.Order, Preference: r.Preference,
				Flags: r.Flags, Service: r.Service, Regexp: r.Regexp,
				Replacement: r.Replacement, TTL: r.TTL,
			})
		}
	}
	if typeFilter == "" || typeFilter == "SVCB" {
		for _, r := range h.rawConfig.Records.SVCB {
			records = append(records, RecordRequest{
				Type: "SVCB", Name: r.Name, Priority: r.Priority,
				Target: r.Target, Params: r.Params, TTL: r.TTL,
			})
		}
	}
	if typeFilter == "" || typeFilter == "HTTPS" {
		for _, r := range h.rawConfig.Records.HTTPS {
			records = append(records, RecordRequest{
				Type: "HTTPS", Name: r.Name, Priority: r.Priority,
				Target: r.Target, Params: r.Params, TTL: r.TTL,
			})
		}
	}
	if typeFilter == "" || typeFilter == "LOC" {
		for _, r := range h.rawConfig.Records.LOC {
			records = append(records, RecordRequest{
				Type: "LOC", Name: r.Name, Latitude: r.Latitude, Longitude: r.Longitude,
				Altitude: r.Altitude, Size: r.Size, HorizPre: r.HorizPre, VertPre: r.VertPre, TTL: r.TTL,
			})
		}
	}

	return records
}

// collectRecordsFiltered returns records filtered by type and tenant
func (h *Handler) collectRecordsFiltered(typeFilter, zoneFilter string, session *auth.Session) []RecordRequest {
	var records []RecordRequest

	// Normalize session tenant
	sessionTenant := ""
	isSuperAdmin := false
	if session != nil {
		sessionTenant = session.TenantID
		if sessionTenant == "" {
			sessionTenant = auth.MainTenantID
		}
		isSuperAdmin = session.IsSuperAdmin || (session.Role == "admin" && sessionTenant == auth.MainTenantID)
	}

	// Helper to check if record belongs to user's tenant
	canAccess := func(recordTenant string) bool {
		if session == nil {
			return true // No auth
		}
		if isSuperAdmin {
			return true // Super admin sees all
		}
		// Empty tenant means main tenant
		if recordTenant == "" {
			recordTenant = auth.MainTenantID
		}
		return sessionTenant == recordTenant
	}

	// Helper to check zone filter
	matchesZone := func(recordZone string) bool {
		if zoneFilter == "" {
			return true // No filter
		}
		return recordZone == zoneFilter
	}

	if typeFilter == "" || typeFilter == "A" {
		for _, r := range h.rawConfig.Records.A {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{Type: "A", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, IP: r.IP, TTL: r.TTL})
			}
		}
	}
	if typeFilter == "" || typeFilter == "AAAA" {
		for _, r := range h.rawConfig.Records.AAAA {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{Type: "AAAA", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, IP: r.IP, TTL: r.TTL})
			}
		}
	}
	if typeFilter == "" || typeFilter == "MX" {
		for _, r := range h.rawConfig.Records.MX {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{Type: "MX", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Priority: r.Priority, Target: r.Target, TTL: r.TTL})
			}
		}
	}
	if typeFilter == "" || typeFilter == "TXT" {
		for _, r := range h.rawConfig.Records.TXT {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{Type: "TXT", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Values: r.Values, TTL: r.TTL})
			}
		}
	}
	if typeFilter == "" || typeFilter == "NS" {
		for _, r := range h.rawConfig.Records.NS {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{Type: "NS", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Target: r.Target, TTL: r.TTL})
			}
		}
	}
	if typeFilter == "" || typeFilter == "SOA" {
		for _, r := range h.rawConfig.Records.SOA {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{
					Type: "SOA", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, MName: r.MName, RName: r.RName,
					Serial: r.Serial, Refresh: r.Refresh, Retry: r.Retry,
					Expire: r.Expire, Minimum: r.Minimum, TTL: r.TTL,
				})
			}
		}
	}
	if typeFilter == "" || typeFilter == "CNAME" {
		for _, r := range h.rawConfig.Records.CNAME {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{Type: "CNAME", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Target: r.Target, TTL: r.TTL})
			}
		}
	}
	if typeFilter == "" || typeFilter == "SRV" {
		for _, r := range h.rawConfig.Records.SRV {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{
					Type: "SRV", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Priority: r.Priority, Weight: r.Weight,
					Port: r.Port, Target: r.Target, TTL: r.TTL,
				})
			}
		}
	}
	if typeFilter == "" || typeFilter == "CAA" {
		for _, r := range h.rawConfig.Records.CAA {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{Type: "CAA", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Flag: r.Flag, Tag: r.Tag, Value: r.Value, TTL: r.TTL})
			}
		}
	}
	if typeFilter == "" || typeFilter == "PTR" {
		for _, r := range h.rawConfig.Records.PTR {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{Type: "PTR", TenantID: r.TenantID, Zone: r.Zone, IP: r.IP, Hostname: r.Hostname, TTL: r.TTL})
			}
		}
	}
	if typeFilter == "" || typeFilter == "ALIAS" {
		for _, r := range h.rawConfig.Records.ALIAS {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{Type: "ALIAS", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Target: r.Target, TTL: r.TTL})
			}
		}
	}
	if typeFilter == "" || typeFilter == "SSHFP" {
		for _, r := range h.rawConfig.Records.SSHFP {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{
					Type: "SSHFP", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Algorithm: r.Algorithm,
					FPType: r.Type, Fingerprint: r.Fingerprint, TTL: r.TTL,
				})
			}
		}
	}
	if typeFilter == "" || typeFilter == "TLSA" {
		for _, r := range h.rawConfig.Records.TLSA {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{
					Type: "TLSA", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Usage: r.Usage, Selector: r.Selector,
					MatchingType: r.MatchingType, Certificate: r.Certificate, TTL: r.TTL,
				})
			}
		}
	}
	if typeFilter == "" || typeFilter == "NAPTR" {
		for _, r := range h.rawConfig.Records.NAPTR {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{
					Type: "NAPTR", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Order: r.Order, Preference: r.Preference,
					Flags: r.Flags, Service: r.Service, Regexp: r.Regexp,
					Replacement: r.Replacement, TTL: r.TTL,
				})
			}
		}
	}
	if typeFilter == "" || typeFilter == "SVCB" {
		for _, r := range h.rawConfig.Records.SVCB {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{
					Type: "SVCB", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Priority: r.Priority,
					Target: r.Target, Params: r.Params, TTL: r.TTL,
				})
			}
		}
	}
	if typeFilter == "" || typeFilter == "HTTPS" {
		for _, r := range h.rawConfig.Records.HTTPS {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{
					Type: "HTTPS", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Priority: r.Priority,
					Target: r.Target, Params: r.Params, TTL: r.TTL,
				})
			}
		}
	}
	if typeFilter == "" || typeFilter == "LOC" {
		for _, r := range h.rawConfig.Records.LOC {
			if canAccess(r.TenantID) && matchesZone(r.Zone) {
				records = append(records, RecordRequest{
					Type: "LOC", TenantID: r.TenantID, Zone: r.Zone, Name: r.Name, Latitude: r.Latitude, Longitude: r.Longitude,
					Altitude: r.Altitude, Size: r.Size, HorizPre: r.HorizPre, VertPre: r.VertPre, TTL: r.TTL,
				})
			}
		}
	}

	return records
}

func (h *Handler) addRecord(req RecordRequest) error {
	switch strings.ToUpper(req.Type) {
	case "A":
		h.rawConfig.Records.A = append(h.rawConfig.Records.A, config.ARecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, IP: req.IP, TTL: req.TTL})
	case "AAAA":
		h.rawConfig.Records.AAAA = append(h.rawConfig.Records.AAAA, config.AAAARecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, IP: req.IP, TTL: req.TTL})
	case "MX":
		h.rawConfig.Records.MX = append(h.rawConfig.Records.MX, config.MXRecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Priority: req.Priority, Target: req.Target, TTL: req.TTL})
	case "TXT":
		h.rawConfig.Records.TXT = append(h.rawConfig.Records.TXT, config.TXTRecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Values: req.Values, TTL: req.TTL})
	case "NS":
		h.rawConfig.Records.NS = append(h.rawConfig.Records.NS, config.NSRecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Target: req.Target, TTL: req.TTL})
	case "SOA":
		h.rawConfig.Records.SOA = append(h.rawConfig.Records.SOA, config.SOARecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, MName: req.MName, RName: req.RName,
			Serial: req.Serial, Refresh: req.Refresh, Retry: req.Retry,
			Expire: req.Expire, Minimum: req.Minimum, TTL: req.TTL,
		})
	case "CNAME":
		h.rawConfig.Records.CNAME = append(h.rawConfig.Records.CNAME, config.CNAMERecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Target: req.Target, TTL: req.TTL})
	case "SRV":
		h.rawConfig.Records.SRV = append(h.rawConfig.Records.SRV, config.SRVRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Priority: req.Priority, Weight: req.Weight,
			Port: req.Port, Target: req.Target, TTL: req.TTL,
		})
	case "CAA":
		h.rawConfig.Records.CAA = append(h.rawConfig.Records.CAA, config.CAARecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Flag: req.Flag, Tag: req.Tag, Value: req.Value, TTL: req.TTL})
	case "PTR":
		h.rawConfig.Records.PTR = append(h.rawConfig.Records.PTR, config.PTRRecord{TenantID: req.TenantID, Zone: req.Zone, IP: req.IP, Hostname: req.Hostname, TTL: req.TTL})
	case "ALIAS":
		h.rawConfig.Records.ALIAS = append(h.rawConfig.Records.ALIAS, config.ALIASRecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Target: req.Target, TTL: req.TTL})
	case "SSHFP":
		h.rawConfig.Records.SSHFP = append(h.rawConfig.Records.SSHFP, config.SSHFPRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Algorithm: req.Algorithm, Type: req.FPType, Fingerprint: req.Fingerprint, TTL: req.TTL,
		})
	case "TLSA":
		h.rawConfig.Records.TLSA = append(h.rawConfig.Records.TLSA, config.TLSARecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Usage: req.Usage, Selector: req.Selector,
			MatchingType: req.MatchingType, Certificate: req.Certificate, TTL: req.TTL,
		})
	case "NAPTR":
		h.rawConfig.Records.NAPTR = append(h.rawConfig.Records.NAPTR, config.NAPTRRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Order: req.Order, Preference: req.Preference,
			Flags: req.Flags, Service: req.Service, Regexp: req.Regexp,
			Replacement: req.Replacement, TTL: req.TTL,
		})
	case "SVCB":
		h.rawConfig.Records.SVCB = append(h.rawConfig.Records.SVCB, config.SVCBRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Priority: req.Priority, Target: req.Target, Params: req.Params, TTL: req.TTL,
		})
	case "HTTPS":
		h.rawConfig.Records.HTTPS = append(h.rawConfig.Records.HTTPS, config.HTTPSRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Priority: req.Priority, Target: req.Target, Params: req.Params, TTL: req.TTL,
		})
	case "LOC":
		h.rawConfig.Records.LOC = append(h.rawConfig.Records.LOC, config.LOCRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Latitude: req.Latitude, Longitude: req.Longitude,
			Altitude: req.Altitude, Size: req.Size, HorizPre: req.HorizPre, VertPre: req.VertPre, TTL: req.TTL,
		})
	default:
		return &apiError{"Unknown record type: " + req.Type}
	}
	return nil
}

func (h *Handler) deleteRecord(recordType string, index int) error {
	switch recordType {
	case "A":
		if index < 0 || index >= len(h.rawConfig.Records.A) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.A = append(h.rawConfig.Records.A[:index], h.rawConfig.Records.A[index+1:]...)
	case "AAAA":
		if index < 0 || index >= len(h.rawConfig.Records.AAAA) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.AAAA = append(h.rawConfig.Records.AAAA[:index], h.rawConfig.Records.AAAA[index+1:]...)
	case "MX":
		if index < 0 || index >= len(h.rawConfig.Records.MX) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.MX = append(h.rawConfig.Records.MX[:index], h.rawConfig.Records.MX[index+1:]...)
	case "TXT":
		if index < 0 || index >= len(h.rawConfig.Records.TXT) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.TXT = append(h.rawConfig.Records.TXT[:index], h.rawConfig.Records.TXT[index+1:]...)
	case "NS":
		if index < 0 || index >= len(h.rawConfig.Records.NS) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.NS = append(h.rawConfig.Records.NS[:index], h.rawConfig.Records.NS[index+1:]...)
	case "SOA":
		if index < 0 || index >= len(h.rawConfig.Records.SOA) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.SOA = append(h.rawConfig.Records.SOA[:index], h.rawConfig.Records.SOA[index+1:]...)
	case "CNAME":
		if index < 0 || index >= len(h.rawConfig.Records.CNAME) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.CNAME = append(h.rawConfig.Records.CNAME[:index], h.rawConfig.Records.CNAME[index+1:]...)
	case "SRV":
		if index < 0 || index >= len(h.rawConfig.Records.SRV) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.SRV = append(h.rawConfig.Records.SRV[:index], h.rawConfig.Records.SRV[index+1:]...)
	case "CAA":
		if index < 0 || index >= len(h.rawConfig.Records.CAA) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.CAA = append(h.rawConfig.Records.CAA[:index], h.rawConfig.Records.CAA[index+1:]...)
	case "PTR":
		if index < 0 || index >= len(h.rawConfig.Records.PTR) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.PTR = append(h.rawConfig.Records.PTR[:index], h.rawConfig.Records.PTR[index+1:]...)
	case "ALIAS":
		if index < 0 || index >= len(h.rawConfig.Records.ALIAS) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.ALIAS = append(h.rawConfig.Records.ALIAS[:index], h.rawConfig.Records.ALIAS[index+1:]...)
	case "SSHFP":
		if index < 0 || index >= len(h.rawConfig.Records.SSHFP) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.SSHFP = append(h.rawConfig.Records.SSHFP[:index], h.rawConfig.Records.SSHFP[index+1:]...)
	case "TLSA":
		if index < 0 || index >= len(h.rawConfig.Records.TLSA) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.TLSA = append(h.rawConfig.Records.TLSA[:index], h.rawConfig.Records.TLSA[index+1:]...)
	case "NAPTR":
		if index < 0 || index >= len(h.rawConfig.Records.NAPTR) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.NAPTR = append(h.rawConfig.Records.NAPTR[:index], h.rawConfig.Records.NAPTR[index+1:]...)
	case "SVCB":
		if index < 0 || index >= len(h.rawConfig.Records.SVCB) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.SVCB = append(h.rawConfig.Records.SVCB[:index], h.rawConfig.Records.SVCB[index+1:]...)
	case "HTTPS":
		if index < 0 || index >= len(h.rawConfig.Records.HTTPS) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.HTTPS = append(h.rawConfig.Records.HTTPS[:index], h.rawConfig.Records.HTTPS[index+1:]...)
	case "LOC":
		if index < 0 || index >= len(h.rawConfig.Records.LOC) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.LOC = append(h.rawConfig.Records.LOC[:index], h.rawConfig.Records.LOC[index+1:]...)
	default:
		return &apiError{"Unknown record type: " + recordType}
	}
	return nil
}

func (h *Handler) updateRecord(recordType string, index int, req RecordRequest) error {
	switch recordType {
	case "A":
		if index < 0 || index >= len(h.rawConfig.Records.A) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.A[index] = config.ARecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, IP: req.IP, TTL: req.TTL}
	case "AAAA":
		if index < 0 || index >= len(h.rawConfig.Records.AAAA) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.AAAA[index] = config.AAAARecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, IP: req.IP, TTL: req.TTL}
	case "MX":
		if index < 0 || index >= len(h.rawConfig.Records.MX) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.MX[index] = config.MXRecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Priority: req.Priority, Target: req.Target, TTL: req.TTL}
	case "TXT":
		if index < 0 || index >= len(h.rawConfig.Records.TXT) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.TXT[index] = config.TXTRecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Values: req.Values, TTL: req.TTL}
	case "NS":
		if index < 0 || index >= len(h.rawConfig.Records.NS) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.NS[index] = config.NSRecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Target: req.Target, TTL: req.TTL}
	case "SOA":
		if index < 0 || index >= len(h.rawConfig.Records.SOA) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.SOA[index] = config.SOARecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, MName: req.MName, RName: req.RName,
			Serial: req.Serial, Refresh: req.Refresh, Retry: req.Retry,
			Expire: req.Expire, Minimum: req.Minimum, TTL: req.TTL,
		}
	case "CNAME":
		if index < 0 || index >= len(h.rawConfig.Records.CNAME) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.CNAME[index] = config.CNAMERecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Target: req.Target, TTL: req.TTL}
	case "SRV":
		if index < 0 || index >= len(h.rawConfig.Records.SRV) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.SRV[index] = config.SRVRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Priority: req.Priority, Weight: req.Weight,
			Port: req.Port, Target: req.Target, TTL: req.TTL,
		}
	case "CAA":
		if index < 0 || index >= len(h.rawConfig.Records.CAA) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.CAA[index] = config.CAARecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Flag: req.Flag, Tag: req.Tag, Value: req.Value, TTL: req.TTL}
	case "PTR":
		if index < 0 || index >= len(h.rawConfig.Records.PTR) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.PTR[index] = config.PTRRecord{TenantID: req.TenantID, Zone: req.Zone, IP: req.IP, Hostname: req.Hostname, TTL: req.TTL}
	case "ALIAS":
		if index < 0 || index >= len(h.rawConfig.Records.ALIAS) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.ALIAS[index] = config.ALIASRecord{TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Target: req.Target, TTL: req.TTL}
	case "SSHFP":
		if index < 0 || index >= len(h.rawConfig.Records.SSHFP) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.SSHFP[index] = config.SSHFPRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Algorithm: req.Algorithm, Type: req.FPType, Fingerprint: req.Fingerprint, TTL: req.TTL,
		}
	case "TLSA":
		if index < 0 || index >= len(h.rawConfig.Records.TLSA) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.TLSA[index] = config.TLSARecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Usage: req.Usage, Selector: req.Selector,
			MatchingType: req.MatchingType, Certificate: req.Certificate, TTL: req.TTL,
		}
	case "NAPTR":
		if index < 0 || index >= len(h.rawConfig.Records.NAPTR) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.NAPTR[index] = config.NAPTRRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Order: req.Order, Preference: req.Preference,
			Flags: req.Flags, Service: req.Service, Regexp: req.Regexp,
			Replacement: req.Replacement, TTL: req.TTL,
		}
	case "SVCB":
		if index < 0 || index >= len(h.rawConfig.Records.SVCB) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.SVCB[index] = config.SVCBRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Priority: req.Priority, Target: req.Target, Params: req.Params, TTL: req.TTL,
		}
	case "HTTPS":
		if index < 0 || index >= len(h.rawConfig.Records.HTTPS) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.HTTPS[index] = config.HTTPSRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Priority: req.Priority, Target: req.Target, Params: req.Params, TTL: req.TTL,
		}
	case "LOC":
		if index < 0 || index >= len(h.rawConfig.Records.LOC) {
			return &apiError{"Record not found"}
		}
		h.rawConfig.Records.LOC[index] = config.LOCRecord{
			TenantID: req.TenantID, Zone: req.Zone, Name: req.Name, Latitude: req.Latitude, Longitude: req.Longitude,
			Altitude: req.Altitude, Size: req.Size, HorizPre: req.HorizPre, VertPre: req.VertPre, TTL: req.TTL,
		}
	default:
		return &apiError{"Unknown record type: " + recordType}
	}
	return nil
}

func (h *Handler) handleSecondaryZones(w http.ResponseWriter, r *http.Request) {
	session := auth.GetSession(r.Context())

	// Use storage backend if available
	if h.hasStorage() {
		h.handleSecondaryZonesStorage(w, r, session)
		return
	}

	switch r.Method {
	case "GET":
		h.configMu.RLock()
		zones := h.rawConfig.SecondaryZones
		h.configMu.RUnlock()
		h.jsonResponse(w, zones)

	case "POST":
		var zone config.SecondaryZoneConfig
		if err := json.NewDecoder(r.Body).Decode(&zone); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		h.configMu.Lock()
		h.rawConfig.SecondaryZones = append(h.rawConfig.SecondaryZones, zone)
		h.configMu.Unlock()

		if err := h.saveAndReload(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleSecondaryZone(w http.ResponseWriter, r *http.Request) {
	session := auth.GetSession(r.Context())

	// Use storage backend if available
	if h.hasStorage() {
		h.handleSecondaryZoneStorage(w, r, session)
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/secondary-zones/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		h.errorResponse(w, "Zone index required", http.StatusBadRequest)
		return
	}

	index, err := strconv.Atoi(parts[0])
	if err != nil {
		h.errorResponse(w, "Invalid index", http.StatusBadRequest)
		return
	}

	h.configMu.Lock()
	defer h.configMu.Unlock()

	if index < 0 || index >= len(h.rawConfig.SecondaryZones) {
		h.errorResponse(w, "Zone not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case "DELETE":
		h.rawConfig.SecondaryZones = append(h.rawConfig.SecondaryZones[:index], h.rawConfig.SecondaryZones[index+1:]...)

		if err := h.saveAndReloadUnlocked(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	case "PUT":
		var zone config.SecondaryZoneConfig
		if err := json.NewDecoder(r.Body).Decode(&zone); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		h.rawConfig.SecondaryZones[index] = zone

		if err := h.saveAndReloadUnlocked(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleTransfer(w http.ResponseWriter, r *http.Request) {
	session := auth.GetSession(r.Context())

	// Use storage backend if available
	if h.hasStorage() {
		h.handleTransferStorage(w, r, session)
		return
	}

	switch r.Method {
	case "GET":
		h.configMu.RLock()
		transfer := h.rawConfig.Transfer
		h.configMu.RUnlock()
		h.jsonResponse(w, transfer)

	case "PUT":
		var transfer config.TransferConfig
		if err := json.NewDecoder(r.Body).Decode(&transfer); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		h.configMu.Lock()
		h.rawConfig.Transfer = transfer
		h.configMu.Unlock()

		if err := h.saveAndReload(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleRecursion(w http.ResponseWriter, r *http.Request) {
	// Use storage backend if available
	if h.hasStorage() {
		h.handleRecursionStorage(w, r)
		return
	}

	switch r.Method {
	case "GET":
		h.configMu.RLock()
		recursion := h.rawConfig.Recursion
		h.configMu.RUnlock()
		h.jsonResponse(w, recursion)

	case "PUT":
		var recursion config.RecursionConfig
		if err := json.NewDecoder(r.Body).Decode(&recursion); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		h.configMu.Lock()
		h.rawConfig.Recursion = recursion
		h.configMu.Unlock()

		if err := h.saveAndReload(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleDNSSEC(w http.ResponseWriter, r *http.Request) {
	// Use storage backend if available
	if h.hasStorage() {
		h.handleDNSSECStorage(w, r)
		return
	}

	switch r.Method {
	case "GET":
		h.configMu.RLock()
		dnssec := h.rawConfig.DNSSEC
		h.configMu.RUnlock()
		h.jsonResponse(w, dnssec)

	case "PUT":
		var dnssec []config.DNSSECKeyConfig
		if err := json.NewDecoder(r.Body).Decode(&dnssec); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		h.configMu.Lock()
		h.rawConfig.DNSSEC = dnssec
		h.configMu.Unlock()

		if err := h.saveAndReload(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ServerSettings represents configurable server settings
type ServerSettings struct {
	Listen string `json:"listen"`
}

func (h *Handler) handleSettings(w http.ResponseWriter, r *http.Request) {
	// Use storage backend if available
	if h.hasStorage() {
		h.handleSettingsStorage(w, r)
		return
	}

	switch r.Method {
	case "GET":
		h.configMu.RLock()
		settings := ServerSettings{
			Listen: h.rawConfig.Listen,
		}
		h.configMu.RUnlock()
		h.jsonResponse(w, settings)

	case "PUT":
		var settings ServerSettings
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		h.configMu.Lock()
		h.rawConfig.Listen = settings.Listen
		h.configMu.Unlock()

		if err := h.saveAndReload(); err != nil {
			h.errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]string{"status": "ok", "message": "Settings saved. Restart server to apply listen address changes."})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) saveAndReload() error {
	h.configMu.Lock()
	defer h.configMu.Unlock()
	return h.saveAndReloadUnlocked()
}

func (h *Handler) saveAndReloadUnlocked() error {
	// Save to file
	if err := config.SaveConfig(h.configPath, h.rawConfig); err != nil {
		return &apiError{"Failed to save config: " + err.Error()}
	}

	// Parse the new config
	parsed, err := h.rawConfig.Parse()
	if err != nil {
		return &apiError{"Failed to parse config: " + err.Error()}
	}

	h.config = parsed

	// Notify server of update
	if h.onConfigUpdate != nil {
		h.onConfigUpdate(parsed)
	}

	log.Printf("API: Configuration saved and reloaded")
	return nil
}

func (h *Handler) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	store, ok := h.store.(*storage.Store)
	if !ok || store == nil {
		http.Error(w, "Audit logging requires storage backend", http.StatusNotImplemented)
		return
	}

	// Parse query parameters
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	resource := r.URL.Query().Get("resource")
	userID := r.URL.Query().Get("user_id")

	entries, err := store.ListAuditEntries(limit, resource, userID)
	if err != nil {
		log.Printf("Failed to list audit entries: %v", err)
		h.errorResponse(w, "Failed to list audit entries", http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, entries)
}

func (h *Handler) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (h *Handler) errorResponse(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

type apiError struct {
	message string
}

func (e *apiError) Error() string {
	return e.message
}
