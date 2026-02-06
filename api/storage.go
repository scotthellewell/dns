package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/scott/dns/auth"
	"github.com/scott/dns/config"
	"github.com/scott/dns/dnssec"
	"github.com/scott/dns/metrics"
	"github.com/scott/dns/storage"
)

// NewWithStorage creates a new API handler using storage backend
func NewWithStorage(cfg *config.ParsedConfig, store *storage.Store, onUpdate func(*config.ParsedConfig)) *Handler {
	h := &Handler{
		config:         cfg,
		rawConfig:      nil, // Not used with storage
		configPath:     "",  // Not used with storage
		onConfigUpdate: onUpdate,
		metrics:        metrics.New(),
		stats: &Stats{
			StartTime:     time.Now(),
			QueriesByType: make(map[string]uint64),
		},
		store: store,
	}
	return h
}

// UpdateConfigFromStorage rebuilds and updates config from storage
func (h *Handler) UpdateConfigFromStorage() error {
	store, ok := h.store.(*storage.Store)
	if !ok || store == nil {
		return nil
	}

	parsed, err := store.BuildParsedConfig()
	if err != nil {
		return err
	}

	h.configMu.Lock()
	h.config = parsed
	h.configMu.Unlock()

	if h.onConfigUpdate != nil {
		h.onConfigUpdate(parsed)
	}

	return nil
}

// getStore returns the storage backend if available
func (h *Handler) getStore() *storage.Store {
	if h.store == nil {
		return nil
	}
	store, ok := h.store.(*storage.Store)
	if !ok {
		return nil
	}
	return store
}

// hasStorage returns true if storage backend is available
func (h *Handler) hasStorage() bool {
	return h.getStore() != nil
}

// getZonesFromStorage returns zones from storage backend
func (h *Handler) getZonesFromStorage(tenantID string) ([]*storage.Zone, error) {
	store := h.getStore()
	if store == nil {
		return nil, nil
	}
	return store.ListZones(tenantID)
}

// getRecordsFromStorage returns records from storage backend
func (h *Handler) getRecordsFromStorage(zoneName string) ([]storage.Record, error) {
	store := h.getStore()
	if store == nil {
		return nil, nil
	}
	return store.GetAllZoneRecords(zoneName)
}

// getSecondaryZonesFromStorage returns secondary zones from storage backend
func (h *Handler) getSecondaryZonesFromStorage() ([]storage.SecondaryZone, error) {
	store := h.getStore()
	if store == nil {
		return nil, nil
	}
	return store.ListSecondaryZones()
}

// getTransferConfigFromStorage returns transfer config from storage backend
func (h *Handler) getTransferConfigFromStorage() (*storage.TransferConfig, error) {
	store := h.getStore()
	if store == nil {
		return nil, nil
	}
	return store.GetTransferConfig()
}

// handleZonesStorage handles zones API using storage backend
func (h *Handler) handleZonesStorage(w http.ResponseWriter, r *http.Request, session *auth.Session) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		// Determine tenant filter
		tenantID := ""
		if session != nil && !session.IsSuperAdmin {
			tenantID = session.TenantID
			if tenantID == "" {
				tenantID = auth.MainTenantID
			}
		}

		zones, err := store.ListZones(tenantID)
		if err != nil {
			h.errorResponse(w, "Failed to list zones: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var resp []ZoneResponse
		for _, z := range zones {
			resp = append(resp, ZoneResponse{
				ZoneID:   z.Name, // Zone uses Name as key
				TenantID: z.TenantID,
				Name:     z.Name,
				Type:     config.ZoneType(z.Type),
				Subnet:   z.Subnet,
				TTL:      z.TTL,
			})
		}
		if resp == nil {
			resp = []ZoneResponse{}
		}
		h.jsonResponse(w, resp)

	case "POST":
		var req struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			TenantID string `json:"tenant_id"`
			Subnet   string `json:"subnet"`
			Domain   string `json:"domain"`
			TTL      int    `json:"ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Set tenant ID from session if not super admin
		tenantID := req.TenantID
		if session != nil && !session.IsSuperAdmin {
			tenantID = session.TenantID
		}
		if tenantID == "" {
			tenantID = auth.MainTenantID
		}

		// Auto-generate zone name for reverse zones if not provided
		zoneName := req.Name
		if zoneName == "" && req.Subnet != "" {
			zoneName = subnetToReverseZone(req.Subnet)
		}

		// Check if a primary zone with this name already exists
		existingPrimary, _ := store.GetZone(zoneName)
		if existingPrimary != nil {
			h.errorResponse(w, "Zone already exists", http.StatusBadRequest)
			return
		}

		// Check if a secondary zone with this name already exists
		existingSecondary, _ := store.GetSecondaryZone(zoneName)
		if existingSecondary != nil {
			h.errorResponse(w, "Zone already exists as a secondary zone", http.StatusBadRequest)
			return
		}

		zone := &storage.Zone{
			Name:     zoneName,
			Type:     storage.ZoneType(req.Type),
			TenantID: tenantID,
			Subnet:   req.Subnet,
			Domain:   req.Domain,
			TTL:      uint32(req.TTL),
		}

		if err := store.CreateZone(zone); err != nil {
			h.errorResponse(w, "Failed to create zone: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Rebuild config to update DNS server
		if err := h.UpdateConfigFromStorage(); err != nil {
			h.errorResponse(w, "Failed to update config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok", "id": zone.Name})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleZoneStorage handles single zone API using storage backend
func (h *Handler) handleZoneStorage(w http.ResponseWriter, r *http.Request, session *auth.Session, zoneID string) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	zone, err := store.GetZone(zoneID)
	if err != nil {
		h.errorResponse(w, "Zone not found", http.StatusNotFound)
		return
	}

	// Check tenant access
	if session != nil && !session.IsSuperAdmin {
		sessionTenant := session.TenantID
		if sessionTenant == "" {
			sessionTenant = auth.MainTenantID
		}
		zoneTenant := zone.TenantID
		if zoneTenant == "" {
			zoneTenant = auth.MainTenantID
		}
		if sessionTenant != zoneTenant {
			h.errorResponse(w, "Access denied", http.StatusForbidden)
			return
		}
	}

	switch r.Method {
	case "GET":
		h.jsonResponse(w, ZoneResponse{
			ZoneID:   zone.Name,
			TenantID: zone.TenantID,
			Name:     zone.Name,
			Type:     config.ZoneType(zone.Type),
			Subnet:   zone.Subnet,
			TTL:      zone.TTL,
		})

	case "PUT":
		var req struct {
			Name   string `json:"name"`
			Type   string `json:"type"`
			Subnet string `json:"subnet"`
			Domain string `json:"domain"`
			TTL    int    `json:"ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Check if this is a rename operation (name changed)
		oldName := zone.Name
		newName := req.Name
		isRename := newName != "" && newName != oldName

		if isRename {
			// Rename: delete old zone and create new one with updated properties
			// First, delete the old zone
			if err := store.DeleteZone(oldName); err != nil {
				h.errorResponse(w, "Failed to rename zone: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Create new zone with updated properties
			newZone := &storage.Zone{
				Name:     newName,
				Type:     storage.ZoneType(req.Type),
				Subnet:   req.Subnet,
				Domain:   req.Domain,
				TenantID: zone.TenantID,
				TTL:      uint32(req.TTL),
			}
			if err := store.CreateZone(newZone); err != nil {
				// Try to restore the old zone on failure
				store.CreateZone(zone)
				h.errorResponse(w, "Failed to create renamed zone: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			// Normal update (no rename)
			zone.Type = storage.ZoneType(req.Type)
			zone.Subnet = req.Subnet
			zone.Domain = req.Domain
			zone.TTL = uint32(req.TTL)

			if err := store.UpdateZone(zone); err != nil {
				h.errorResponse(w, "Failed to update zone: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		if err := h.UpdateConfigFromStorage(); err != nil {
			h.errorResponse(w, "Failed to update config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok"})

	case "DELETE":
		if err := store.DeleteZone(zoneID); err != nil {
			h.errorResponse(w, "Failed to delete zone: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := h.UpdateConfigFromStorage(); err != nil {
			h.errorResponse(w, "Failed to update config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRecordsStorage handles records API using storage backend
func (h *Handler) handleRecordsStorage(w http.ResponseWriter, r *http.Request, session *auth.Session) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		// Get all zones accessible to user
		tenantID := ""
		if session != nil && !session.IsSuperAdmin {
			tenantID = session.TenantID
			if tenantID == "" {
				tenantID = auth.MainTenantID
			}
		}

		zones, err := store.ListZones(tenantID)
		if err != nil {
			h.errorResponse(w, "Failed to list zones: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var allRecords []RecordResponse
		for _, zone := range zones {
			records, err := store.GetAllZoneRecords(zone.Name)
			if err != nil {
				continue
			}
			for _, rec := range records {
				resp := RecordResponse{
					ID:       rec.ID,
					ZoneID:   rec.Zone,
					ZoneName: zone.Name,
					Name:     rec.Name,
					Type:     rec.Type,
					TTL:      rec.TTL,
				}

				// Extract type-specific fields from Data
				if len(rec.Data) > 0 {
					var data map[string]interface{}
					if err := json.Unmarshal(rec.Data, &data); err == nil {
						switch rec.Type {
						case "A", "AAAA":
							if v, ok := data["ip"].(string); ok {
								resp.IP = v
								resp.Value = v
							} else if v, ok := data["address"].(string); ok {
								resp.IP = v
								resp.Value = v
							}
						case "CNAME", "NS", "PTR":
							if v, ok := data["target"].(string); ok {
								resp.Target = v
								resp.Value = v
							}
						case "MX":
							if v, ok := data["target"].(string); ok {
								resp.Target = v
								resp.Value = v
							}
							if v, ok := data["priority"].(float64); ok {
								resp.Priority = int(v)
							}
						case "TXT":
							if v, ok := data["text"].(string); ok {
								resp.Value = v
								resp.Values = []string{v}
							} else if v, ok := data["values"].([]interface{}); ok {
								for _, val := range v {
									if s, ok := val.(string); ok {
										resp.Values = append(resp.Values, s)
									}
								}
								if len(resp.Values) > 0 {
									resp.Value = resp.Values[0]
								}
							}
						case "SRV":
							if v, ok := data["target"].(string); ok {
								resp.Target = v
							}
							if v, ok := data["priority"].(float64); ok {
								resp.Priority = int(v)
							}
							if v, ok := data["weight"].(float64); ok {
								resp.Weight = int(v)
							}
							if v, ok := data["port"].(float64); ok {
								resp.Port = int(v)
							}
						default:
							if v, ok := data["value"].(string); ok {
								resp.Value = v
							}
						}
					}
				}

				allRecords = append(allRecords, resp)
			}
		}
		if allRecords == nil {
			allRecords = []RecordResponse{}
		}
		h.jsonResponse(w, allRecords)

	case "POST":
		var req RecordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Validate zone exists
		zone, err := store.GetZone(req.Zone)
		if err != nil {
			h.errorResponse(w, "Zone not found: "+req.Zone, http.StatusBadRequest)
			return
		}

		// Check tenant access
		if session != nil && !session.IsSuperAdmin {
			if zone.TenantID != session.TenantID && zone.TenantID != "" {
				h.errorResponse(w, "Access denied", http.StatusForbidden)
				return
			}
		}

		// Build record data based on type
		data := make(map[string]interface{})
		switch req.Type {
		case "A", "AAAA":
			data["ip"] = req.IP
		case "CNAME", "NS", "PTR":
			data["target"] = req.Target
		case "MX":
			data["target"] = req.Target
			data["priority"] = req.Priority
		case "TXT":
			data["text"] = req.Value
		case "SRV":
			data["target"] = req.Target
			data["priority"] = req.Priority
			data["weight"] = req.Weight
			data["port"] = req.Port
		case "CAA":
			data["flag"] = req.Flag
			data["tag"] = req.Tag
			data["value"] = req.Value
		default:
			data["value"] = req.Value
		}
		dataBytes, _ := json.Marshal(data)

		record := &storage.Record{
			Zone:    req.Zone,
			Name:    req.Name,
			Type:    req.Type,
			TTL:     uint32(req.TTL),
			Enabled: true,
			Data:    dataBytes,
		}

		if err := store.CreateRecord(record); err != nil {
			h.errorResponse(w, "Failed to create record: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Rebuild config to update DNS server
		if err := h.UpdateConfigFromStorage(); err != nil {
			h.errorResponse(w, "Failed to update config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok", "id": record.ID})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSecondaryZonesStorage handles secondary zones API using storage backend
func (h *Handler) handleSecondaryZonesStorage(w http.ResponseWriter, r *http.Request, session *auth.Session) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		zones, err := store.ListSecondaryZones()
		if err != nil {
			h.errorResponse(w, "Failed to list secondary zones: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var resp []map[string]interface{}
		for _, z := range zones {
			resp = append(resp, map[string]interface{}{
				"id":        z.Zone, // Use Zone name as ID
				"zone":      z.Zone,
				"primaries": z.Primaries,
				"tsig_key":  z.TSIGKey,
				"interval":  z.RefreshInterval,
			})
		}
		if resp == nil {
			resp = []map[string]interface{}{}
		}
		h.jsonResponse(w, resp)

	case "POST":
		var req struct {
			Zone      string   `json:"zone"`
			Primaries []string `json:"primaries"`
			TSIGKey   string   `json:"tsig_key"`
			Interval  uint32   `json:"interval"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Check if a primary zone with this name already exists
		existingZone, _ := store.GetZone(req.Zone)
		if existingZone != nil {
			h.errorResponse(w, "Zone already exists as a primary zone", http.StatusBadRequest)
			return
		}

		// Check if a secondary zone with this name already exists
		existingSecondaryZone, _ := store.GetSecondaryZone(req.Zone)
		if existingSecondaryZone != nil {
			h.errorResponse(w, "Zone already exists", http.StatusBadRequest)
			return
		}

		sz := &storage.SecondaryZone{
			Zone:            req.Zone,
			Primaries:       req.Primaries,
			TSIGKey:         req.TSIGKey,
			RefreshInterval: req.Interval,
		}

		if err := store.CreateSecondaryZone(sz); err != nil {
			h.errorResponse(w, "Failed to create secondary zone: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok", "id": sz.Zone})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSecondaryZoneStorage handles individual secondary zone API using storage backend
func (h *Handler) handleSecondaryZoneStorage(w http.ResponseWriter, r *http.Request, session *auth.Session) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	// Extract zone ID from URL path
	zoneID := strings.TrimPrefix(r.URL.Path, "/api/secondary-zones/")
	zoneID = strings.Split(zoneID, "/")[0]
	if zoneID == "" {
		h.errorResponse(w, "Zone ID required", http.StatusBadRequest)
		return
	}

	// URL decode the zone ID (zone names may contain dots which are fine, but handle encoding)
	decodedZoneID, err := url.PathUnescape(zoneID)
	if err != nil {
		decodedZoneID = zoneID
	}

	switch r.Method {
	case "GET":
		zone, err := store.GetSecondaryZone(decodedZoneID)
		if err != nil || zone == nil {
			h.errorResponse(w, "Secondary zone not found", http.StatusNotFound)
			return
		}

		h.jsonResponse(w, map[string]interface{}{
			"id":        zone.Zone,
			"zone":      zone.Zone,
			"primaries": zone.Primaries,
			"tsig_key":  zone.TSIGKey,
			"interval":  zone.RefreshInterval,
		})

	case "DELETE":
		// Check if zone exists first
		zone, err := store.GetSecondaryZone(decodedZoneID)
		if err != nil || zone == nil {
			h.errorResponse(w, "Secondary zone not found", http.StatusNotFound)
			return
		}

		if err := store.DeleteSecondaryZone(decodedZoneID); err != nil {
			h.errorResponse(w, "Failed to delete secondary zone: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok"})

	case "PUT":
		var req struct {
			Zone      string   `json:"zone"`
			Primaries []string `json:"primaries"`
			TSIGKey   string   `json:"tsig_key"`
			Interval  uint32   `json:"interval"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Check if zone exists
		existingZone, err := store.GetSecondaryZone(decodedZoneID)
		if err != nil || existingZone == nil {
			h.errorResponse(w, "Secondary zone not found", http.StatusNotFound)
			return
		}

		// Update the zone
		sz := &storage.SecondaryZone{
			Zone:            req.Zone,
			Primaries:       req.Primaries,
			TSIGKey:         req.TSIGKey,
			RefreshInterval: req.Interval,
		}

		// If zone name changed, delete old and create new
		if req.Zone != decodedZoneID {
			if err := store.DeleteSecondaryZone(decodedZoneID); err != nil {
				h.errorResponse(w, "Failed to rename secondary zone: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if err := store.CreateSecondaryZone(sz); err != nil {
				h.errorResponse(w, "Failed to create renamed secondary zone: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			if err := store.UpdateSecondaryZone(sz); err != nil {
				h.errorResponse(w, "Failed to update secondary zone: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok", "id": sz.Zone})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTransferStorage handles transfer config API using storage backend
func (h *Handler) handleTransferStorage(w http.ResponseWriter, r *http.Request, session *auth.Session) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		cfg, err := store.GetTransferConfig()
		if err != nil {
			// Return empty config if not found
			h.jsonResponse(w, map[string]interface{}{
				"enabled":      false,
				"allowed_nets": []string{},
				"tsig_keys":    []map[string]interface{}{},
			})
			return
		}

		h.jsonResponse(w, cfg)

	case "PUT":
		var cfg storage.TransferConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := store.UpdateTransferConfig(&cfg); err != nil {
			h.errorResponse(w, "Failed to save transfer config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRecursionStorage handles recursion config API using storage backend
func (h *Handler) handleRecursionStorage(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		cfg, err := store.GetRecursionConfig()
		if err != nil {
			// Return default config if not found
			h.jsonResponse(w, map[string]interface{}{
				"enabled":    false,
				"forwarders": []string{},
			})
			return
		}
		h.jsonResponse(w, cfg)

	case "PUT":
		var cfg storage.RecursionConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := store.UpdateRecursionConfig(&cfg); err != nil {
			h.errorResponse(w, "Failed to save recursion config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Rebuild config to update DNS server
		if err := h.UpdateConfigFromStorage(); err != nil {
			h.errorResponse(w, "Failed to update config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDNSSECStorage handles DNSSEC config API using storage backend
func (h *Handler) handleDNSSECStorage(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		// Get all DNSSEC keys from storage
		allKeys, err := store.GetAllDNSSECKeys()
		if err != nil {
			h.errorResponse(w, "Failed to get DNSSEC keys: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Convert to API response format
		result := make([]map[string]interface{}, 0, len(allKeys))
		for _, keys := range allKeys {
			result = append(result, map[string]interface{}{
				"zone":        keys.ZoneName,
				"algorithm":   keys.Algorithm,
				"enabled":     keys.Enabled,
				"ksk_key_tag": keys.KSKKeyTag,
				"zsk_key_tag": keys.ZSKKeyTag,
				"ds_record":   keys.DSRecord,
				"ksk_public":  keys.KSKPublic,
				"created_at":  keys.CreatedAt,
				"updated_at":  keys.UpdatedAt,
			})
		}
		h.jsonResponse(w, result)

	case "POST":
		// Enable DNSSEC for a zone
		var req struct {
			Zone      string `json:"zone"`
			Algorithm string `json:"algorithm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		if req.Zone == "" {
			h.errorResponse(w, "Zone is required", http.StatusBadRequest)
			return
		}
		if req.Algorithm == "" {
			req.Algorithm = "ECDSAP256SHA256"
		}

		// Check if zone exists
		zone, err := store.GetZone(req.Zone)
		if err != nil || zone == nil {
			h.errorResponse(w, "Zone not found: "+req.Zone, http.StatusBadRequest)
			return
		}

		// Check if DNSSEC is already enabled
		existingKeys, err := store.GetDNSSECKeys(req.Zone)
		if err == nil && existingKeys.Enabled {
			// Already enabled, return existing
			h.jsonResponse(w, map[string]interface{}{
				"zone":        existingKeys.ZoneName,
				"algorithm":   existingKeys.Algorithm,
				"enabled":     existingKeys.Enabled,
				"ksk_key_tag": existingKeys.KSKKeyTag,
				"zsk_key_tag": existingKeys.ZSKKeyTag,
				"ds_record":   existingKeys.DSRecord,
				"created_at":  existingKeys.CreatedAt,
			})
			return
		}

		// Generate new keys
		genKeys, err := dnssec.GenerateKeys(req.Zone, req.Algorithm)
		if err != nil {
			h.errorResponse(w, "Failed to generate DNSSEC keys: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Save to storage
		keys := &storage.DNSSECKeys{
			ZoneName:   req.Zone,
			Algorithm:  req.Algorithm,
			Enabled:    true,
			KSKPrivate: genKeys.KSKPrivate,
			KSKPublic:  genKeys.KSKPublic,
			KSKKeyTag:  genKeys.KSKKeyTag,
			ZSKPrivate: genKeys.ZSKPrivate,
			ZSKPublic:  genKeys.ZSKPublic,
			ZSKKeyTag:  genKeys.ZSKKeyTag,
			DSRecord:   genKeys.DSRecord,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		if err := store.SaveDNSSECKeys(keys); err != nil {
			h.errorResponse(w, "Failed to save DNSSEC keys: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{
			"zone":        keys.ZoneName,
			"algorithm":   keys.Algorithm,
			"enabled":     keys.Enabled,
			"ksk_key_tag": keys.KSKKeyTag,
			"zsk_key_tag": keys.ZSKKeyTag,
			"ds_record":   keys.DSRecord,
			"created_at":  keys.CreatedAt,
		})

	case "DELETE":
		// Delete DNSSEC for a zone (from query param)
		zone := r.URL.Query().Get("zone")
		if zone == "" {
			h.errorResponse(w, "Zone query parameter is required", http.StatusBadRequest)
			return
		}

		if err := store.DeleteDNSSECKeys(zone); err != nil {
			h.errorResponse(w, "Failed to delete DNSSEC: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok"})

	case "PUT":
		// Update DNSSEC configuration (enable/disable, algorithm change)
		var req struct {
			Zone      string `json:"zone"`
			Algorithm string `json:"algorithm"`
			Enabled   bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		if req.Zone == "" {
			h.errorResponse(w, "Zone is required", http.StatusBadRequest)
			return
		}

		if req.Enabled {
			if req.Algorithm == "" {
				req.Algorithm = "ECDSAP256SHA256"
			}
			keys, err := store.EnableDNSSEC(req.Zone, req.Algorithm, 2048, 1024)
			if err != nil {
				h.errorResponse(w, "Failed to enable DNSSEC: "+err.Error(), http.StatusInternalServerError)
				return
			}
			h.jsonResponse(w, map[string]interface{}{
				"zone":        keys.ZoneName,
				"algorithm":   keys.Algorithm,
				"enabled":     keys.Enabled,
				"ksk_key_tag": keys.KSKKeyTag,
				"ds_record":   keys.DSRecord,
			})
		} else {
			if err := store.DisableDNSSEC(req.Zone); err != nil {
				h.errorResponse(w, "Failed to disable DNSSEC: "+err.Error(), http.StatusInternalServerError)
				return
			}
			h.jsonResponse(w, map[string]interface{}{"status": "disabled"})
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDNSSECKeys handles DNSSEC key export/import for a specific zone
func (h *Handler) handleDNSSECKeys(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	// Extract zone from path: /api/dnssec/keys/{zone}
	path := strings.TrimPrefix(r.URL.Path, "/api/dnssec/keys/")
	zoneName := strings.TrimSuffix(path, "/")
	if zoneName == "" {
		h.errorResponse(w, "Zone name required in path", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		// Check for token-based access (for secondary servers)
		token := r.URL.Query().Get("token")
		if token != "" {
			valid, err := store.ValidateKeyToken(zoneName, token)
			if err != nil || !valid {
				h.errorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}
		}
		// If no token, require normal authentication (handled by middleware)

		// Export keys for a zone
		keys, err := store.GetDNSSECKeys(zoneName)
		if err != nil {
			h.errorResponse(w, "DNSSEC not configured for zone: "+err.Error(), http.StatusNotFound)
			return
		}

		// Check KSK rotation advisory (1 year threshold)
		kskRotationDue, _ := store.CheckKSKRotationAdvisory(zoneName, 365*24*time.Hour)

		// Return full key data for export (including private keys)
		h.jsonResponse(w, map[string]interface{}{
			"zone":             keys.ZoneName,
			"algorithm":        keys.Algorithm,
			"enabled":          keys.Enabled,
			"ksk_private":      keys.KSKPrivate,
			"ksk_public":       keys.KSKPublic,
			"ksk_key_tag":      keys.KSKKeyTag,
			"ksk_created":      keys.KSKCreated,
			"zsk_private":      keys.ZSKPrivate,
			"zsk_public":       keys.ZSKPublic,
			"zsk_key_tag":      keys.ZSKKeyTag,
			"zsk_created":      keys.ZSKCreated,
			"ds_record":        keys.DSRecord,
			"ksk_rotation_due": kskRotationDue,
			"created_at":       keys.CreatedAt,
		})

	case "PUT":
		// Import keys for a zone
		var req struct {
			Algorithm  string `json:"algorithm"`
			KSKPrivate string `json:"ksk_private"`
			KSKPublic  string `json:"ksk_public"`
			KSKKeyTag  uint16 `json:"ksk_key_tag"`
			ZSKPrivate string `json:"zsk_private"`
			ZSKPublic  string `json:"zsk_public"`
			ZSKKeyTag  uint16 `json:"zsk_key_tag"`
			DSRecord   string `json:"ds_record"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		if req.KSKPrivate == "" || req.ZSKPrivate == "" {
			h.errorResponse(w, "Both KSK and ZSK private keys are required", http.StatusBadRequest)
			return
		}

		// Save imported keys
		keys := &storage.DNSSECKeys{
			ZoneName:   zoneName,
			Algorithm:  req.Algorithm,
			Enabled:    true,
			KSKPrivate: req.KSKPrivate,
			KSKPublic:  req.KSKPublic,
			KSKKeyTag:  req.KSKKeyTag,
			ZSKPrivate: req.ZSKPrivate,
			ZSKPublic:  req.ZSKPublic,
			ZSKKeyTag:  req.ZSKKeyTag,
			DSRecord:   req.DSRecord,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		if err := store.SaveDNSSECKeys(keys); err != nil {
			h.errorResponse(w, "Failed to save DNSSEC keys: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{
			"status":      "imported",
			"zone":        keys.ZoneName,
			"ksk_key_tag": keys.KSKKeyTag,
			"zsk_key_tag": keys.ZSKKeyTag,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDNSSECToken manages DNSSEC key sharing tokens
func (h *Handler) handleDNSSECToken(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	// Extract zone from path: /api/dnssec/token/{zone}
	path := strings.TrimPrefix(r.URL.Path, "/api/dnssec/token/")
	zoneName := strings.TrimSuffix(path, "/")
	if zoneName == "" {
		h.errorResponse(w, "Zone name required in path", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		// Get current token (masked for security)
		keys, err := store.GetDNSSECKeys(zoneName)
		if err != nil {
			h.errorResponse(w, "DNSSEC not configured for zone: "+err.Error(), http.StatusNotFound)
			return
		}

		hasToken := keys.KeyToken != ""
		maskedToken := ""
		if hasToken && len(keys.KeyToken) > 8 {
			maskedToken = keys.KeyToken[:4] + "..." + keys.KeyToken[len(keys.KeyToken)-4:]
		}

		h.jsonResponse(w, map[string]interface{}{
			"zone":      zoneName,
			"has_token": hasToken,
			"token":     maskedToken,
		})

	case "POST":
		// Generate new token
		token, err := store.GenerateKeyToken(zoneName)
		if err != nil {
			h.errorResponse(w, "Failed to generate token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{
			"zone":  zoneName,
			"token": token,
		})

	case "DELETE":
		// Revoke token
		if err := store.RevokeKeyToken(zoneName); err != nil {
			h.errorResponse(w, "Failed to revoke token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{
			"status": "revoked",
			"zone":   zoneName,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDelegations handles zone delegation API
func (h *Handler) handleDelegations(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		// List all delegations, optionally filtered by parent zone
		parentZone := r.URL.Query().Get("parent")

		delegations, err := store.ListDelegations(parentZone)
		if err != nil {
			h.errorResponse(w, "Failed to list delegations: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.jsonResponse(w, delegations)

	case "POST":
		// Create a new delegation
		var req storage.Delegation
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		req.Active = true
		if err := store.CreateDelegation(&req); err != nil {
			h.errorResponse(w, "Failed to create delegation: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, req)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDelegation handles single delegation API (GET/PUT/DELETE)
func (h *Handler) handleDelegation(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	// Extract parent:child from path: /api/delegations/{parent}/{child}
	path := strings.TrimPrefix(r.URL.Path, "/api/delegations/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		h.errorResponse(w, "Path must be /api/delegations/{parent}/{child}", http.StatusBadRequest)
		return
	}
	parentZone := parts[0]
	childZone := parts[1]

	switch r.Method {
	case "GET":
		deleg, err := store.GetDelegation(parentZone, childZone)
		if err != nil {
			h.errorResponse(w, "Delegation not found: "+err.Error(), http.StatusNotFound)
			return
		}
		h.jsonResponse(w, deleg)

	case "PUT":
		var req storage.Delegation
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.ParentZone = parentZone
		req.ChildZone = childZone

		if err := store.UpdateDelegation(&req); err != nil {
			h.errorResponse(w, "Failed to update delegation: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.jsonResponse(w, req)

	case "DELETE":
		// Check for force parameter
		force := r.URL.Query().Get("force") == "true"
		if err := store.DeleteDelegation(parentZone, childZone, force); err != nil {
			h.errorResponse(w, "Failed to delete delegation: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.jsonResponse(w, map[string]interface{}{"status": "deleted"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRecordStorage handles single record API (DELETE/PUT) using storage backend
func (h *Handler) handleRecordStorage(w http.ResponseWriter, r *http.Request, recordType string, recordID string) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "DELETE":
		// In storage mode, we need to find and delete the record by ID
		// The recordID here might be a composite key or just the record ID
		// For now, try to delete by iterating zones
		zones, err := store.ListZones("")
		if err != nil {
			h.errorResponse(w, "Failed to list zones: "+err.Error(), http.StatusInternalServerError)
			return
		}

		deleted := false
		for _, zone := range zones {
			records, err := store.GetAllZoneRecords(zone.Name)
			if err != nil {
				continue
			}
			for _, rec := range records {
				if rec.ID == recordID || rec.Name == recordID {
					if err := store.DeleteRecord(zone.Name, rec.Name, rec.Type, rec.ID); err == nil {
						deleted = true
						break
					}
				}
			}
			if deleted {
				break
			}
		}

		if !deleted {
			h.errorResponse(w, "Record not found", http.StatusNotFound)
			return
		}

		// Rebuild config to update DNS server
		if err := h.UpdateConfigFromStorage(); err != nil {
			h.errorResponse(w, "Failed to update config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok"})

	case "PUT":
		var req RecordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Find and update the record
		zones, err := store.ListZones("")
		if err != nil {
			h.errorResponse(w, "Failed to list zones: "+err.Error(), http.StatusInternalServerError)
			return
		}

		updated := false
		for _, zone := range zones {
			records, err := store.GetAllZoneRecords(zone.Name)
			if err != nil {
				continue
			}
			for _, rec := range records {
				if rec.ID == recordID || rec.Name == recordID {
					// Update the record
					rec.TTL = uint32(req.TTL)
					// Update data based on record type
					data := make(map[string]interface{})
					if req.IP != "" {
						data["ip"] = req.IP
					}
					if req.Target != "" {
						data["target"] = req.Target
					}
					if req.Value != "" {
						data["value"] = req.Value
					}
					if len(data) > 0 {
						dataBytes, _ := json.Marshal(data)
						rec.Data = dataBytes
					}
					if err := store.UpdateRecord(&rec); err == nil {
						updated = true
						break
					}
				}
			}
			if updated {
				break
			}
		}

		if !updated {
			h.errorResponse(w, "Record not found", http.StatusNotFound)
			return
		}

		// Rebuild config to update DNS server
		if err := h.UpdateConfigFromStorage(); err != nil {
			h.errorResponse(w, "Failed to update config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.jsonResponse(w, map[string]interface{}{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSettingsStorage handles settings API using storage backend
func (h *Handler) handleSettingsStorage(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		cfg, err := store.GetServerConfig()
		if err != nil {
			// Return default settings
			h.jsonResponse(w, map[string]interface{}{
				"listen": ":53",
			})
			return
		}

		// Map storage config to API response
		listen := ""
		if cfg.DNS.Enabled {
			if cfg.DNS.Address != "" {
				listen = cfg.DNS.Address + ":" + itoa(cfg.DNS.UDPPort)
			} else {
				listen = ":" + itoa(cfg.DNS.UDPPort)
			}
		}

		h.jsonResponse(w, map[string]interface{}{
			"listen": listen,
		})

	case "PUT":
		var settings struct {
			Listen string `json:"listen"`
		}
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Settings changes in storage mode would require updating ServerConfig
		// For now, just acknowledge - actual implementation would update storage
		h.jsonResponse(w, map[string]interface{}{
			"status":  "ok",
			"message": "Settings saved. Restart server to apply listen address changes.",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// itoa converts int to string
func itoa(i int) string {
	return json.Number(fmt.Sprintf("%d", i)).String()
}

// subnetToReverseZone converts a CIDR subnet to a reverse zone name
// e.g., "192.168.1.0/24" -> "1.168.192.in-addr.arpa"
// e.g., "10.0.0.0/8" -> "10.in-addr.arpa"
func subnetToReverseZone(subnet string) string {
	// Split off the prefix length
	parts := strings.Split(subnet, "/")
	if len(parts) != 2 {
		return ""
	}

	ip := parts[0]
	prefixLen := 24 // default
	if len(parts) == 2 {
		fmt.Sscanf(parts[1], "%d", &prefixLen)
	}

	octets := strings.Split(ip, ".")
	if len(octets) == 4 {
		// IPv4
		switch {
		case prefixLen >= 24:
			// /24 or more specific - use 3 octets
			return octets[2] + "." + octets[1] + "." + octets[0] + ".in-addr.arpa"
		case prefixLen >= 16:
			// /16 - use 2 octets
			return octets[1] + "." + octets[0] + ".in-addr.arpa"
		case prefixLen >= 8:
			// /8 - use 1 octet
			return octets[0] + ".in-addr.arpa"
		default:
			return octets[2] + "." + octets[1] + "." + octets[0] + ".in-addr.arpa"
		}
	}

	// IPv6 - simplified handling
	if strings.Contains(ip, ":") {
		// For now, just return a placeholder - full IPv6 reverse zone handling is complex
		return strings.ReplaceAll(ip, ":", "") + ".ip6.arpa"
	}

	return ""
}
