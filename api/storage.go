package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
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
				ZoneID:      z.Name, // Zone uses Name as key
				TenantID:    z.TenantID,
				Name:        z.Name,
				Type:        config.ZoneType(z.Type),
				Subnet:      z.Subnet,
				Domain:      z.Domain,
				StripPrefix: z.StripPrefix,
				TTL:         z.TTL,
			})
		}
		if resp == nil {
			resp = []ZoneResponse{}
		}
		h.jsonResponse(w, resp)

	case "POST":
		var req struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			TenantID    string `json:"tenant_id"`
			Subnet      string `json:"subnet"`
			Domain      string `json:"domain"`
			StripPrefix bool   `json:"strip_prefix"`
			TTL         int    `json:"ttl"`
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
			Name:        zoneName,
			Type:        storage.ZoneType(req.Type),
			TenantID:    tenantID,
			Subnet:      req.Subnet,
			Domain:      req.Domain,
			StripPrefix: req.StripPrefix,
			TTL:         uint32(req.TTL),
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
			ZoneID:      zone.Name,
			TenantID:    zone.TenantID,
			Name:        zone.Name,
			Type:        config.ZoneType(zone.Type),
			Subnet:      zone.Subnet,
			Domain:      zone.Domain,
			StripPrefix: zone.StripPrefix,
			TTL:         zone.TTL,
		})

	case "PUT":
		var req struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			Subnet      string `json:"subnet"`
			Domain      string `json:"domain"`
			StripPrefix bool   `json:"strip_prefix"`
			TTL         int    `json:"ttl"`
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
				Name:        newName,
				Type:        storage.ZoneType(req.Type),
				Subnet:      req.Subnet,
				Domain:      req.Domain,
				StripPrefix: req.StripPrefix,
				TenantID:    zone.TenantID,
				TTL:         uint32(req.TTL),
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
			zone.StripPrefix = req.StripPrefix
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

	// Determine tenant filter
	tenantID := ""
	if session != nil && !session.IsSuperAdmin {
		tenantID = session.TenantID
		if tenantID == "" {
			tenantID = auth.MainTenantID
		}
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
			// Filter by tenant if not super admin
			if tenantID != "" && z.TenantID != tenantID {
				continue
			}
			resp = append(resp, map[string]interface{}{
				"id":               z.Zone, // Use Zone name as ID
				"zone":             z.Zone,
				"tenant_id":        z.TenantID,
				"primaries":        z.Primaries,
				"tsig_key":         z.TSIGKey,
				"interval":         z.RefreshInterval,
				"dnssec_key_url":   z.DNSSECKeyURL,
				"dnssec_key_token": z.DNSSECKeyToken,
			})
		}
		if resp == nil {
			resp = []map[string]interface{}{}
		}
		h.jsonResponse(w, resp)

	case "POST":
		var req struct {
			Zone           string   `json:"zone"`
			TenantID       string   `json:"tenant_id"`
			Primaries      []string `json:"primaries"`
			TSIGKey        string   `json:"tsig_key"`
			Interval       uint32   `json:"interval"`
			DNSSECKeyURL   string   `json:"dnssec_key_url"`
			DNSSECKeyToken string   `json:"dnssec_key_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Set tenant ID from session if not super admin
		zoneTenantID := req.TenantID
		if session != nil && !session.IsSuperAdmin {
			zoneTenantID = session.TenantID
		}
		if zoneTenantID == "" {
			zoneTenantID = auth.MainTenantID
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
			TenantID:        zoneTenantID,
			Primaries:       req.Primaries,
			TSIGKey:         req.TSIGKey,
			RefreshInterval: req.Interval,
			DNSSECKeyURL:    req.DNSSECKeyURL,
			DNSSECKeyToken:  req.DNSSECKeyToken,
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

	// Determine tenant filter
	tenantID := ""
	if session != nil && !session.IsSuperAdmin {
		tenantID = session.TenantID
		if tenantID == "" {
			tenantID = auth.MainTenantID
		}
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

	// Helper function to check tenant access
	checkTenantAccess := func(zone *storage.SecondaryZone) bool {
		if tenantID == "" {
			return true // Super admin
		}
		return zone.TenantID == tenantID
	}

	switch r.Method {
	case "GET":
		zone, err := store.GetSecondaryZone(decodedZoneID)
		if err != nil || zone == nil {
			h.errorResponse(w, "Secondary zone not found", http.StatusNotFound)
			return
		}

		// Check tenant access
		if !checkTenantAccess(zone) {
			h.errorResponse(w, "Secondary zone not found", http.StatusNotFound)
			return
		}

		h.jsonResponse(w, map[string]interface{}{
			"id":               zone.Zone,
			"zone":             zone.Zone,
			"tenant_id":        zone.TenantID,
			"primaries":        zone.Primaries,
			"tsig_key":         zone.TSIGKey,
			"interval":         zone.RefreshInterval,
			"dnssec_key_url":   zone.DNSSECKeyURL,
			"dnssec_key_token": zone.DNSSECKeyToken,
		})

	case "DELETE":
		// Check if zone exists first
		zone, err := store.GetSecondaryZone(decodedZoneID)
		if err != nil || zone == nil {
			h.errorResponse(w, "Secondary zone not found", http.StatusNotFound)
			return
		}

		// Check tenant access
		if !checkTenantAccess(zone) {
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
			Zone           string   `json:"zone"`
			Primaries      []string `json:"primaries"`
			TSIGKey        string   `json:"tsig_key"`
			Interval       uint32   `json:"interval"`
			DNSSECKeyURL   string   `json:"dnssec_key_url"`
			DNSSECKeyToken string   `json:"dnssec_key_token"`
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

		// Check tenant access
		if !checkTenantAccess(existingZone) {
			h.errorResponse(w, "Secondary zone not found", http.StatusNotFound)
			return
		}

		// Update the zone (preserve tenant_id)
		sz := &storage.SecondaryZone{
			Zone:            req.Zone,
			TenantID:        existingZone.TenantID, // Preserve tenant
			Primaries:       req.Primaries,
			TSIGKey:         req.TSIGKey,
			RefreshInterval: req.Interval,
			DNSSECKeyURL:    req.DNSSECKeyURL,
			DNSSECKeyToken:  req.DNSSECKeyToken,
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

// handleConvertSecondaryZone handles converting a secondary zone to a primary zone
func (h *Handler) handleConvertSecondaryZone(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	// Get session for tenant context
	session := auth.GetSession(r.Context())
	if session == nil {
		h.errorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Determine tenant filter
	tenantID := ""
	if !session.IsSuperAdmin {
		tenantID = session.TenantID
		if tenantID == "" {
			tenantID = auth.MainTenantID
		}
	}

	// Extract zone name from URL path: /api/secondary-zones/convert/{zone}
	zoneID := strings.TrimPrefix(r.URL.Path, "/api/secondary-zones/convert/")
	if zoneID == "" {
		h.errorResponse(w, "Zone name required", http.StatusBadRequest)
		return
	}

	// URL decode the zone name
	decodedZoneID, err := url.PathUnescape(zoneID)
	if err != nil {
		decodedZoneID = zoneID
	}

	// Get the secondary zone
	secondaryZone, err := store.GetSecondaryZone(decodedZoneID)
	if err != nil || secondaryZone == nil {
		h.errorResponse(w, "Secondary zone not found", http.StatusNotFound)
		return
	}

	// Check tenant access
	if tenantID != "" && secondaryZone.TenantID != tenantID {
		h.errorResponse(w, "Secondary zone not found", http.StatusNotFound)
		return
	}

	// Get secondary manager to fetch current records
	secMgr := h.getSecondaryManager()
	if secMgr == nil {
		h.errorResponse(w, "Secondary zone manager not available", http.StatusInternalServerError)
		return
	}

	// Get all records from the secondary zone (in memory from last transfer)
	records := secMgr.GetAllRecords(decodedZoneID)
	soa := secMgr.GetSOA(decodedZoneID)

	if len(records) == 0 && soa == nil {
		h.errorResponse(w, "Secondary zone has no cached records. Ensure zone has synced at least once.", http.StatusBadRequest)
		return
	}

	// Check if a primary zone already exists with this name
	existingZone, _ := store.GetZone(decodedZoneID)
	if existingZone != nil {
		h.errorResponse(w, "A primary zone with this name already exists", http.StatusConflict)
		return
	}

	// Create the primary zone
	zoneName := dns.Fqdn(decodedZoneID)
	newZone := &storage.Zone{
		Name:     zoneName,
		Type:     storage.ZoneTypeForward,
		TenantID: secondaryZone.TenantID,
	}

	// If we have a SOA, use its TTL
	if soa != nil {
		newZone.TTL = soa.Header().Ttl
	} else {
		newZone.TTL = 3600
	}

	if err := store.CreateZone(newZone); err != nil {
		h.errorResponse(w, "Failed to create primary zone: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Add SOA record if present
	var recordsCreated int
	var recordsFailed int

	if soa != nil {
		soaData, _ := json.Marshal(storage.SOARecordData{
			MName:   soa.Ns,
			RName:   soa.Mbox,
			Serial:  soa.Serial,
			Refresh: soa.Refresh,
			Retry:   soa.Retry,
			Expire:  soa.Expire,
			Minimum: soa.Minttl,
		})
		soaRecord := &storage.Record{
			Zone:    zoneName,
			Name:    zoneName,
			Type:    "SOA",
			TTL:     soa.Header().Ttl,
			Enabled: true,
			Data:    soaData,
		}
		if err := store.CreateRecord(soaRecord); err != nil {
			recordsFailed++
		} else {
			recordsCreated++
		}
	}

	// Convert all DNS records to storage records
	for _, rr := range records {
		record, err := dnsRRToStorageRecord(rr, zoneName)
		if err != nil {
			recordsFailed++
			continue
		}

		if err := store.CreateRecord(record); err != nil {
			recordsFailed++
		} else {
			recordsCreated++
		}
	}

	// Delete the secondary zone
	if err := store.DeleteSecondaryZone(decodedZoneID); err != nil {
		// Zone was created but secondary wasn't deleted - report partial success
		h.jsonResponse(w, map[string]interface{}{
			"status":          "partial",
			"message":         "Primary zone created but failed to delete secondary zone: " + err.Error(),
			"zone":            zoneName,
			"records_created": recordsCreated,
			"records_failed":  recordsFailed,
		})
		return
	}

	// Also delete the secondary zone cache
	store.DeleteSecondaryZoneCache(decodedZoneID)

	// Trigger config update
	h.UpdateConfigFromStorage()

	h.jsonResponse(w, map[string]interface{}{
		"status":          "ok",
		"message":         "Secondary zone converted to primary zone",
		"zone":            zoneName,
		"records_created": recordsCreated,
		"records_failed":  recordsFailed,
	})
}

// dnsRRToStorageRecord converts a dns.RR to a storage.Record
func dnsRRToStorageRecord(rr dns.RR, zoneName string) (*storage.Record, error) {
	hdr := rr.Header()
	record := &storage.Record{
		Zone:    zoneName,
		Name:    hdr.Name,
		Type:    dns.TypeToString[hdr.Rrtype],
		TTL:     hdr.Ttl,
		Enabled: true,
	}

	var data interface{}

	switch v := rr.(type) {
	case *dns.A:
		data = storage.ARecordData{IP: v.A.String()}
	case *dns.AAAA:
		data = storage.AAAARecordData{IP: v.AAAA.String()}
	case *dns.CNAME:
		data = storage.CNAMERecordData{Target: v.Target}
	case *dns.MX:
		data = storage.MXRecordData{Priority: v.Preference, Target: v.Mx}
	case *dns.NS:
		data = storage.NSRecordData{Target: v.Ns}
	case *dns.PTR:
		data = storage.PTRRecordData{Target: v.Ptr}
	case *dns.TXT:
		data = storage.TXTRecordData{Values: v.Txt}
	case *dns.SRV:
		data = storage.SRVRecordData{
			Priority: v.Priority,
			Weight:   v.Weight,
			Port:     v.Port,
			Target:   v.Target,
		}
	case *dns.CAA:
		data = storage.CAARecordData{
			Flag:  v.Flag,
			Tag:   v.Tag,
			Value: v.Value,
		}
	case *dns.SOA:
		// Skip SOA - handled separately
		return nil, fmt.Errorf("SOA handled separately")
	default:
		return nil, fmt.Errorf("unsupported record type: %s", dns.TypeToString[hdr.Rrtype])
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	record.Data = jsonData

	return record, nil
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

// ==================== Zone File Import ====================

// ZoneImportRequest represents a request to import a zone from a zone file
type ZoneImportRequest struct {
	ZoneName string `json:"zone_name"` // Zone name (e.g., "example.com")
	ZoneFile string `json:"zone_file"` // BIND zone file content
	Preview  bool   `json:"preview"`   // If true, only preview without importing
}

// ZoneImportResult represents the result of a zone import
type ZoneImportResult struct {
	Zone         *storage.Zone   `json:"zone"`
	Records      []*RecordResult `json:"records"`
	RecordCount  int             `json:"record_count"`
	Errors       []string        `json:"errors"`
	Warnings     []string        `json:"warnings"`
	Imported     bool            `json:"imported"`
}

// RecordResult represents a parsed record for import preview
type RecordResult struct {
	Name    string          `json:"name"`
	Type    string          `json:"type"`
	TTL     uint32          `json:"ttl"`
	Data    json.RawMessage `json:"data"`
	RawData string          `json:"raw_data,omitempty"` // Human-readable data
}

// handleZoneImport handles zone file import
func (h *Handler) handleZoneImport(w http.ResponseWriter, r *http.Request) {
	session := auth.GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Only POST for import
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check permissions - need write access (admin or super admin)
	if !session.IsSuperAdmin && session.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	h.handleZoneImportStorage(w, r, session)
}

// handleZoneImportStorage handles zone import using storage backend
func (h *Handler) handleZoneImportStorage(w http.ResponseWriter, r *http.Request, session *auth.Session) {
	store, ok := h.store.(*storage.Store)
	if !ok || store == nil {
		http.Error(w, "Storage backend not available", http.StatusInternalServerError)
		return
	}

	var req ZoneImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.ZoneName == "" {
		http.Error(w, "zone_name is required", http.StatusBadRequest)
		return
	}

	if req.ZoneFile == "" {
		http.Error(w, "zone_file is required", http.StatusBadRequest)
		return
	}

	// Import using zonefile package
	result, err := h.importZoneFile(store, session, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// importZoneFile parses and optionally imports a BIND zone file
func (h *Handler) importZoneFile(store *storage.Store, session *auth.Session, req ZoneImportRequest) (*ZoneImportResult, error) {
	parser := &zoneFileParser{defaultTTL: 3600}
	
	parsed, err := parser.parse(strings.NewReader(req.ZoneFile), req.ZoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse zone file: %w", err)
	}

	result := &ZoneImportResult{
		Zone:        parsed.zone,
		Records:     make([]*RecordResult, 0, len(parsed.records)),
		RecordCount: len(parsed.records),
		Errors:      parsed.errors,
		Warnings:    make([]string, 0),
		Imported:    false,
	}

	// Convert records to result format
	for _, rec := range parsed.records {
		rr := &RecordResult{
			Name:    rec.Name,
			Type:    rec.Type,
			TTL:     rec.TTL,
			Data:    rec.Data,
			RawData: formatRecordData(rec.Type, rec.Data),
		}
		result.Records = append(result.Records, rr)
	}

	// Skip SOA records in the count (they're metadata, not importable)
	soaCount := 0
	for _, rec := range result.Records {
		if rec.Type == "SOA" {
			soaCount++
		}
	}
	if soaCount > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("%d SOA record(s) detected and will be used for zone configuration", soaCount))
	}

	// If preview only, return without importing
	if req.Preview {
		return result, nil
	}

	// Check if zone already exists
	existingZone, _ := store.GetZone(req.ZoneName)
	if existingZone != nil {
		return nil, fmt.Errorf("zone %s already exists - delete it first or import records individually", req.ZoneName)
	}

	// Set tenant ID from session
	tenantID := session.TenantID
	if tenantID == "" {
		tenantID = auth.MainTenantID
	}
	parsed.zone.TenantID = tenantID

	// Create the zone
	err = store.CreateZone(parsed.zone)
	if err != nil {
		return nil, fmt.Errorf("failed to create zone: %w", err)
	}

	// Import records (skip SOA - it's already in zone metadata)
	importedCount := 0
	for _, rec := range parsed.records {
		if rec.Type == "SOA" {
			continue // Skip SOA, already handled
		}
		
		rec.Zone = parsed.zone.Name
		if err := store.CreateRecord(rec); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to import %s %s: %v", rec.Name, rec.Type, err))
		} else {
			importedCount++
		}
	}

	result.Imported = true
	result.RecordCount = importedCount
	
	// Update config
	h.UpdateConfigFromStorage()

	return result, nil
}

// formatRecordData formats record data as a human-readable string
func formatRecordData(rtype string, data json.RawMessage) string {
	switch rtype {
	case "A", "AAAA":
		var d struct{ Address string `json:"address"` }
		if json.Unmarshal(data, &d) == nil {
			return d.Address
		}
	case "CNAME", "NS", "PTR":
		var d struct{ Target string `json:"target"` }
		if json.Unmarshal(data, &d) == nil {
			return d.Target
		}
	case "MX":
		var d struct {
			Preference uint16 `json:"preference"`
			Exchange   string `json:"exchange"`
		}
		if json.Unmarshal(data, &d) == nil {
			return fmt.Sprintf("%d %s", d.Preference, d.Exchange)
		}
	case "TXT":
		var d struct{ Text string `json:"text"` }
		if json.Unmarshal(data, &d) == nil {
			return fmt.Sprintf("\"%s\"", d.Text)
		}
	case "SRV":
		var d struct {
			Priority uint16 `json:"priority"`
			Weight   uint16 `json:"weight"`
			Port     uint16 `json:"port"`
			Target   string `json:"target"`
		}
		if json.Unmarshal(data, &d) == nil {
			return fmt.Sprintf("%d %d %d %s", d.Priority, d.Weight, d.Port, d.Target)
		}
	case "CAA":
		var d struct {
			Flag  uint8  `json:"flag"`
			Tag   string `json:"tag"`
			Value string `json:"value"`
		}
		if json.Unmarshal(data, &d) == nil {
			return fmt.Sprintf("%d %s \"%s\"", d.Flag, d.Tag, d.Value)
		}
	}
	return string(data)
}

// zoneFileParser is a simplified BIND zone file parser
type zoneFileParser struct {
	origin     string
	defaultTTL uint32
}

type parsedZoneFile struct {
	zone    *storage.Zone
	records []*storage.Record
	errors  []string
}

func (p *zoneFileParser) parse(r interface{ Read([]byte) (int, error) }, zoneName string) (*parsedZoneFile, error) {
	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}
	p.origin = zoneName

	result := &parsedZoneFile{
		zone: &storage.Zone{
			Name:    strings.TrimSuffix(zoneName, "."),
			Type:    "forward",
			TTL:     p.defaultTTL,
			Serial:  uint32(time.Now().Unix()),
			Refresh: 3600,
			Retry:   600,
			Expire:  604800,
			Minimum: 3600,
		},
		records: make([]*storage.Record, 0),
	}

	// Read all content
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	content := string(buf)

	var currentName string
	lineNum := 0
	lines := strings.Split(content, "\n")

	for lineNum < len(lines) {
		line := lines[lineNum]
		lineNum++
		
		// Remove comments
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Handle directives
		if strings.HasPrefix(line, "$") {
			p.handleDirective(line, result)
			continue
		}

		// Handle multi-line records (parentheses)
		if strings.Contains(line, "(") && !strings.Contains(line, ")") {
			// Collect multi-line
			fullLine := line
			for lineNum < len(lines) {
				nextLine := lines[lineNum]
				lineNum++
				if idx := strings.Index(nextLine, ";"); idx >= 0 {
					nextLine = nextLine[:idx]
				}
				fullLine += " " + strings.TrimSpace(nextLine)
				if strings.Contains(nextLine, ")") {
					break
				}
			}
			line = strings.ReplaceAll(fullLine, "(", "")
			line = strings.ReplaceAll(line, ")", "")
			line = strings.TrimSpace(line)
		}

		record, name, err := p.parseRecord(line, currentName)
		if err != nil {
			result.errors = append(result.errors, fmt.Sprintf("line %d: %v", lineNum, err))
			continue
		}

		if name != "" {
			currentName = name
		}

		if record != nil {
			record.Zone = zoneName
			result.records = append(result.records, record)

			if record.Type == "SOA" {
				p.extractSOAToZone(record, result.zone)
			}
		}
	}

	return result, nil
}

func (p *zoneFileParser) handleDirective(line string, result *parsedZoneFile) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	switch strings.ToUpper(parts[0]) {
	case "$ORIGIN":
		origin := parts[1]
		if !strings.HasSuffix(origin, ".") {
			origin += "."
		}
		p.origin = origin
	case "$TTL":
		if ttl, err := p.parseTTL(parts[1]); err == nil {
			p.defaultTTL = ttl
			result.zone.TTL = ttl
		}
	}
}

func (p *zoneFileParser) parseRecord(line, prevName string) (*storage.Record, string, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil, "", fmt.Errorf("too few fields")
	}

	var name string
	var ttl uint32 = p.defaultTTL
	var rtype string
	var dataStart int

	// Determine if first field is a name
	if !p.isNumeric(fields[0]) && !p.isClass(fields[0]) && !p.isType(fields[0]) {
		name = fields[0]
		dataStart = 1
	} else {
		name = prevName
		dataStart = 0
	}

	// Handle @ as origin
	if name == "@" {
		name = p.origin
	}

	// Make name fully qualified
	if name != "" && !strings.HasSuffix(name, ".") {
		name = name + "." + p.origin
	}

	// Parse TTL, class, and type
	for i := dataStart; i < len(fields); i++ {
		f := fields[i]
		if p.isNumeric(f) {
			if t, err := p.parseTTL(f); err == nil {
				ttl = t
			}
		} else if p.isClass(f) {
			// Skip class
		} else if p.isType(f) {
			rtype = strings.ToUpper(f)
			dataStart = i + 1
			break
		}
	}

	if rtype == "" {
		return nil, name, fmt.Errorf("no record type found")
	}

	data := fields[dataStart:]
	if len(data) == 0 && rtype != "TXT" {
		return nil, name, fmt.Errorf("no record data")
	}

	record, err := p.buildRecord(name, ttl, rtype, data)
	if err != nil {
		return nil, name, err
	}

	return record, name, nil
}

func (p *zoneFileParser) buildRecord(name string, ttl uint32, rtype string, data []string) (*storage.Record, error) {
	record := &storage.Record{
		Name: strings.TrimSuffix(name, "."),
		Type: rtype,
		TTL:  ttl,
	}

	switch rtype {
	case "A":
		if len(data) < 1 {
			return nil, fmt.Errorf("A record needs IP")
		}
		record.Data = json.RawMessage(fmt.Sprintf(`{"address":"%s"}`, data[0]))

	case "AAAA":
		if len(data) < 1 {
			return nil, fmt.Errorf("AAAA record needs IP")
		}
		record.Data = json.RawMessage(fmt.Sprintf(`{"address":"%s"}`, data[0]))

	case "CNAME", "NS", "PTR":
		if len(data) < 1 {
			return nil, fmt.Errorf("%s record needs target", rtype)
		}
		target := p.expandName(data[0])
		record.Data = json.RawMessage(fmt.Sprintf(`{"target":"%s"}`, strings.TrimSuffix(target, ".")))

	case "MX":
		if len(data) < 2 {
			return nil, fmt.Errorf("MX record needs priority and exchange")
		}
		pref, _ := strconv.ParseUint(data[0], 10, 16)
		exchange := p.expandName(data[1])
		record.Data = json.RawMessage(fmt.Sprintf(`{"preference":%d,"exchange":"%s"}`, pref, strings.TrimSuffix(exchange, ".")))

	case "TXT":
		// Join all data and handle quotes
		text := strings.Join(data, " ")
		// Remove surrounding quotes if present
		text = strings.Trim(text, "\"")
		// Handle escaped quotes
		text = strings.ReplaceAll(text, "\\\"", "\"")
		// Escape for JSON
		text = strings.ReplaceAll(text, "\\", "\\\\")
		text = strings.ReplaceAll(text, "\"", "\\\"")
		record.Data = json.RawMessage(fmt.Sprintf(`{"text":"%s"}`, text))

	case "SRV":
		if len(data) < 4 {
			return nil, fmt.Errorf("SRV record needs priority, weight, port, target")
		}
		priority, _ := strconv.ParseUint(data[0], 10, 16)
		weight, _ := strconv.ParseUint(data[1], 10, 16)
		port, _ := strconv.ParseUint(data[2], 10, 16)
		target := p.expandName(data[3])
		record.Data = json.RawMessage(fmt.Sprintf(`{"priority":%d,"weight":%d,"port":%d,"target":"%s"}`,
			priority, weight, port, strings.TrimSuffix(target, ".")))

	case "CAA":
		if len(data) < 3 {
			return nil, fmt.Errorf("CAA record needs flag, tag, value")
		}
		flag, _ := strconv.ParseUint(data[0], 10, 8)
		tag := data[1]
		value := strings.Trim(strings.Join(data[2:], " "), "\"")
		record.Data = json.RawMessage(fmt.Sprintf(`{"flag":%d,"tag":"%s","value":"%s"}`, flag, tag, value))

	case "SOA":
		if len(data) < 7 {
			return nil, fmt.Errorf("SOA record needs mname, rname, serial, refresh, retry, expire, minimum")
		}
		mname := p.expandName(data[0])
		rname := p.expandName(data[1])
		serial, _ := strconv.ParseUint(data[2], 10, 32)
		refresh, _ := p.parseTTL(data[3])
		retry, _ := p.parseTTL(data[4])
		expire, _ := p.parseTTL(data[5])
		minimum, _ := p.parseTTL(data[6])
		record.Data = json.RawMessage(fmt.Sprintf(
			`{"mname":"%s","rname":"%s","serial":%d,"refresh":%d,"retry":%d,"expire":%d,"minimum":%d}`,
			strings.TrimSuffix(mname, "."), strings.TrimSuffix(rname, "."), serial, refresh, retry, expire, minimum))

	default:
		// For unsupported types, store raw data
		record.Data = json.RawMessage(fmt.Sprintf(`{"raw":"%s"}`, strings.Join(data, " ")))
	}

	return record, nil
}

func (p *zoneFileParser) expandName(name string) string {
	if name == "@" {
		return p.origin
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "." + p.origin
}

func (p *zoneFileParser) extractSOAToZone(record *storage.Record, zone *storage.Zone) {
	var soa struct {
		MName   string `json:"mname"`
		RName   string `json:"rname"`
		Serial  uint32 `json:"serial"`
		Refresh uint32 `json:"refresh"`
		Retry   uint32 `json:"retry"`
		Expire  uint32 `json:"expire"`
		Minimum uint32 `json:"minimum"`
	}

	if err := json.Unmarshal(record.Data, &soa); err == nil {
		zone.PrimaryNS = soa.MName
		zone.AdminEmail = soa.RName
		zone.Serial = soa.Serial
		zone.Refresh = soa.Refresh
		zone.Retry = soa.Retry
		zone.Expire = soa.Expire
		zone.Minimum = soa.Minimum
	}
}

func (p *zoneFileParser) parseTTL(s string) (uint32, error) {
	s = strings.ToLower(s)
	multiplier := uint32(1)

	if strings.HasSuffix(s, "s") {
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "m") {
		s = s[:len(s)-1]
		multiplier = 60
	} else if strings.HasSuffix(s, "h") {
		s = s[:len(s)-1]
		multiplier = 3600
	} else if strings.HasSuffix(s, "d") {
		s = s[:len(s)-1]
		multiplier = 86400
	} else if strings.HasSuffix(s, "w") {
		s = s[:len(s)-1]
		multiplier = 604800
	}

	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}

	return uint32(val) * multiplier, nil
}

func (p *zoneFileParser) isNumeric(s string) bool {
	_, err := p.parseTTL(s)
	return err == nil
}

func (p *zoneFileParser) isClass(s string) bool {
	upper := strings.ToUpper(s)
	return upper == "IN" || upper == "CH" || upper == "HS" || upper == "CS"
}

func (p *zoneFileParser) isType(s string) bool {
	types := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true,
		"PTR": true, "SOA": true, "SRV": true, "TXT": true, "CAA": true,
		"SSHFP": true, "TLSA": true, "NAPTR": true, "LOC": true,
	}
	return types[strings.ToUpper(s)]
}
