package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/scott/dns/storage"
)

// handleGeofeed handles geofeed entry management (CRUD)
func (h *Handler) handleGeofeed(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		entries, err := store.ListGeoEntries()
		if err != nil {
			h.errorResponse(w, "Failed to list geofeed entries: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []*storage.GeoEntry{}
		}
		h.jsonResponse(w, entries)

	case "POST":
		var entry storage.GeoEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := store.CreateGeoEntry(&entry); err != nil {
			h.errorResponse(w, "Failed to create geofeed entry: "+err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("[geofeed] Created entry: %s → %s, %s, %s", entry.Prefix, entry.Country, entry.Region, entry.City)
		h.jsonResponse(w, entry)

	default:
		h.errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGeofeedEntry handles individual geofeed entry operations (GET/PUT/DELETE by ID)
func (h *Handler) handleGeofeedEntry(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	// Extract ID from URL path: /api/geofeed/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/geofeed/")
	if id == "" {
		h.errorResponse(w, "ID is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		entry, err := store.GetGeoEntry(id)
		if err != nil {
			h.errorResponse(w, "Failed to get geofeed entry: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if entry == nil {
			h.errorResponse(w, "Geofeed entry not found", http.StatusNotFound)
			return
		}
		h.jsonResponse(w, entry)

	case "PUT":
		var entry storage.GeoEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		entry.ID = id

		if err := store.UpdateGeoEntry(&entry); err != nil {
			if err == storage.ErrNotFound {
				h.errorResponse(w, "Geofeed entry not found", http.StatusNotFound)
				return
			}
			h.errorResponse(w, "Failed to update geofeed entry: "+err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("[geofeed] Updated entry: %s → %s, %s, %s", entry.Prefix, entry.Country, entry.Region, entry.City)
		h.jsonResponse(w, entry)

	case "DELETE":
		if err := store.DeleteGeoEntry(id); err != nil {
			h.errorResponse(w, "Failed to delete geofeed entry: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("[geofeed] Deleted entry: %s", id)
		h.jsonResponse(w, map[string]string{"status": "deleted"})

	default:
		h.errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGeofeedCSV serves the RFC 8805/9632 geofeed CSV at a public endpoint.
// This endpoint does NOT require authentication so it can be used by RIRs and geolocation services.
func (h *Handler) handleGeofeedCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		h.errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	csv, err := store.GenerateGeofeedCSV()
	if err != nil {
		h.errorResponse(w, "Failed to generate geofeed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=\"geofeed.csv\"")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// RFC 9632 Section 6 / RFC 8805 Section 3.4: Use Expires header to signal refetch interval
	// Geofeed data changes infrequently; signal weekly refetch
	w.Header().Set("Cache-Control", "public, max-age=604800") // 7 days
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(csv))
}
