package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/scott/dns/storage"
)

// handleRedirects handles redirect rule management
func (h *Handler) handleRedirects(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		rules, err := store.ListRedirects()
		if err != nil {
			h.errorResponse(w, "Failed to list redirects: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if rules == nil {
			rules = []*storage.RedirectRule{}
		}
		
		// Also include presets for safe search
		presets := []map[string]interface{}{
			{
				"id":          "google-safesearch",
				"name":        "Google Safe Search",
				"description": "Enforces Safe Search on all Google domains",
				"match":       "*.google.*",
				"target":      "forcesafesearch.google.com",
			},
			{
				"id":          "youtube-restricted",
				"name":        "YouTube Restricted Mode (Strict)",
				"description": "Enforces strict restricted mode on YouTube",
				"match":       "*.youtube.com",
				"target":      "restrict.youtube.com",
			},
			{
				"id":          "youtube-moderate",
				"name":        "YouTube Restricted Mode (Moderate)",
				"description": "Enforces moderate restricted mode on YouTube",
				"match":       "*.youtube.com",
				"target":      "restrictmoderate.youtube.com",
			},
			{
				"id":          "bing-safesearch",
				"name":        "Bing Safe Search",
				"description": "Enforces Safe Search on Bing",
				"match":       "*.bing.com",
				"target":      "strict.bing.com",
			},
			{
				"id":          "duckduckgo-safesearch",
				"name":        "DuckDuckGo Safe Search",
				"description": "Enforces Safe Search on DuckDuckGo",
				"match":       "duckduckgo.com",
				"target":      "safe.duckduckgo.com",
			},
		}

		h.jsonResponse(w, map[string]interface{}{
			"rules":   rules,
			"presets": presets,
		})

	case "POST":
		var rule storage.RedirectRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if rule.ID == "" {
			h.errorResponse(w, "ID is required", http.StatusBadRequest)
			return
		}
		if rule.MatchDomain == "" {
			h.errorResponse(w, "Match domain is required", http.StatusBadRequest)
			return
		}
		if rule.TargetHost == "" {
			h.errorResponse(w, "Target host is required", http.StatusBadRequest)
			return
		}

		if err := store.CreateRedirect(&rule); err != nil {
			h.errorResponse(w, "Failed to create redirect: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("[redirects] Created redirect rule: %s -> %s", rule.MatchDomain, rule.TargetHost)
		w.WriteHeader(http.StatusCreated)
		h.jsonResponse(w, rule)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRedirect handles individual redirect rule operations
func (h *Handler) handleRedirect(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	// Extract ID from path: /api/redirects/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/redirects/")
	id := strings.TrimSuffix(path, "/")
	if id == "" {
		h.errorResponse(w, "Redirect ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		rule, err := store.GetRedirect(id)
		if err != nil {
			h.errorResponse(w, "Failed to get redirect: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if rule == nil {
			h.errorResponse(w, "Redirect not found", http.StatusNotFound)
			return
		}
		h.jsonResponse(w, rule)

	case "PUT":
		var rule storage.RedirectRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		rule.ID = id

		if err := store.UpdateRedirect(&rule); err != nil {
			h.errorResponse(w, "Failed to update redirect: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("[redirects] Updated redirect rule: %s -> %s (enabled=%v)", rule.MatchDomain, rule.TargetHost, rule.Enabled)
		h.jsonResponse(w, rule)

	case "DELETE":
		if err := store.DeleteRedirect(id); err != nil {
			h.errorResponse(w, "Failed to delete redirect: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("[redirects] Deleted redirect rule: %s", id)
		h.jsonResponse(w, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
