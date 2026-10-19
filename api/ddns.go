package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/scott/dns/storage"
)

// Dynamic DNS: a client holding a host's token can point that one name (A or
// AAAA) at a public address, and nothing else. Routers use it to publish their
// own changing WAN address.
//
//	POST /api/ddns/update   Authorization: Bearer <token>   [ip=<address>]
//
// Without ip=, the caller's source address is used. Behind the sniproxy on the
// Proxmox hosts (dns-3, dns-4) that is the proxy, which is not public, so the
// update is refused rather than recorded wrong. Replies are dyndns-style
// plain text: "good <ip>", "nochg <ip>", or an error.
//
// Hosts are managed by server admins through /api/ddns/hosts.

const (
	ddnsTokenPrefix  = "ddns_"
	ddnsDefaultTTL   = 60
	ddnsFailLimit    = 20
	ddnsFailInterval = 10 * time.Minute
)

// ddnsFailures counts failed token attempts per source address, so a client
// guessing tokens gets throttled. Tokens are 256-bit random, so this is about
// noise and load, not about making guessing feasible.
type ddnsFailures struct {
	mu    sync.Mutex
	count map[string][]time.Time
}

var ddnsFails = &ddnsFailures{count: map[string][]time.Time{}}

func (f *ddnsFailures) recent(src string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range f.count[src] {
		if now.Sub(t) < ddnsFailInterval {
			keep = append(keep, t)
		}
	}
	return keep
}

func (f *ddnsFailures) blocked(src string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	keep := f.recent(src, time.Now())
	f.count[src] = keep
	return len(keep) >= ddnsFailLimit
}

func (f *ddnsFailures) add(src string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	f.count[src] = append(f.recent(src, now), now)
}

func hashDDNSToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newDDNSToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return ddnsTokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ddnsToken reads the token from "Authorization: Bearer" or "X-DDNS-Token".
// It is not accepted in the URL, where it would end up in logs.
func ddnsToken(r *http.Request) string {
	if v := r.Header.Get("X-DDNS-Token"); v != "" {
		return strings.TrimSpace(v)
	}
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicAddr parses s and accepts only a global unicast, non-private address.
func publicAddr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("not an IP address: %q", s)
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || cgnat.Contains(addr) {
		return netip.Addr{}, fmt.Errorf("not a public address: %s", addr)
	}
	return addr, nil
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func ddnsReply(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	fmt.Fprintln(w, msg)
}

// handleDDNSUpdate is the token-authenticated update endpoint. It is not
// behind the session auth middleware; the token is the credential.
func (h *Handler) handleDDNSUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		ddnsReply(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	store := h.getStore()
	if store == nil {
		ddnsReply(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	src := remoteHost(r)
	if ddnsFails.blocked(src) {
		ddnsReply(w, http.StatusTooManyRequests, "too many failed attempts")
		return
	}

	host, err := h.ddnsHostForToken(store, ddnsToken(r))
	if err != nil {
		ddnsReply(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if host == nil {
		ddnsFails.add(src)
		log.Printf("[ddns] rejected update from %s: bad or missing token", src)
		ddnsReply(w, http.StatusUnauthorized, "badauth")
		return
	}

	want := r.FormValue("ip")
	if want == "" {
		want = src
	}
	addr, err := publicAddr(want)
	if err != nil {
		ddnsReply(w, http.StatusBadRequest, err.Error())
		return
	}

	changed, err := h.setDDNSAddress(store, host, addr)
	if err != nil {
		log.Printf("[ddns] %s: update to %s failed: %v", host.ID, addr, err)
		ddnsReply(w, http.StatusInternalServerError, "update failed")
		return
	}
	if !changed {
		ddnsReply(w, http.StatusOK, "nochg "+addr.String())
		return
	}
	log.Printf("[ddns] %s -> %s (request from %s)", host.ID, addr, src)
	ddnsReply(w, http.StatusOK, "good "+addr.String())
}

// ddnsHostForToken finds the host whose token hash matches, or nil.
func (h *Handler) ddnsHostForToken(store *storage.Store, token string) (*storage.DDNSHost, error) {
	if !strings.HasPrefix(token, ddnsTokenPrefix) {
		return nil, nil
	}
	hosts, err := store.ListDDNSHosts()
	if err != nil {
		return nil, err
	}
	want := []byte(hashDDNSToken(token))
	var found *storage.DDNSHost
	for _, host := range hosts {
		if subtle.ConstantTimeCompare(want, []byte(host.TokenHash)) == 1 {
			found = host
		}
	}
	return found, nil
}

// setDDNSAddress makes the host's record of the address's family (A or AAAA)
// hold exactly that address. It reports whether anything changed.
func (h *Handler) setDDNSAddress(store *storage.Store, host *storage.DDNSHost, addr netip.Addr) (bool, error) {
	rtype := "A"
	if addr.Is6() {
		rtype = "AAAA"
	}
	ip := addr.String()
	data, _ := json.Marshal(map[string]string{"ip": ip})

	existing, err := store.GetRecords(host.Zone, host.Name, rtype)
	if err != nil && err != storage.ErrNotFound {
		return false, err
	}

	changed := false
	switch {
	case len(existing) == 0:
		rec := &storage.Record{Zone: host.Zone, Name: host.Name, Type: rtype, TTL: host.TTL, Enabled: true, Data: data}
		if err := store.CreateRecord(rec); err != nil {
			return false, err
		}
		changed = true
	default:
		// Keep the first record and update it in place; drop any others.
		rec := existing[0]
		var cur struct {
			IP string `json:"ip"`
		}
		_ = json.Unmarshal(rec.Data, &cur)
		if cur.IP != ip || rec.TTL != host.TTL || !rec.Enabled {
			rec.Data = data
			rec.TTL = host.TTL
			rec.Enabled = true
			if err := store.UpdateRecord(&rec); err != nil {
				return false, err
			}
			changed = true
		}
		for _, extra := range existing[1:] {
			if err := store.DeleteRecord(host.Zone, extra.Name, extra.Type, extra.ID); err != nil {
				return false, err
			}
			changed = true
		}
	}

	if !changed {
		return false, nil
	}
	if host.LastIP != ip {
		host.LastIP = ip
		host.UpdatedAt = time.Now().UTC()
		if err := store.PutDDNSHost(host); err != nil {
			log.Printf("[ddns] %s: saving last address failed: %v", host.ID, err)
		}
	}
	if err := h.UpdateConfigFromStorage(); err != nil {
		return true, err
	}
	return true, nil
}

// ddnsHostView is a host as the admin API shows it: never the token hash.
type ddnsHostView struct {
	ID          string    `json:"id"`
	Zone        string    `json:"zone"`
	Name        string    `json:"name"`
	TTL         uint32    `json:"ttl"`
	Description string    `json:"description,omitempty"`
	LastIP      string    `json:"last_ip,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Token       string    `json:"token,omitempty"` // only when just issued
}

func viewDDNSHost(host *storage.DDNSHost, token string) ddnsHostView {
	return ddnsHostView{
		ID: host.ID, Zone: host.Zone, Name: host.Name, TTL: host.TTL,
		Description: host.Description, LastIP: host.LastIP,
		CreatedAt: host.CreatedAt, UpdatedAt: host.UpdatedAt, Token: token,
	}
}

// handleDDNSHosts lists hosts (GET) or creates one (POST {zone, name, ttl,
// description}). Creating returns the token, once.
func (h *Handler) handleDDNSHosts(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		hosts, err := store.ListDDNSHosts()
		if err != nil {
			h.errorResponse(w, "Failed to list DDNS hosts: "+err.Error(), http.StatusInternalServerError)
			return
		}
		views := []ddnsHostView{}
		for _, host := range hosts {
			views = append(views, viewDDNSHost(host, ""))
		}
		h.jsonResponse(w, views)

	case http.MethodPost:
		var req struct {
			Zone        string `json:"zone"`
			Name        string `json:"name"`
			TTL         uint32 `json:"ttl"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.errorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		zoneName := strings.TrimSuffix(strings.ToLower(req.Zone), ".")
		name := strings.TrimSuffix(strings.ToLower(req.Name), ".")
		if zoneName == "" || name == "" {
			h.errorResponse(w, "zone and name are required", http.StatusBadRequest)
			return
		}
		if _, err := store.GetZone(zoneName); err != nil {
			h.errorResponse(w, "Zone not found: "+zoneName, http.StatusBadRequest)
			return
		}
		id := storage.DDNSHostID(zoneName, name)
		if existing, _ := store.GetDDNSHost(id); existing != nil {
			h.errorResponse(w, "DDNS host already exists: "+id, http.StatusConflict)
			return
		}
		ttl := req.TTL
		if ttl == 0 {
			ttl = ddnsDefaultTTL
		}
		token, err := newDDNSToken()
		if err != nil {
			h.errorResponse(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}
		now := time.Now().UTC()
		host := &storage.DDNSHost{
			ID: id, Zone: zoneName, Name: name, TTL: ttl,
			TokenHash: hashDDNSToken(token), Description: req.Description,
			CreatedAt: now, UpdatedAt: now,
		}
		if err := store.PutDDNSHost(host); err != nil {
			h.errorResponse(w, "Failed to save DDNS host: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.jsonResponse(w, viewDDNSHost(host, token))

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDDNSHost deletes a host (DELETE /api/ddns/hosts/{id}) or issues it a
// new token (POST /api/ddns/hosts/{id}/token), which stops the old one working.
func (h *Handler) handleDDNSHost(w http.ResponseWriter, r *http.Request) {
	store := h.getStore()
	if store == nil {
		h.errorResponse(w, "Storage not available", http.StatusInternalServerError)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/ddns/hosts/")
	id, action, _ := strings.Cut(path, "/")
	id = strings.TrimSuffix(strings.ToLower(id), ".")

	host, err := store.GetDDNSHost(id)
	if err != nil {
		h.errorResponse(w, "Failed to read DDNS host: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if host == nil {
		h.errorResponse(w, "DDNS host not found: "+id, http.StatusNotFound)
		return
	}

	switch {
	case r.Method == http.MethodGet && action == "":
		h.jsonResponse(w, viewDDNSHost(host, ""))

	case r.Method == http.MethodDelete && action == "":
		if err := store.DeleteDDNSHost(id); err != nil {
			h.errorResponse(w, "Failed to delete DDNS host: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.jsonResponse(w, map[string]string{"status": "ok"})

	case r.Method == http.MethodPost && action == "token":
		token, err := newDDNSToken()
		if err != nil {
			h.errorResponse(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}
		host.TokenHash = hashDDNSToken(token)
		host.UpdatedAt = time.Now().UTC()
		if err := store.PutDDNSHost(host); err != nil {
			h.errorResponse(w, "Failed to save DDNS host: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.jsonResponse(w, viewDDNSHost(host, token))

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
