package server

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/scott/dns/resolver"
)

// UpdateConfig holds dynamic update configuration
type UpdateConfig struct {
	Enabled     bool     `json:"enabled"`
	AllowedNets []string `json:"allowed_nets"` // List of allowed IP networks (CIDR)
	AllowedKeys []string `json:"allowed_keys"` // List of allowed TSIG key names
	AutoPTR     bool     `json:"auto_ptr"`     // Auto-create reverse PTR records
}

// UpdateHandler handles RFC 2136 dynamic DNS updates
type UpdateHandler struct {
	server *Server
	config UpdateConfig
}

// NewUpdateHandler creates a new update handler
func NewUpdateHandler(s *Server) *UpdateHandler {
	return &UpdateHandler{
		server: s,
		config: UpdateConfig{
			Enabled:     false,
			AllowedNets: []string{},
			AllowedKeys: []string{},
			AutoPTR:     true,
		},
	}
}

// SetConfig updates the update handler configuration
func (h *UpdateHandler) SetConfig(cfg UpdateConfig) {
	h.config = cfg
}

// HandleUpdate processes a DNS UPDATE message (RFC 2136)
func (h *UpdateHandler) HandleUpdate(w dns.ResponseWriter, r *dns.Msg) {
	// Create response
	m := new(dns.Msg)
	m.SetReply(r)
	m.Opcode = dns.OpcodeUpdate

	// Check if updates are enabled
	if !h.config.Enabled {
		log.Printf("[update] Dynamic updates disabled, refusing request")
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}

	// Check client authorization
	clientAddr := w.RemoteAddr()
	var clientIP net.IP
	switch addr := clientAddr.(type) {
	case *net.UDPAddr:
		clientIP = addr.IP
	case *net.TCPAddr:
		clientIP = addr.IP
	}

	if !h.isAuthorized(clientIP, r) {
		log.Printf("[update] Unauthorized update request from %s", clientIP)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}

	// Extract zone from the zone section
	if len(r.Question) != 1 {
		log.Printf("[update] Invalid zone section: expected 1 entry, got %d", len(r.Question))
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m)
		return
	}

	zone := strings.ToLower(r.Question[0].Name)
	if r.Question[0].Qtype != dns.TypeSOA {
		log.Printf("[update] Zone section must have SOA type")
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m)
		return
	}

	// Verify we're authoritative for this zone
	cfg := h.server.getConfig()
	if !h.server.isAuthoritative(zone, cfg) {
		log.Printf("[update] Not authoritative for zone %s", zone)
		m.Rcode = dns.RcodeNotAuth
		w.WriteMsg(m)
		return
	}

	// Process prerequisites (Answer section in UPDATE)
	// These are conditions that must be met for update to proceed
	if err := h.checkPrerequisites(r.Answer, zone); err != nil {
		log.Printf("[update] Prerequisite check failed: %v", err)
		m.Rcode = dns.RcodeNXRrset // Prerequisites not satisfied
		w.WriteMsg(m)
		return
	}

	// Process updates (Ns section in UPDATE - the actual update operations)
	if err := h.processUpdates(r.Ns, zone, clientIP.String()); err != nil {
		log.Printf("[update] Failed to process updates: %v", err)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	log.Printf("[update] Successfully processed update for zone %s from %s (%d operations)", zone, clientIP, len(r.Ns))
	m.Rcode = dns.RcodeSuccess
	w.WriteMsg(m)
}

// isAuthorized checks if the client is authorized to send updates
func (h *UpdateHandler) isAuthorized(clientIP net.IP, r *dns.Msg) bool {
	// Check IP-based authorization
	ipAllowed := len(h.config.AllowedNets) == 0 // If no nets configured, allow all IPs
	for _, netStr := range h.config.AllowedNets {
		_, network, err := net.ParseCIDR(netStr)
		if err != nil {
			// Try as single IP
			if allowedIP := net.ParseIP(netStr); allowedIP != nil {
				if allowedIP.Equal(clientIP) {
					ipAllowed = true
					break
				}
			}
			continue
		}
		if network.Contains(clientIP) {
			ipAllowed = true
			break
		}
	}

	if !ipAllowed {
		return false
	}

	// Check TSIG if keys are configured
	if len(h.config.AllowedKeys) > 0 {
		tsig := r.IsTsig()
		if tsig == nil {
			log.Printf("[update] TSIG required but not provided")
			return false
		}

		// Verify TSIG key is in allowed list
		keyName := strings.ToLower(tsig.Hdr.Name)
		keyAllowed := false
		for _, allowedKey := range h.config.AllowedKeys {
			if strings.ToLower(allowedKey) == keyName {
				keyAllowed = true
				break
			}
		}
		if !keyAllowed {
			log.Printf("[update] TSIG key %s not in allowed list", keyName)
			return false
		}

		// TSIG validation is done by the DNS server's TSIG handler
		// We just check that it was present and the key name is allowed
	}

	return true
}

// checkPrerequisites verifies that prerequisites are met
func (h *UpdateHandler) checkPrerequisites(prereqs []dns.RR, zone string) error {
	// Types of prerequisites:
	// - Name in use (class=ANY, type=ANY, RDATA empty)
	// - Name not in use (class=NONE, type=ANY, RDATA empty)
	// - RRset exists (value independent) (class=ANY, RDATA empty)
	// - RRset exists (value dependent) (class=IN, full RDATA)
	// - RRset does not exist (class=NONE, RDATA empty)

	resolver := h.server.getResolver()

	for _, rr := range prereqs {
		name := strings.ToLower(rr.Header().Name)
		class := rr.Header().Class
		rrtype := rr.Header().Rrtype

		switch class {
		case dns.ClassANY:
			// Name or RRset must exist
			exists := h.recordExists(resolver, name, rrtype)
			if !exists {
				if rrtype == dns.TypeANY {
					return &updateError{name: name, msg: "name not in use"}
				}
				return &updateError{name: name, msg: "RRset does not exist"}
			}

		case dns.ClassNONE:
			// Name or RRset must NOT exist
			exists := h.recordExists(resolver, name, rrtype)
			if exists {
				if rrtype == dns.TypeANY {
					return &updateError{name: name, msg: "name is in use"}
				}
				return &updateError{name: name, msg: "RRset exists"}
			}

		case dns.ClassINET:
			// RRset must exist with exact value
			// This is used for value-dependent prerequisites
			// For now, just check if the name/type exists
			log.Printf("[update] Value-dependent prerequisite for %s (not fully implemented)", name)
		}
	}

	return nil
}

// recordExists checks if a record exists for a name/type
func (h *UpdateHandler) recordExists(res *resolver.Resolver, name string, rrtype uint16) bool {
	switch rrtype {
	case dns.TypeANY:
		// Check if any record exists at this name
		_, _, foundA := res.LookupA(name)
		if foundA {
			return true
		}
		_, _, foundAAAA := res.LookupAAAA(name)
		if foundAAAA {
			return true
		}
		_, _, foundCNAME := res.LookupCNAME(name)
		if foundCNAME {
			return true
		}
		mxRecords := res.LookupMX(name)
		if len(mxRecords) > 0 {
			return true
		}
		txtRecords := res.LookupTXT(name)
		if len(txtRecords) > 0 {
			return true
		}
		_, _, foundPTR := res.LookupPTR(name)
		return foundPTR
	case dns.TypeA:
		_, _, found := res.LookupA(name)
		return found
	case dns.TypeAAAA:
		_, _, found := res.LookupAAAA(name)
		return found
	case dns.TypeCNAME:
		_, _, found := res.LookupCNAME(name)
		return found
	case dns.TypeMX:
		return len(res.LookupMX(name)) > 0
	case dns.TypeTXT:
		return len(res.LookupTXT(name)) > 0
	case dns.TypePTR:
		_, _, found := res.LookupPTR(name)
		return found
	case dns.TypeNS:
		return len(res.LookupNS(name)) > 0
	case dns.TypeSRV:
		return len(res.LookupSRV(name)) > 0
	default:
		return false
	}
}

// processUpdates processes the actual update operations
func (h *UpdateHandler) processUpdates(updates []dns.RR, zone, source string) error {
	storage := h.server.getStorage()
	if storage == nil {
		return &updateError{msg: "storage not available"}
	}

	for _, rr := range updates {
		name := strings.ToLower(rr.Header().Name)
		class := rr.Header().Class
		rrtype := rr.Header().Rrtype
		ttl := rr.Header().Ttl

		// Verify record is within the zone
		if !strings.HasSuffix(name, zone) && name != zone {
			log.Printf("[update] Record %s not within zone %s", name, zone)
			continue
		}

		switch class {
		case dns.ClassINET:
			// Add record
			if err := h.addRecord(name, zone, rrtype, ttl, rr, source); err != nil {
				log.Printf("[update] Failed to add record %s: %v", name, err)
				return err
			}
			log.Printf("[update] Added %s %s", dns.TypeToString[rrtype], name)

			// Auto-create PTR if enabled
			if h.config.AutoPTR {
				h.createReversePTR(rr, zone, source)
			}

		case dns.ClassNONE:
			// Delete specific RRset
			if err := h.deleteRecord(name, zone, rrtype, rr); err != nil {
				log.Printf("[update] Failed to delete record %s: %v", name, err)
				return err
			}
			log.Printf("[update] Deleted %s %s", dns.TypeToString[rrtype], name)

		case dns.ClassANY:
			// Delete all records at name (if type=ANY) or all records of type
			if err := h.deleteAllRecords(name, zone, rrtype); err != nil {
				log.Printf("[update] Failed to delete records for %s: %v", name, err)
				return err
			}
			log.Printf("[update] Deleted all %s at %s", dns.TypeToString[rrtype], name)
		}
	}

	return nil
}

// addRecord adds a new DNS record
func (h *UpdateHandler) addRecord(name, zone string, rrtype uint16, ttl uint32, rr dns.RR, source string) error {
	storage := h.server.getStorage()
	if storage == nil {
		return &updateError{msg: "storage not available"}
	}

	// Convert to storage record format
	record := map[string]interface{}{
		"zone":         zone,
		"name":         name,
		"ttl":          int(ttl),
		"auto_managed": true, // Mark as dynamic update
		"source":       source,
		"created_at":   time.Now().UTC().Format(time.RFC3339),
	}

	switch rrtype {
	case dns.TypeA:
		if a, ok := rr.(*dns.A); ok {
			record["type"] = "A"
			record["data"] = map[string]interface{}{
				"ip": a.A.String(),
			}
		}
	case dns.TypeAAAA:
		if aaaa, ok := rr.(*dns.AAAA); ok {
			record["type"] = "AAAA"
			record["data"] = map[string]interface{}{
				"ip": aaaa.AAAA.String(),
			}
		}
	case dns.TypeCNAME:
		if cname, ok := rr.(*dns.CNAME); ok {
			record["type"] = "CNAME"
			record["data"] = map[string]interface{}{
				"target": cname.Target,
			}
		}
	case dns.TypeMX:
		if mx, ok := rr.(*dns.MX); ok {
			record["type"] = "MX"
			record["data"] = map[string]interface{}{
				"priority": int(mx.Preference),
				"host":     mx.Mx,
			}
		}
	case dns.TypeTXT:
		if txt, ok := rr.(*dns.TXT); ok {
			record["type"] = "TXT"
			record["data"] = map[string]interface{}{
				"text": strings.Join(txt.Txt, ""),
			}
		}
	case dns.TypePTR:
		if ptr, ok := rr.(*dns.PTR); ok {
			record["type"] = "PTR"
			record["data"] = map[string]interface{}{
				"ptrdname": ptr.Ptr,
			}
		}
	default:
		return &updateError{msg: "unsupported record type"}
	}

	// Try to update via storage interface
	// This is a simplified approach - would need proper storage method
	return h.server.addDynamicRecord(record)
}

// deleteRecord deletes a specific DNS record
func (h *UpdateHandler) deleteRecord(name, zone string, rrtype uint16, rr dns.RR) error {
	// Delete via storage
	return h.server.deleteDynamicRecord(name, zone, rrtype, rr)
}

// deleteAllRecords deletes all records of a type at a name
func (h *UpdateHandler) deleteAllRecords(name, zone string, rrtype uint16) error {
	// For TYPE ANY, delete all records at the name
	// For specific type, delete only that type
	return h.server.deleteAllDynamicRecords(name, zone, rrtype)
}

// createReversePTR creates a PTR record for A/AAAA records
func (h *UpdateHandler) createReversePTR(rr dns.RR, zone, source string) {
	var ip net.IP
	var hostname string

	switch r := rr.(type) {
	case *dns.A:
		ip = r.A
		hostname = r.Hdr.Name
	case *dns.AAAA:
		ip = r.AAAA
		hostname = r.Hdr.Name
	default:
		return
	}

	if ip == nil {
		return
	}

	// Generate reverse DNS name
	var reverseName string
	if ip.To4() != nil {
		// IPv4 reverse
		parts := strings.Split(ip.String(), ".")
		reverseName = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa."
	} else {
		// IPv6 reverse
		full := ip.To16()
		var nibbles []string
		for i := len(full) - 1; i >= 0; i-- {
			nibbles = append(nibbles, string("0123456789abcdef"[full[i]&0x0f]))
			nibbles = append(nibbles, string("0123456789abcdef"[full[i]>>4]))
		}
		reverseName = strings.Join(nibbles, ".") + ".ip6.arpa."
	}

	// Create PTR record
	ptr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   reverseName,
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ptr: hostname,
	}

	// Determine the reverse zone (in-addr.arpa or ip6.arpa)
	var reverseZone string
	if ip.To4() != nil {
		parts := strings.Split(ip.String(), ".")
		reverseZone = parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa."
	} else {
		reverseZone = "ip6.arpa."
	}

	if err := h.addRecord(reverseName, reverseZone, dns.TypePTR, 3600, ptr, source); err != nil {
		log.Printf("[update] Failed to auto-create PTR %s: %v", reverseName, err)
	} else {
		log.Printf("[update] Auto-created PTR %s -> %s", reverseName, hostname)
	}
}

// updateError represents an update error
type updateError struct {
	name string
	msg  string
}

func (e *updateError) Error() string {
	if e.name != "" {
		return e.name + ": " + e.msg
	}
	return e.msg
}
