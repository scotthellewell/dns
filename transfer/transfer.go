package transfer

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/scott/dns/config"
)

// Handler handles zone transfers (AXFR/IXFR) and NOTIFY
type Handler struct {
	config        *config.ParsedConfig
	zoneData      ZoneDataProvider
	tsigSecret    map[string]string // Key name -> secret
	notifyHandler func(zone string) // Callback when NOTIFY is received
}

// ZoneDataProvider interface for getting zone records
type ZoneDataProvider interface {
	// GetZoneRecords returns all records for a zone (for AXFR)
	GetZoneRecords(zone string) []dns.RR
	// GetZoneSOA returns the SOA record for a zone
	GetZoneSOA(zone string) *dns.SOA
	// GetZoneSerial returns the current serial for a zone
	GetZoneSerial(zone string) uint32
	// IsPatternZone returns true if the zone uses dynamic pattern generation (e.g., reverse DNS)
	IsPatternZone(zone string) bool
	// GetPatternZoneInfo returns human-readable info about a pattern zone
	GetPatternZoneInfo(zone string) string
}

// New creates a new transfer handler
func New(cfg *config.ParsedConfig, provider ZoneDataProvider) *Handler {
	h := &Handler{
		config:     cfg,
		zoneData:   provider,
		tsigSecret: make(map[string]string),
	}

	// Build TSIG secret map
	for name, key := range cfg.Transfer.TSIGKeys {
		h.tsigSecret[name] = key.Secret
	}

	return h
}

// UpdateConfig updates the handler configuration
func (h *Handler) UpdateConfig(cfg *config.ParsedConfig) {
	h.config = cfg
	h.tsigSecret = make(map[string]string)
	for name, key := range cfg.Transfer.TSIGKeys {
		h.tsigSecret[name] = key.Secret
	}
}

// SetNotifyHandler sets a callback function to be called when NOTIFY is received
func (h *Handler) SetNotifyHandler(handler func(zone string)) {
	h.notifyHandler = handler
}

// HandleAXFR handles AXFR (full zone transfer) requests
func (h *Handler) HandleAXFR(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		h.sendError(w, r, dns.RcodeFormatError)
		return
	}

	zone := r.Question[0].Name
	log.Printf("AXFR request for zone %s from %s", zone, w.RemoteAddr())

	// Check ACL
	if !h.isTransferAllowed(zone, w.RemoteAddr(), r) {
		log.Printf("AXFR denied for zone %s from %s", zone, w.RemoteAddr())
		h.sendError(w, r, dns.RcodeRefused)
		return
	}

	// Get SOA record
	soa := h.zoneData.GetZoneSOA(zone)
	if soa == nil {
		log.Printf("AXFR: Zone %s not found", zone)
		h.sendError(w, r, dns.RcodeNameError)
		return
	}

	// Check if this is a pattern-based zone (dynamic reverse DNS)
	isPattern := h.zoneData.IsPatternZone(zone)
	if isPattern {
		info := h.zoneData.GetPatternZoneInfo(zone)
		log.Printf("AXFR WARNING: Zone %s is pattern-based (%s) - only explicit overrides will be transferred", zone, info)
	}

	// Get all zone records (for pattern zones, this returns only explicit overrides)
	records := h.zoneData.GetZoneRecords(zone)
	if len(records) == 0 && !isPattern {
		log.Printf("AXFR: No records for zone %s", zone)
		h.sendError(w, r, dns.RcodeServerFailure)
		return
	}
	
	if isPattern && len(records) == 0 {
		log.Printf("AXFR: Pattern zone %s has no explicit overrides - transfer will contain only SOA", zone)
	}

	// AXFR format: SOA, records..., SOA
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)

	go func() {
		// First message: SOA
		env := &dns.Envelope{
			RR: []dns.RR{soa},
		}
		ch <- env

		// Send records in batches
		batch := make([]dns.RR, 0, 100)
		for _, rr := range records {
			batch = append(batch, rr)
			if len(batch) >= 100 {
				ch <- &dns.Envelope{RR: batch}
				batch = make([]dns.RR, 0, 100)
			}
		}
		if len(batch) > 0 {
			ch <- &dns.Envelope{RR: batch}
		}

		// Final message: SOA again
		ch <- &dns.Envelope{RR: []dns.RR{soa}}
		close(ch)
	}()

	err := tr.Out(w, r, ch)
	if err != nil {
		log.Printf("AXFR transfer failed for zone %s: %v", zone, err)
	} else {
		log.Printf("AXFR completed for zone %s", zone)
	}
}

// HandleIXFR handles IXFR (incremental zone transfer) requests
func (h *Handler) HandleIXFR(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		h.sendError(w, r, dns.RcodeFormatError)
		return
	}

	zone := r.Question[0].Name
	log.Printf("IXFR request for zone %s from %s", zone, w.RemoteAddr())

	// Check ACL
	if !h.isTransferAllowed(zone, w.RemoteAddr(), r) {
		log.Printf("IXFR denied for zone %s from %s", zone, w.RemoteAddr())
		h.sendError(w, r, dns.RcodeRefused)
		return
	}

	// For simplicity, we fall back to AXFR
	// A full IXFR implementation would track zone changes and send deltas
	log.Printf("IXFR: Falling back to AXFR for zone %s", zone)
	h.HandleAXFR(w, r)
}

// HandleNotify handles incoming NOTIFY messages
func (h *Handler) HandleNotify(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		h.sendError(w, r, dns.RcodeFormatError)
		return
	}

	zone := r.Question[0].Name
	log.Printf("NOTIFY received for zone %s from %s", zone, w.RemoteAddr())

	// Check ACL
	if !h.isNotifyAllowed(zone, w.RemoteAddr(), r) {
		log.Printf("NOTIFY denied for zone %s from %s", zone, w.RemoteAddr())
		h.sendError(w, r, dns.RcodeRefused)
		return
	}

	// Send acknowledgment
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeSuccess

	// Handle TSIG if present
	if r.IsTsig() != nil {
		h.signResponse(m, r)
	}

	w.WriteMsg(m)
	log.Printf("NOTIFY acknowledged for zone %s", zone)

	// Trigger zone refresh for secondary zone
	if h.notifyHandler != nil {
		h.notifyHandler(zone)
	}
}

// SendNotify sends NOTIFY messages to configured targets for a zone
func (h *Handler) SendNotify(zone string) {
	zone = dns.Fqdn(zone)

	for _, target := range h.config.Transfer.NotifyTargets {
		if !strings.EqualFold(target.Zone, zone) {
			continue
		}

		for _, addr := range target.Targets {
			go h.sendNotifyTo(zone, addr, target.TSIGKey)
		}
	}
}

func (h *Handler) sendNotifyTo(zone, addr, tsigKeyName string) {
	m := new(dns.Msg)
	m.SetNotify(zone)

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	// Add TSIG if configured
	if tsigKeyName != "" {
		if key, ok := h.config.Transfer.TSIGKeys[tsigKeyName]; ok {
			algo := h.getTSIGAlgorithm(key.Algorithm)
			m.SetTsig(key.Name, algo, 300, time.Now().Unix())
			c.TsigSecret = map[string]string{key.Name: key.Secret}
		}
	}

	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		log.Printf("NOTIFY to %s for zone %s failed: %v", addr, zone, err)
		return
	}

	if resp.Rcode != dns.RcodeSuccess {
		log.Printf("NOTIFY to %s for zone %s returned %s", addr, zone, dns.RcodeToString[resp.Rcode])
		return
	}

	log.Printf("NOTIFY sent to %s for zone %s", addr, zone)
}

// isTransferAllowed checks if a transfer request is allowed
func (h *Handler) isTransferAllowed(zone string, remoteAddr net.Addr, r *dns.Msg) bool {
	if !h.config.Transfer.Enabled {
		return false
	}

	ip := h.extractIP(remoteAddr)
	if ip == nil {
		return false
	}

	// Check ACLs (most specific first)
	for _, acl := range h.config.Transfer.ACLs {
		if acl.Zone != "*" && !strings.EqualFold(acl.Zone, zone) {
			continue
		}

		// Check TSIG requirement
		if acl.TSIGKey != "" {
			if !h.verifyTSIG(r, acl.TSIGKey) {
				continue
			}
		}

		// Check IP allowlist
		for _, network := range acl.AllowTransfer {
			if network.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// isNotifyAllowed checks if a NOTIFY is allowed from a source
func (h *Handler) isNotifyAllowed(zone string, remoteAddr net.Addr, r *dns.Msg) bool {
	if !h.config.Transfer.Enabled {
		return false
	}

	ip := h.extractIP(remoteAddr)
	if ip == nil {
		return false
	}

	// Check ACLs
	for _, acl := range h.config.Transfer.ACLs {
		if acl.Zone != "*" && !strings.EqualFold(acl.Zone, zone) {
			continue
		}

		// Check TSIG requirement
		if acl.TSIGKey != "" {
			if !h.verifyTSIG(r, acl.TSIGKey) {
				continue
			}
		}

		// Check IP allowlist
		for _, network := range acl.AllowNotify {
			if network.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// verifyTSIG verifies TSIG signature on a message
func (h *Handler) verifyTSIG(r *dns.Msg, requiredKey string) bool {
	tsig := r.IsTsig()
	if tsig == nil {
		return false
	}

	// Check key name matches
	if !strings.EqualFold(tsig.Hdr.Name, requiredKey) {
		return false
	}

	// Get the secret for this key
	secret, ok := h.tsigSecret[dns.Fqdn(requiredKey)]
	if !ok {
		return false
	}

	// Pack the message to verify
	wire, err := r.Pack()
	if err != nil {
		return false
	}

	// Verify the signature
	err = dns.TsigVerify(wire, secret, "", false)
	return err == nil
}

// signResponse adds TSIG to response if request had TSIG
func (h *Handler) signResponse(m, r *dns.Msg) {
	tsig := r.IsTsig()
	if tsig == nil {
		return
	}

	keyName := tsig.Hdr.Name
	if secret, ok := h.tsigSecret[keyName]; ok {
		algo := tsig.Algorithm
		m.SetTsig(keyName, algo, 300, time.Now().Unix())
		// Note: actual signing happens in dns library when writing
		_ = secret // Used by the server's TSIG handling
	}
}

func (h *Handler) getTSIGAlgorithm(algo string) string {
	switch strings.ToLower(algo) {
	case "hmac-sha256":
		return dns.HmacSHA256
	case "hmac-sha512":
		return dns.HmacSHA512
	case "hmac-sha1":
		return dns.HmacSHA1
	case "hmac-md5":
		return dns.HmacMD5
	default:
		return dns.HmacSHA256
	}
}

func (h *Handler) extractIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	default:
		return nil
	}
}

func (h *Handler) sendError(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	w.WriteMsg(m)
}
