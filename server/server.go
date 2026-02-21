package server

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/scott/dns/config"
	"github.com/scott/dns/dnssec"
	"github.com/scott/dns/querylog"
	"github.com/scott/dns/recurse"
	"github.com/scott/dns/resolver"
	"github.com/scott/dns/rrl"
	"github.com/scott/dns/secondary"
	"github.com/scott/dns/transfer"
)

// BlocklistChecker interface for blocklist functionality.
type BlocklistChecker interface {
	Check(domain string) bool
	GetResponse() string
	GetRedirectIP() string
	GetConfig() *BlocklistConfig
}

// BlocklistConfig holds blocklist configuration for the server.
type BlocklistConfig struct {
	Enabled    bool
	Response   string
	RedirectIP string
	LogBlocked bool
}

// StorageInterface defines methods for dynamic record storage
type StorageInterface interface {
	AddRecord(zone string, record interface{}) error
	DeleteRecord(zone, name string, recordType string) error
	ReloadConfig() error
}

// Server represents the DNS server
type Server struct {
	config    *config.ParsedConfig
	resolver  *resolver.Resolver
	recursion *recurse.Resolver
	dnssec    *dnssec.Manager
	transfer  *transfer.Handler
	secondary *secondary.Manager
	update    *UpdateHandler    // RFC 2136 dynamic updates
	rrl       *rrl.Limiter      // Response Rate Limiter
	querylog  *querylog.Logger  // Query Logger
	blocklist BlocklistChecker  // Blocklist checker
	storage   StorageInterface  // Storage for dynamic records
	mu        sync.RWMutex

	// DNSSEC key store for loading keys from database
	dnssecKeyStore DNSSECKeyStore

	// Redirect checker for safe search enforcement
	redirectChecker RedirectChecker

	// ACME challenge records (temporary TXT records for DNS-01 validation)
	acmeRecords   map[string]string
	acmeRecordsMu sync.RWMutex
}

// RedirectChecker interface for DNS redirect functionality
type RedirectChecker interface {
	// Match checks if a domain should be redirected and returns the target host
	Match(domain string) (targetHost string, found bool)
}

// New creates a new DNS server
func New(cfg *config.ParsedConfig) *Server {
	srv := &Server{
		config:      cfg,
		resolver:    resolver.New(cfg),
		recursion:   recurse.New(cfg.Recursion),
		dnssec:      dnssec.NewManager(),
		acmeRecords: make(map[string]string),
	}

	// Initialize rate limiter
	srv.rrl = rrl.New(&rrl.Config{
		Enabled:         cfg.RateLimit.Enabled,
		ResponsesPerSec: cfg.RateLimit.ResponsesPerSec,
		SlipRatio:       cfg.RateLimit.SlipRatio,
		WindowSeconds:   cfg.RateLimit.WindowSeconds,
		WhitelistCIDRs:  cfg.RateLimit.WhitelistCIDRs,
	})

	// Initialize query logger
	srv.querylog = querylog.New(&querylog.Config{
		Enabled:     cfg.QueryLog.Enabled,
		LogSuccess:  cfg.QueryLog.LogSuccess,
		LogNXDomain: cfg.QueryLog.LogNXDomain,
		LogErrors:   cfg.QueryLog.LogErrors,
	})

	srv.loadDNSSEC(cfg)
	// Initialize transfer handler (srv implements ZoneDataProvider)
	srv.transfer = transfer.New(cfg, srv)
	// Initialize update handler (RFC 2136)
	srv.update = NewUpdateHandler(srv)
	// Initialize secondary zone manager
	if len(cfg.SecondaryZones) > 0 {
		srv.secondary = secondary.New(cfg)
		// Connect transfer handler's NOTIFY to secondary manager
		srv.transfer.SetNotifyHandler(srv.secondary.HandleNotify)
		srv.secondary.Start()
	}
	return srv
}

// DNSSECKeyData interface for DNSSEC key data from storage
type DNSSECKeyData interface {
	GetZoneName() string
	GetAlgorithm() string
	GetKSKPrivate() string
	GetZSKPrivate() string
	IsEnabled() bool
}

// DNSSECKeyStore interface for loading DNSSEC keys from storage
type DNSSECKeyStore interface {
	GetDNSSECKeys(zoneName string) (DNSSECKeyData, error)
	ListZonesWithDNSSEC() ([]string, error)
}

// SetDNSSECKeyStore sets the key store for loading DNSSEC keys from database
func (s *Server) SetDNSSECKeyStore(store DNSSECKeyStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnssecKeyStore = store
}

// loadDNSSEC loads DNSSEC keys from configuration (legacy file-based)
func (s *Server) loadDNSSEC(cfg *config.ParsedConfig) {
	for _, keyCfg := range cfg.DNSSEC {
		err := s.dnssec.LoadKey(dnssec.KeyConfig{
			Zone:       keyCfg.Zone,
			KeyDir:     keyCfg.KeyDir,
			Algorithm:  keyCfg.Algorithm,
			AutoCreate: keyCfg.AutoCreate,
		})
		if err != nil {
			log.Printf("Failed to load DNSSEC key for %s: %v", keyCfg.Zone, err)
		} else {
			log.Printf("Loaded DNSSEC keys for zone %s", keyCfg.Zone)
		}
	}
}

// LoadDNSSECFromStorage loads all DNSSEC keys from the database
func (s *Server) LoadDNSSECFromStorage() error {
	log.Printf("[DNSSEC] LoadDNSSECFromStorage called")
	s.mu.RLock()
	store := s.dnssecKeyStore
	s.mu.RUnlock()

	return s.loadDNSSECFromStorageWithStore(store)
}

// loadDNSSECFromStorageWithStore loads DNSSEC keys using the provided store
// Called from both LoadDNSSECFromStorage (public) and UpdateConfig (internal)
func (s *Server) loadDNSSECFromStorageWithStore(store DNSSECKeyStore) error {
	if store == nil {
		log.Printf("[DNSSEC] No key store configured, skipping storage loading")
		return nil // No storage configured, use file-based loading
	}

	zones, err := store.ListZonesWithDNSSEC()
	if err != nil {
		return fmt.Errorf("failed to list DNSSEC zones: %w", err)
	}

	log.Printf("[DNSSEC] Found %d zones with DNSSEC enabled", len(zones))
	for _, zoneName := range zones {
		log.Printf("[DNSSEC] Processing zone: %s", zoneName)
		keys, err := store.GetDNSSECKeys(zoneName)
		if err != nil {
			log.Printf("[DNSSEC] Failed to get DNSSEC keys for %s: %v", zoneName, err)
			continue
		}

		if !keys.IsEnabled() {
			log.Printf("[DNSSEC] Zone %s has DNSSEC disabled, skipping", zoneName)
			continue
		}

		log.Printf("[DNSSEC] Loading keys for zone %s (algorithm: %s)", zoneName, keys.GetAlgorithm())
		err = s.dnssec.LoadKeyFromData(dnssec.StoredKeyData{
			Zone:       keys.GetZoneName(),
			Algorithm:  keys.GetAlgorithm(),
			KSKPrivate: keys.GetKSKPrivate(),
			ZSKPrivate: keys.GetZSKPrivate(),
		})
		if err != nil {
			log.Printf("[DNSSEC] Failed to load DNSSEC keys for %s from storage: %v", zoneName, err)
		} else {
			log.Printf("[DNSSEC] Successfully loaded DNSSEC keys for zone %s from storage", zoneName)
		}
	}

	return nil
}

// UpdateConfig updates the server configuration atomically
func (s *Server) UpdateConfig(cfg *config.ParsedConfig) {
	s.mu.Lock()

	// Track old serials to detect changes
	oldSerials := make(map[string]uint32)
	for name, soa := range s.config.SOARecords {
		oldSerials[name] = soa.Serial
	}

	s.config = cfg
	s.resolver = resolver.New(cfg)
	s.recursion = recurse.New(cfg.Recursion)
	s.dnssec = dnssec.NewManager()
	s.loadDNSSEC(cfg)
	// Also load DNSSEC keys from storage (database) - important for cluster sync
	store := s.dnssecKeyStore
	if store != nil {
		if err := s.loadDNSSECFromStorageWithStore(store); err != nil {
			log.Printf("[DNSSEC] Warning: Failed to load DNSSEC keys from storage during config update: %v", err)
		}
	}
	if s.transfer != nil {
		s.transfer.UpdateConfig(cfg)
	}
	if s.secondary != nil {
		s.secondary.UpdateConfig(cfg)
	}

	// Update rate limiter config
	if s.rrl != nil {
		s.rrl.UpdateConfig(&rrl.Config{
			Enabled:         cfg.RateLimit.Enabled,
			ResponsesPerSec: cfg.RateLimit.ResponsesPerSec,
			SlipRatio:       cfg.RateLimit.SlipRatio,
			WindowSeconds:   cfg.RateLimit.WindowSeconds,
			WhitelistCIDRs:  cfg.RateLimit.WhitelistCIDRs,
		})
	}

	// Update query logger config
	if s.querylog != nil {
		s.querylog.UpdateConfig(&querylog.Config{
			Enabled:     cfg.QueryLog.Enabled,
			LogSuccess:  cfg.QueryLog.LogSuccess,
			LogNXDomain: cfg.QueryLog.LogNXDomain,
			LogErrors:   cfg.QueryLog.LogErrors,
		})
	}

	// Check for zones with changed serials and send NOTIFY
	var changedZones []string
	for name, soa := range cfg.SOARecords {
		oldSerial, exists := oldSerials[name]
		if !exists || soa.Serial != oldSerial {
			changedZones = append(changedZones, name)
		}
	}

	s.mu.Unlock()

	log.Printf("Configuration reloaded: %d zones, %d secondary zones (recursion: %v)",
		len(cfg.Zones), len(cfg.SecondaryZones), cfg.Recursion.Enabled)

	// Send NOTIFY for zones with changed serials
	if s.transfer != nil && len(changedZones) > 0 {
		for _, zone := range changedZones {
			log.Printf("Zone %s serial changed, sending NOTIFY", zone)
			s.transfer.SendNotify(zone)
		}
	}
}

// Start starts the DNS server on UDP and TCP
func (s *Server) Start() error {
	dns.HandleFunc(".", s.handleRequest)

	// Start UDP server
	go func() {
		udpServer := &dns.Server{Addr: s.config.Listen, Net: "udp"}
		log.Printf("Starting UDP DNS server on %s", s.config.Listen)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP server: %v", err)
		}
	}()

	// Start TCP server
	tcpServer := &dns.Server{Addr: s.config.Listen, Net: "tcp"}
	log.Printf("Starting TCP DNS server on %s", s.config.Listen)
	return tcpServer.ListenAndServe()
}

// getResolver returns the current resolver with read lock
func (s *Server) getResolver() *resolver.Resolver {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resolver
}

// getConfig returns the current config with read lock
func (s *Server) getConfig() *config.ParsedConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// getRecursion returns the current recursive resolver with read lock
func (s *Server) getRecursion() *recurse.Resolver {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.recursion
}

// getSecondary returns the secondary zone manager
func (s *Server) getSecondary() *secondary.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.secondary
}

// SetSecondaryCacheStore sets the cache store for the secondary zone manager
func (s *Server) SetSecondaryCacheStore(store secondary.CacheStore) {
	s.mu.RLock()
	sec := s.secondary
	s.mu.RUnlock()
	if sec != nil {
		sec.SetCacheStore(store)
	}
}

// WarmupRecursionCache pre-caches popular domains for faster recursive lookups
// This runs in a background goroutine and returns immediately
func (s *Server) WarmupRecursionCache() {
	s.mu.RLock()
	recursion := s.recursion
	s.mu.RUnlock()

	if recursion != nil {
		go recursion.Warmup()
	}
}

// SetBlocklist sets the blocklist checker for the server.
func (s *Server) SetBlocklist(bl BlocklistChecker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocklist = bl
}

// getBlocklist returns the current blocklist checker with read lock.
func (s *Server) getBlocklist() BlocklistChecker {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blocklist
}

// SetRedirectChecker sets the redirect checker for safe search enforcement.
func (s *Server) SetRedirectChecker(rc RedirectChecker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redirectChecker = rc
}

// getRedirectChecker returns the current redirect checker with read lock.
func (s *Server) getRedirectChecker() RedirectChecker {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.redirectChecker
}

// lookupSecondaryRecords looks up records from secondary zones
func (s *Server) lookupSecondaryRecords(name string, qtype uint16) []dns.RR {
	sec := s.getSecondary()
	if sec == nil {
		return nil
	}
	return sec.GetRecords(name, qtype)
}

// getDNSSEC returns the current DNSSEC manager with read lock
func (s *Server) getDNSSEC() *dnssec.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dnssec
}

// GetRRL returns the rate limiter for external access
func (s *Server) GetRRL() *rrl.Limiter {
	return s.rrl
}

// GetQueryLog returns the query logger for external access
func (s *Server) GetQueryLog() *querylog.Logger {
	return s.querylog
}

// ClearDNSSECCache clears DNSSEC validation cache for a zone
// Call this when zone records are added/changed/deleted
func (s *Server) ClearDNSSECCache(zone string) {
	s.mu.RLock()
	rec := s.recursion
	s.mu.RUnlock()
	if rec != nil {
		rec.ClearDNSSECCache(zone)
	}
}

// ClearAllDNSSECCaches clears all DNSSEC validation caches
func (s *Server) ClearAllDNSSECCaches() {
	s.mu.RLock()
	rec := s.recursion
	s.mu.RUnlock()
	if rec != nil {
		rec.ClearAllDNSSECCaches()
	}
}

// isAuthoritative checks if the server is authoritative for the given name.
func (s *Server) isAuthoritative(name string, cfg *config.ParsedConfig) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	// Check if name matches any of our zones
	for _, pz := range cfg.Zones {
		zone := strings.TrimSuffix(pz.Name, ".")
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}

	// Check secondary zones
	for _, sz := range cfg.SecondaryZones {
		zone := strings.TrimSuffix(sz.Zone, ".")
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}

	return false
}

// createSOAForZone creates a SOA record for the given zone to include in Authority section
func (s *Server) createSOAForZone(zoneName string, cfg *config.ParsedConfig) *dns.SOA {
	// Use resolver's LookupSOA which has the actual SOA data
	record, found := s.getResolver().LookupSOA(zoneName)
	if !found {
		// Try without trailing dot
		record, found = s.getResolver().LookupSOA(strings.TrimSuffix(zoneName, "."))
	}
	if found {
		return &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   zoneName,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    record.TTL,
			},
			Ns:      record.MName,
			Mbox:    record.RName,
			Serial:  record.Serial,
			Refresh: record.Refresh,
			Retry:   record.Retry,
			Expire:  record.Expire,
			Minttl:  record.Minimum,
		}
	}
	return nil
}

// handleRedirect handles DNS redirects by looking up the target host and returning its IPs
// This is used for safe search enforcement (e.g., google.com -> forcesafesearch.google.com)
func (s *Server) handleRedirect(w dns.ResponseWriter, r *dns.Msg, m *dns.Msg, originalDomain string, targetHost string, startTime time.Time, clientIP string) bool {
	if len(r.Question) == 0 {
		return false
	}

	q := r.Question[0]

	// Only handle A and AAAA queries
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return false
	}

	// Resolve the target host to get its IPs
	var ips []net.IP
	var err error

	switch q.Qtype {
	case dns.TypeA:
		ips, err = net.LookupIP(targetHost)
		if err != nil {
			log.Printf("[redirect] Failed to resolve %s: %v", targetHost, err)
			return false
		}
		// Filter to IPv4 only
		var ipv4s []net.IP
		for _, ip := range ips {
			if ip.To4() != nil {
				ipv4s = append(ipv4s, ip.To4())
			}
		}
		ips = ipv4s
	case dns.TypeAAAA:
		ips, err = net.LookupIP(targetHost)
		if err != nil {
			log.Printf("[redirect] Failed to resolve %s: %v", targetHost, err)
			return false
		}
		// Filter to IPv6 only
		var ipv6s []net.IP
		for _, ip := range ips {
			if ip.To4() == nil && ip.To16() != nil {
				ipv6s = append(ipv6s, ip)
			}
		}
		ips = ipv6s
	}

	if len(ips) == 0 {
		log.Printf("[redirect] No IPs found for %s (qtype=%s)", targetHost, dns.TypeToString[q.Qtype])
		return false
	}

	// Build response with redirected IPs
	log.Printf("[redirect] %s -> %s (resolved to %d IPs)", originalDomain, targetHost, len(ips))

	for _, ip := range ips {
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: ip.To4(),
			})
		} else {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: ip,
			})
		}
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("WriteMsg error (redirect): %v", err)
	}

	// Log the redirect
	if s.querylog != nil {
		s.querylog.Log(clientIP, r, m, time.Since(startTime))
	}

	return true
}

// sendBlockedResponse sends a blocked response based on blocklist configuration.
func (s *Server) sendBlockedResponse(w dns.ResponseWriter, r *dns.Msg, m *dns.Msg, bl BlocklistChecker) {
	response := bl.GetResponse()

	switch response {
	case "nxdomain":
		// Return NXDOMAIN
		m.Rcode = dns.RcodeNameError
		m.Answer = nil

	case "zero":
		// Return 0.0.0.0 for A queries, :: for AAAA
		if len(r.Question) > 0 {
			q := r.Question[0]
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						A: net.ParseIP("0.0.0.0").To4(),
					},
				}
			case dns.TypeAAAA:
				m.Answer = []dns.RR{
					&dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						AAAA: net.ParseIP("::"),
					},
				}
			default:
				m.Rcode = dns.RcodeNameError
			}
		}

	case "redirect":
		// Return configured redirect IP
		redirectIP := bl.GetRedirectIP()
		if redirectIP == "" {
			redirectIP = "0.0.0.0"
		}
		ip := net.ParseIP(redirectIP)
		if ip == nil {
			m.Rcode = dns.RcodeNameError
			break
		}

		if len(r.Question) > 0 {
			q := r.Question[0]
			if ip.To4() != nil && q.Qtype == dns.TypeA {
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						A: ip.To4(),
					},
				}
			} else if ip.To4() == nil && q.Qtype == dns.TypeAAAA {
				m.Answer = []dns.RR{
					&dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						AAAA: ip,
					},
				}
			} else {
				m.Rcode = dns.RcodeNameError
			}
		}

	default:
		// Default to NXDOMAIN
		m.Rcode = dns.RcodeNameError
		m.Answer = nil
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("WriteMsg error (blocked): %v", err)
	}
}

// ServeDNS implements the dns.Handler interface
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	s.handleRequest(w, r)
}

// handleRequest handles incoming DNS requests
func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	// Add panic recovery to catch any issues
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] handleRequest panic: %v", r)
		}
	}()

	// Debug: log opcode for all requests
	log.Printf("[DEBUG] handleRequest: opcode=%d (OpcodeUpdate=%d), questions=%d", r.Opcode, dns.OpcodeUpdate, len(r.Question))

	startTime := time.Now()

	// Extract client IP for RRL and logging
	clientAddr := w.RemoteAddr()
	var clientIP net.IP
	switch addr := clientAddr.(type) {
	case *net.UDPAddr:
		clientIP = addr.IP
	case *net.TCPAddr:
		clientIP = addr.IP
	}
	clientIPStr := ""
	if clientIP != nil {
		clientIPStr = clientIP.String()
	}

	// Response Rate Limiting (RRL) check
	if s.rrl != nil && clientIP != nil {
		action := s.rrl.Check(clientIP)
		switch action {
		case rrl.Refuse:
			// Silently drop - don't send response for DDoS mitigation
			return
		case rrl.Slip:
			// Send truncated response to force TCP retry
			m := new(dns.Msg)
			m.SetReply(r)
			m.Truncated = true
			w.WriteMsg(m)
			return
		}
	}

	// Handle NOTIFY messages (opcode 4)
	if r.Opcode == dns.OpcodeNotify {
		if s.transfer != nil {
			s.transfer.HandleNotify(w, r)
			return
		}
		// No transfer handler, refuse
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}

	// Handle UPDATE messages (opcode 5, RFC 2136)
	if r.Opcode == dns.OpcodeUpdate {
		if s.update != nil {
			s.update.HandleUpdate(w, r)
			return
		}
		// No update handler, refuse
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Set RecursionAvailable flag based on recursion config
	cfg := s.getConfig()
	if cfg.Recursion.Enabled {
		m.RecursionAvailable = true
	}

	// Check for DNSSEC OK (DO) bit in EDNS
	wantDNSSEC := false
	if opt := r.IsEdns0(); opt != nil {
		wantDNSSEC = opt.Do()
		// Copy EDNS to response
		edns := &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
		}
		edns.SetUDPSize(opt.UDPSize())
		edns.SetDo(opt.Do())
		m.Extra = append(m.Extra, edns)
	}

	// Blocklist check - only for recursive queries (non-authoritative domains)
	// and only if recursion is enabled
	if cfg.Recursion.Enabled && len(r.Question) > 0 {
		qname := strings.ToLower(r.Question[0].Name)

		// Check if this is NOT an authoritative query (i.e., we'd need to recurse)
		if !s.isAuthoritative(qname, cfg) {
			bl := s.getBlocklist()
			if bl != nil && bl.Check(qname) {
				s.sendBlockedResponse(w, r, m, bl)
				// Log the blocked query
				if s.querylog != nil {
					s.querylog.Log(clientIPStr, r, m, time.Since(startTime))
				}
				return
			}

			// Check for redirect rules (e.g., safe search enforcement)
			rc := s.getRedirectChecker()
			if rc != nil {
				if targetHost, found := rc.Match(qname); found {
					if s.handleRedirect(w, r, m, qname, targetHost, startTime, clientIPStr) {
						return
					}
				}
			}
		}
	}

	for _, q := range r.Question {
		log.Printf("Query: %s %s from %s (DNSSEC: %v)", dns.TypeToString[q.Qtype], q.Name, clientIPStr, wantDNSSEC)

		// Check for delegation before local processing
		if del, found := cfg.FindDelegation(q.Name); found {
			log.Printf("[DEBUG] Found delegation for %s -> %s (forward: %v)", q.Name, del.Zone, del.Forward)
			if s.handleDelegation(w, r, m, q, del, wantDNSSEC) {
				log.Printf("[DEBUG] Delegation handled, returning")
				return // Delegation handled the request
			}
			log.Printf("[DEBUG] Delegation not handled, continuing to local processing")
		}

		switch q.Qtype {
		case dns.TypePTR:
			s.handlePTR(m, q)
		case dns.TypeA:
			s.handleA(m, q)
		case dns.TypeAAAA:
			s.handleAAAA(m, q)
		case dns.TypeCNAME:
			s.handleCNAME(m, q)
		case dns.TypeMX:
			s.handleMX(m, q)
		case dns.TypeTXT:
			s.handleTXT(m, q)
		case dns.TypeNS:
			s.handleNS(m, q)
		case dns.TypeSRV:
			s.handleSRV(m, q)
		case dns.TypeSOA:
			s.handleSOA(m, q)
		case dns.TypeCAA:
			s.handleCAA(m, q)
		case dns.TypeDNSKEY:
			s.handleDNSKEY(m, q)
		case dns.TypeDS:
			s.handleDS(m, q)
		case dns.TypeSSHFP:
			s.handleSSHFP(m, q)
		case dns.TypeTLSA:
			s.handleTLSA(m, q)
		case dns.TypeNAPTR:
			s.handleNAPTR(m, q)
		case dns.TypeSVCB:
			s.handleSVCB(m, q)
		case dns.TypeHTTPS:
			s.handleHTTPS(m, q)
		case dns.TypeLOC:
			s.handleLOC(m, q)
		case dns.TypeAXFR:
			// AXFR zone transfer - handled specially
			if s.transfer != nil {
				s.transfer.HandleAXFR(w, r)
				return // AXFR sends its own responses
			}
			m.Rcode = dns.RcodeRefused
			w.WriteMsg(m)
			return
		case dns.TypeIXFR:
			// IXFR incremental zone transfer - handled specially
			if s.transfer != nil {
				s.transfer.HandleIXFR(w, r)
				return // IXFR sends its own responses
			}
			m.Rcode = dns.RcodeRefused
			w.WriteMsg(m)
			return
		}
	}

	// Only set NXDOMAIN if the name doesn't exist at all
	// If name exists but has no records of the requested type, use NOERROR
	if len(m.Answer) == 0 && len(r.Question) > 0 {
		qname := r.Question[0].Name
		qtype := r.Question[0].Qtype
		isAuth := s.isAuthoritative(qname, cfg)
		log.Printf("[NSEC DEBUG] Empty answer for %s type %d, isAuthoritative=%v, numZones=%d", qname, qtype, isAuth, len(cfg.Zones))
		// Check if this is an authoritative zone and if the name exists
		if isAuth {
			log.Printf("[NSEC DEBUG] isAuthoritative=true for %s", qname)
			// For authoritative zones, check if name exists
			resolver := s.getResolver()
			dnssecMgr := s.getDNSSEC()

			// Find the zone for this query by looking for SOA record
			var zoneName string
			// First try the exact name
			qnameLower := strings.ToLower(qname)
			if _, found := resolver.LookupSOA(qnameLower); found {
				zoneName = qnameLower
				if !strings.HasSuffix(zoneName, ".") {
					zoneName += "."
				}
			} else {
				// Walk up the domain hierarchy to find the zone apex
				parts := strings.Split(strings.TrimSuffix(qnameLower, "."), ".")
				for i := 1; i < len(parts); i++ {
					testZone := strings.Join(parts[i:], ".") + "."
					if _, found := resolver.LookupSOA(testZone); found {
						zoneName = testZone
						break
					}
				}
			}
			log.Printf("[NSEC DEBUG] zoneName=%q (from SOA lookup), wantDNSSEC=%v, HasDNSSEC=%v", zoneName, wantDNSSEC, dnssecMgr.HasDNSSEC())

			if resolver.NameExists(qname) {
				// Name exists, just no records of this type - NOERROR (NODATA)
				m.Rcode = dns.RcodeSuccess
				log.Printf("[NSEC DEBUG] NODATA for %s, wantDNSSEC=%v, hasDNSSEC=%v, zoneName=%q", qname, wantDNSSEC, dnssecMgr.HasDNSSEC(), zoneName)

				// For DNSSEC, add SOA and NSEC to Authority section
				if wantDNSSEC && dnssecMgr.HasDNSSEC() && zoneName != "" {
					// Add SOA to Authority section
					if soa := s.createSOAForZone(zoneName, cfg); soa != nil {
						m.Ns = append(m.Ns, soa)
						log.Printf("[NSEC DEBUG] Added SOA for %s", zoneName)
					} else {
						log.Printf("[NSEC DEBUG] Failed to create SOA for %s", zoneName)
					}

					// Get record types that exist at this name
					types := resolver.GetRecordTypes(qname)
					log.Printf("[NSEC DEBUG] Got %d record types for %s: %v", len(types), qname, types)
					if len(types) > 0 {
						signer := dnssecMgr.GetSigner(qname)
						if signer != nil {
							log.Printf("[NSEC DEBUG] Got signer for %s", qname)
							// Create NSEC record - for NODATA, next domain points to itself (simplified)
							nsec := signer.CreateNSEC(qname, qname, types, 3600)
							m.Ns = append(m.Ns, nsec)

							// Sign NSEC
							inception := uint32(time.Now().Add(-1 * time.Hour).Unix())
							expiration := uint32(time.Now().Add(7 * 24 * time.Hour).Unix())
							if rrsig, err := signer.SignNSEC(nsec, inception, expiration); err == nil {
								m.Ns = append(m.Ns, rrsig)
							} else {
								log.Printf("[NSEC DEBUG] SignNSEC error: %v", err)
							}

							// Sign SOA
							if len(m.Ns) > 0 {
								soaRRset := []dns.RR{m.Ns[0]}
								if soaRRsig, err := signer.SignRRSet(soaRRset, inception, expiration); err == nil {
									m.Ns = append(m.Ns, soaRRsig)
								} else {
									log.Printf("[NSEC DEBUG] SignRRSet error: %v", err)
								}
							}
						} else {
							log.Printf("[NSEC DEBUG] No signer found for %s", qname)
						}
					}
				}
			} else {
				// Name truly doesn't exist - NXDOMAIN
				m.Rcode = dns.RcodeNameError

				// For DNSSEC, add SOA and NSEC to prove non-existence
				if wantDNSSEC && dnssecMgr.HasDNSSEC() && zoneName != "" {
					// Add SOA to Authority section
					if soa := s.createSOAForZone(zoneName, cfg); soa != nil {
						m.Ns = append(m.Ns, soa)

						signer := dnssecMgr.GetSigner(qname)
						if signer != nil {
							inception := uint32(time.Now().Add(-1 * time.Hour).Unix())
							expiration := uint32(time.Now().Add(7 * 24 * time.Hour).Unix())

							// Sign SOA
							soaRRset := []dns.RR{soa}
							if soaRRsig, err := signer.SignRRSet(soaRRset, inception, expiration); err == nil {
								m.Ns = append(m.Ns, soaRRsig)
							}

							// For NXDOMAIN, create NSEC proving this name doesn't exist
							// Use zone apex with types that exist at apex: SOA, NS, etc.
							types := resolver.GetRecordTypes(strings.TrimSuffix(zoneName, "."))
							if len(types) == 0 {
								// At minimum, apex has SOA and NS
								types = []uint16{6, 2, 46, 47, 48} // SOA, NS, RRSIG, NSEC, DNSKEY
							}
							nsec := signer.CreateNSEC(zoneName, zoneName, types, 3600)
							m.Ns = append(m.Ns, nsec)

							if rrsig, err := signer.SignNSEC(nsec, inception, expiration); err == nil {
								m.Ns = append(m.Ns, rrsig)
							}
						}
					}
				}
			}

			// If requested type is A but we're returning NODATA, don't proceed further
			if qtype == dns.TypeA || qtype == dns.TypeAAAA {
				// Already handled above
			}
		} else {
			// Not authoritative - default to success (let caching handle it)
			m.Rcode = dns.RcodeSuccess
		}
	}

	// Sign response if DNSSEC is requested and we have keys
	if wantDNSSEC && len(m.Answer) > 0 {
		dnssecMgr := s.getDNSSEC()
		if dnssecMgr.HasDNSSEC() {
			// Find the signer for this query
			if len(r.Question) > 0 {
				if signer := dnssecMgr.GetSigner(r.Question[0].Name); signer != nil {
					if err := signer.Sign(m); err != nil {
						log.Printf("Failed to sign response: %v", err)
					}
				}
			}
		}
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("WriteMsg error: %v", err)
	}

	// Log query if enabled
	if s.querylog != nil {
		s.querylog.Log(clientIPStr, r, m, time.Since(startTime))
	}
}

// handlePTR handles PTR (reverse DNS) queries
func (s *Server) handlePTR(m *dns.Msg, q dns.Question) {
	name := strings.ToLower(q.Name)

	// Handle both ip6.arpa and in-addr.arpa queries
	if !strings.HasSuffix(name, ".ip6.arpa.") && !strings.HasSuffix(name, ".in-addr.arpa.") {
		return
	}

	hostname, ttl, found := s.getResolver().LookupPTR(name)
	if !found {
		return
	}

	// Ensure hostname ends with a dot
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	rr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: hostname,
	}
	m.Answer = append(m.Answer, rr)
}

// handleA handles A (IPv4 forward) queries
func (s *Server) handleA(m *dns.Msg, q dns.Question) {
	// First check secondary zones
	if rrs := s.lookupSecondaryRecords(q.Name, dns.TypeA); len(rrs) > 0 {
		m.Answer = append(m.Answer, rrs...)
		return
	}

	res := s.getResolver()
	rec := s.getRecursion()

	// Use recursive resolver which handles CNAME following and external lookups
	localLookup := func(name string) (net.IP, uint32, bool) {
		// Check secondary zones first
		if rrs := s.lookupSecondaryRecords(name, dns.TypeA); len(rrs) > 0 {
			if a, ok := rrs[0].(*dns.A); ok {
				return a.A, rrs[0].Header().Ttl, true
			}
		}
		return res.LookupA(name)
	}
	localCNAME := func(name string) (string, uint32, bool) {
		// Check secondary zones first
		if rrs := s.lookupSecondaryRecords(name, dns.TypeCNAME); len(rrs) > 0 {
			if cname, ok := rrs[0].(*dns.CNAME); ok {
				return cname.Target, rrs[0].Header().Ttl, true
			}
		}
		return res.LookupCNAME(name)
	}

	result := rec.ResolveA(q.Name, 0, localLookup, localCNAME)

	// Add CNAME records to the answer (if any were followed)
	for i, cname := range result.CNAMEs {
		target := ""
		if i+1 < len(result.CNAMEs) {
			target = result.CNAMEs[i+1]
		} else if len(result.IPs) > 0 {
			// Last CNAME points to the final name that has the A record
			// We need to get the actual CNAME target
			if t, ttl, found := res.LookupCNAME(cname); found {
				target = t
				rr := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   cname,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					Target: target,
				}
				m.Answer = append(m.Answer, rr)
			}
			continue
		}
		if target != "" {
			if _, ttl, found := res.LookupCNAME(cname); found {
				rr := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   cname,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					Target: target,
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}

	// Add A records
	for _, ip := range result.IPs {
		if ip.To4() != nil {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    result.TTL,
				},
				A: ip.To4(),
			}
			m.Answer = append(m.Answer, rr)
		}
	}

	// If no results from recursion, check for ALIAS record
	if !result.Found {
		target, aliasTTL, hasAlias := res.LookupALIAS(q.Name)
		if hasAlias {
			// Use external recursive resolution for the ALIAS target (bypasses partial mode)
			aliasResult := rec.ResolveAExternal(target, localLookup, localCNAME)
			for _, ip := range aliasResult.IPs {
				if ip.To4() != nil {
					useTTL := aliasTTL
					if aliasResult.TTL < useTTL {
						useTTL = aliasResult.TTL
					}
					rr := &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    useTTL,
						},
						A: ip.To4(),
					}
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

// handleAAAA handles AAAA (IPv6 forward) queries
func (s *Server) handleAAAA(m *dns.Msg, q dns.Question) {
	// First check secondary zones
	if rrs := s.lookupSecondaryRecords(q.Name, dns.TypeAAAA); len(rrs) > 0 {
		m.Answer = append(m.Answer, rrs...)
		return
	}

	res := s.getResolver()
	rec := s.getRecursion()

	// Use recursive resolver which handles CNAME following and external lookups
	localLookup := func(name string) (net.IP, uint32, bool) {
		// Check secondary zones first
		if rrs := s.lookupSecondaryRecords(name, dns.TypeAAAA); len(rrs) > 0 {
			if aaaa, ok := rrs[0].(*dns.AAAA); ok {
				return aaaa.AAAA, rrs[0].Header().Ttl, true
			}
		}
		return res.LookupAAAA(name)
	}
	localCNAME := func(name string) (string, uint32, bool) {
		// Check secondary zones first
		if rrs := s.lookupSecondaryRecords(name, dns.TypeCNAME); len(rrs) > 0 {
			if cname, ok := rrs[0].(*dns.CNAME); ok {
				return cname.Target, rrs[0].Header().Ttl, true
			}
		}
		return res.LookupCNAME(name)
	}

	result := rec.ResolveAAAA(q.Name, 0, localLookup, localCNAME)

	// Add CNAME records to the answer (if any were followed)
	for i, cname := range result.CNAMEs {
		target := ""
		if i+1 < len(result.CNAMEs) {
			target = result.CNAMEs[i+1]
		} else if len(result.IPs) > 0 {
			// Last CNAME points to the final name that has the AAAA record
			if t, ttl, found := res.LookupCNAME(cname); found {
				target = t
				rr := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   cname,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					Target: target,
				}
				m.Answer = append(m.Answer, rr)
			}
			continue
		}
		if target != "" {
			if _, ttl, found := res.LookupCNAME(cname); found {
				rr := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   cname,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					Target: target,
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}

	// Add AAAA records
	for _, ip := range result.IPs {
		if ip.To4() == nil {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    result.TTL,
				},
				AAAA: ip,
			}
			m.Answer = append(m.Answer, rr)
		}
	}

	// If no results from recursion, check for ALIAS record
	if !result.Found {
		target, aliasTTL, hasAlias := res.LookupALIAS(q.Name)
		if hasAlias {
			// Use external recursive resolution for the ALIAS target (bypasses partial mode)
			aliasResult := rec.ResolveAAAAExternal(target, localLookup, localCNAME)
			for _, ip := range aliasResult.IPs {
				if ip.To4() == nil {
					useTTL := aliasTTL
					if aliasResult.TTL < useTTL {
						useTTL = aliasResult.TTL
					}
					rr := &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    useTTL,
						},
						AAAA: ip,
					}
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

// handleCNAME handles CNAME queries
func (s *Server) handleCNAME(m *dns.Msg, q dns.Question) {
	// Check secondary zones first
	if rrs := s.lookupSecondaryRecords(q.Name, dns.TypeCNAME); len(rrs) > 0 {
		m.Answer = append(m.Answer, rrs...)
		return
	}

	target, ttl, found := s.getResolver().LookupCNAME(q.Name)
	if found {
		rr := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Target: target,
		}
		m.Answer = append(m.Answer, rr)
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeCNAME)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// handleMX handles MX queries
func (s *Server) handleMX(m *dns.Msg, q dns.Question) {
	// Check secondary zones first
	if rrs := s.lookupSecondaryRecords(q.Name, dns.TypeMX); len(rrs) > 0 {
		m.Answer = append(m.Answer, rrs...)
		return
	}

	records := s.getResolver().LookupMX(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			// Ensure target has trailing dot for FQDN
			target := rec.Target
			if !strings.HasSuffix(target, ".") {
				target += "."
			}
			rr := &dns.MX{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				Preference: rec.Priority,
				Mx:         target,
			}
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeMX)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// handleTXT handles TXT queries
func (s *Server) handleTXT(m *dns.Msg, q dns.Question) {
	// Check ACME challenge records first (for Let's Encrypt DNS-01 validation)
	s.acmeRecordsMu.RLock()
	acmeValue, hasACME := s.acmeRecords[strings.ToLower(q.Name)]
	s.acmeRecordsMu.RUnlock()

	if hasACME {
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    60, // Short TTL for challenge records
			},
			Txt: []string{acmeValue},
		}
		m.Answer = append(m.Answer, rr)
		return
	}

	// Check secondary zones first
	if rrs := s.lookupSecondaryRecords(q.Name, dns.TypeTXT); len(rrs) > 0 {
		m.Answer = append(m.Answer, rrs...)
		return
	}

	records := s.getResolver().LookupTXT(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				Txt: rec.Values,
			}
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeTXT)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// handleNS handles NS queries
func (s *Server) handleNS(m *dns.Msg, q dns.Question) {
	// Check secondary zones first
	if rrs := s.lookupSecondaryRecords(q.Name, dns.TypeNS); len(rrs) > 0 {
		m.Answer = append(m.Answer, rrs...)
		return
	}

	resolver := s.getResolver()
	records := resolver.LookupNS(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			rr := &dns.NS{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				Ns: rec.Target,
			}
			m.Answer = append(m.Answer, rr)

			// Add glue records (A/AAAA) for the nameserver if we have them
			s.addGlueRecords(m, rec.Target, rec.TTL)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeNS)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// addGlueRecords adds A and AAAA records for the given nameserver to the Extra section
func (s *Server) addGlueRecords(m *dns.Msg, nameserver string, ttl uint32) {
	resolver := s.getResolver()

	// Look up A records for the nameserver
	aRecords := resolver.LookupAAll(nameserver)
	for _, rec := range aRecords {
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   nameserver,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			A: rec.IP,
		}
		m.Extra = append(m.Extra, rr)
	}

	// Look up AAAA records for the nameserver
	aaaaRecords := resolver.LookupAAAAAll(nameserver)
	for _, rec := range aaaaRecords {
		rr := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   nameserver,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			AAAA: rec.IP,
		}
		m.Extra = append(m.Extra, rr)
	}
}

// handleSRV handles SRV queries
func (s *Server) handleSRV(m *dns.Msg, q dns.Question) {
	// Check secondary zones first
	if rrs := s.lookupSecondaryRecords(q.Name, dns.TypeSRV); len(rrs) > 0 {
		m.Answer = append(m.Answer, rrs...)
		return
	}

	records := s.getResolver().LookupSRV(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			rr := &dns.SRV{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				Priority: rec.Priority,
				Weight:   rec.Weight,
				Port:     rec.Port,
				Target:   rec.Target,
			}
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeSRV)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// handleSOA handles SOA queries
func (s *Server) handleSOA(m *dns.Msg, q dns.Question) {
	// Check secondary zones first
	if rrs := s.lookupSecondaryRecords(q.Name, dns.TypeSOA); len(rrs) > 0 {
		m.Answer = append(m.Answer, rrs...)
		return
	}
	// Check secondary zone SOA
	if sec := s.getSecondary(); sec != nil {
		if soa := sec.GetSOA(q.Name); soa != nil {
			m.Answer = append(m.Answer, soa)
			return
		}
	}

	record, found := s.getResolver().LookupSOA(q.Name)
	if found {
		rr := &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    record.TTL,
			},
			Ns:      record.MName,
			Mbox:    record.RName,
			Serial:  record.Serial,
			Refresh: record.Refresh,
			Retry:   record.Retry,
			Expire:  record.Expire,
			Minttl:  record.Minimum,
		}
		m.Answer = append(m.Answer, rr)
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeSOA)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// handleCAA handles CAA queries
func (s *Server) handleCAA(m *dns.Msg, q dns.Question) {
	// Check secondary zones first
	if rrs := s.lookupSecondaryRecords(q.Name, dns.TypeCAA); len(rrs) > 0 {
		m.Answer = append(m.Answer, rrs...)
		return
	}

	records := s.getResolver().LookupCAA(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			rr := &dns.CAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeCAA,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				Flag:  rec.Flag,
				Tag:   rec.Tag,
				Value: rec.Value,
			}
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeCAA)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// handleDNSKEY handles DNSKEY queries
func (s *Server) handleDNSKEY(m *dns.Msg, q dns.Question) {
	dnssecMgr := s.getDNSSEC()
	signer := dnssecMgr.GetSigner(q.Name)
	if signer == nil {
		return
	}

	// Only respond if the query is for the exact zone
	if !strings.EqualFold(dns.Fqdn(q.Name), signer.Zone()) {
		return
	}

	for _, key := range signer.GetDNSKEYs() {
		m.Answer = append(m.Answer, key)
	}
}

// handleDS handles DS queries
func (s *Server) handleDS(m *dns.Msg, q dns.Question) {
	dnssecMgr := s.getDNSSEC()
	signer := dnssecMgr.GetSigner(q.Name)
	if signer == nil {
		return
	}

	// Only respond if the query is for the exact zone
	if !strings.EqualFold(dns.Fqdn(q.Name), signer.Zone()) {
		return
	}

	ds := signer.GetDS()
	if ds != nil {
		ds.Hdr.Name = q.Name
		m.Answer = append(m.Answer, ds)
	}
}

// handleDelegation handles queries for delegated zones
// Returns true if the delegation was handled (response sent), false to continue normal processing
func (s *Server) handleDelegation(w dns.ResponseWriter, r *dns.Msg, m *dns.Msg, q dns.Question, del *config.ParsedDelegation, wantDNSSEC bool) bool {
	log.Printf("Delegation: %s -> %s (forward: %v)", q.Name, del.Zone, del.Forward)

	// If forward mode is enabled, query the delegated nameservers and return the answer
	if del.Forward {
		return s.handleDelegationForward(w, r, m, q, del, wantDNSSEC)
	}

	// Referral mode: return NS records and glue in authority/additional sections
	return s.handleDelegationReferral(w, r, m, q, del)
}

// handleDelegationForward queries the delegated nameservers and returns the answer
func (s *Server) handleDelegationForward(w dns.ResponseWriter, r *dns.Msg, m *dns.Msg, q dns.Question, del *config.ParsedDelegation, wantDNSSEC bool) bool {
	// Build list of nameserver addresses to query
	var servers []string
	for _, ns := range del.Nameservers {
		if ips, ok := del.Glue[ns]; ok {
			// Use glue records
			for _, ip := range ips {
				servers = append(servers, net.JoinHostPort(ip.String(), "53"))
			}
		} else {
			// Try to resolve the nameserver (if we have it locally or via recursion)
			// For now, just try common DNS port
			servers = append(servers, net.JoinHostPort(strings.TrimSuffix(ns, "."), "53"))
		}
	}

	if len(servers) == 0 {
		log.Printf("Delegation: No servers available for %s", del.Zone)
		return false
	}

	// Query the delegated servers
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	for _, server := range servers {
		resp, _, err := c.Exchange(r, server)
		if err != nil {
			log.Printf("Delegation forward to %s failed: %v", server, err)
			continue
		}

		// Got a response, forward it back
		resp.Id = r.Id
		w.WriteMsg(resp)
		return true
	}

	// All servers failed
	log.Printf("Delegation: All servers failed for %s", del.Zone)
	return false
}

// handleDelegationReferral returns NS referral records
func (s *Server) handleDelegationReferral(w dns.ResponseWriter, r *dns.Msg, m *dns.Msg, q dns.Question, del *config.ParsedDelegation) bool {
	m.Authoritative = false
	m.Rcode = dns.RcodeSuccess

	// Add NS records to authority section
	for _, ns := range del.Nameservers {
		rr := &dns.NS{
			Hdr: dns.RR_Header{
				Name:   del.Zone,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    del.TTL,
			},
			Ns: ns,
		}
		m.Ns = append(m.Ns, rr)
	}

	// Add glue records to additional section
	for hostname, ips := range del.Glue {
		for _, ip := range ips {
			if ip.To4() != nil {
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   hostname,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    del.TTL,
					},
					A: ip.To4(),
				}
				m.Extra = append(m.Extra, rr)
			} else {
				rr := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   hostname,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    del.TTL,
					},
					AAAA: ip,
				}
				m.Extra = append(m.Extra, rr)
			}
		}
	}

	w.WriteMsg(m)
	return true
}

// handleSSHFP handles SSHFP queries
func (s *Server) handleSSHFP(m *dns.Msg, q dns.Question) {
	records := s.getResolver().LookupSSHFP(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			rr := &dns.SSHFP{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeSSHFP,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				Algorithm:   rec.Algorithm,
				Type:        rec.Type,
				FingerPrint: rec.Fingerprint,
			}
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeSSHFP)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// handleTLSA handles TLSA queries (DANE)
func (s *Server) handleTLSA(m *dns.Msg, q dns.Question) {
	records := s.getResolver().LookupTLSA(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			rr := &dns.TLSA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTLSA,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				Usage:        rec.Usage,
				Selector:     rec.Selector,
				MatchingType: rec.MatchingType,
				Certificate:  rec.Certificate,
			}
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeTLSA)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// handleNAPTR handles NAPTR queries
func (s *Server) handleNAPTR(m *dns.Msg, q dns.Question) {
	records := s.getResolver().LookupNAPTR(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			rr := &dns.NAPTR{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeNAPTR,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				Order:       rec.Order,
				Preference:  rec.Preference,
				Flags:       rec.Flags,
				Service:     rec.Service,
				Regexp:      rec.Regexp,
				Replacement: rec.Replacement,
			}
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeNAPTR)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// handleSVCB handles SVCB queries
func (s *Server) handleSVCB(m *dns.Msg, q dns.Question) {
	records := s.getResolver().LookupSVCB(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			rr := &dns.SVCB{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeSVCB,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				Priority: rec.Priority,
				Target:   rec.Target,
			}
			// Parse SVCB params
			parseSVCBParams(rr, rec.Params)
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeSVCB)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// handleHTTPS handles HTTPS queries (HTTPS-specific SVCB)
func (s *Server) handleHTTPS(m *dns.Msg, q dns.Question) {
	records := s.getResolver().LookupHTTPS(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			rr := &dns.HTTPS{
				SVCB: dns.SVCB{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeHTTPS,
						Class:  dns.ClassINET,
						Ttl:    rec.TTL,
					},
					Priority: rec.Priority,
					Target:   rec.Target,
				},
			}
			// Parse SVCB params for HTTPS record
			parseSVCBParams(&rr.SVCB, rec.Params)
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeHTTPS)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// parseSVCBParams parses SVCB/HTTPS parameters
func parseSVCBParams(rr *dns.SVCB, params map[string]string) {
	if params == nil {
		return
	}
	for key, value := range params {
		var kv dns.SVCBKeyValue
		switch key {
		case "alpn":
			alpns := strings.Split(value, ",")
			kv = &dns.SVCBAlpn{Alpn: alpns}
		case "no-default-alpn":
			kv = &dns.SVCBNoDefaultAlpn{}
		case "port":
			if port, err := strconv.ParseUint(value, 10, 16); err == nil {
				kv = &dns.SVCBPort{Port: uint16(port)}
			}
		case "ipv4hint":
			var ips []net.IP
			for _, ipStr := range strings.Split(value, ",") {
				if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil {
					if ip4 := ip.To4(); ip4 != nil {
						ips = append(ips, ip4)
					}
				}
			}
			if len(ips) > 0 {
				kv = &dns.SVCBIPv4Hint{Hint: ips}
			}
		case "ipv6hint":
			var ips []net.IP
			for _, ipStr := range strings.Split(value, ",") {
				if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil {
					ips = append(ips, ip)
				}
			}
			if len(ips) > 0 {
				kv = &dns.SVCBIPv6Hint{Hint: ips}
			}
		case "ech":
			// ECH is base64 encoded
			kv = &dns.SVCBECHConfig{ECH: []byte(value)}
		}
		if kv != nil {
			rr.Value = append(rr.Value, kv)
		}
	}
}

// handleLOC handles LOC queries (geographic location)
func (s *Server) handleLOC(m *dns.Msg, q dns.Question) {
	records := s.getResolver().LookupLOC(q.Name)
	if len(records) > 0 {
		for _, rec := range records {
			// Convert lat/lon to LOC format (stored as hundredths of arc seconds + 2^31)
			// LOC uses unsigned 32-bit values where 2^31 is the equator/prime meridian
			const base uint32 = 1 << 31 // 2147483648
			lat := base + uint32(int64(rec.Latitude*3600000))
			lon := base + uint32(int64(rec.Longitude*3600000))
			alt := uint32((rec.Altitude + 100000) * 100) // Altitude in cm from -100000m

			rr := &dns.LOC{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeLOC,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				Version:   0,
				Size:      sizeToDNS(rec.Size),
				HorizPre:  sizeToDNS(rec.HorizPre),
				VertPre:   sizeToDNS(rec.VertPre),
				Latitude:  lat,
				Longitude: lon,
				Altitude:  alt,
			}
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// No local records - try recursive resolution if enabled in full mode
	rec := s.getRecursion()
	cfg := s.getConfig()
	if cfg.Recursion.Mode == "full" {
		resp, err := rec.QueryAny(q.Name, dns.TypeLOC)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
		}
	}
}

// sizeToDNS converts size in meters to DNS LOC format (4-bit mantissa, 4-bit exponent)
func sizeToDNS(meters float64) uint8 {
	if meters <= 0 {
		return 0x12 // Default 1m (1 * 10^2 cm)
	}
	// Convert to centimeters
	cm := meters * 100
	exp := 0
	for cm >= 10 && exp < 9 {
		cm /= 10
		exp++
	}
	mantissa := int(cm)
	if mantissa > 9 {
		mantissa = 9
	}
	return uint8((mantissa << 4) | exp)
}

// ============================================================================
// ZoneDataProvider implementation for zone transfers
// ============================================================================

// GetZoneRecords returns all records for a zone (implements transfer.ZoneDataProvider)
func (s *Server) GetZoneRecords(zone string) []dns.RR {
	zone = dns.Fqdn(strings.ToLower(zone))

	// Check if this is a secondary zone first
	if sec := s.getSecondary(); sec != nil {
		if rrs := sec.GetAllRecords(zone); len(rrs) > 0 {
			return rrs
		}
	}

	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	var records []dns.RR

	// Helper to check if a name belongs to this zone
	inZone := func(name string) bool {
		name = dns.Fqdn(strings.ToLower(name))
		return name == zone || strings.HasSuffix(name, "."+zone)
	}

	// Collect A records
	for name, recs := range cfg.ARecords {
		if !inZone(name) {
			continue
		}
		for _, rec := range recs {
			records = append(records, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rec.TTL},
				A:   rec.IP,
			})
		}
	}

	// Collect AAAA records
	for name, recs := range cfg.AAAARecords {
		if !inZone(name) {
			continue
		}
		for _, rec := range recs {
			records = append(records, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rec.TTL},
				AAAA: rec.IP,
			})
		}
	}

	// Collect CNAME records
	for name, rec := range cfg.CNAMERecords {
		if !inZone(name) {
			continue
		}
		records = append(records, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rec.TTL},
			Target: rec.Target,
		})
	}

	// Collect MX records
	for name, recs := range cfg.MXRecords {
		if !inZone(name) {
			continue
		}
		for _, rec := range recs {
			records = append(records, &dns.MX{
				Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: rec.TTL},
				Preference: rec.Priority,
				Mx:         rec.Target,
			})
		}
	}

	// Collect TXT records
	for name, recs := range cfg.TXTRecords {
		if !inZone(name) {
			continue
		}
		for _, rec := range recs {
			records = append(records, &dns.TXT{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: rec.TTL},
				Txt: rec.Values,
			})
		}
	}

	// Collect NS records
	for name, recs := range cfg.NSRecords {
		if !inZone(name) {
			continue
		}
		for _, rec := range recs {
			records = append(records, &dns.NS{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rec.TTL},
				Ns:  rec.Target,
			})
		}
	}

	// Collect SRV records
	for name, recs := range cfg.SRVRecords {
		if !inZone(name) {
			continue
		}
		for _, rec := range recs {
			records = append(records, &dns.SRV{
				Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: rec.TTL},
				Priority: rec.Priority,
				Weight:   rec.Weight,
				Port:     rec.Port,
				Target:   rec.Target,
			})
		}
	}

	// Collect CAA records
	for name, recs := range cfg.CAARecords {
		if !inZone(name) {
			continue
		}
		for _, rec := range recs {
			records = append(records, &dns.CAA{
				Hdr:   dns.RR_Header{Name: name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: rec.TTL},
				Flag:  rec.Flag,
				Tag:   rec.Tag,
				Value: rec.Value,
			})
		}
	}

	// Collect explicit PTR records (overrides for pattern zones)
	for ipStr, rec := range cfg.PTRRecords {
		// Convert IP to reverse DNS name
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		var ptrName string
		if ip.To4() != nil {
			// IPv4 reverse
			ip4 := ip.To4()
			ptrName = fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip4[3], ip4[2], ip4[1], ip4[0])
		} else {
			// IPv6 reverse
			ip6 := ip.To16()
			var parts []string
			for i := 15; i >= 0; i-- {
				parts = append(parts, fmt.Sprintf("%x", ip6[i]&0x0f))
				parts = append(parts, fmt.Sprintf("%x", ip6[i]>>4))
			}
			ptrName = strings.Join(parts, ".") + ".ip6.arpa."
		}

		if !inZone(ptrName) {
			continue
		}

		records = append(records, &dns.PTR{
			Hdr: dns.RR_Header{Name: ptrName, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: rec.TTL},
			Ptr: dns.Fqdn(rec.Hostname),
		})
	}

	return records
}

// GetZoneSOA returns the SOA record for a zone (implements transfer.ZoneDataProvider)
func (s *Server) GetZoneSOA(zone string) *dns.SOA {
	zone = dns.Fqdn(strings.ToLower(zone))

	// Check secondary zones first
	if sec := s.getSecondary(); sec != nil {
		if soa := sec.GetSOA(zone); soa != nil {
			return soa
		}
	}

	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if rec, ok := cfg.SOARecords[zone]; ok {
		return &dns.SOA{
			Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: rec.TTL},
			Ns:      rec.MName,
			Mbox:    rec.RName,
			Serial:  rec.Serial,
			Refresh: rec.Refresh,
			Retry:   rec.Retry,
			Expire:  rec.Expire,
			Minttl:  rec.Minimum,
		}
	}
	return nil
}

// GetZoneSerial returns the current serial for a zone (implements transfer.ZoneDataProvider)
func (s *Server) GetZoneSerial(zone string) uint32 {
	if soa := s.GetZoneSOA(zone); soa != nil {
		return soa.Serial
	}
	return 0
}

// IsPatternZone returns true if the zone is a pattern-based reverse DNS zone
func (s *Server) IsPatternZone(zone string) bool {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	zone = dns.Fqdn(strings.ToLower(zone))

	// Check if this zone corresponds to any of our configured reverse DNS zones
	for i := range cfg.Zones {
		// Compute the reverse zone for this pattern
		reverseZone := s.computeReverseZone(&cfg.Zones[i])
		if strings.EqualFold(reverseZone, zone) {
			return true
		}
	}
	return false
}

// GetPatternZoneInfo returns human-readable info about a pattern zone
func (s *Server) GetPatternZoneInfo(zone string) string {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	zone = dns.Fqdn(strings.ToLower(zone))

	for i := range cfg.Zones {
		z := &cfg.Zones[i]
		reverseZone := s.computeReverseZone(z)
		if strings.EqualFold(reverseZone, zone) {
			if z.IsIPv6 {
				ones, _ := z.Network.Mask.Size()
				return fmt.Sprintf("IPv6 /%d - 2^%d possible addresses", ones, 128-ones)
			} else {
				ones, _ := z.Network.Mask.Size()
				return fmt.Sprintf("IPv4 /%d - %d possible addresses", ones, 1<<(32-ones))
			}
		}
	}
	return "unknown pattern zone"
}

// computeReverseZone computes the reverse DNS zone name for a network
func (s *Server) computeReverseZone(z *config.ParsedZone) string {
	if z.IsIPv6 {
		// For IPv6, build ip6.arpa zone
		ip := z.Network.IP.To16()
		ones, _ := z.Network.Mask.Size()
		nibbles := ones / 4 // Number of nibbles in the zone

		var parts []string
		for i := 0; i < nibbles; i++ {
			byteIndex := i / 2
			nibbleInByte := i % 2
			var nibble byte
			if nibbleInByte == 0 {
				nibble = (ip[byteIndex] >> 4) & 0x0f // High nibble first
			} else {
				nibble = ip[byteIndex] & 0x0f // Low nibble second
			}
			parts = append(parts, fmt.Sprintf("%x", nibble))
		}
		// Reverse the parts for proper ip6.arpa format
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		return dns.Fqdn(strings.Join(parts, ".") + ".ip6.arpa")
	} else {
		// For IPv4, build in-addr.arpa zone
		ip := z.Network.IP.To4()
		ones, _ := z.Network.Mask.Size()
		octets := ones / 8

		var parts []string
		for i := octets - 1; i >= 0; i-- {
			parts = append(parts, fmt.Sprintf("%d", ip[i]))
		}
		return dns.Fqdn(strings.Join(parts, ".") + ".in-addr.arpa")
	}
}

// SendNotify sends NOTIFY messages for a zone change
func (s *Server) SendNotify(zone string) {
	s.mu.RLock()
	t := s.transfer
	s.mu.RUnlock()

	if t != nil {
		t.SendNotify(zone)
	}
}

// SetTXTRecord sets a temporary TXT record for ACME DNS-01 challenge
// This implements the certs.DNSProvider interface
func (s *Server) SetTXTRecord(fqdn, value string) error {
	s.acmeRecordsMu.Lock()
	defer s.acmeRecordsMu.Unlock()

	// Normalize the FQDN to lowercase
	fqdn = strings.ToLower(fqdn)
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	s.acmeRecords[fqdn] = value
	log.Printf("Added ACME challenge TXT record: %s = %s", fqdn, value)
	return nil
}

// RemoveTXTRecord removes a temporary TXT record after ACME challenge
// This implements the certs.DNSProvider interface
func (s *Server) RemoveTXTRecord(fqdn string) error {
	s.acmeRecordsMu.Lock()
	defer s.acmeRecordsMu.Unlock()

	// Normalize the FQDN to lowercase
	fqdn = strings.ToLower(fqdn)
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	delete(s.acmeRecords, fqdn)
	log.Printf("Removed ACME challenge TXT record: %s", fqdn)
	return nil
}

// SetStorage sets the storage interface for dynamic records
func (s *Server) SetStorage(storage StorageInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storage = storage
}

// getStorage returns the storage interface (thread-safe)
func (s *Server) getStorage() StorageInterface {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.storage
}

// SetUpdateConfig sets the dynamic update configuration
func (s *Server) SetUpdateConfig(cfg UpdateConfig) {
	if s.update != nil {
		s.update.SetConfig(cfg)
	}
}

// GetUpdateHandler returns the update handler
func (s *Server) GetUpdateHandler() *UpdateHandler {
	return s.update
}

// addDynamicRecord adds a record via storage (for RFC 2136 updates)
func (s *Server) addDynamicRecord(record map[string]interface{}) error {
	storage := s.getStorage()
	if storage == nil {
		return fmt.Errorf("storage not configured")
	}

	zone, ok := record["zone"].(string)
	if !ok {
		return fmt.Errorf("zone not specified in record")
	}

	if err := storage.AddRecord(zone, record); err != nil {
		return err
	}

	// Reload config to pick up new record
	return storage.ReloadConfig()
}

// deleteDynamicRecord deletes a specific record via storage
func (s *Server) deleteDynamicRecord(name, zone string, rrtype uint16, rr dns.RR) error {
	storage := s.getStorage()
	if storage == nil {
		return fmt.Errorf("storage not configured")
	}

	recordType := dns.TypeToString[rrtype]
	if err := storage.DeleteRecord(zone, name, recordType); err != nil {
		return err
	}

	return storage.ReloadConfig()
}

// deleteAllDynamicRecords deletes all records of a type at a name
func (s *Server) deleteAllDynamicRecords(name, zone string, rrtype uint16) error {
	storage := s.getStorage()
	if storage == nil {
		return fmt.Errorf("storage not configured")
	}

	var recordType string
	if rrtype == dns.TypeANY {
		recordType = "" // Empty means all types
	} else {
		recordType = dns.TypeToString[rrtype]
	}

	if err := storage.DeleteRecord(zone, name, recordType); err != nil {
		return err
	}

	return storage.ReloadConfig()
}
