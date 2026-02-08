package secondary

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/scott/dns/config"
)

// ZoneCache represents cached zone data for persistence
type ZoneCache struct {
	Zone      string    `json:"zone"`
	Serial    uint32    `json:"serial"`
	Records   []string  `json:"records"` // Wire format base64 encoded
	LastSync  time.Time `json:"last_sync"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CacheStore interface for persisting secondary zone records
type CacheStore interface {
	SaveSecondaryZoneCache(cache *ZoneCache) error
	GetSecondaryZoneCache(zone string) (*ZoneCache, error)
	DeleteSecondaryZoneCache(zone string) error
}

// ZoneData holds the transferred records for a zone
type ZoneData struct {
	Zone      string
	Records   []dns.RR
	SOA       *dns.SOA
	Serial    uint32
	LastSync  time.Time
	NextSync  time.Time
	SyncError error
}

// Manager handles secondary zone management
type Manager struct {
	mu     sync.RWMutex
	zones  map[string]*ZoneData
	config []config.ParsedSecondaryZone
	store  CacheStore
	stop   chan struct{}
	wg     sync.WaitGroup
}

// New creates a new secondary zone manager
func New(cfg *config.ParsedConfig) *Manager {
	m := &Manager{
		zones:  make(map[string]*ZoneData),
		config: cfg.SecondaryZones,
		stop:   make(chan struct{}),
	}
	return m
}

// SetCacheStore sets the cache store for persisting zone records
func (m *Manager) SetCacheStore(store CacheStore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store = store
}

// Start begins the initial zone transfers and refresh loops
func (m *Manager) Start() {
	for _, szCfg := range m.config {
		// Initialize zone data
		m.mu.Lock()
		m.zones[szCfg.Zone] = &ZoneData{
			Zone: szCfg.Zone,
		}
		m.mu.Unlock()

		// Try to load from cache first
		if m.loadFromCache(szCfg.Zone) {
			log.Printf("Secondary: Loaded %s from cache, checking if refresh needed", szCfg.Zone)
			// Check if we need to refresh (SOA serial check)
			if m.needsRefresh(szCfg) {
				m.transferZone(szCfg)
			} else {
				log.Printf("Secondary: Zone %s is up to date (cached serial matches primary)", szCfg.Zone)
			}
		} else {
			// No cache, do full transfer
			m.transferZone(szCfg)
		}

		// Start refresh goroutine
		m.wg.Add(1)
		go m.refreshLoop(szCfg)
	}
}

// loadFromCache loads zone data from the persistent cache
func (m *Manager) loadFromCache(zone string) bool {
	m.mu.RLock()
	store := m.store
	m.mu.RUnlock()

	if store == nil {
		return false
	}

	cache, err := store.GetSecondaryZoneCache(zone)
	if err != nil {
		return false
	}

	// Decode the records from wire format
	var records []dns.RR
	var soa *dns.SOA

	for _, encoded := range cache.Records {
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			log.Printf("Secondary: Failed to decode cached record for %s: %v", zone, err)
			continue
		}

		rr, _, err := dns.UnpackRR(data, 0)
		if err != nil {
			log.Printf("Secondary: Failed to unpack cached record for %s: %v", zone, err)
			continue
		}

		// Extract SOA if present
		if s, ok := rr.(*dns.SOA); ok {
			if soa == nil {
				soa = s
			}
		}
		records = append(records, rr)
	}

	if len(records) == 0 {
		return false
	}

	// Update zone data
	m.mu.Lock()
	zd := m.zones[zone]
	zd.Records = records
	zd.SOA = soa
	zd.Serial = cache.Serial
	zd.LastSync = cache.LastSync
	// Set next sync based on refresh interval
	zd.NextSync = time.Now().Add(5 * time.Minute) // Will be updated after SOA check
	m.mu.Unlock()

	log.Printf("Secondary: Loaded %d cached records for %s (serial %d, synced %v ago)",
		len(records), zone, cache.Serial, time.Since(cache.LastSync).Round(time.Second))

	return true
}

// saveToCache persists the current zone data to cache
func (m *Manager) saveToCache(zone string) {
	m.mu.RLock()
	store := m.store
	zd := m.zones[zone]
	m.mu.RUnlock()

	if store == nil || zd == nil || len(zd.Records) == 0 {
		return
	}

	// Encode records to wire format
	var encoded []string
	for _, rr := range zd.Records {
		buf := make([]byte, dns.MaxMsgSize)
		off, err := dns.PackRR(rr, buf, 0, nil, false)
		if err != nil {
			log.Printf("Secondary: Failed to pack record for cache: %v", err)
			continue
		}
		encoded = append(encoded, base64.StdEncoding.EncodeToString(buf[:off]))
	}

	// Also encode SOA
	if zd.SOA != nil {
		buf := make([]byte, dns.MaxMsgSize)
		off, err := dns.PackRR(zd.SOA, buf, 0, nil, false)
		if err == nil {
			encoded = append(encoded, base64.StdEncoding.EncodeToString(buf[:off]))
		}
	}

	cache := &ZoneCache{
		Zone:      zone,
		Serial:    zd.Serial,
		Records:   encoded,
		LastSync:  zd.LastSync,
		UpdatedAt: time.Now(),
	}

	if err := store.SaveSecondaryZoneCache(cache); err != nil {
		log.Printf("Secondary: Failed to save cache for %s: %v", zone, err)
	} else {
		log.Printf("Secondary: Cached %d records for %s", len(encoded), zone)
	}
}

// needsRefresh checks if the zone needs to be refreshed by comparing serials
func (m *Manager) needsRefresh(szCfg config.ParsedSecondaryZone) bool {
	m.mu.RLock()
	zd := m.zones[szCfg.Zone]
	cachedSerial := zd.Serial
	m.mu.RUnlock()

	// Query SOA from primary to check serial
	for _, primary := range szCfg.Primaries {
		serial, err := m.querySOASerial(szCfg.Zone, primary, szCfg)
		if err != nil {
			log.Printf("Secondary: Failed to query SOA for %s from %s: %v", szCfg.Zone, primary, err)
			continue
		}

		if serial > cachedSerial {
			log.Printf("Secondary: Zone %s needs refresh (cached serial %d, primary serial %d)",
				szCfg.Zone, cachedSerial, serial)
			return true
		}

		// Serial is same or lower - no refresh needed
		return false
	}

	// Couldn't reach any primary - assume refresh needed to be safe
	return true
}

// querySOASerial queries the SOA serial from a server
func (m *Manager) querySOASerial(zone, server string, szCfg config.ParsedSecondaryZone) (uint32, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	msg.RecursionDesired = false

	// Add TSIG if configured
	if szCfg.TSIGKeyName != "" {
		algo := getTSIGAlgorithm(szCfg.TSIGAlgorithm)
		msg.SetTsig(szCfg.TSIGKeyName, algo, 300, time.Now().Unix())
	}

	client := new(dns.Client)
	client.Net = "tcp"
	if szCfg.TSIGKeyName != "" {
		client.TsigSecret = map[string]string{szCfg.TSIGKeyName: szCfg.TSIGSecret}
	}

	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		return 0, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return 0, fmt.Errorf("SOA query failed with rcode %d", resp.Rcode)
	}

	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, nil
		}
	}

	return 0, fmt.Errorf("no SOA record in response")
}

// Stop stops all refresh loops
func (m *Manager) Stop() {
	close(m.stop)
	m.wg.Wait()
}

// UpdateConfig updates the secondary zone configuration
func (m *Manager) UpdateConfig(cfg *config.ParsedConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// For now, just update the config - a full implementation would
	// detect added/removed zones and update accordingly
	m.config = cfg.SecondaryZones
}

// HasZone returns true if this zone is managed as a secondary
func (m *Manager) HasZone(zone string) bool {
	zone = dns.Fqdn(strings.ToLower(zone))
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.zones[zone]
	return ok
}

// GetRecords returns records matching the query from a secondary zone
func (m *Manager) GetRecords(name string, qtype uint16) []dns.RR {
	name = dns.Fqdn(strings.ToLower(name))

	// Find which zone this name belongs to
	zoneName := m.findZone(name)
	if zoneName == "" {
		return nil
	}

	m.mu.RLock()
	zd, ok := m.zones[zoneName]
	m.mu.RUnlock()

	if !ok || zd.Records == nil {
		return nil
	}

	var result []dns.RR
	for _, rr := range zd.Records {
		if strings.EqualFold(rr.Header().Name, name) {
			if qtype == dns.TypeANY || rr.Header().Rrtype == qtype {
				result = append(result, rr)
			}
		}
	}
	return result
}

// GetSOA returns the SOA record for a secondary zone
func (m *Manager) GetSOA(zone string) *dns.SOA {
	zone = dns.Fqdn(strings.ToLower(zone))
	m.mu.RLock()
	defer m.mu.RUnlock()
	if zd, ok := m.zones[zone]; ok {
		return zd.SOA
	}
	return nil
}

// GetAllRecords returns all records for a zone (for AXFR)
func (m *Manager) GetAllRecords(zone string) []dns.RR {
	zone = dns.Fqdn(strings.ToLower(zone))
	m.mu.RLock()
	defer m.mu.RUnlock()
	if zd, ok := m.zones[zone]; ok {
		return zd.Records
	}
	return nil
}

// GetSerial returns the current serial for a zone
func (m *Manager) GetSerial(zone string) uint32 {
	zone = dns.Fqdn(strings.ToLower(zone))
	m.mu.RLock()
	defer m.mu.RUnlock()
	if zd, ok := m.zones[zone]; ok {
		return zd.Serial
	}
	return 0
}

// GetZoneStatus returns status information about a secondary zone
func (m *Manager) GetZoneStatus(zone string) (lastSync time.Time, nextSync time.Time, err error) {
	zone = dns.Fqdn(strings.ToLower(zone))
	m.mu.RLock()
	defer m.mu.RUnlock()
	if zd, ok := m.zones[zone]; ok {
		return zd.LastSync, zd.NextSync, zd.SyncError
	}
	return time.Time{}, time.Time{}, nil
}

// findZone finds the zone a name belongs to
func (m *Manager) findZone(name string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for zoneName := range m.zones {
		if name == zoneName || strings.HasSuffix(name, "."+zoneName) {
			return zoneName
		}
	}
	return ""
}

// refreshLoop periodically checks for zone updates
func (m *Manager) refreshLoop(szCfg config.ParsedSecondaryZone) {
	defer m.wg.Done()

	for {
		// Get current zone data
		m.mu.RLock()
		zd := m.zones[szCfg.Zone]
		nextSync := zd.NextSync
		m.mu.RUnlock()

		// Wait until next sync or stop
		waitDuration := time.Until(nextSync)
		if waitDuration <= 0 {
			// Already past due - check immediately
			select {
			case <-m.stop:
				return
			default:
				m.checkAndRefresh(szCfg)
				continue
			}
		}

		select {
		case <-m.stop:
			return
		case <-time.After(waitDuration):
			// Check if zone has updated
			m.checkAndRefresh(szCfg)
		}
	}
}

// checkAndRefresh checks the serial and does AXFR if needed
func (m *Manager) checkAndRefresh(szCfg config.ParsedSecondaryZone) {
	m.mu.RLock()
	zd := m.zones[szCfg.Zone]
	currentSerial := zd.Serial
	m.mu.RUnlock()

	// Query SOA to check serial
	for _, primary := range szCfg.Primaries {
		newSerial, err := m.querySOASerial(szCfg.Zone, primary, szCfg)
		if err != nil {
			log.Printf("Secondary: Failed to query SOA for %s from %s: %v", szCfg.Zone, primary, err)
			continue
		}

		// Check if serial has increased (with wraparound handling)
		if serialGreater(newSerial, currentSerial) {
			log.Printf("Secondary: Zone %s serial changed %d -> %d, refreshing", szCfg.Zone, currentSerial, newSerial)
			m.transferZone(szCfg)
			return
		}

		// Update next sync time
		m.updateNextSync(szCfg)
		return
	}

	// All primaries failed - use retry interval
	m.mu.Lock()
	retryInterval := szCfg.RetryInterval
	if retryInterval == 0 && zd.SOA != nil {
		retryInterval = zd.SOA.Retry
	}
	if retryInterval == 0 {
		retryInterval = 900 // 15 minutes default
	}
	zd.NextSync = time.Now().Add(time.Duration(retryInterval) * time.Second)
	zd.SyncError = nil
	m.mu.Unlock()
}

// transferZone performs an AXFR from the primary
func (m *Manager) transferZone(szCfg config.ParsedSecondaryZone) {
	zone := szCfg.Zone
	log.Printf("Secondary: Starting zone transfer for %s", zone)

	for _, primary := range szCfg.Primaries {
		records, soa, err := m.doAXFR(zone, primary, szCfg)
		if err != nil {
			log.Printf("Secondary: AXFR failed for %s from %s: %v", zone, primary, err)
			continue
		}

		// Success - store the records
		m.mu.Lock()
		zd := m.zones[zone]
		zd.Records = records
		zd.SOA = soa
		if soa != nil {
			zd.Serial = soa.Serial
		}
		zd.LastSync = time.Now()
		zd.SyncError = nil

		// Calculate next sync time
		refreshInterval := szCfg.RefreshInterval
		if refreshInterval == 0 && soa != nil {
			refreshInterval = soa.Refresh
		}
		if refreshInterval == 0 {
			refreshInterval = 3600 // 1 hour default
		}
		zd.NextSync = time.Now().Add(time.Duration(refreshInterval) * time.Second)
		m.mu.Unlock()

		log.Printf("Secondary: Zone %s transferred successfully (%d records, serial %d, next refresh in %ds)",
			zone, len(records), soa.Serial, refreshInterval)

		// Save to persistent cache
		m.saveToCache(zone)

		// Fetch DNSSEC keys if configured (async to not block)
		if szCfg.DNSSECKeyURL != "" {
			go func(cfg config.ParsedSecondaryZone) {
				if err := m.FetchDNSSECKeys(cfg); err != nil {
					log.Printf("Secondary: Failed to fetch DNSSEC keys for %s: %v", cfg.Zone, err)
				}
			}(szCfg)
		}
		return
	}

	// All primaries failed
	m.mu.Lock()
	zd := m.zones[zone]
	retryInterval := szCfg.RetryInterval
	if retryInterval == 0 && zd.SOA != nil {
		retryInterval = zd.SOA.Retry
	}
	if retryInterval == 0 {
		retryInterval = 900
	}
	zd.NextSync = time.Now().Add(time.Duration(retryInterval) * time.Second)
	m.mu.Unlock()
}

// doAXFR performs the actual zone transfer
func (m *Manager) doAXFR(zone, server string, szCfg config.ParsedSecondaryZone) ([]dns.RR, *dns.SOA, error) {
	t := new(dns.Transfer)
	msg := new(dns.Msg)
	msg.SetAxfr(zone)

	// Add TSIG if configured
	if szCfg.TSIGKeyName != "" {
		algo := getTSIGAlgorithm(szCfg.TSIGAlgorithm)
		msg.SetTsig(szCfg.TSIGKeyName, algo, 300, time.Now().Unix())
		t.TsigSecret = map[string]string{szCfg.TSIGKeyName: szCfg.TSIGSecret}
	}

	// Perform the transfer
	ch, err := t.In(msg, server)
	if err != nil {
		return nil, nil, err
	}

	var records []dns.RR
	var soa *dns.SOA

	for env := range ch {
		if env.Error != nil {
			return nil, nil, env.Error
		}
		for _, rr := range env.RR {
			// Skip the trailing SOA (AXFR has SOA at start and end)
			if s, ok := rr.(*dns.SOA); ok {
				if soa == nil {
					soa = s
				}
			} else {
				records = append(records, rr)
			}
		}
	}

	return records, soa, nil
}

// updateNextSync updates the next sync time based on refresh interval
func (m *Manager) updateNextSync(szCfg config.ParsedSecondaryZone) {
	m.mu.Lock()
	defer m.mu.Unlock()

	zd := m.zones[szCfg.Zone]
	refreshInterval := szCfg.RefreshInterval
	if refreshInterval == 0 && zd.SOA != nil {
		refreshInterval = zd.SOA.Refresh
	}
	if refreshInterval == 0 {
		refreshInterval = 3600
	}
	zd.NextSync = time.Now().Add(time.Duration(refreshInterval) * time.Second)
}

// HandleNotify handles incoming NOTIFY for a secondary zone
func (m *Manager) HandleNotify(zone string) {
	zone = dns.Fqdn(strings.ToLower(zone))

	// Find the config for this zone
	var szCfg *config.ParsedSecondaryZone
	for i := range m.config {
		if strings.EqualFold(m.config[i].Zone, zone) {
			szCfg = &m.config[i]
			break
		}
	}

	if szCfg == nil {
		return
	}

	log.Printf("Secondary: Received NOTIFY for %s, triggering refresh", zone)
	go m.transferZone(*szCfg)
}

// serialGreater returns true if a > b with serial arithmetic (RFC 1982)
func serialGreater(a, b uint32) bool {
	if a == b {
		return false
	}
	return (a < b && b-a > 0x7FFFFFFF) || (a > b && a-b < 0x7FFFFFFF)
}

func getTSIGAlgorithm(algo string) string {
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

// DNSSECKeyData holds DNSSEC key information fetched from a primary
type DNSSECKeyData struct {
	Zone       string `json:"zone"`
	Algorithm  string `json:"algorithm"`
	Enabled    bool   `json:"enabled"`
	KSKPrivate string `json:"ksk_private"`
	KSKPublic  string `json:"ksk_public"`
	KSKKeyTag  uint16 `json:"ksk_key_tag"`
	ZSKPrivate string `json:"zsk_private"`
	ZSKPublic  string `json:"zsk_public"`
	ZSKKeyTag  uint16 `json:"zsk_key_tag"`
	DSRecord   string `json:"ds_record"`
}

// KeyFetchCallback is called when keys are fetched from a primary
type KeyFetchCallback func(zone string, keys *DNSSECKeyData) error

// keyFetchCallback stores the callback for key fetches
var keyFetchCallback KeyFetchCallback

// SetKeyFetchCallback sets the callback to be invoked when DNSSEC keys are fetched
func SetKeyFetchCallback(cb KeyFetchCallback) {
	keyFetchCallback = cb
}

// FetchDNSSECKeys fetches DNSSEC keys from a primary server
func (m *Manager) FetchDNSSECKeys(szCfg config.ParsedSecondaryZone) error {
	if szCfg.DNSSECKeyURL == "" {
		return nil // No key URL configured
	}

	log.Printf("Secondary: Fetching DNSSEC keys for %s from %s", szCfg.Zone, szCfg.DNSSECKeyURL)

	// Build URL with token
	url := szCfg.DNSSECKeyURL
	if szCfg.DNSSECKeyToken != "" {
		if strings.Contains(url, "?") {
			url += "&token=" + szCfg.DNSSECKeyToken
		} else {
			url += "?token=" + szCfg.DNSSECKeyToken
		}
	}

	// Create HTTP client with TLS skip verify for self-signed certs
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("key fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var keys DNSSECKeyData
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return fmt.Errorf("failed to decode keys: %w", err)
	}

	if keys.KSKPrivate == "" || keys.ZSKPrivate == "" {
		return fmt.Errorf("incomplete key data received")
	}

	log.Printf("Secondary: Successfully fetched DNSSEC keys for %s (KSK tag: %d, ZSK tag: %d)",
		szCfg.Zone, keys.KSKKeyTag, keys.ZSKKeyTag)

	// Invoke callback to store the keys
	if keyFetchCallback != nil {
		if err := keyFetchCallback(szCfg.Zone, &keys); err != nil {
			return fmt.Errorf("failed to store fetched keys: %w", err)
		}
	}

	return nil
}

// FetchKeysForAllZones fetches DNSSEC keys for all configured secondary zones
func (m *Manager) FetchKeysForAllZones() {
	m.mu.RLock()
	configs := make([]config.ParsedSecondaryZone, len(m.config))
	copy(configs, m.config)
	m.mu.RUnlock()

	for _, szCfg := range configs {
		if szCfg.DNSSECKeyURL != "" {
			if err := m.FetchDNSSECKeys(szCfg); err != nil {
				log.Printf("Secondary: Failed to fetch DNSSEC keys for %s: %v", szCfg.Zone, err)
			}
		}
	}
}
