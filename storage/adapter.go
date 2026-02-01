// Package storage provides the adapter layer to bridge storage data to the existing
// config.ParsedConfig format used by the DNS server.
package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/scott/dns/config"
	bolt "go.etcd.io/bbolt"
)

// BuildParsedConfig builds a config.ParsedConfig from storage data.
// This allows the existing server code to work with the new storage layer.
func (s *Store) BuildParsedConfig() (*config.ParsedConfig, error) {
	parsed := &config.ParsedConfig{
		Zones:        []config.ParsedZone{},
		DNSSEC:       []config.DNSSECKeyConfig{},
		ARecords:     make(map[string][]config.ParsedARecord),
		AAAARecords:  make(map[string][]config.ParsedAAAARecord),
		CNAMERecords: make(map[string]config.ParsedCNAMERecord),
		MXRecords:    make(map[string][]config.ParsedMXRecord),
		TXTRecords:   make(map[string][]config.ParsedTXTRecord),
		NSRecords:    make(map[string][]config.ParsedNSRecord),
		PTRRecords:   make(map[string]config.ParsedPTRRecord),
		SRVRecords:   make(map[string][]config.ParsedSRVRecord),
		SOARecords:   make(map[string]config.ParsedSOARecord),
		CAARecords:   make(map[string][]config.ParsedCAARecord),
		SSHFPRecords: make(map[string][]config.ParsedSSHFPRecord),
		TLSARecords:  make(map[string][]config.ParsedTLSARecord),
		NAPTRRecords: make(map[string][]config.ParsedNAPTRRecord),
	}

	// Load zones
	zones, err := s.ListZones("")
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}

	for _, zone := range zones {
		// Build ParsedZone
		pz := config.ParsedZone{
			Name: zone.Name,
			Type: config.ZoneType(zone.Type),
			TTL:  zone.TTL,
		}

		// Parse subnet for reverse zones
		if zone.Subnet != "" {
			_, network, err := net.ParseCIDR(zone.Subnet)
			if err == nil {
				pz.Network = network
				ones, _ := network.Mask.Size()
				pz.PrefixLen = ones
				pz.IsIPv6 = network.IP.To4() == nil
			}
		}
		if zone.Domain != "" {
			pz.Domain = zone.Domain
		}

		parsed.Zones = append(parsed.Zones, pz)

		// Build SOA record
		soa := config.ParsedSOARecord{
			Name:    zone.Name,
			MName:   zone.PrimaryNS,
			RName:   zone.AdminEmail,
			Serial:  zone.Serial,
			Refresh: zone.Refresh,
			Retry:   zone.Retry,
			Expire:  zone.Expire,
			Minimum: zone.Minimum,
			TTL:     zone.TTL,
		}
		if soa.MName == "" {
			soa.MName = "ns1." + zone.Name
		}
		if soa.RName == "" {
			soa.RName = "hostmaster." + zone.Name
		}
		if soa.Refresh == 0 {
			soa.Refresh = 3600
		}
		if soa.Retry == 0 {
			soa.Retry = 600
		}
		if soa.Expire == 0 {
			soa.Expire = 86400
		}
		if soa.Minimum == 0 {
			soa.Minimum = 300
		}
		parsed.SOARecords[zone.Name] = soa

		// Load records for zone
		records, err := s.GetAllZoneRecords(zone.Name)
		if err != nil {
			return nil, fmt.Errorf("get records for zone %s: %w", zone.Name, err)
		}

		for _, rec := range records {
			if !rec.Enabled {
				continue
			}

			// Build FQDN
			var fqdn string
			if rec.Name == "@" {
				fqdn = zone.Name
			} else {
				fqdn = rec.Name + "." + zone.Name
			}

			ttl := rec.TTL
			if ttl == 0 {
				ttl = zone.TTL
			}

			if err := s.addRecordToParsed(parsed, &rec, fqdn, ttl); err != nil {
				// Log but continue
				continue
			}
		}
	}

	// Load recursion config
	recursionCfg, err := s.GetRecursionConfig()
	if err == nil {
		// Derive enabled from mode (disabled mode means not enabled)
		enabled := recursionCfg.Mode != "" && recursionCfg.Mode != "disabled"
		parsed.Recursion = config.ParsedRecursion{
			Enabled:  enabled,
			Mode:     recursionCfg.Mode,
			Upstream: recursionCfg.Upstream,
			Timeout:  recursionCfg.Timeout,
			MaxDepth: recursionCfg.MaxDepth,
		}
	}

	// Load secondary zones
	secondaryZones, err := s.ListSecondaryZones()
	if err == nil {
		for _, sz := range secondaryZones {
			parsed.SecondaryZones = append(parsed.SecondaryZones, config.ParsedSecondaryZone{
				Zone:      sz.Zone,
				Primaries: sz.Primaries,
			})
		}
	}

	// Load DNSSEC keys
	dnssecZones, err := s.ListZonesWithDNSSEC()
	if err == nil {
		for _, zoneName := range dnssecZones {
			keys, err := s.GetDNSSECKeys(zoneName)
			if err == nil && keys.Enabled {
				parsed.DNSSEC = append(parsed.DNSSEC, config.DNSSECKeyConfig{
					Zone:      zoneName,
					Algorithm: keys.Algorithm,
				})
			}
		}
	}

	// Load transfer config
	transferCfg, err := s.GetTransferConfig()
	if err == nil {
		parsed.Transfer = config.ParsedTransfer{
			Enabled: transferCfg.Enabled,
		}
	}

	// Load rate limit config
	rateLimitCfg, err := s.GetRateLimitConfig()
	if err == nil {
		parsed.RateLimit = config.RateLimitConfig{
			Enabled:         rateLimitCfg.Enabled,
			ResponsesPerSec: rateLimitCfg.ResponsesPerSec,
			SlipRatio:       rateLimitCfg.SlipRatio,
			WindowSeconds:   rateLimitCfg.WindowSeconds,
			WhitelistCIDRs:  rateLimitCfg.WhitelistCIDRs,
		}
	}

	// Load query log config
	queryLogCfg, err := s.GetQueryLogConfig()
	if err == nil {
		parsed.QueryLog = config.QueryLogConfig{
			Enabled:     queryLogCfg.Enabled,
			LogSuccess:  queryLogCfg.LogSuccess,
			LogNXDomain: queryLogCfg.LogNXDomain,
			LogErrors:   queryLogCfg.LogErrors,
		}
	}

	return parsed, nil
}

// addRecordToParsed adds a record to the parsed config.
func (s *Store) addRecordToParsed(parsed *config.ParsedConfig, rec *Record, fqdn string, ttl uint32) error {
	switch rec.Type {
	case "A":
		var data ARecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.ARecords[fqdn] = append(parsed.ARecords[fqdn], config.ParsedARecord{
			Name: fqdn,
			IP:   net.ParseIP(data.IP),
			TTL:  ttl,
		})

	case "AAAA":
		var data AAAARecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.AAAARecords[fqdn] = append(parsed.AAAARecords[fqdn], config.ParsedAAAARecord{
			Name: fqdn,
			IP:   net.ParseIP(data.IP),
			TTL:  ttl,
		})

	case "CNAME":
		var data CNAMERecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.CNAMERecords[fqdn] = config.ParsedCNAMERecord{
			Name:   fqdn,
			Target: data.Target,
			TTL:    ttl,
		}

	case "MX":
		var data MXRecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.MXRecords[fqdn] = append(parsed.MXRecords[fqdn], config.ParsedMXRecord{
			Name:     fqdn,
			Priority: data.Priority,
			Target:   data.Target,
			TTL:      ttl,
		})

	case "TXT":
		var data TXTRecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.TXTRecords[fqdn] = append(parsed.TXTRecords[fqdn], config.ParsedTXTRecord{
			Name:   fqdn,
			Values: data.Values,
			TTL:    ttl,
		})

	case "NS":
		var data NSRecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.NSRecords[fqdn] = append(parsed.NSRecords[fqdn], config.ParsedNSRecord{
			Name:   fqdn,
			Target: data.Target,
			TTL:    ttl,
		})

	case "PTR":
		var data PTRRecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		// For PTR records, the fqdn contains the reverse IP notation
		// We need to extract the IP from the reverse name if possible
		parsed.PTRRecords[fqdn] = config.ParsedPTRRecord{
			IP:       nil, // PTR records from storage don't have parsed IP
			Hostname: data.Target,
			TTL:      ttl,
		}

	case "SRV":
		var data SRVRecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.SRVRecords[fqdn] = append(parsed.SRVRecords[fqdn], config.ParsedSRVRecord{
			Name:     fqdn,
			Priority: data.Priority,
			Weight:   data.Weight,
			Port:     data.Port,
			Target:   data.Target,
			TTL:      ttl,
		})

	case "CAA":
		var data CAARecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.CAARecords[fqdn] = append(parsed.CAARecords[fqdn], config.ParsedCAARecord{
			Name:  fqdn,
			Flag:  data.Flag,
			Tag:   data.Tag,
			Value: data.Value,
			TTL:   ttl,
		})

	case "SSHFP":
		var data SSHFPRecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.SSHFPRecords[fqdn] = append(parsed.SSHFPRecords[fqdn], config.ParsedSSHFPRecord{
			Name:        fqdn,
			Algorithm:   data.Algorithm,
			Type:        data.Type,
			Fingerprint: data.Fingerprint,
			TTL:         ttl,
		})

	case "TLSA":
		var data TLSARecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.TLSARecords[fqdn] = append(parsed.TLSARecords[fqdn], config.ParsedTLSARecord{
			Name:         fqdn,
			Usage:        data.Usage,
			Selector:     data.Selector,
			MatchingType: data.MatchingType,
			Certificate:  data.Certificate,
			TTL:          ttl,
		})

	case "NAPTR":
		var data NAPTRRecordData
		if err := json.Unmarshal(rec.Data, &data); err != nil {
			return err
		}
		parsed.NAPTRRecords[fqdn] = append(parsed.NAPTRRecords[fqdn], config.ParsedNAPTRRecord{
			Name:        fqdn,
			Order:       data.Order,
			Preference:  data.Preference,
			Flags:       data.Flags,
			Service:     data.Service,
			Regexp:      data.Regexp,
			Replacement: data.Replacement,
			TTL:         ttl,
		})
	}

	return nil
}

// ListSecondaryZones lists all secondary zones.
func (s *Store) ListSecondaryZones() ([]SecondaryZone, error) {
	var zones []SecondaryZone

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketSecondaryZones)
		if bucket == nil {
			return nil
		}

		return bucket.ForEach(func(k, v []byte) error {
			var zone SecondaryZone
			if err := json.Unmarshal(v, &zone); err != nil {
				return err
			}
			zones = append(zones, zone)
			return nil
		})
	})

	return zones, err
}

// CreateSecondaryZone creates a secondary zone.
func (s *Store) CreateSecondaryZone(zone *SecondaryZone) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketSecondaryZones)
		data, err := json.Marshal(zone)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(zone.Zone), data)
	})

	if err == nil {
		recordChange(EntityTypeSecondaryZone, zone.Zone, "", OpCreate, zone)
	}

	return err
}

// DeleteSecondaryZone deletes a secondary zone.
func (s *Store) DeleteSecondaryZone(name string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketSecondaryZones)
		return bucket.Delete([]byte(name))
	})

	if err == nil {
		recordChange(EntityTypeSecondaryZone, name, "", OpDelete, nil)
	}

	return err
}

// GetSecondaryZone retrieves a secondary zone by name.
func (s *Store) GetSecondaryZone(name string) (*SecondaryZone, error) {
	var zone SecondaryZone

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketSecondaryZones)
		if bucket == nil {
			return ErrNotFound
		}
		data := bucket.Get([]byte(name))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &zone)
	})

	if err != nil {
		return nil, err
	}
	return &zone, nil
}

// UpdateSecondaryZone updates an existing secondary zone.
func (s *Store) UpdateSecondaryZone(zone *SecondaryZone) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketSecondaryZones)
		// Check if zone exists
		if bucket.Get([]byte(zone.Zone)) == nil {
			return ErrNotFound
		}
		data, err := json.Marshal(zone)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(zone.Zone), data)
	})

	if err == nil {
		recordChange(EntityTypeSecondaryZone, zone.Zone, "", OpUpdate, zone)
	}

	return err
}

// ============================================================================
// View CRUD (Split-horizon DNS)
// ============================================================================

// CreateView creates a new DNS view for split-horizon DNS.
func (s *Store) CreateView(v *View) error {
	if v.ID == "" {
		v.ID = GenerateID()
	}
	if v.Name == "" {
		return fmt.Errorf("view name required")
	}
	if v.TenantID == "" {
		v.TenantID = MainTenantID
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		// Check tenant exists
		if tx.Bucket(BucketTenants).Get([]byte(v.TenantID)) == nil {
			return fmt.Errorf("tenant not found")
		}

		// Check name uniqueness within tenant
		bucket := tx.Bucket(BucketViews)
		c := bucket.Cursor()
		for k, data := c.First(); k != nil; k, data = c.Next() {
			var existing View
			if err := json.Unmarshal(data, &existing); err == nil {
				if existing.TenantID == v.TenantID && existing.Name == v.Name {
					return ErrAlreadyExists
				}
			}
		}

		return putJSON(tx, BucketViews, v.ID, v)
	})
}

// GetView retrieves a view by ID.
func (s *Store) GetView(id string) (*View, error) {
	var v View
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx, BucketViews, id, &v)
	})
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// GetViewByName retrieves a view by name within a tenant.
func (s *Store) GetViewByName(tenantID, name string) (*View, error) {
	var found *View

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketViews)
		c := bucket.Cursor()
		for k, data := c.First(); k != nil; k, data = c.Next() {
			var v View
			if err := json.Unmarshal(data, &v); err == nil {
				if v.TenantID == tenantID && v.Name == name {
					found = &v
					return nil
				}
			}
		}
		return ErrNotFound
	})

	if err != nil {
		return nil, err
	}
	return found, nil
}

// UpdateView updates an existing view.
func (s *Store) UpdateView(v *View) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketViews)
		if bucket.Get([]byte(v.ID)) == nil {
			return ErrNotFound
		}
		return putJSON(tx, BucketViews, v.ID, v)
	})
}

// DeleteView deletes a view.
func (s *Store) DeleteView(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketViews)
		if bucket.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return bucket.Delete([]byte(id))
	})
}

// ListViews lists all views, optionally filtered by tenant.
func (s *Store) ListViews(tenantID string) ([]*View, error) {
	var views []*View

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketViews)
		if bucket == nil {
			return nil
		}

		return bucket.ForEach(func(k, data []byte) error {
			var v View
			if err := json.Unmarshal(data, &v); err != nil {
				return err
			}
			if tenantID == "" || v.TenantID == tenantID {
				views = append(views, &v)
			}
			return nil
		})
	})

	return views, err
}

// MatchView finds the best matching view for a client IP.
func (s *Store) MatchView(clientIP net.IP, tenantID string) (*View, error) {
	views, err := s.ListViews(tenantID)
	if err != nil {
		return nil, err
	}

	var bestMatch *View
	bestPriority := -1

	for _, v := range views {
		for _, cidrStr := range v.MatchCIDRs {
			_, network, err := net.ParseCIDR(cidrStr)
			if err != nil {
				continue
			}
			if network.Contains(clientIP) && v.Priority > bestPriority {
				bestMatch = v
				bestPriority = v.Priority
			}
		}
	}

	return bestMatch, nil
}

// ============================================================================
// Blocklist CRUD
// ============================================================================

// blocklistKey generates a key for a blocklist entry.
func blocklistKey(entryType, value string) string {
	return fmt.Sprintf("%s:%s", entryType, value)
}

// CreateBlockEntry creates a new blocklist entry.
func (s *Store) CreateBlockEntry(entry *BlockEntry) error {
	if entry.Type == "" {
		return fmt.Errorf("entry type required (domain, ip, cidr)")
	}
	if entry.Value == "" {
		return fmt.Errorf("entry value required")
	}
	if entry.Action == "" {
		entry.Action = "block" // default action
	}
	entry.CreatedAt = time.Now().UTC()

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklist)
		key := blocklistKey(entry.Type, entry.Value)
		if bucket.Get([]byte(key)) != nil {
			return ErrAlreadyExists
		}
		return putJSON(tx, BucketBlocklist, key, entry)
	})
}

// GetBlockEntry retrieves a blocklist entry.
func (s *Store) GetBlockEntry(entryType, value string) (*BlockEntry, error) {
	var entry BlockEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx, BucketBlocklist, blocklistKey(entryType, value), &entry)
	})
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// DeleteBlockEntry deletes a blocklist entry.
func (s *Store) DeleteBlockEntry(entryType, value string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklist)
		key := blocklistKey(entryType, value)
		if bucket.Get([]byte(key)) == nil {
			return ErrNotFound
		}
		return bucket.Delete([]byte(key))
	})
}

// ListBlockEntries lists all blocklist entries, optionally filtered by type.
func (s *Store) ListBlockEntries(entryType string) ([]*BlockEntry, error) {
	var entries []*BlockEntry

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklist)
		if bucket == nil {
			return nil
		}

		prefix := []byte("")
		if entryType != "" {
			prefix = []byte(entryType + ":")
		}

		c := bucket.Cursor()
		for k, data := c.Seek(prefix); k != nil; k, data = c.Next() {
			if entryType != "" && !hasPrefix(string(k), entryType+":") {
				break
			}
			var entry BlockEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				continue
			}
			// Check expiration
			if entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
				continue
			}
			entries = append(entries, &entry)
		}
		return nil
	})

	return entries, err
}

// CheckBlocked checks if a domain or IP is blocked.
func (s *Store) CheckBlocked(checkType, value string) (*BlockEntry, bool) {
	entry, err := s.GetBlockEntry(checkType, value)
	if err == nil {
		// Check expiration
		if entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
			return nil, false
		}
		return entry, true
	}

	// For domains, also check parent domains
	if checkType == "domain" {
		parts := splitDomain(value)
		for i := 1; i < len(parts); i++ {
			parent := joinDomain(parts[i:])
			entry, err := s.GetBlockEntry("domain", parent)
			if err == nil {
				if entry.ExpiresAt == nil || time.Now().Before(*entry.ExpiresAt) {
					return entry, true
				}
			}
		}
	}

	// For IPs, also check CIDR ranges
	if checkType == "ip" {
		ip := net.ParseIP(value)
		if ip != nil {
			entries, _ := s.ListBlockEntries("cidr")
			for _, entry := range entries {
				_, network, err := net.ParseCIDR(entry.Value)
				if err == nil && network.Contains(ip) {
					return entry, true
				}
			}
		}
	}

	return nil, false
}

// CleanupExpiredBlockEntries removes expired blocklist entries.
func (s *Store) CleanupExpiredBlockEntries() (int, error) {
	count := 0

	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BucketBlocklist)
		if bucket == nil {
			return nil
		}

		now := time.Now()
		var toDelete [][]byte

		c := bucket.Cursor()
		for k, data := c.First(); k != nil; k, data = c.Next() {
			var entry BlockEntry
			if err := json.Unmarshal(data, &entry); err == nil {
				if entry.ExpiresAt != nil && now.After(*entry.ExpiresAt) {
					toDelete = append(toDelete, k)
				}
			}
		}

		for _, k := range toDelete {
			if err := bucket.Delete(k); err != nil {
				return err
			}
			count++
		}

		return nil
	})

	return count, err
}

// Helper functions

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func splitDomain(domain string) []string {
	// Remove trailing dot
	domain = strings.TrimSuffix(domain, ".")
	return strings.Split(domain, ".")
}

func joinDomain(parts []string) string {
	return strings.Join(parts, ".")
}
