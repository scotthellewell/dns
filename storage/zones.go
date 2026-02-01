package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	bolt "go.etcd.io/bbolt"
)

// CreateZone creates a new zone.
// For reverse zones, it automatically populates PTR records from existing A/AAAA records.
func (s *Store) CreateZone(zone *Zone) error {
	if zone.Name == "" {
		return fmt.Errorf("zone name required")
	}
	if zone.TenantID == "" {
		zone.TenantID = MainTenantID
	}
	if zone.Type == "" {
		if zone.Subnet != "" {
			zone.Type = ZoneTypeReverse
		} else {
			zone.Type = ZoneTypeForward
		}
	}
	if zone.Status == "" {
		zone.Status = ZoneStatusActive
	}
	if zone.TTL == 0 {
		zone.TTL = 3600
	}

	// Normalize zone name
	zone.Name = dns.Fqdn(strings.ToLower(zone.Name))
	zone.Name = strings.TrimSuffix(zone.Name, ".") // Store without trailing dot

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketZones)

		// Check if already exists
		if b.Get([]byte(zone.Name)) != nil {
			return ErrAlreadyExists
		}

		// Check tenant exists
		if tx.Bucket(BucketTenants).Get([]byte(zone.TenantID)) == nil {
			return fmt.Errorf("tenant not found")
		}

		// For subzones, check delegation requirements
		if err := s.checkSubzonePermission(tx, zone); err != nil {
			return err
		}

		// Generate initial serial (YYYYMMDD01)
		now := time.Now().UTC()
		zone.Serial = uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100 + 1)
		zone.CreatedAt = now
		zone.UpdatedAt = now

		if err := putJSON(tx, BucketZones, zone.Name, zone); err != nil {
			return err
		}

		// Update reverse zone index if this is a reverse zone
		if zone.Type == ZoneTypeReverse && zone.Subnet != "" {
			if err := s.updateReverseZoneIndex(tx, zone.Name, zone.Subnet); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	// Refresh zone cache
	s.refreshZoneCache()

	// Record change for sync
	recordChange(EntityTypeZone, zone.Name, zone.TenantID, OpCreate, zone)

	// For reverse zones, populate PTRs from existing A/AAAA records
	if zone.Type == ZoneTypeReverse && zone.Subnet != "" {
		go s.populatePTRsForReverseZone(zone.Name)
	}

	return nil
}

// checkSubzonePermission verifies that the user can create a subzone.
func (s *Store) checkSubzonePermission(tx *bolt.Tx, zone *Zone) error {
	// Find parent zone
	parentName := findParentZone(zone.Name, tx)
	if parentName == "" {
		// No parent zone in our system - OK to create
		return nil
	}

	// Get parent zone
	var parent Zone
	if err := getJSON(tx, BucketZones, parentName, &parent); err != nil {
		return nil // Parent doesn't exist, OK
	}

	// Check if there's a delegation for this zone
	delegKey := parentName + ":" + zone.Name
	delegBucket := tx.Bucket(BucketDelegations)
	if delegBucket == nil {
		return ErrDelegationRequired
	}

	data := delegBucket.Get([]byte(delegKey))
	if data == nil {
		// No delegation - must be same tenant as parent
		if zone.TenantID != parent.TenantID {
			return ErrDelegationRequired
		}
		return nil
	}

	// Check delegation grants access
	var deleg Delegation
	if err := unmarshalJSON(data, &deleg); err != nil {
		return err
	}

	if !deleg.Active {
		return fmt.Errorf("delegation is inactive")
	}

	// Delegation exists - check if tenant is allowed
	if deleg.GrantedToTenant != "" && deleg.GrantedToTenant != zone.TenantID {
		// Delegation grants to different tenant
		if zone.TenantID != parent.TenantID {
			return ErrForbidden
		}
	}

	return nil
}

// findParentZone finds the parent zone for a given zone name.
func findParentZone(name string, tx *bolt.Tx) string {
	parts := strings.Split(name, ".")
	if len(parts) <= 1 {
		return ""
	}

	b := tx.Bucket(BucketZones)
	if b == nil {
		return ""
	}

	// Walk up the hierarchy
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if parent == "" {
			continue
		}
		if b.Get([]byte(parent)) != nil {
			return parent
		}
	}

	return ""
}

// updateReverseZoneIndex updates the reverse zone index for fast IP->zone lookups.
func (s *Store) updateReverseZoneIndex(tx *bolt.Tx, zoneName, subnet string) error {
	indexes := tx.Bucket(BucketIndexes)
	if indexes == nil {
		return nil
	}

	reverseIdx := indexes.Bucket([]byte(IndexReverseZones))
	if reverseIdx == nil {
		return nil
	}

	// Store with sortable key for range lookups
	// Key format: IP prefix padded for sorting
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("invalid subnet: %w", err)
	}

	key := cidrToSortableKey(ipnet)
	return reverseIdx.Put([]byte(key), []byte(zoneName))
}

// cidrToSortableKey converts a CIDR to a sortable string key.
func cidrToSortableKey(ipnet *net.IPNet) string {
	ones, _ := ipnet.Mask.Size()
	ip := ipnet.IP.To16()
	if ip == nil {
		ip = ipnet.IP
	}
	// Format: prefix_length:ip_bytes_hex
	return fmt.Sprintf("%03d:%x", ones, ip)
}

// GetZone retrieves a zone by name.
func (s *Store) GetZone(name string) (*Zone, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")

	var zone Zone
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx, BucketZones, name, &zone)
	})
	if err != nil {
		return nil, err
	}
	return &zone, nil
}

// GetZoneForName finds the authoritative zone for a given name.
func (s *Store) GetZoneForName(name string) (*Zone, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find longest matching zone
	parts := strings.Split(name, ".")
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		if zone, ok := s.zoneCache[candidate]; ok {
			if zone.Status == ZoneStatusActive {
				return zone, nil
			}
		}
	}

	return nil, ErrNotFound
}

// GetReverseZoneForIP finds the reverse zone for an IP address.
func (s *Store) GetReverseZoneForIP(ip net.IP) (*Zone, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find matching reverse zone
	for _, zone := range s.zoneCache {
		if zone.Type != ZoneTypeReverse || zone.Subnet == "" {
			continue
		}
		if zone.Status != ZoneStatusActive {
			continue
		}

		_, ipnet, err := net.ParseCIDR(zone.Subnet)
		if err != nil {
			continue
		}

		if ipnet.Contains(ip) {
			return zone, nil
		}
	}

	return nil, ErrNotFound
}

// UpdateZone updates an existing zone.
func (s *Store) UpdateZone(zone *Zone) error {
	if zone.Name == "" {
		return fmt.Errorf("zone name required")
	}

	zone.Name = strings.TrimSuffix(strings.ToLower(zone.Name), ".")
	zone.UpdatedAt = time.Now().UTC()

	// Increment serial
	zone.Serial = incrementSerial(zone.Serial)

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketZones)
		if b.Get([]byte(zone.Name)) == nil {
			return ErrNotFound
		}

		return putJSON(tx, BucketZones, zone.Name, zone)
	})

	if err == nil {
		s.refreshZoneCache()
		// Record change for sync
		recordChange(EntityTypeZone, zone.Name, zone.TenantID, OpUpdate, zone)
	}

	return err
}

// DeleteZone deletes a zone and all its records.
func (s *Store) DeleteZone(name string) error {
	name = strings.TrimSuffix(strings.ToLower(name), ".")

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketZones)
		if b.Get([]byte(name)) == nil {
			return ErrNotFound
		}

		// Check for dependent zones (subzones using delegations)
		deleg := tx.Bucket(BucketDelegations)
		if deleg != nil {
			c := deleg.Cursor()
			prefix := []byte(name + ":")
			for k, _ := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, _ = c.Next() {
				return ErrZoneInUse
			}
		}

		// Delete all records in this zone
		records := tx.Bucket(BucketRecords)
		if records != nil {
			c := records.Cursor()
			prefix := []byte(name + ":")
			var toDelete [][]byte
			for k, _ := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, _ = c.Next() {
				toDelete = append(toDelete, append([]byte{}, k...))
			}
			for _, k := range toDelete {
				records.Delete(k)
			}
		}

		// Delete DNSSEC keys
		dnssec := tx.Bucket(BucketDNSSECKeys)
		if dnssec != nil {
			dnssec.Delete([]byte(name))
		}

		// Remove from reverse zone index
		indexes := tx.Bucket(BucketIndexes)
		if indexes != nil {
			reverseIdx := indexes.Bucket([]byte(IndexReverseZones))
			if reverseIdx != nil {
				// Find and delete the index entry
				c := reverseIdx.Cursor()
				for k, v := c.First(); k != nil; k, v = c.Next() {
					if string(v) == name {
						reverseIdx.Delete(k)
						break
					}
				}
			}
		}

		return delete(tx, BucketZones, name)
	})

	if err == nil {
		s.refreshZoneCache()
		// Record change for sync (we don't have tenantID here, but it's in the zone)
		recordChange(EntityTypeZone, name, "", OpDelete, nil)
	}

	return err
}

// ListZones returns all zones, optionally filtered by tenant.
func (s *Store) ListZones(tenantID string) ([]*Zone, error) {
	var zones []*Zone

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketZones)
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var zone Zone
			if err := unmarshalJSON(v, &zone); err != nil {
				return err
			}
			if tenantID == "" || zone.TenantID == tenantID {
				zones = append(zones, &zone)
			}
			return nil
		})
	})

	// Sort by name
	sort.Slice(zones, func(i, j int) bool {
		return zones[i].Name < zones[j].Name
	})

	return zones, err
}

// IncrementZoneSerial increments the zone serial number.
func (s *Store) IncrementZoneSerial(zoneName string) error {
	zoneName = strings.TrimSuffix(strings.ToLower(zoneName), ".")

	return s.db.Update(func(tx *bolt.Tx) error {
		var zone Zone
		if err := getJSON(tx, BucketZones, zoneName, &zone); err != nil {
			return err
		}

		zone.Serial = incrementSerial(zone.Serial)
		zone.UpdatedAt = time.Now().UTC()

		return putJSON(tx, BucketZones, zoneName, &zone)
	})
}

// incrementSerial increments a zone serial in YYYYMMDDNN format.
func incrementSerial(current uint32) uint32 {
	now := time.Now().UTC()
	today := uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100)

	if current >= today && current < today+99 {
		// Same day, increment counter
		return current + 1
	}
	// New day or overflow, start fresh
	return today + 1
}

// populatePTRsForReverseZone scans A/AAAA records and creates PTRs for IPs in this zone's range.
func (s *Store) populatePTRsForReverseZone(zoneName string) error {
	zone, err := s.GetZone(zoneName)
	if err != nil {
		return err
	}

	if zone.Type != ZoneTypeReverse || zone.Subnet == "" {
		return nil
	}

	_, ipnet, err := net.ParseCIDR(zone.Subnet)
	if err != nil {
		return fmt.Errorf("invalid subnet: %w", err)
	}

	isIPv6 := ipnet.IP.To4() == nil

	return s.db.Update(func(tx *bolt.Tx) error {
		records := tx.Bucket(BucketRecords)
		if records == nil {
			return nil
		}

		// Scan all records for A or AAAA
		c := records.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			// Parse record type from key (zone:name:type)
			parts := strings.Split(string(k), ":")
			if len(parts) < 3 {
				continue
			}
			rtype := parts[len(parts)-1]

			// Only process A (for IPv4 zones) or AAAA (for IPv6 zones)
			if (rtype == "A" && isIPv6) || (rtype == "AAAA" && !isIPv6) {
				continue
			}
			if rtype != "A" && rtype != "AAAA" {
				continue
			}

			var recordList []Record
			if err := unmarshalJSON(v, &recordList); err != nil {
				continue
			}

			for _, rec := range recordList {
				// Skip if AutoPTR is disabled
				if !rec.AutoPTR {
					continue
				}

				// Only create PTRs for same tenant
				recZone, err := s.GetZone(rec.Zone)
				if err != nil {
					continue
				}
				if recZone.TenantID != zone.TenantID {
					continue
				}

				// Parse the IP from record data
				var ip net.IP
				if rtype == "A" {
					var data ARecordData
					if err := unmarshalJSON(rec.Data, &data); err != nil {
						continue
					}
					ip = net.ParseIP(data.IP)
				} else {
					var data AAAARecordData
					if err := unmarshalJSON(rec.Data, &data); err != nil {
						continue
					}
					ip = net.ParseIP(data.IP)
				}

				if ip == nil || !ipnet.Contains(ip) {
					continue
				}

				// Create PTR record
				ptrName := ipToReverseName(ip, zone)
				fqdn := rec.Name
				if !strings.HasSuffix(fqdn, ".") {
					fqdn = rec.Name + "." + rec.Zone + "."
				}

				ptrData := PTRRecordData{Target: fqdn}
				dataBytes, _ := marshalJSON(ptrData)

				ptr := Record{
					ID:           GenerateID(),
					Zone:         zone.Name,
					Name:         ptrName,
					Type:         "PTR",
					TTL:          rec.TTL,
					Enabled:      true,
					AutoManaged:  true,
					SourceRecord: rec.Zone + ":" + rec.Name + ":" + rtype,
					Data:         dataBytes,
					CreatedAt:    time.Now().UTC(),
					UpdatedAt:    time.Now().UTC(),
				}

				// Store PTR
				ptrKey := zone.Name + ":" + ptrName + ":PTR"
				var existing []Record
				if data := records.Get([]byte(ptrKey)); data != nil {
					unmarshalJSON(data, &existing)
				}
				existing = append(existing, ptr)

				ptrBytes, _ := marshalJSON(existing)
				records.Put([]byte(ptrKey), ptrBytes)

				// Update PTR source index
				s.updatePTRSourceIndex(tx, ptr.SourceRecord, ptrKey)
			}
		}

		return nil
	})
}

// updatePTRSourceIndex updates the PTR source index for quick lookups.
func (s *Store) updatePTRSourceIndex(tx *bolt.Tx, sourceRecord, ptrKey string) error {
	indexes := tx.Bucket(BucketIndexes)
	if indexes == nil {
		return nil
	}

	ptrIdx := indexes.Bucket([]byte(IndexPTRSources))
	if ptrIdx == nil {
		return nil
	}

	return ptrIdx.Put([]byte(sourceRecord), []byte(ptrKey))
}

// GetZoneSerial returns the current serial for a zone.
func (s *Store) GetZoneSerial(zoneName string) (uint32, error) {
	zone, err := s.GetZone(zoneName)
	if err != nil {
		return 0, err
	}
	return zone.Serial, nil
}

// marshalJSON is a helper for json.Marshal
func marshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// ============================================================================
// Delegation CRUD
// ============================================================================

// delegationKey generates the key for a delegation.
func delegationKey(parentZone, childZone string) string {
	return fmt.Sprintf("%s:%s", parentZone, childZone)
}

// CreateDelegation creates a new zone delegation.
func (s *Store) CreateDelegation(d *Delegation) error {
	if d.ParentZone == "" {
		return fmt.Errorf("parent zone required")
	}
	if d.ChildZone == "" {
		return fmt.Errorf("child zone required")
	}
	if len(d.Nameservers) == 0 {
		return fmt.Errorf("at least one nameserver required")
	}

	d.CreatedAt = time.Now().UTC()
	if d.TTL == 0 {
		d.TTL = 3600
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		// Verify parent zone exists
		zonesBucket := tx.Bucket(BucketZones)
		if zonesBucket.Get([]byte(d.ParentZone)) == nil {
			return fmt.Errorf("parent zone %s not found", d.ParentZone)
		}

		// Check if delegation already exists
		delegBucket := tx.Bucket(BucketDelegations)
		key := delegationKey(d.ParentZone, d.ChildZone)
		if delegBucket.Get([]byte(key)) != nil {
			return ErrAlreadyExists
		}

		// Create NS records for the delegation in the parent zone
		for _, ns := range d.Nameservers {
			// Calculate relative name for NS record
			relativeName := strings.TrimSuffix(d.ChildZone, "."+d.ParentZone)
			relativeName = strings.TrimSuffix(relativeName, d.ParentZone)
			relativeName = strings.Trim(relativeName, ".")
			if relativeName == "" {
				relativeName = "@"
			}

			nsRecord := &Record{
				ID:          GenerateID(),
				Zone:        d.ParentZone,
				Name:        relativeName,
				Type:        "NS",
				TTL:         d.TTL,
				Enabled:     true,
				AutoManaged: true, // Mark as auto-managed by delegation
				Data:        mustMarshalJSON(NSRecordData{Target: dns.Fqdn(ns)}),
				CreatedAt:   d.CreatedAt,
				UpdatedAt:   d.CreatedAt,
			}

			// Add to records bucket
			recordsBucket := tx.Bucket(BucketRecords)
			recKey := recordKey(nsRecord.Zone, nsRecord.Name, nsRecord.Type)

			var records []Record
			existing := recordsBucket.Get([]byte(recKey))
			if existing != nil {
				json.Unmarshal(existing, &records)
			}
			records = append(records, *nsRecord)

			data, _ := json.Marshal(records)
			recordsBucket.Put([]byte(recKey), data)
		}

		// Create glue records if provided
		if d.Glue != nil {
			for nsName, ips := range d.Glue {
				relativeName := strings.TrimSuffix(nsName, "."+d.ParentZone)
				relativeName = strings.TrimSuffix(relativeName, d.ParentZone)
				relativeName = strings.Trim(relativeName, ".")

				for _, ipStr := range ips {
					ip := net.ParseIP(ipStr)
					if ip == nil {
						continue
					}

					recordType := "A"
					var recordData json.RawMessage
					if ip.To4() != nil {
						recordData = mustMarshalJSON(ARecordData{IP: ipStr})
					} else {
						recordType = "AAAA"
						recordData = mustMarshalJSON(AAAARecordData{IP: ipStr})
					}

					glueRecord := &Record{
						ID:          GenerateID(),
						Zone:        d.ParentZone,
						Name:        relativeName,
						Type:        recordType,
						TTL:         d.TTL,
						Enabled:     true,
						AutoManaged: true,
						Data:        recordData,
						CreatedAt:   d.CreatedAt,
						UpdatedAt:   d.CreatedAt,
					}

					recordsBucket := tx.Bucket(BucketRecords)
					recKey := recordKey(glueRecord.Zone, glueRecord.Name, glueRecord.Type)

					var records []Record
					existing := recordsBucket.Get([]byte(recKey))
					if existing != nil {
						json.Unmarshal(existing, &records)
					}
					records = append(records, *glueRecord)

					data, _ := json.Marshal(records)
					recordsBucket.Put([]byte(recKey), data)
				}
			}
		}

		// Create DS records for DNSSEC chain of trust
		if len(d.DSRecords) > 0 {
			relativeName := strings.TrimSuffix(d.ChildZone, "."+d.ParentZone)
			relativeName = strings.TrimSuffix(relativeName, d.ParentZone)
			relativeName = strings.Trim(relativeName, ".")
			if relativeName == "" {
				relativeName = "@"
			}

			recordsBucket := tx.Bucket(BucketRecords)
			recKey := recordKey(d.ParentZone, relativeName, "DS")

			var records []Record
			for _, ds := range d.DSRecords {
				dsRecord := &Record{
					ID:          GenerateID(),
					Zone:        d.ParentZone,
					Name:        relativeName,
					Type:        "DS",
					TTL:         d.TTL,
					Enabled:     true,
					AutoManaged: true,
					Data:        mustMarshalJSON(ds),
					CreatedAt:   d.CreatedAt,
					UpdatedAt:   d.CreatedAt,
				}
				records = append(records, *dsRecord)
			}

			data, _ := json.Marshal(records)
			recordsBucket.Put([]byte(recKey), data)
		}

		return putJSON(tx, BucketDelegations, key, d)
	})

	if err == nil {
		recordChange(EntityTypeDelegation, delegationKey(d.ParentZone, d.ChildZone), "", OpCreate, d)
	}

	return err
}

// GetDelegation retrieves a delegation by parent and child zone.
func (s *Store) GetDelegation(parentZone, childZone string) (*Delegation, error) {
	var d Delegation
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx, BucketDelegations, delegationKey(parentZone, childZone), &d)
	})
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// UpdateDelegation updates an existing delegation.
func (s *Store) UpdateDelegation(d *Delegation) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		key := delegationKey(d.ParentZone, d.ChildZone)
		delegBucket := tx.Bucket(BucketDelegations)
		if delegBucket.Get([]byte(key)) == nil {
			return ErrNotFound
		}
		return putJSON(tx, BucketDelegations, key, d)
	})

	if err == nil {
		recordChange(EntityTypeDelegation, delegationKey(d.ParentZone, d.ChildZone), "", OpUpdate, d)
	}

	return err
}

// DeleteDelegation removes a delegation.
// If the child zone exists and is active, this will fail unless force is true.
func (s *Store) DeleteDelegation(parentZone, childZone string, force bool) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		key := delegationKey(parentZone, childZone)
		delegBucket := tx.Bucket(BucketDelegations)

		// Check if delegation exists
		if delegBucket.Get([]byte(key)) == nil {
			return ErrNotFound
		}

		// Check if child zone exists and is active
		if !force {
			zonesBucket := tx.Bucket(BucketZones)
			if zoneData := zonesBucket.Get([]byte(childZone)); zoneData != nil {
				var zone Zone
				if json.Unmarshal(zoneData, &zone) == nil && zone.Status == ZoneStatusActive {
					return fmt.Errorf("cannot delete delegation: child zone is active")
				}
			}
		}

		// Delete auto-managed NS and glue records
		// First get the delegation to know what records to clean up
		var d Delegation
		if err := getJSON(tx, BucketDelegations, key, &d); err != nil {
			return err
		}

		// Calculate relative name for the delegation
		relativeName := strings.TrimSuffix(childZone, "."+parentZone)
		relativeName = strings.TrimSuffix(relativeName, parentZone)
		relativeName = strings.Trim(relativeName, ".")
		if relativeName == "" {
			relativeName = "@"
		}

		// Remove auto-managed NS records
		recordsBucket := tx.Bucket(BucketRecords)
		nsKey := recordKey(parentZone, relativeName, "NS")
		if nsData := recordsBucket.Get([]byte(nsKey)); nsData != nil {
			var records []Record
			if json.Unmarshal(nsData, &records) == nil {
				// Keep only non-auto-managed records
				var remaining []Record
				for _, r := range records {
					if !r.AutoManaged {
						remaining = append(remaining, r)
					}
				}
				if len(remaining) == 0 {
					recordsBucket.Delete([]byte(nsKey))
				} else {
					data, _ := json.Marshal(remaining)
					recordsBucket.Put([]byte(nsKey), data)
				}
			}
		}

		return delegBucket.Delete([]byte(key))
	})

	if err == nil {
		recordChange(EntityTypeDelegation, delegationKey(parentZone, childZone), "", OpDelete, nil)
	}

	return err
}

// ListDelegations lists all delegations, optionally filtered by parent zone.
func (s *Store) ListDelegations(parentZone string) ([]*Delegation, error) {
	var delegations []*Delegation

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketDelegations)
		if b == nil {
			return nil
		}

		prefix := []byte("")
		if parentZone != "" {
			prefix = []byte(parentZone + ":")
		}

		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil; k, v = c.Next() {
			if parentZone != "" && !strings.HasPrefix(string(k), parentZone+":") {
				break
			}

			var d Delegation
			if err := json.Unmarshal(v, &d); err != nil {
				continue
			}
			delegations = append(delegations, &d)
		}

		return nil
	})

	return delegations, err
}

// mustMarshalJSON marshals to JSON, panicking on error (for known-good data).
func mustMarshalJSON(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal JSON: %v", err))
	}
	return data
}
