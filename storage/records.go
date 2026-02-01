package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Record key format: {zone}:{name}:{type}
// Example: "example.com:www:A" or "example.com:@:MX"

func recordKey(zone, name, recordType string) string {
	return fmt.Sprintf("%s:%s:%s", zone, name, recordType)
}

func parseRecordKey(key string) (zone, name, recordType string, ok bool) {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// CreateRecord creates a new DNS record.
// For A/AAAA records, it automatically creates PTR records in matching reverse zones.
func (s *Store) CreateRecord(record *Record) error {
	if record.Zone == "" {
		return fmt.Errorf("zone name required")
	}
	if record.Name == "" {
		return fmt.Errorf("record name required")
	}
	if record.Type == "" {
		return fmt.Errorf("record type required")
	}
	if record.Data == nil {
		return fmt.Errorf("record data required")
	}

	now := time.Now()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now

	return s.db.Update(func(tx *bolt.Tx) error {
		// Verify zone exists
		zonesBucket := tx.Bucket([]byte("zones"))
		zoneData := zonesBucket.Get([]byte(record.Zone))
		if zoneData == nil {
			return fmt.Errorf("zone %s not found", record.Zone)
		}

		var zone Zone
		if err := json.Unmarshal(zoneData, &zone); err != nil {
			return err
		}

		// Get records bucket
		recordsBucket := tx.Bucket([]byte("records"))
		key := recordKey(record.Zone, record.Name, record.Type)

		// Get existing records at this key (can have multiple records per type)
		var records []Record
		existing := recordsBucket.Get([]byte(key))
		if existing != nil {
			if err := json.Unmarshal(existing, &records); err != nil {
				return err
			}
		}

		// Append the new record
		records = append(records, *record)

		// Save records
		data, err := json.Marshal(records)
		if err != nil {
			return err
		}
		if err := recordsBucket.Put([]byte(key), data); err != nil {
			return err
		}

		// Increment zone serial
		zone.Serial++
		zone.UpdatedAt = now
		zoneData, err = json.Marshal(&zone)
		if err != nil {
			return err
		}
		if err := zonesBucket.Put([]byte(zone.Name), zoneData); err != nil {
			return err
		}

		// Handle PTR auto-creation for A/AAAA records
		if record.Type == "A" || record.Type == "AAAA" {
			if err := s.createPTRForRecord(tx, record, &zone); err != nil {
				// Log but don't fail - PTR creation is best-effort
				// In production, we'd use a proper logger
				fmt.Printf("Warning: failed to create PTR for %s: %v\n", record.Name, err)
			}
		}

		// Record change for sync
		recordChange(EntityTypeRecord, record.ID, zone.TenantID, OpCreate, record)

		return nil
	})
}

// GetRecords retrieves all records for a zone/name/type combination.
func (s *Store) GetRecords(zoneName, name, recordType string) ([]Record, error) {
	var records []Record

	err := s.db.View(func(tx *bolt.Tx) error {
		recordsBucket := tx.Bucket([]byte("records"))
		key := recordKey(zoneName, name, recordType)

		data := recordsBucket.Get([]byte(key))
		if data == nil {
			return nil // No records found is not an error
		}

		return json.Unmarshal(data, &records)
	})

	return records, err
}

// GetRecordsByName retrieves all records for a zone/name across all types.
func (s *Store) GetRecordsByName(zoneName, name string) ([]Record, error) {
	var allRecords []Record

	err := s.db.View(func(tx *bolt.Tx) error {
		recordsBucket := tx.Bucket([]byte("records"))
		prefix := []byte(fmt.Sprintf("%s:%s:", zoneName, name))

		c := recordsBucket.Cursor()
		for k, v := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, v = c.Next() {
			var records []Record
			if err := json.Unmarshal(v, &records); err != nil {
				return err
			}
			allRecords = append(allRecords, records...)
		}

		return nil
	})

	return allRecords, err
}

// GetAllZoneRecords retrieves all records for a zone.
func (s *Store) GetAllZoneRecords(zoneName string) ([]Record, error) {
	var allRecords []Record

	err := s.db.View(func(tx *bolt.Tx) error {
		recordsBucket := tx.Bucket([]byte("records"))
		prefix := []byte(zoneName + ":")

		c := recordsBucket.Cursor()
		for k, v := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, v = c.Next() {
			var records []Record
			if err := json.Unmarshal(v, &records); err != nil {
				return err
			}
			allRecords = append(allRecords, records...)
		}

		return nil
	})

	return allRecords, err
}

// UpdateRecord updates a specific record by matching its ID within a record set.
// For A/AAAA records, it syncs PTR records when the IP changes.
func (s *Store) UpdateRecord(record *Record) error {
	if record.ID == "" {
		return fmt.Errorf("record ID required for update")
	}

	record.UpdatedAt = time.Now()

	return s.db.Update(func(tx *bolt.Tx) error {
		recordsBucket := tx.Bucket([]byte("records"))
		zonesBucket := tx.Bucket([]byte("zones"))

		key := recordKey(record.Zone, record.Name, record.Type)

		// Get existing records
		existing := recordsBucket.Get([]byte(key))
		if existing == nil {
			return ErrNotFound
		}

		var records []Record
		if err := json.Unmarshal(existing, &records); err != nil {
			return err
		}

		// Find and update the matching record
		found := false
		var oldRecord Record
		for i, r := range records {
			if r.ID == record.ID {
				oldRecord = r
				records[i] = *record
				found = true
				break
			}
		}

		if !found {
			return ErrNotFound
		}

		// Save updated records
		data, err := json.Marshal(records)
		if err != nil {
			return err
		}
		if err := recordsBucket.Put([]byte(key), data); err != nil {
			return err
		}

		// Update zone serial
		zoneData := zonesBucket.Get([]byte(record.Zone))
		if zoneData != nil {
			var zone Zone
			if err := json.Unmarshal(zoneData, &zone); err == nil {
				zone.Serial++
				zone.UpdatedAt = time.Now()
				zoneData, _ = json.Marshal(&zone)
				zonesBucket.Put([]byte(zone.Name), zoneData)
			}
		}

		// Handle PTR sync for A/AAAA records
		if record.Type == "A" || record.Type == "AAAA" {
			if err := s.syncPTRForRecord(tx, &oldRecord, record); err != nil {
				fmt.Printf("Warning: failed to sync PTR for %s: %v\n", record.Name, err)
			}
		}

		// Record change for sync
		recordChange(EntityTypeRecord, record.ID, "", OpUpdate, record)

		return nil
	})
}

// DeleteRecord deletes a specific record by ID from a record set.
// For A/AAAA records, it deletes the associated PTR record.
func (s *Store) DeleteRecord(zoneName, name, recordType, recordID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		recordsBucket := tx.Bucket([]byte("records"))
		zonesBucket := tx.Bucket([]byte("zones"))

		key := recordKey(zoneName, name, recordType)

		// Get existing records
		existing := recordsBucket.Get([]byte(key))
		if existing == nil {
			return ErrNotFound
		}

		var records []Record
		if err := json.Unmarshal(existing, &records); err != nil {
			return err
		}

		// Find and remove the matching record
		found := false
		var deletedRecord Record
		newRecords := make([]Record, 0, len(records)-1)
		for _, r := range records {
			if r.ID == recordID {
				deletedRecord = r
				found = true
			} else {
				newRecords = append(newRecords, r)
			}
		}

		if !found {
			return ErrNotFound
		}

		// Save or delete key
		if len(newRecords) == 0 {
			if err := recordsBucket.Delete([]byte(key)); err != nil {
				return err
			}
		} else {
			data, err := json.Marshal(newRecords)
			if err != nil {
				return err
			}
			if err := recordsBucket.Put([]byte(key), data); err != nil {
				return err
			}
		}

		// Update zone serial
		zoneData := zonesBucket.Get([]byte(zoneName))
		if zoneData != nil {
			var zone Zone
			if err := json.Unmarshal(zoneData, &zone); err == nil {
				zone.Serial++
				zone.UpdatedAt = time.Now()
				zoneData, _ = json.Marshal(&zone)
				zonesBucket.Put([]byte(zone.Name), zoneData)
			}
		}

		// Handle PTR deletion for A/AAAA records
		if recordType == "A" || recordType == "AAAA" {
			if err := s.deletePTRForRecord(tx, &deletedRecord); err != nil {
				fmt.Printf("Warning: failed to delete PTR for %s: %v\n", name, err)
			}
		}

		// Record change for sync
		recordChange(EntityTypeRecord, recordID, "", OpDelete, nil)

		return nil
	})
}

// DeleteRecordsByType deletes all records of a specific type for a zone/name.
func (s *Store) DeleteRecordsByType(zoneName, name, recordType string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		recordsBucket := tx.Bucket([]byte("records"))
		zonesBucket := tx.Bucket([]byte("zones"))

		key := recordKey(zoneName, name, recordType)

		// Get records before deleting (for PTR cleanup)
		var records []Record
		existing := recordsBucket.Get([]byte(key))
		if existing != nil {
			json.Unmarshal(existing, &records)
		}

		if err := recordsBucket.Delete([]byte(key)); err != nil {
			return err
		}

		// Update zone serial
		zoneData := zonesBucket.Get([]byte(zoneName))
		if zoneData != nil {
			var zone Zone
			if err := json.Unmarshal(zoneData, &zone); err == nil {
				zone.Serial++
				zone.UpdatedAt = time.Now()
				zoneData, _ = json.Marshal(&zone)
				zonesBucket.Put([]byte(zone.Name), zoneData)
			}
		}

		// Clean up PTRs for A/AAAA records
		if recordType == "A" || recordType == "AAAA" {
			for _, r := range records {
				s.deletePTRForRecord(tx, &r)
			}
		}

		return nil
	})
}

// QueryRecords queries records matching the given FQDN and type.
// This is the main lookup function for DNS resolution.
func (s *Store) QueryRecords(fqdn string, recordType string) ([]Record, error) {
	// Find the zone for this FQDN
	zone, err := s.GetZoneForName(fqdn)
	if err != nil {
		return nil, err
	}
	if zone == nil {
		return nil, nil // No zone covers this name
	}

	// Calculate the relative name within the zone
	name := fqdnToRelativeName(fqdn, zone.Name)

	// Try exact match first
	records, err := s.GetRecords(zone.Name, name, recordType)
	if err != nil {
		return nil, err
	}
	if len(records) > 0 {
		return records, nil
	}

	// Try wildcard match
	return s.GetWildcardRecords(zone.Name, name, recordType)
}

// GetWildcardRecords looks for wildcard records matching the given name.
// It walks up the name hierarchy looking for wildcard matches.
// e.g., for "foo.bar.example.com", it checks "*.bar.example.com", then "*.example.com"
func (s *Store) GetWildcardRecords(zoneName, name, recordType string) ([]Record, error) {
	if name == "@" || name == "*" {
		return nil, nil // No wildcard matching at apex or for wildcards themselves
	}

	var records []Record

	err := s.db.View(func(tx *bolt.Tx) error {
		recordsBucket := tx.Bucket([]byte("records"))

		// Split the name into labels
		labels := strings.Split(name, ".")

		// Try wildcards at each level
		// For "foo.bar", try "*.bar" then "*"
		for i := 0; i < len(labels); i++ {
			wildcardName := "*"
			if i < len(labels)-1 {
				wildcardName = "*." + strings.Join(labels[i+1:], ".")
			}

			key := recordKey(zoneName, wildcardName, recordType)
			data := recordsBucket.Get([]byte(key))
			if data != nil {
				var recs []Record
				if err := json.Unmarshal(data, &recs); err != nil {
					return err
				}
				// Only return enabled records
				for _, r := range recs {
					if r.Enabled {
						// Clone the record and update the name to the original queried name
						rec := r
						records = append(records, rec)
					}
				}
				if len(records) > 0 {
					return nil // Found wildcard match
				}
			}
		}

		return nil
	})

	return records, err
}

// fqdnToRelativeName converts an FQDN to a name relative to a zone.
// e.g., "www.example.com." with zone "example.com" returns "www"
// e.g., "example.com." with zone "example.com" returns "@"
func fqdnToRelativeName(fqdn, zoneName string) string {
	// Normalize: ensure trailing dots
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}
	if !strings.HasSuffix(zoneName, ".") {
		zoneName = zoneName + "."
	}

	// If they're the same, it's the apex
	if strings.EqualFold(fqdn, zoneName) {
		return "@"
	}

	// Strip the zone suffix
	suffix := "." + zoneName
	if strings.HasSuffix(strings.ToLower(fqdn), strings.ToLower(suffix)) {
		return strings.TrimSuffix(fqdn, suffix)
	}

	// Fallback - shouldn't happen if zone matching is correct
	return fqdn
}

// createPTRForRecord creates a PTR record for an A/AAAA record.
func (s *Store) createPTRForRecord(tx *bolt.Tx, record *Record, zone *Zone) error {
	var ip net.IP

	// Parse the IP from the record data
	switch record.Type {
	case "A":
		var data ARecordData
		if err := json.Unmarshal(record.Data, &data); err != nil {
			return fmt.Errorf("unmarshal A record data: %w", err)
		}
		ip = net.ParseIP(data.IP)
	case "AAAA":
		var data AAAARecordData
		if err := json.Unmarshal(record.Data, &data); err != nil {
			return fmt.Errorf("unmarshal AAAA record data: %w", err)
		}
		ip = net.ParseIP(data.IP)
	default:
		return fmt.Errorf("unsupported record type for PTR: %s", record.Type)
	}

	if ip == nil {
		return fmt.Errorf("could not parse IP from record data")
	}

	// Find reverse zone for this IP (same tenant only)
	reverseZone, err := s.getReverseZoneForIPInTx(tx, ip, zone.TenantID)
	if err != nil || reverseZone == nil {
		// No matching reverse zone - that's OK
		return nil
	}

	// Build PTR name
	ptrName := ipToReverseName(ip, reverseZone)
	if ptrName == "" {
		return nil
	}

	// Build FQDN for the PTR target
	var targetFQDN string
	if record.Name == "@" {
		targetFQDN = zone.Name
	} else {
		if strings.HasSuffix(zone.Name, ".") {
			targetFQDN = record.Name + "." + zone.Name
		} else {
			targetFQDN = record.Name + "." + zone.Name + "."
		}
	}

	// Marshal PTR data
	ptrData, err := json.Marshal(PTRRecordData{Target: targetFQDN})
	if err != nil {
		return fmt.Errorf("marshal PTR data: %w", err)
	}

	// Create PTR record
	ptrRecord := Record{
		ID:           generateID(),
		Zone:         reverseZone.Name,
		Name:         ptrName,
		Type:         "PTR",
		TTL:          record.TTL,
		Enabled:      true,
		Data:         ptrData,
		AutoManaged:  true,
		SourceRecord: fmt.Sprintf("%s:%s:%s:%s", record.Zone, record.Name, record.Type, record.ID),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Save PTR record
	recordsBucket := tx.Bucket([]byte("records"))
	key := recordKey(reverseZone.Name, ptrName, "PTR")

	var records []Record
	existing := recordsBucket.Get([]byte(key))
	if existing != nil {
		json.Unmarshal(existing, &records)
	}
	records = append(records, ptrRecord)

	data, err := json.Marshal(records)
	if err != nil {
		return err
	}

	if err := recordsBucket.Put([]byte(key), data); err != nil {
		return err
	}

	// Store PTR source index for quick lookup
	indexBucket := tx.Bucket([]byte("indexes"))
	ptrSourceKey := fmt.Sprintf("ptr_source:%s", ptrRecord.SourceRecord)
	ptrLocation := fmt.Sprintf("%s:%s:%s", ptrRecord.Zone, ptrRecord.Name, ptrRecord.ID)
	if err := indexBucket.Put([]byte(ptrSourceKey), []byte(ptrLocation)); err != nil {
		return err
	}

	// Update reverse zone serial
	zonesBucket := tx.Bucket([]byte("zones"))
	reverseZone.Serial++
	reverseZone.UpdatedAt = time.Now()
	zoneData, _ := json.Marshal(reverseZone)
	zonesBucket.Put([]byte(reverseZone.Name), zoneData)

	return nil
}

// syncPTRForRecord syncs PTR when an A/AAAA record IP changes.
func (s *Store) syncPTRForRecord(tx *bolt.Tx, oldRecord, newRecord *Record) error {
	// Delete old PTR
	if err := s.deletePTRForRecord(tx, oldRecord); err != nil {
		return err
	}

	// Get zone for creating new PTR
	zonesBucket := tx.Bucket([]byte("zones"))
	zoneData := zonesBucket.Get([]byte(newRecord.Zone))
	if zoneData == nil {
		return nil
	}

	var zone Zone
	if err := json.Unmarshal(zoneData, &zone); err != nil {
		return err
	}

	// Create new PTR
	return s.createPTRForRecord(tx, newRecord, &zone)
}

// deletePTRForRecord deletes the PTR record associated with an A/AAAA record.
func (s *Store) deletePTRForRecord(tx *bolt.Tx, record *Record) error {
	// Look up PTR location in index
	indexBucket := tx.Bucket([]byte("indexes"))
	sourceKey := fmt.Sprintf("ptr_source:%s:%s:%s:%s", record.Zone, record.Name, record.Type, record.ID)

	ptrLocation := indexBucket.Get([]byte(sourceKey))
	if ptrLocation == nil {
		return nil // No PTR to delete
	}

	// Parse location: zone:name:id
	parts := strings.SplitN(string(ptrLocation), ":", 3)
	if len(parts) != 3 {
		return nil
	}
	ptrZone, ptrName, ptrID := parts[0], parts[1], parts[2]

	// Delete from records
	recordsBucket := tx.Bucket([]byte("records"))
	key := recordKey(ptrZone, ptrName, "PTR")

	existing := recordsBucket.Get([]byte(key))
	if existing == nil {
		return nil
	}

	var records []Record
	if err := json.Unmarshal(existing, &records); err != nil {
		return err
	}

	// Remove the specific PTR record
	newRecords := make([]Record, 0, len(records))
	for _, r := range records {
		if r.ID != ptrID {
			newRecords = append(newRecords, r)
		}
	}

	if len(newRecords) == 0 {
		recordsBucket.Delete([]byte(key))
	} else {
		data, _ := json.Marshal(newRecords)
		recordsBucket.Put([]byte(key), data)
	}

	// Delete from index
	indexBucket.Delete([]byte(sourceKey))

	// Update reverse zone serial
	zonesBucket := tx.Bucket([]byte("zones"))
	zoneData := zonesBucket.Get([]byte(ptrZone))
	if zoneData != nil {
		var zone Zone
		if err := json.Unmarshal(zoneData, &zone); err == nil {
			zone.Serial++
			zone.UpdatedAt = time.Now()
			zoneData, _ = json.Marshal(&zone)
			zonesBucket.Put([]byte(zone.Name), zoneData)
		}
	}

	return nil
}

// getReverseZoneForIPInTx finds a reverse zone for an IP within a transaction.
// Only returns zones owned by the specified tenant (for same-tenant PTR rule).
func (s *Store) getReverseZoneForIPInTx(tx *bolt.Tx, ip net.IP, tenantID string) (*Zone, error) {
	indexBucket := tx.Bucket([]byte("indexes"))
	zonesBucket := tx.Bucket([]byte("zones"))

	// Iterate through reverse zone index to find matching zone
	prefix := []byte("reverse_zone:")
	c := indexBucket.Cursor()

	var bestMatch *Zone
	var bestBits int

	for k, v := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, v = c.Next() {
		zoneName := string(v)

		zoneData := zonesBucket.Get([]byte(zoneName))
		if zoneData == nil {
			continue
		}

		var zone Zone
		if err := json.Unmarshal(zoneData, &zone); err != nil {
			continue
		}

		// Only same-tenant reverse zones
		if zone.TenantID != tenantID {
			continue
		}

		// Check if IP is in this zone's subnet
		_, subnet, err := net.ParseCIDR(zone.Subnet)
		if err != nil {
			continue
		}

		if subnet.Contains(ip) {
			bits, _ := subnet.Mask.Size()
			if bits > bestBits {
				bestMatch = &zone
				bestBits = bits
			}
		}
	}

	return bestMatch, nil
}

// ipToReverseName converts an IP to a name relative to a reverse zone.
// For IPv4: 192.168.1.10 in zone 1.168.192.in-addr.arpa returns "10"
// For IPv6: uses nibble format
func ipToReverseName(ip net.IP, zone *Zone) string {
	if zone.Subnet == "" {
		return ""
	}

	_, subnet, err := net.ParseCIDR(zone.Subnet)
	if err != nil {
		return ""
	}

	maskBits, totalBits := subnet.Mask.Size()

	if ip4 := ip.To4(); ip4 != nil && totalBits == 32 {
		// IPv4
		// Calculate how many octets are in the zone name
		zoneOctets := maskBits / 8
		hostOctets := 4 - zoneOctets

		if hostOctets <= 0 {
			return ""
		}

		// Build the host part in reverse order
		var parts []string
		for i := 3; i >= zoneOctets; i-- {
			parts = append(parts, fmt.Sprintf("%d", ip4[i]))
		}
		// Reverse to get correct order (least significant first)
		for i := 0; i < len(parts)/2; i++ {
			parts[i], parts[len(parts)-1-i] = parts[len(parts)-1-i], parts[i]
		}
		return strings.Join(parts, ".")
	}

	if ip6 := ip.To16(); ip6 != nil && totalBits == 128 {
		// IPv6 - nibble format
		zoneNibbles := maskBits / 4
		hostNibbles := 32 - zoneNibbles

		if hostNibbles <= 0 {
			return ""
		}

		// Convert to full hex string (32 nibbles)
		hex := fmt.Sprintf("%032x", ip6)

		// Take host nibbles in reverse order
		var parts []string
		for i := 31; i >= zoneNibbles; i-- {
			parts = append(parts, string(hex[i]))
		}
		return strings.Join(parts, ".")
	}

	return ""
}

// CountRecords returns the total number of record sets in a zone.
func (s *Store) CountRecords(zoneName string) (int, error) {
	var count int

	err := s.db.View(func(tx *bolt.Tx) error {
		recordsBucket := tx.Bucket([]byte("records"))
		prefix := []byte(zoneName + ":")

		c := recordsBucket.Cursor()
		for k, _ := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, _ = c.Next() {
			count++
		}

		return nil
	})

	return count, err
}

// generateID creates a unique ID for records.
// Uses timestamp + random suffix for uniqueness.
func generateID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().UnixNano()%10000)
}

// BulkCreateRecords creates multiple records efficiently in a single transaction.
func (s *Store) BulkCreateRecords(records []Record) error {
	now := time.Now()

	return s.db.Update(func(tx *bolt.Tx) error {
		recordsBucket := tx.Bucket([]byte("records"))
		zonesBucket := tx.Bucket([]byte("zones"))

		// Track zones that need serial updates
		updatedZones := make(map[string]bool)

		for i := range records {
			record := &records[i]

			if record.ID == "" {
				record.ID = generateID()
			}
			if record.CreatedAt.IsZero() {
				record.CreatedAt = now
			}
			record.UpdatedAt = now

			key := recordKey(record.Zone, record.Name, record.Type)

			// Get existing records
			var existing []Record
			data := recordsBucket.Get([]byte(key))
			if data != nil {
				json.Unmarshal(data, &existing)
			}

			existing = append(existing, *record)

			data, err := json.Marshal(existing)
			if err != nil {
				return err
			}

			if err := recordsBucket.Put([]byte(key), data); err != nil {
				return err
			}

			updatedZones[record.Zone] = true

			// Handle PTR creation for A/AAAA
			if record.Type == "A" || record.Type == "AAAA" {
				zoneData := zonesBucket.Get([]byte(record.Zone))
				if zoneData != nil {
					var zone Zone
					if json.Unmarshal(zoneData, &zone) == nil {
						s.createPTRForRecord(tx, record, &zone)
					}
				}
			}
		}

		// Update zone serials
		for zoneName := range updatedZones {
			zoneData := zonesBucket.Get([]byte(zoneName))
			if zoneData != nil {
				var zone Zone
				if json.Unmarshal(zoneData, &zone) == nil {
					zone.Serial++
					zone.UpdatedAt = now
					data, _ := json.Marshal(&zone)
					zonesBucket.Put([]byte(zone.Name), data)
				}
			}
		}

		return nil
	})
}
