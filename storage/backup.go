package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Backup represents a complete database backup.
type Backup struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Zones     []*Zone   `json:"zones,omitempty"`
	Records   []*Record `json:"records,omitempty"`
	Users     []*User   `json:"users,omitempty"`
	APIKeys   []*APIKey `json:"api_keys,omitempty"`
	Config    struct {
		Server    *ServerConfig    `json:"server,omitempty"`
		Recursion *RecursionConfig `json:"recursion,omitempty"`
		RateLimit *RateLimitConfig `json:"rate_limit,omitempty"`
		QueryLog  *QueryLogConfig  `json:"query_log,omitempty"`
		Transfer  *TransferConfig  `json:"transfer,omitempty"`
		OIDC      *OIDCConfig      `json:"oidc,omitempty"`
		WebAuthn  *WebAuthnConfig  `json:"webauthn,omitempty"`
		ACME      *ACMEConfig      `json:"acme,omitempty"`
	} `json:"config"`
	SecondaryZones []*SecondaryZone       `json:"secondary_zones,omitempty"`
	DNSSECKeys     map[string]*DNSSECKeys `json:"dnssec_keys,omitempty"`
}

// Export exports the entire database to JSON.
func (s *Store) Export(w io.Writer) error {
	backup := &Backup{
		Version:    "1.0",
		Timestamp:  time.Now(),
		DNSSECKeys: make(map[string]*DNSSECKeys),
	}

	err := s.db.View(func(tx *bolt.Tx) error {
		// Export zones
		zonesBucket := tx.Bucket(BucketZones)
		if zonesBucket != nil {
			zonesBucket.ForEach(func(k, v []byte) error {
				var zone Zone
				if err := json.Unmarshal(v, &zone); err == nil {
					backup.Zones = append(backup.Zones, &zone)
				}
				return nil
			})
		}

		// Export records
		recordsBucket := tx.Bucket(BucketRecords)
		if recordsBucket != nil {
			recordsBucket.ForEach(func(k, v []byte) error {
				var record Record
				if err := json.Unmarshal(v, &record); err == nil {
					backup.Records = append(backup.Records, &record)
				}
				return nil
			})
		}

		// Export users
		usersBucket := tx.Bucket(BucketUsers)
		if usersBucket != nil {
			usersBucket.ForEach(func(k, v []byte) error {
				var user User
				if err := json.Unmarshal(v, &user); err == nil {
					backup.Users = append(backup.Users, &user)
				}
				return nil
			})
		}

		// Export API keys
		apiKeysBucket := tx.Bucket(BucketAPIKeys)
		if apiKeysBucket != nil {
			apiKeysBucket.ForEach(func(k, v []byte) error {
				var key APIKey
				if err := json.Unmarshal(v, &key); err == nil {
					backup.APIKeys = append(backup.APIKeys, &key)
				}
				return nil
			})
		}

		// Export secondary zones
		secondaryBucket := tx.Bucket(BucketSecondaryZones)
		if secondaryBucket != nil {
			secondaryBucket.ForEach(func(k, v []byte) error {
				var sz SecondaryZone
				if err := json.Unmarshal(v, &sz); err == nil {
					backup.SecondaryZones = append(backup.SecondaryZones, &sz)
				}
				return nil
			})
		}

		// Export DNSSEC keys
		dnssecBucket := tx.Bucket(BucketDNSSECKeys)
		if dnssecBucket != nil {
			dnssecBucket.ForEach(func(k, v []byte) error {
				var keys DNSSECKeys
				if err := json.Unmarshal(v, &keys); err == nil {
					backup.DNSSECKeys[string(k)] = &keys
				}
				return nil
			})
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("export view: %w", err)
	}

	// Export configs
	if cfg, err := s.GetServerConfig(); err == nil {
		backup.Config.Server = cfg
	}
	if cfg, err := s.GetRecursionConfig(); err == nil {
		backup.Config.Recursion = cfg
	}
	if cfg, err := s.GetRateLimitConfig(); err == nil {
		backup.Config.RateLimit = cfg
	}
	if cfg, err := s.GetQueryLogConfig(); err == nil {
		backup.Config.QueryLog = cfg
	}
	if cfg, err := s.GetTransferConfig(); err == nil {
		backup.Config.Transfer = cfg
	}
	if cfg, err := s.GetOIDCConfig(); err == nil {
		backup.Config.OIDC = cfg
	}
	if cfg, err := s.GetWebAuthnConfig(); err == nil {
		backup.Config.WebAuthn = cfg
	}
	if cfg, err := s.GetACMEConfig(); err == nil {
		backup.Config.ACME = cfg
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(backup)
}

// Import imports data from a JSON backup.
func (s *Store) Import(r io.Reader, overwrite bool) error {
	var backup Backup
	if err := json.NewDecoder(r).Decode(&backup); err != nil {
		return fmt.Errorf("decode backup: %w", err)
	}

	// Import zones
	for _, zone := range backup.Zones {
		existing, _ := s.GetZone(zone.Name)
		if existing != nil && !overwrite {
			continue
		}
		if err := s.CreateZone(zone); err != nil && overwrite {
			s.UpdateZone(zone)
		}
	}

	// Import records
	for _, record := range backup.Records {
		existing, _ := s.GetRecords(record.Zone, record.Name, record.Type)
		if existing != nil && !overwrite {
			continue
		}
		if err := s.CreateRecord(record); err != nil && overwrite {
			s.UpdateRecord(record)
		}
	}

	// Import users
	for _, user := range backup.Users {
		existing, _ := s.GetUser(user.ID)
		if existing != nil && !overwrite {
			continue
		}
		if err := s.CreateUser(user); err != nil && overwrite {
			s.UpdateUser(user)
		}
	}

	// Import API keys
	for _, key := range backup.APIKeys {
		existing, _ := s.GetAPIKey(key.ID)
		if existing != nil && !overwrite {
			continue
		}
		if err := s.CreateAPIKey(key); err != nil && overwrite {
			// No update for API keys - delete and recreate
			s.DeleteAPIKey(key.ID)
			s.CreateAPIKey(key)
		}
	}

	// Import secondary zones
	for _, sz := range backup.SecondaryZones {
		existing, _ := s.GetSecondaryZone(sz.Zone)
		if existing != nil && !overwrite {
			continue
		}
		if err := s.CreateSecondaryZone(sz); err != nil && overwrite {
			s.DeleteSecondaryZone(sz.Zone)
			s.CreateSecondaryZone(sz)
		}
	}

	// Import DNSSEC keys
	for zone, keys := range backup.DNSSECKeys {
		keys.ZoneName = zone
		if err := s.SaveDNSSECKeys(keys); err != nil {
			return fmt.Errorf("import dnssec keys for %s: %w", zone, err)
		}
	}

	// Import configs
	if backup.Config.Server != nil {
		s.UpdateServerConfig(backup.Config.Server)
	}
	if backup.Config.Recursion != nil {
		s.UpdateRecursionConfig(backup.Config.Recursion)
	}
	if backup.Config.RateLimit != nil {
		s.UpdateRateLimitConfig(backup.Config.RateLimit)
	}
	if backup.Config.QueryLog != nil {
		s.UpdateQueryLogConfig(backup.Config.QueryLog)
	}
	if backup.Config.Transfer != nil {
		s.UpdateTransferConfig(backup.Config.Transfer)
	}
	if backup.Config.OIDC != nil {
		s.UpdateOIDCConfig(backup.Config.OIDC)
	}
	if backup.Config.WebAuthn != nil {
		s.UpdateWebAuthnConfig(backup.Config.WebAuthn)
	}
	if backup.Config.ACME != nil {
		s.UpdateACMEConfig(backup.Config.ACME)
	}

	return nil
}

// ExportZoneFile exports a zone in BIND zone file format.
func (s *Store) ExportZoneFile(zoneName string, w io.Writer) error {
	zone, err := s.GetZone(zoneName)
	if err != nil {
		return fmt.Errorf("get zone: %w", err)
	}

	records, err := s.GetAllZoneRecords(zoneName)
	if err != nil {
		return fmt.Errorf("list records: %w", err)
	}

	// Write header
	fmt.Fprintf(w, "; Zone file for %s\n", zoneName)
	fmt.Fprintf(w, "; Exported at %s\n\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "$ORIGIN %s\n", zoneName)
	fmt.Fprintf(w, "$TTL %d\n\n", zone.TTL)

	// Write SOA
	fmt.Fprintf(w, "@ IN SOA %s %s (\n", zone.PrimaryNS, zone.AdminEmail)
	fmt.Fprintf(w, "    %d ; serial\n", zone.Serial)
	fmt.Fprintf(w, "    %d ; refresh\n", zone.Refresh)
	fmt.Fprintf(w, "    %d ; retry\n", zone.Retry)
	fmt.Fprintf(w, "    %d ; expire\n", zone.Expire)
	fmt.Fprintf(w, "    %d ; minimum\n", zone.Minimum)
	fmt.Fprintf(w, ")\n\n")

	// Write records
	for _, record := range records {
		name := record.Name
		if name == zoneName || name == zoneName+"." {
			name = "@"
		} else {
			// Make relative to zone
			if len(name) > len(zoneName) {
				name = name[:len(name)-len(zoneName)-1]
			}
		}

		line, err := formatRecordLine(name, &record)
		if err != nil {
			fmt.Fprintf(w, "; Error formatting %s %s: %v\n", record.Name, record.Type, err)
			continue
		}
		fmt.Fprintf(w, "%s\n", line)
	}

	return nil
}

func formatRecordLine(name string, record *Record) (string, error) {
	switch record.Type {
	case "A":
		var data ARecordData
		if err := json.Unmarshal(record.Data, &data); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s %d IN A %s", name, record.TTL, data.IP), nil

	case "AAAA":
		var data AAAARecordData
		if err := json.Unmarshal(record.Data, &data); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s %d IN AAAA %s", name, record.TTL, data.IP), nil

	case "CNAME":
		var data CNAMERecordData
		if err := json.Unmarshal(record.Data, &data); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s %d IN CNAME %s", name, record.TTL, data.Target), nil

	case "MX":
		var data MXRecordData
		if err := json.Unmarshal(record.Data, &data); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s %d IN MX %d %s", name, record.TTL, data.Priority, data.Target), nil

	case "NS":
		var data NSRecordData
		if err := json.Unmarshal(record.Data, &data); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s %d IN NS %s", name, record.TTL, data.Target), nil

	case "TXT":
		var data TXTRecordData
		if err := json.Unmarshal(record.Data, &data); err != nil {
			return "", err
		}
		values := ""
		for i, v := range data.Values {
			if i > 0 {
				values += " "
			}
			values += fmt.Sprintf("\"%s\"", v)
		}
		return fmt.Sprintf("%s %d IN TXT %s", name, record.TTL, values), nil

	case "SRV":
		var data SRVRecordData
		if err := json.Unmarshal(record.Data, &data); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s %d IN SRV %d %d %d %s",
			name, record.TTL, data.Priority, data.Weight, data.Port, data.Target), nil

	case "CAA":
		var data CAARecordData
		if err := json.Unmarshal(record.Data, &data); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s %d IN CAA %d %s \"%s\"",
			name, record.TTL, data.Flag, data.Tag, data.Value), nil

	default:
		return fmt.Sprintf("; %s %d IN %s (unsupported)", name, record.TTL, record.Type), nil
	}
}
