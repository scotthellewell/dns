package storage

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// DDNSHost is a name a client may point at its own address with a token,
// dyndns style. The token itself is never stored, only its SHA-256 hash.
type DDNSHost struct {
	ID          string    `json:"id"`         // FQDN, lower case, no trailing dot
	Zone        string    `json:"zone"`       // Zone holding the record
	Name        string    `json:"name"`       // Record name relative to the zone
	TTL         uint32    `json:"ttl"`        // TTL for the A/AAAA record
	TokenHash   string    `json:"token_hash"` // Hex SHA-256 of the token
	Description string    `json:"description,omitempty"`
	LastIP      string    `json:"last_ip,omitempty"` // Address last set by the client
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DDNSHostID returns the ID (FQDN) for a record name in a zone.
func DDNSHostID(zone, name string) string {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" || name == "@" {
		return zone
	}
	return name + "." + zone
}

// GetDDNSHost returns the host with the given ID, or nil if there is none.
func (s *Store) GetDDNSHost(id string) (*DDNSHost, error) {
	var host *DDNSHost
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketDDNSHosts)
		if b == nil {
			return nil
		}
		data := b.Get([]byte(id))
		if data == nil {
			return nil
		}
		host = &DDNSHost{}
		return json.Unmarshal(data, host)
	})
	return host, err
}

// ListDDNSHosts returns all DDNS hosts.
func (s *Store) ListDDNSHosts() ([]*DDNSHost, error) {
	var hosts []*DDNSHost
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketDDNSHosts)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var h DDNSHost
			if err := json.Unmarshal(v, &h); err != nil {
				return err
			}
			hosts = append(hosts, &h)
			return nil
		})
	})
	return hosts, err
}

// PutDDNSHost creates or replaces a host and records the change for cluster
// sync, so a token issued on one server works on all of them.
func (s *Store) PutDDNSHost(host *DDNSHost) error {
	if host.ID == "" || host.Zone == "" || host.TokenHash == "" {
		return fmt.Errorf("ddns host needs an ID, zone and token hash")
	}
	op := OpUpdate
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(BucketDDNSHosts)
		if err != nil {
			return err
		}
		if b.Get([]byte(host.ID)) == nil {
			op = OpCreate
		}
		data, err := json.Marshal(host)
		if err != nil {
			return err
		}
		return b.Put([]byte(host.ID), data)
	})
	if err == nil {
		recordChange(EntityTypeDDNSHost, host.ID, "", op, host)
	}
	return err
}

// DeleteDDNSHost removes a host. Its DNS record is left in place.
func (s *Store) DeleteDDNSHost(id string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketDDNSHosts)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	})
	if err == nil {
		recordChange(EntityTypeDDNSHost, id, "", OpDelete, nil)
	}
	return err
}
