package storage

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// CreateTenant creates a new tenant.
func (s *Store) CreateTenant(tenant *Tenant) error {
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID required")
	}
	if tenant.Name == "" {
		return fmt.Errorf("tenant name required")
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketTenants)

		// Check if already exists
		if b.Get([]byte(tenant.ID)) != nil {
			return ErrAlreadyExists
		}

		tenant.CreatedAt = time.Now().UTC()
		return putJSON(tx, BucketTenants, tenant.ID, tenant)
	})

	if err == nil {
		recordChange(EntityTypeTenant, tenant.ID, tenant.ID, OpCreate, tenant)
	}

	return err
}

// GetTenant retrieves a tenant by ID.
func (s *Store) GetTenant(id string) (*Tenant, error) {
	var tenant Tenant
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx, BucketTenants, id, &tenant)
	})
	if err != nil {
		return nil, err
	}
	return &tenant, nil
}

// UpdateTenant updates an existing tenant.
func (s *Store) UpdateTenant(tenant *Tenant) error {
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID required")
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketTenants)

		// Check if exists
		if b.Get([]byte(tenant.ID)) == nil {
			return ErrNotFound
		}

		return putJSON(tx, BucketTenants, tenant.ID, tenant)
	})

	if err == nil {
		recordChange(EntityTypeTenant, tenant.ID, tenant.ID, OpUpdate, tenant)
	}

	return err
}

// DeleteTenant deletes a tenant.
// This will fail if the tenant has any zones, users, or other resources.
func (s *Store) DeleteTenant(id string) error {
	if id == MainTenantID {
		return fmt.Errorf("cannot delete main tenant")
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		// Check if tenant exists
		b := tx.Bucket(BucketTenants)
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}

		// Check for zones owned by this tenant
		zones := tx.Bucket(BucketZones)
		if zones != nil {
			c := zones.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var zone Zone
				if err := unmarshalJSON(v, &zone); err == nil {
					if zone.TenantID == id {
						return fmt.Errorf("tenant has zones - delete zones first")
					}
				}
			}
		}

		// Check for users in this tenant
		users := tx.Bucket(BucketUsers)
		if users != nil {
			c := users.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var user User
				if err := unmarshalJSON(v, &user); err == nil {
					if user.TenantID == id {
						return fmt.Errorf("tenant has users - delete users first")
					}
				}
			}
		}

		return delete(tx, BucketTenants, id)
	})

	if err == nil {
		recordChange(EntityTypeTenant, id, id, OpDelete, nil)
	}

	return err
}

// ListTenants returns all tenants.
func (s *Store) ListTenants() ([]*Tenant, error) {
	var tenants []*Tenant

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketTenants)
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var tenant Tenant
			if err := unmarshalJSON(v, &tenant); err != nil {
				return err
			}
			tenants = append(tenants, &tenant)
			return nil
		})
	})

	return tenants, err
}

// unmarshalJSON is a helper that wraps json.Unmarshal
func unmarshalJSON(data []byte, v interface{}) error {
	if data == nil {
		return ErrNotFound
	}
	return json.Unmarshal(data, v)
}
