package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

// CreateUser creates a new user.
func (s *Store) CreateUser(user *User) error {
	if user.ID == "" {
		user.ID = GenerateID()
	}
	if user.Username == "" {
		return fmt.Errorf("username required")
	}
	if user.TenantID == "" {
		return fmt.Errorf("tenant ID required")
	}
	if user.Role == "" {
		user.Role = RoleUser
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		// Check tenant exists
		if tx.Bucket(BucketTenants).Get([]byte(user.TenantID)) == nil {
			return fmt.Errorf("tenant not found")
		}

		// Check username uniqueness
		users := tx.Bucket(BucketUsers)
		c := users.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var existing User
			if err := unmarshalJSON(v, &existing); err == nil {
				if strings.EqualFold(existing.Username, user.Username) {
					return ErrAlreadyExists
				}
			}
		}

		user.CreatedAt = time.Now().UTC()
		return putJSON(tx, BucketUsers, user.ID, user)
	})

	if err == nil {
		// Record change for sync (exclude password hash from sync data)
		syncUser := *user
		syncUser.PasswordHash = "" // Don't sync password hashes
		recordChange(EntityTypeUser, user.ID, user.TenantID, OpCreate, &syncUser)
	}

	return err
}

// CreateUserWithPassword creates a user with a hashed password.
func (s *Store) CreateUserWithPassword(user *User, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	user.PasswordHash = string(hash)
	return s.CreateUser(user)
}

// GetUser retrieves a user by ID.
func (s *Store) GetUser(id string) (*User, error) {
	var user User
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx, BucketUsers, id, &user)
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername retrieves a user by username.
func (s *Store) GetUserByUsername(username string) (*User, error) {
	var found *User

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketUsers)
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var user User
			if err := unmarshalJSON(v, &user); err == nil {
				if strings.EqualFold(user.Username, username) {
					found = &user
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

// UpdateUser updates an existing user.
func (s *Store) UpdateUser(user *User) error {
	if user.ID == "" {
		return fmt.Errorf("user ID required")
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketUsers)
		if b.Get([]byte(user.ID)) == nil {
			return ErrNotFound
		}

		return putJSON(tx, BucketUsers, user.ID, user)
	})

	if err == nil {
		// Record change for sync (exclude password hash)
		syncUser := *user
		syncUser.PasswordHash = ""
		recordChange(EntityTypeUser, user.ID, user.TenantID, OpUpdate, &syncUser)
	}

	return err
}

// UpdateUserPassword updates a user's password.
func (s *Store) UpdateUserPassword(userID, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		var user User
		if err := getJSON(tx, BucketUsers, userID, &user); err != nil {
			return err
		}

		user.PasswordHash = string(hash)
		return putJSON(tx, BucketUsers, userID, &user)
	})
}

// DeleteUser deletes a user.
func (s *Store) DeleteUser(id string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketUsers)
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}

		// Delete any sessions for this user
		sessions := tx.Bucket(BucketSessions)
		if sessions != nil {
			c := sessions.Cursor()
			var toDelete [][]byte
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var session Session
				if err := unmarshalJSON(v, &session); err == nil {
					if session.UserID == id {
						toDelete = append(toDelete, k)
					}
				}
			}
			for _, k := range toDelete {
				sessions.Delete(k)
			}
		}

		return delete(tx, BucketUsers, id)
	})

	if err == nil {
		// Record change for sync
		recordChange(EntityTypeUser, id, "", OpDelete, nil)
	}

	return err
}

// ListUsers returns all users, optionally filtered by tenant.
func (s *Store) ListUsers(tenantID string) ([]*User, error) {
	var users []*User

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketUsers)
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var user User
			if err := unmarshalJSON(v, &user); err != nil {
				return err
			}
			if tenantID == "" || user.TenantID == tenantID {
				// Don't return password hash in list
				user.PasswordHash = ""
				users = append(users, &user)
			}
			return nil
		})
	})

	return users, err
}

// ValidatePassword checks if the password matches the user's hash.
func (s *Store) ValidatePassword(username, password string) (*User, error) {
	user, err := s.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrUnauthorized
	}

	// Update last login
	user.LastLogin = time.Now().UTC()
	s.UpdateUser(user)

	return user, nil
}

// AddWebAuthnCredential adds a WebAuthn credential to a user.
func (s *Store) AddWebAuthnCredential(userID string, cred *WebAuthnCredential) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var user User
		if err := getJSON(tx, BucketUsers, userID, &user); err != nil {
			return err
		}

		cred.ID = GenerateID()
		cred.CreatedAt = time.Now().UTC()
		user.WebAuthnCredentials = append(user.WebAuthnCredentials, *cred)

		return putJSON(tx, BucketUsers, userID, &user)
	})
}

// RemoveWebAuthnCredential removes a WebAuthn credential from a user.
func (s *Store) RemoveWebAuthnCredential(userID, credID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var user User
		if err := getJSON(tx, BucketUsers, userID, &user); err != nil {
			return err
		}

		for i, cred := range user.WebAuthnCredentials {
			if cred.ID == credID {
				user.WebAuthnCredentials = append(
					user.WebAuthnCredentials[:i],
					user.WebAuthnCredentials[i+1:]...,
				)
				return putJSON(tx, BucketUsers, userID, &user)
			}
		}

		return ErrNotFound
	})
}

// UpdateWebAuthnCredentialSignCount updates the sign count after authentication.
func (s *Store) UpdateWebAuthnCredentialSignCount(userID string, credentialID []byte, signCount uint32) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var user User
		if err := getJSON(tx, BucketUsers, userID, &user); err != nil {
			return err
		}

		for i, cred := range user.WebAuthnCredentials {
			if subtle.ConstantTimeCompare(cred.CredentialID, credentialID) == 1 {
				user.WebAuthnCredentials[i].SignCount = signCount
				now := time.Now().UTC()
				user.WebAuthnCredentials[i].LastUsed = &now
				return putJSON(tx, BucketUsers, userID, &user)
			}
		}

		return ErrNotFound
	})
}

// GetUserByCredentialID finds a user by WebAuthn credential ID.
func (s *Store) GetUserByCredentialID(credentialID []byte) (*User, error) {
	var found *User

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketUsers)
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var user User
			if err := unmarshalJSON(v, &user); err == nil {
				for _, cred := range user.WebAuthnCredentials {
					if subtle.ConstantTimeCompare(cred.CredentialID, credentialID) == 1 {
						found = &user
						return nil
					}
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

// CountUsers returns the number of users, optionally filtered by tenant.
func (s *Store) CountUsers(tenantID string) (int, error) {
	count := 0

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketUsers)
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			if tenantID == "" {
				count++
			} else {
				var user User
				if err := unmarshalJSON(v, &user); err == nil {
					if user.TenantID == tenantID {
						count++
					}
				}
			}
			return nil
		})
	})

	return count, err
}

// GenerateAPIKey generates a new random API key.
func GenerateAPIKey() (key string, hash string, prefix string, err error) {
	// Generate 32 random bytes
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate random: %w", err)
	}

	// Encode as hex for the key
	key = hex.EncodeToString(b)

	// Hash it for storage
	h := sha256.Sum256([]byte(key))
	hash = hex.EncodeToString(h[:])

	// Prefix for display
	prefix = key[:8]

	return key, hash, prefix, nil
}

// HashAPIKey hashes an API key for comparison.
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
