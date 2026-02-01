package storage

import (
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// CreateSession creates a new session.
func (s *Store) CreateSession(session *Session) error {
	if session.ID == "" {
		return fmt.Errorf("session ID required")
	}
	if session.UserID == "" {
		return fmt.Errorf("user ID required")
	}

	session.CreatedAt = time.Now().UTC()
	if session.ExpiresAt.IsZero() {
		session.ExpiresAt = session.CreatedAt.Add(24 * time.Hour)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx, BucketSessions, session.ID, session)
	})
}

// GetSession retrieves a session by ID.
func (s *Store) GetSession(id string) (*Session, error) {
	var session Session
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx, BucketSessions, id, &session)
	})
	if err != nil {
		return nil, err
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		// Delete expired session
		s.DeleteSession(id)
		return nil, ErrNotFound
	}

	return &session, nil
}

// DeleteSession deletes a session.
func (s *Store) DeleteSession(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return delete(tx, BucketSessions, id)
	})
}

// DeleteUserSessions deletes all sessions for a user.
func (s *Store) DeleteUserSessions(userID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketSessions)
		if b == nil {
			return nil
		}

		c := b.Cursor()
		var toDelete [][]byte
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var session Session
			if err := unmarshalJSON(v, &session); err == nil {
				if session.UserID == userID {
					toDelete = append(toDelete, k)
				}
			}
		}

		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
		}

		return nil
	})
}

// CleanupExpiredSessions removes all expired sessions.
func (s *Store) CleanupExpiredSessions() (int, error) {
	count := 0

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketSessions)
		if b == nil {
			return nil
		}

		now := time.Now()
		c := b.Cursor()
		var toDelete [][]byte

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var session Session
			if err := unmarshalJSON(v, &session); err == nil {
				if now.After(session.ExpiresAt) {
					toDelete = append(toDelete, k)
				}
			}
		}

		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
			count++
		}

		return nil
	})

	return count, err
}

// ListUserSessions returns all sessions for a user.
func (s *Store) ListUserSessions(userID string) ([]*Session, error) {
	var sessions []*Session

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketSessions)
		if b == nil {
			return nil
		}

		now := time.Now()
		return b.ForEach(func(k, v []byte) error {
			var session Session
			if err := unmarshalJSON(v, &session); err != nil {
				return err
			}
			if session.UserID == userID && now.Before(session.ExpiresAt) {
				sessions = append(sessions, &session)
			}
			return nil
		})
	})

	return sessions, err
}

// ExtendSession extends a session's expiry time.
func (s *Store) ExtendSession(id string, duration time.Duration) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var session Session
		if err := getJSON(tx, BucketSessions, id, &session); err != nil {
			return err
		}

		session.ExpiresAt = time.Now().Add(duration)
		return putJSON(tx, BucketSessions, id, &session)
	})
}
