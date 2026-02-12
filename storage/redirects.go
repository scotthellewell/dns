package storage

import (
	"encoding/json"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// RedirectRule represents a DNS redirect/rewrite rule
type RedirectRule struct {
	ID          string `json:"id"`          // Unique identifier
	MatchDomain string `json:"match"`       // Domain to match (supports wildcards like *.google.com)
	TargetHost  string `json:"target"`      // Domain/IP to redirect to
	Enabled     bool   `json:"enabled"`     // Whether the rule is active
	Description string `json:"description"` // Human-readable description
}

// GetRedirect retrieves a redirect rule by ID
func (s *Store) GetRedirect(id string) (*RedirectRule, error) {
	var rule RedirectRule
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketRedirects)
		if b == nil {
			return nil
		}
		data := b.Get([]byte(id))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &rule)
	})
	if err != nil {
		return nil, err
	}
	if rule.ID == "" {
		return nil, nil
	}
	return &rule, nil
}

// CreateRedirect creates a new redirect rule
func (s *Store) CreateRedirect(rule *RedirectRule) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(BucketRedirects)
		if err != nil {
			return err
		}
		data, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		return b.Put([]byte(rule.ID), data)
	})
}

// UpdateRedirect updates an existing redirect rule
func (s *Store) UpdateRedirect(rule *RedirectRule) error {
	return s.CreateRedirect(rule)
}

// DeleteRedirect deletes a redirect rule by ID
func (s *Store) DeleteRedirect(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketRedirects)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	})
}

// ListRedirects returns all redirect rules
func (s *Store) ListRedirects() ([]*RedirectRule, error) {
	var rules []*RedirectRule
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketRedirects)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var rule RedirectRule
			if err := json.Unmarshal(v, &rule); err != nil {
				return err
			}
			rules = append(rules, &rule)
			return nil
		})
	})
	return rules, err
}

// GetEnabledRedirects returns only enabled redirect rules
func (s *Store) GetEnabledRedirects() ([]*RedirectRule, error) {
	all, err := s.ListRedirects()
	if err != nil {
		return nil, err
	}
	var enabled []*RedirectRule
	for _, r := range all {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	return enabled, nil
}

// MatchRedirect finds a redirect rule that matches the given domain
// Returns nil if no match found
func (s *Store) MatchRedirect(domain string) (*RedirectRule, error) {
	rules, err := s.GetEnabledRedirects()
	if err != nil {
		return nil, err
	}
	
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	
	for _, rule := range rules {
		if matchDomain(rule.MatchDomain, domain) {
			return rule, nil
		}
	}
	return nil, nil
}

// matchDomain checks if domain matches the pattern
// Supports:
// - Exact match: "google.com" matches "google.com"
// - Wildcard: "*.google.com" matches "www.google.com", "mail.google.com"
// - TLD wildcard: "google.*" matches "google.com", "google.co.uk"
// - Double wildcard: "*.google.*" matches "www.google.com", "www.google.co.uk"
func matchDomain(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	
	// Exact match
	if pattern == domain {
		return true
	}
	
	// Double wildcard: *.google.*
	if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(pattern, ".*") {
		// Extract the middle part: "google" from "*.google.*"
		middle := pattern[2:len(pattern)-2] // "google"
		// Check if domain contains ".google." or starts with "google."
		return strings.Contains(domain, "."+middle+".") || 
		       strings.HasPrefix(domain, middle+".") ||
		       domain == middle
	}
	
	// Wildcard at start: *.google.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".google.com"
		if strings.HasSuffix(domain, suffix) {
			return true
		}
		// Also match the base domain (*.google.com should match google.com)
		if domain == pattern[2:] {
			return true
		}
	}
	
	// Wildcard at end: google.*
	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-2] + "." // "google."
		if strings.HasPrefix(domain, prefix) {
			return true
		}
	}
	
	return false
}
