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

// putRedirect writes the rule and records the change for cluster sync.
//
// Redirect rules were previously stored without recording a sync change, so
// they never replicated: a rule added on one server stayed on that server and
// the cluster answered the same name differently depending on which node a
// client happened to use. That is how a SafeSearch rule ended up on two of
// five resolvers, making a Google service host resolve to the SafeSearch VIP
// on some servers and correctly on others.
func (s *Store) putRedirect(rule *RedirectRule, op string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
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
	if err == nil {
		recordChange(EntityTypeRedirect, rule.ID, "", op, rule)
	}
	return err
}

// CreateRedirect creates a new redirect rule
func (s *Store) CreateRedirect(rule *RedirectRule) error {
	return s.putRedirect(rule, OpCreate)
}

// UpdateRedirect updates an existing redirect rule
func (s *Store) UpdateRedirect(rule *RedirectRule) error {
	return s.putRedirect(rule, OpUpdate)
}

// DeleteRedirect deletes a redirect rule by ID
func (s *Store) DeleteRedirect(id string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketRedirects)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	})
	if err == nil {
		recordChange(EntityTypeRedirect, id, "", OpDelete, nil)
	}
	return err
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

	// Double wildcard: *.google.* - "the label google, under any TLD".
	//
	// This must stay anchored to the end of the name. An earlier version tested
	// strings.Contains(domain, ".google.") || strings.HasPrefix(domain,
	// "google."), which matches any name that merely has a google label
	// somewhere - including google.com.example.com, a domain Google does not
	// own. A redirect rule built on that pattern silently hijacks third-party
	// names.
	if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(pattern, ".*") {
		middle := pattern[2 : len(pattern)-2] // "google"
		return matchesLabelUnderTLD(domain, middle)
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

	// Wildcard at end: google.* or www.google.* - the name IS <prefix>.<tld>,
	// not merely a name beginning with the prefix. Matching on prefix alone
	// would accept google.com.example.com.
	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-2] // "google" or "www.google"
		if rest, ok := strings.CutPrefix(domain, prefix+"."); ok {
			// What follows must be a public suffix and nothing more.
			if n := len(strings.Split(rest, ".")); n >= 1 && n <= 2 {
				return true
			}
		}
	}

	return false
}

// matchesLabelUnderTLD reports whether label appears as a domain label that is
// followed only by a public suffix - so "google" matches google.com,
// www.google.com and google.co.uk, but not google.com.example.com.
//
// There is no public suffix list here, so the suffix is approximated as at most
// two trailing labels. That covers com, net, co.uk, com.au and the like. The
// approximation is deliberately conservative: erring towards NOT matching
// leaves a name resolving normally, whereas erring the other way silently
// redirects somebody else's domain.
func matchesLabelUnderTLD(domain, label string) bool {
	if label == "" {
		return false
	}
	parts := strings.Split(domain, ".")
	for i, p := range parts {
		if p != label {
			continue
		}
		if trailing := len(parts) - i - 1; trailing >= 1 && trailing <= 2 {
			return true
		}
	}
	return false
}
