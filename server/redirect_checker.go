package server

import (
	"log"
	"strings"
	"sync"

	"github.com/scott/dns/storage"
)

// StorageRedirectChecker implements RedirectChecker using storage backend
type StorageRedirectChecker struct {
	store *storage.Store
	mu    sync.RWMutex
	cache map[string]string // domain -> target cache
}

// NewStorageRedirectChecker creates a redirect checker backed by storage
func NewStorageRedirectChecker(store *storage.Store) *StorageRedirectChecker {
	return &StorageRedirectChecker{
		store: store,
		cache: make(map[string]string),
	}
}

// Match checks if a domain matches any redirect rule
func (rc *StorageRedirectChecker) Match(domain string) (targetHost string, found bool) {
	if rc.store == nil {
		return "", false
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	rule, err := rc.store.MatchRedirect(domain)
	if err != nil {
		log.Printf("[redirect] Error matching redirect: %v", err)
		return "", false
	}

	if rule == nil {
		return "", false
	}

	return rule.TargetHost, true
}

// InvalidateCache clears the redirect cache (call when rules change)
func (rc *StorageRedirectChecker) InvalidateCache() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.cache = make(map[string]string)
}
