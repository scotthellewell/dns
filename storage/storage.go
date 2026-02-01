// Package storage provides persistent storage using bbolt database.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bucket names
var (
	BucketTenants        = []byte("tenants")
	BucketUsers          = []byte("users")
	BucketAPIKeys        = []byte("api_keys")
	BucketSessions       = []byte("sessions")
	BucketZones          = []byte("zones")
	BucketRecords        = []byte("records")
	BucketDNSSECKeys     = []byte("dnssec_keys")
	BucketDelegations    = []byte("delegations")
	BucketSecondaryZones = []byte("secondary_zones")
	BucketViews          = []byte("views")
	BucketBlocklist      = []byte("blocklist")
	BucketConfig         = []byte("config")
	BucketSettings       = []byte("settings")
	BucketCertificates   = []byte("certificates")
	BucketCache          = []byte("cache")
	BucketAudit          = []byte("audit")
	BucketQueryLog       = []byte("query_log")
	BucketMetrics        = []byte("metrics")
	BucketIndexes        = []byte("indexes")
	BucketSyncOpLog      = []byte("sync_oplog")
	BucketSyncPeers      = []byte("sync_peers")
)

// All buckets to create on init
var allBuckets = [][]byte{
	BucketTenants,
	BucketUsers,
	BucketAPIKeys,
	BucketSessions,
	BucketZones,
	BucketRecords,
	BucketDNSSECKeys,
	BucketDelegations,
	BucketSecondaryZones,
	BucketViews,
	BucketBlocklist,
	BucketConfig,
	BucketSettings,
	BucketCertificates,
	BucketCache,
	BucketAudit,
	BucketQueryLog,
	BucketMetrics,
	BucketIndexes,
	BucketSyncOpLog,
	BucketSyncPeers,
}

// Certificate keys
const (
	CertKeyTLS         = "tls"
	CertKeyACMEConfig  = "acme_config"
	CertKeyACMEState   = "acme_state"
	CertKeyACMEAccount = "acme_account"
)

// Index sub-bucket names
const (
	IndexReverseZones = "reverse_zones"
	IndexPTRSources   = "ptr_sources"
)

// Store is the main storage interface backed by bbolt.
type Store struct {
	db        *bolt.DB
	dataDir   string
	mu        sync.RWMutex
	zoneCache map[string]*Zone // In-memory zone cache for fast lookups
}

// Options configures the Store.
type Options struct {
	// DataDir is the directory where data.db will be created.
	// Defaults to ~/.dns-server
	DataDir string
}

// DefaultDataDir returns the default data directory.
func DefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".dns-server"
	}
	return filepath.Join(home, ".dns-server")
}

// Open opens or creates a new Store.
func Open(opts Options) (*Store, error) {
	if opts.DataDir == "" {
		opts.DataDir = DefaultDataDir()
	}

	// Create data directory if needed
	if err := os.MkdirAll(opts.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(opts.DataDir, "data.db")

	// Check if this is a new database
	isNew := false
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		isNew = true
	}

	// Open bbolt database
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	s := &Store{
		db:        db,
		dataDir:   opts.DataDir,
		zoneCache: make(map[string]*Zone),
	}

	// Initialize buckets
	if err := s.initBuckets(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize buckets: %w", err)
	}

	// If new database, create default data
	if isNew {
		if err := s.initDefaults(); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to initialize defaults: %w", err)
		}
	}

	// Load zone cache
	if err := s.refreshZoneCache(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load zone cache: %w", err)
	}

	return s, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// DataDir returns the data directory path.
func (s *Store) DataDir() string {
	return s.dataDir
}

// DB returns the underlying bbolt database for sync operations
func (s *Store) DB() *bolt.DB {
	return s.db
}

// initBuckets creates all required buckets.
func (s *Store) initBuckets() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return fmt.Errorf("create bucket %s: %w", bucket, err)
			}
		}

		// Create index sub-buckets
		indexes, err := tx.CreateBucketIfNotExists(BucketIndexes)
		if err != nil {
			return fmt.Errorf("create indexes bucket: %w", err)
		}
		if _, err := indexes.CreateBucketIfNotExists([]byte(IndexReverseZones)); err != nil {
			return fmt.Errorf("create reverse_zones index: %w", err)
		}
		if _, err := indexes.CreateBucketIfNotExists([]byte(IndexPTRSources)); err != nil {
			return fmt.Errorf("create ptr_sources index: %w", err)
		}

		return nil
	})
}

// initDefaults creates default data for a new database.
func (s *Store) initDefaults() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		// Create main tenant
		mainTenant := &Tenant{
			ID:        MainTenantID,
			Name:      "Main",
			IsMain:    true,
			CreatedAt: time.Now().UTC(),
		}
		if err := putJSON(tx, BucketTenants, MainTenantID, mainTenant); err != nil {
			return fmt.Errorf("create main tenant: %w", err)
		}

		// Create default server config
		serverConfig := &ServerConfig{
			DNS: DNSConfig{
				Enabled: true,
				UDPPort: 53,
				TCPPort: 53,
				Address: "",
			},
			DoT: DoTConfig{
				Enabled: true,
				Port:    853,
				Address: "",
			},
			DoH: DoHConfig{
				Enabled: true,
				Path:    "/dns-query",
			},
			Web: WebConfig{
				Enabled: true,
				Port:    443,
				Address: "",
				TLS:     true,
			},
		}
		if err := putJSON(tx, BucketConfig, ConfigKeyServer, serverConfig); err != nil {
			return fmt.Errorf("create server config: %w", err)
		}

		// Create default recursion config (disabled)
		recursionConfig := &RecursionConfig{
			Enabled:  false,
			Mode:     "disabled",
			Upstream: []string{},
			Timeout:  5,
			MaxDepth: 10,
		}
		if err := putJSON(tx, BucketConfig, ConfigKeyRecursion, recursionConfig); err != nil {
			return fmt.Errorf("create recursion config: %w", err)
		}

		// Create default rate limit config
		rateLimitConfig := &RateLimitConfig{
			Enabled:         true,
			ResponsesPerSec: 10,
			SlipRatio:       2,
			WindowSeconds:   1,
			WhitelistCIDRs:  []string{"127.0.0.1/8", "::1/128"},
		}
		if err := putJSON(tx, BucketConfig, ConfigKeyRateLimit, rateLimitConfig); err != nil {
			return fmt.Errorf("create rate limit config: %w", err)
		}

		return nil
	})
}

// refreshZoneCache loads all zones into memory for fast lookups.
func (s *Store) refreshZoneCache() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.zoneCache = make(map[string]*Zone)

	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketZones)
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var zone Zone
			if err := json.Unmarshal(v, &zone); err != nil {
				return fmt.Errorf("unmarshal zone %s: %w", k, err)
			}
			s.zoneCache[string(k)] = &zone
			return nil
		})
	})
}

// Transaction helpers

// putJSON marshals value as JSON and stores it in bucket with key.
func putJSON(tx *bolt.Tx, bucketName []byte, key string, value interface{}) error {
	b := tx.Bucket(bucketName)
	if b == nil {
		return fmt.Errorf("bucket %s not found", bucketName)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return b.Put([]byte(key), data)
}

// getJSON retrieves a value from bucket and unmarshals it.
func getJSON(tx *bolt.Tx, bucketName []byte, key string, dest interface{}) error {
	b := tx.Bucket(bucketName)
	if b == nil {
		return fmt.Errorf("bucket %s not found", bucketName)
	}
	data := b.Get([]byte(key))
	if data == nil {
		return ErrNotFound
	}
	return json.Unmarshal(data, dest)
}

// delete removes a key from bucket.
func delete(tx *bolt.Tx, bucketName []byte, key string) error {
	b := tx.Bucket(bucketName)
	if b == nil {
		return fmt.Errorf("bucket %s not found", bucketName)
	}
	return b.Delete([]byte(key))
}

// Utility functions

// GenerateID generates a unique ID with timestamp prefix for ordering.
func GenerateID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomString(8))
}

// randomString generates a random alphanumeric string.
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(time.Nanosecond) // Ensure different values
	}
	return string(b)
}
