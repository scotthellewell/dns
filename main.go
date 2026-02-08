package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scott/dns/api"
	"github.com/scott/dns/auth"
	"github.com/scott/dns/certs"
	"github.com/scott/dns/config"
	"github.com/scott/dns/ports"
	"github.com/scott/dns/secondary"
	"github.com/scott/dns/server"
	"github.com/scott/dns/storage"
	"github.com/scott/dns/sync"
	bolt "go.etcd.io/bbolt"
)

// secondaryCacheAdapter adapts storage.Store to secondary.CacheStore interface
type secondaryCacheAdapter struct {
	store *storage.Store
}

func (a *secondaryCacheAdapter) SaveSecondaryZoneCache(cache *secondary.ZoneCache) error {
	return a.store.SaveSecondaryZoneCache(&storage.SecondaryZoneCache{
		Zone:      cache.Zone,
		Serial:    cache.Serial,
		Records:   cache.Records,
		LastSync:  cache.LastSync,
		UpdatedAt: cache.UpdatedAt,
	})
}

func (a *secondaryCacheAdapter) GetSecondaryZoneCache(zone string) (*secondary.ZoneCache, error) {
	c, err := a.store.GetSecondaryZoneCache(zone)
	if err != nil {
		return nil, err
	}
	return &secondary.ZoneCache{
		Zone:      c.Zone,
		Serial:    c.Serial,
		Records:   c.Records,
		LastSync:  c.LastSync,
		UpdatedAt: c.UpdatedAt,
	}, nil
}

func (a *secondaryCacheAdapter) DeleteSecondaryZoneCache(zone string) error {
	return a.store.DeleteSecondaryZoneCache(zone)
}

// dnssecKeyStoreAdapter adapts storage.Store to server.DNSSECKeyStore interface
type dnssecKeyStoreAdapter struct {
	store *storage.Store
}

func (a *dnssecKeyStoreAdapter) GetDNSSECKeys(zoneName string) (server.DNSSECKeyData, error) {
	return a.store.GetDNSSECKeys(zoneName)
}

func (a *dnssecKeyStoreAdapter) ListZonesWithDNSSEC() ([]string, error) {
	return a.store.ListZonesWithDNSSEC()
}

func main() {
	dataDir := flag.String("data", "./data", "Data directory for bbolt database")
	flag.Parse()

	log.Printf("DNS Server starting with data directory: %s", *dataDir)

	// Open storage
	store, err := storage.Open(storage.Options{DataDir: *dataDir})
	if err != nil {
		log.Fatalf("Failed to open storage: %v", err)
	}
	defer store.Close()

	log.Printf("Storage initialized at %s", store.DataDir())

	// Initialize cluster sync manager (always, so API endpoints work)
	var syncMgr *sync.Manager
	syncConfig := loadSyncConfig(store)
	if syncConfig == nil {
		// Create default disabled config
		syncConfig = &config.SyncConfig{Enabled: false}
	}
	syncMgr = initSyncManager(store, syncConfig)
	if syncMgr != nil && syncConfig.Enabled {
		log.Printf("Cluster sync enabled with node ID: %s", syncConfig.NodeID)
	}

	// Build parsed config from storage
	parsed, err := store.BuildParsedConfig()
	if err != nil {
		log.Fatalf("Failed to build config from storage: %v", err)
	}

	log.Printf("Loaded %d zones from storage", len(parsed.Zones))

	// Create DNS server
	srv := server.New(parsed)

	// Set up secondary zone cache persistence
	srv.SetSecondaryCacheStore(&secondaryCacheAdapter{store: store})

	// Set up DNSSEC key store for loading keys from database
	srv.SetDNSSECKeyStore(&dnssecKeyStoreAdapter{store: store})

	// Load DNSSEC keys from storage (database) instead of file system
	if err := srv.LoadDNSSECFromStorage(); err != nil {
		log.Printf("Warning: Failed to load DNSSEC keys from storage: %v", err)
	}

	// Set up DNSSEC key fetch callback for secondary zones
	secondary.SetKeyFetchCallback(func(zone string, keys *secondary.DNSSECKeyData) error {
		// Store the fetched keys in storage
		dnssecKeys := &storage.DNSSECKeys{
			ZoneName:   zone,
			Algorithm:  keys.Algorithm,
			Enabled:    keys.Enabled,
			KSKPrivate: keys.KSKPrivate,
			KSKPublic:  keys.KSKPublic,
			KSKKeyTag:  keys.KSKKeyTag,
			ZSKPrivate: keys.ZSKPrivate,
			ZSKPublic:  keys.ZSKPublic,
			ZSKKeyTag:  keys.ZSKKeyTag,
			DSRecord:   keys.DSRecord,
		}
		if err := store.SaveDNSSECKeys(dnssecKeys); err != nil {
			return err
		}
		log.Printf("Stored DNSSEC keys for secondary zone %s", zone)
		return nil
	})

	// Initialize auth manager with storage backend
	authMgr := auth.NewManagerWithStorage(store)
	if authMgr.IsEnabled() {
		log.Printf("Authentication enabled")
	}

	// Initialize ACME manager first (needed for SNI manager)
	certMgr := certs.NewManagerWithStorage(store)
	var acmeMgr *certs.ACMEManager
	if certMgr != nil {
		var err error
		acmeMgr, err = certs.NewACMEManagerWithStorage(certMgr, store)
		if err != nil {
			log.Printf("Warning: Failed to initialize ACME manager: %v", err)
		} else {
			log.Printf("ACME manager initialized")
			api.SetACMEManager(acmeMgr)
			acmeMgr.SetDNSProvider(srv)
		}
	}

	// Initialize SNI-based certificate manager with automatic ACME provisioning
	sniMgr := certs.NewSNIManager(store, acmeMgr)
	if sniMgr != nil {
		log.Printf("SNI certificate manager initialized")
		api.SetCertManager(sniMgr)

		// Update ACME manager to upload certificates to the SNI manager
		// so the cache gets updated when new certs are obtained
		if acmeMgr != nil {
			acmeMgr.SetCertUploader(sniMgr)
		}

		// Preload existing certificates
		if err := sniMgr.PreloadCertificates(); err != nil {
			log.Printf("Warning: Failed to preload certificates: %v", err)
		}

		// Start auto-renewal if configured
		if acmeMgr != nil && acmeMgr.GetConfig().AutoRenew {
			acmeMgr.StartAutoRenew()
		}
	}

	// Initialize port manager with storage
	portMgr := ports.NewManagerWithStorage(store)
	if portMgr != nil {
		portMgr.SetDNSHandler(srv)
		if sniMgr != nil {
			portMgr.SetTLSProvider(sniMgr)
		}
		api.SetPortManager(portMgr)
	}

	// Initialize API handler with storage
	apiHandler := api.NewWithStorage(parsed, store, func(newCfg *config.ParsedConfig) {
		srv.UpdateConfig(newCfg)
	})

	// Create web mux and start services
	if portMgr != nil && portMgr.GetConfig().Web.Enabled {
		mux := createWebMux(apiHandler, authMgr, store, syncMgr)

		portMgr.SetWebMux(mux)
		if err := portMgr.Start(); err != nil {
			log.Printf("Warning: Some services failed to start: %v", err)
		}
	} else {
		if err := srv.Start(); err != nil {
			log.Fatalf("DNS server failed: %v", err)
		}
	}

	select {}
}

func createWebMux(apiHandler *api.Handler, authMgr *auth.Manager, store *storage.Store, syncMgr *sync.Manager) *http.ServeMux {
	mux := http.NewServeMux()

	if authMgr != nil {
		authMgr.RegisterAuthRoutes(mux)
		authMgr.RegisterWebAuthnRoutes(mux)

		authConfig := authMgr.GetConfig()
		if authConfig.OIDC != nil && authConfig.OIDC.Enabled {
			oidcMgr, err := auth.NewOIDCManager(context.Background(), authConfig.OIDC)
			if err != nil {
				log.Printf("Warning: Failed to initialize OIDC: %v", err)
			} else {
				authMgr.RegisterOIDCRoutes(mux, oidcMgr)
				log.Printf("OIDC authentication enabled")
			}
		}
	}

	corsMiddleware := api.CORSMiddleware
	if authMgr != nil && authMgr.IsEnabled() {
		apiHandler.RegisterRoutesWithAuth(mux, authMgr)
		api.RegisterPortRoutesWithAuth(mux, corsMiddleware, authMgr.MiddlewareFunc)
		api.RegisterCertRoutesWithAuth(mux, corsMiddleware, authMgr.MiddlewareFunc)
	} else {
		apiHandler.RegisterRoutes(mux)
		api.RegisterPortRoutes(mux, corsMiddleware)
		api.RegisterCertRoutes(mux, corsMiddleware)
	}

	// Register sync routes if sync manager is available
	if syncMgr != nil {
		sync.RegisterRoutes(mux, syncMgr, corsMiddleware)
		log.Printf("Sync API routes registered")
	}

	webDir := "web/dist/dns-admin/browser"
	fs := http.FileServer(http.Dir(webDir))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Set cache headers - aggressive caching for hashed files, no caching for index.html
		if path == "/" || path == "/index.html" {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		} else if strings.Contains(path, ".") && (strings.Contains(path, "-") || strings.HasPrefix(filepath.Base(path), "chunk-")) {
			// Hashed files (main-HASH.js, chunk-HASH.js, styles-HASH.css) can be cached forever
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}

		if path != "/" && !hasFileExtension(path) {
			fullPath := filepath.Join(webDir, path)
			if _, err := os.Stat(fullPath); os.IsNotExist(err) {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				http.ServeFile(w, r, filepath.Join(webDir, "index.html"))
				return
			}
		}
		fs.ServeHTTP(w, r)
	})

	return mux
}

func hasFileExtension(path string) bool {
	ext := filepath.Ext(path)
	return ext != "" && ext != "."
}

// loadSyncConfig loads sync configuration from storage
// Reads from the "config" bucket where the sync API saves its configuration
func loadSyncConfig(store *storage.Store) *config.SyncConfig {
	var cfg config.SyncConfig
	var foundData bool

	err := store.DB().View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		if bucket == nil {
			return nil // No config bucket yet
		}

		data := bucket.Get([]byte("sync"))
		if data == nil {
			return nil // No sync config saved yet
		}

		foundData = true

		// Parse the stored format
		var stored struct {
			Enabled                bool   `json:"enabled"`
			NodeID                 string `json:"node_id"`
			ServerName             string `json:"server_name"`
			SharedSecret           string `json:"shared_secret"`
			TombstoneRetentionDays int    `json:"tombstone_retention_days"`
			Peers                  []struct {
				ID                 string `json:"id"`
				Address            string `json:"address"`
				URL                string `json:"url"`
				APIKey             string `json:"api_key"`
				InsecureSkipVerify bool   `json:"insecure_skip_verify"`
			} `json:"peers"`
		}

		if err := json.Unmarshal(data, &stored); err != nil {
			return err
		}

		cfg.Enabled = stored.Enabled
		cfg.NodeID = stored.NodeID
		cfg.ServerName = stored.ServerName
		cfg.SharedSecret = stored.SharedSecret
		cfg.TombstoneRetentionDays = stored.TombstoneRetentionDays

		for _, p := range stored.Peers {
			// Use URL if available, fall back to Address for compatibility
			peerURL := p.URL
			if peerURL == "" {
				peerURL = p.Address
			}
			cfg.Peers = append(cfg.Peers, config.SyncPeerConfig{
				ID:                 p.ID,
				Address:            peerURL,
				APIKey:             p.APIKey,
				InsecureSkipVerify: p.InsecureSkipVerify,
			})
		}

		return nil
	})

	if err != nil {
		log.Printf("Warning: Failed to load sync config: %v", err)
		return nil
	}

	if !foundData {
		return nil
	}

	log.Printf("[sync] Loaded config from database: enabled=%v, nodeID=%s, serverName=%s, peers=%d", cfg.Enabled, cfg.NodeID, cfg.ServerName, len(cfg.Peers))
	return &cfg
}

// initSyncManager initializes the cluster sync manager
func initSyncManager(store *storage.Store, cfg *config.SyncConfig) *sync.Manager {
	// Convert config
	syncCfg := &sync.Config{
		Enabled:           cfg.Enabled,
		ServerID:          cfg.NodeID,
		ServerName:        cfg.ServerName,
		SharedSecret:      cfg.SharedSecret,
		BatchSize:         1000,
		ReconnectInterval: 5 * time.Second,
		PingInterval:      30 * time.Second,
	}

	// Add peers
	for _, p := range cfg.Peers {
		syncCfg.Peers = append(syncCfg.Peers, sync.PeerConfig{
			ID:                 p.ID,
			URL:                p.Address,
			APIKey:             p.APIKey,
			InsecureSkipVerify: p.InsecureSkipVerify,
		})
	}

	// Set tombstone retention
	if cfg.TombstoneRetentionDays > 0 {
		syncCfg.TombstoneRetention = time.Duration(cfg.TombstoneRetentionDays) * 24 * time.Hour
	} else {
		syncCfg.TombstoneRetention = 7 * 24 * time.Hour
	}

	// Create manager
	mgr, err := sync.NewManager(store.DB(), syncCfg)
	if err != nil {
		log.Printf("Warning: Failed to create sync manager: %v", err)
		return nil
	}

	// Set up apply callback to handle incoming changes
	mgr.SetApplyCallback(createApplyCallback(store))

	// Set up full sync provider to enumerate all data
	mgr.SetFullSyncProvider(createFullSyncProvider(store))

	// Set up storage hook to record changes
	storage.SetSyncHook(func(entityType, entityID, tenantID, operation string, data interface{}) error {
		return mgr.RecordChange(entityType, entityID, tenantID, operation, data)
	})

	// Start the sync manager
	if err := mgr.Start(); err != nil {
		log.Printf("Warning: Failed to start sync manager: %v", err)
		return nil
	}

	// Repair: replay oplog entries to catch any that weren't properly applied
	// This handles the case where an entity type was added after entries were synced
	repairSyncEntries(mgr, store)

	return mgr
}

// repairSyncEntries replays oplog entries from remote servers to ensure they're applied
// This handles the case where entity type support was added after entries were synced
func repairSyncEntries(mgr *sync.Manager, store *storage.Store) {
	localServerID := mgr.ServerID()
	repaired := 0

	err := mgr.ReplayAllEntries(func(entry *sync.OpLogEntry) error {
		// Only repair entries from OTHER servers
		if entry.ServerID == localServerID {
			return nil
		}

		// Check if entity needs to be applied based on type
		switch entry.EntityType {
		case sync.EntityAPIKey:
			// Check if API key exists
			apiKey, _ := store.GetAPIKey(entry.EntityID)
			if apiKey == nil && entry.Operation != sync.OpDelete {
				// API key doesn't exist but oplog has it - apply it
				log.Printf("[sync-repair] Applying missed API key entry: %s", entry.EntityID)
				if err := storage.WithSyncHookDisabled(func() error {
					return applyCreateOrUpdate(store, entry)
				}); err != nil {
					log.Printf("[sync-repair] Error applying API key %s: %v", entry.EntityID, err)
				} else {
					repaired++
				}
			}

		case sync.EntityUser:
			user, _ := store.GetUser(entry.EntityID)
			if user == nil && entry.Operation != sync.OpDelete {
				log.Printf("[sync-repair] Applying missed user entry: %s", entry.EntityID)
				if err := storage.WithSyncHookDisabled(func() error {
					return applyCreateOrUpdate(store, entry)
				}); err != nil {
					log.Printf("[sync-repair] Error applying user %s: %v", entry.EntityID, err)
				} else {
					repaired++
				}
			}

		case sync.EntityZone:
			zone, _ := store.GetZone(entry.EntityID)
			if zone == nil && entry.Operation != sync.OpDelete {
				log.Printf("[sync-repair] Applying missed zone entry: %s", entry.EntityID)
				if err := storage.WithSyncHookDisabled(func() error {
					return applyCreateOrUpdate(store, entry)
				}); err != nil {
					log.Printf("[sync-repair] Error applying zone %s: %v", entry.EntityID, err)
				} else {
					repaired++
				}
			}

		case sync.EntityTenant:
			tenant, _ := store.GetTenant(entry.EntityID)
			if tenant == nil && entry.Operation != sync.OpDelete {
				log.Printf("[sync-repair] Applying missed tenant entry: %s", entry.EntityID)
				if err := storage.WithSyncHookDisabled(func() error {
					return applyCreateOrUpdate(store, entry)
				}); err != nil {
					log.Printf("[sync-repair] Error applying tenant %s: %v", entry.EntityID, err)
				} else {
					repaired++
				}
			}

		case sync.EntitySession:
			session, _ := store.GetSession(entry.EntityID)
			if session == nil && entry.Operation != sync.OpDelete {
				log.Printf("[sync-repair] Applying missed session entry: %s", entry.EntityID)
				if err := storage.WithSyncHookDisabled(func() error {
					return applyCreateOrUpdate(store, entry)
				}); err != nil {
					log.Printf("[sync-repair] Error applying session %s: %v", entry.EntityID, err)
				} else {
					repaired++
				}
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("[sync-repair] Error replaying entries: %v", err)
	} else if repaired > 0 {
		log.Printf("[sync-repair] Repaired %d missing entries", repaired)
	}
}

// createApplyCallback creates a callback function to apply remote changes to local storage
func createApplyCallback(store *storage.Store) sync.ApplyCallback {
	return func(entry *sync.OpLogEntry) error {
		// Wrap in WithSyncHookDisabled to prevent re-broadcasting received changes
		return storage.WithSyncHookDisabled(func() error {
			// Skip if data is empty (tombstone/delete with no data)
			if entry.Operation == sync.OpDelete {
				return applyDelete(store, entry.EntityType, entry.EntityID)
			}

			// Apply create or update
			return applyCreateOrUpdate(store, entry)
		})
	}
}

// applyDelete handles deletion of entities
func applyDelete(store *storage.Store, entityType, entityID string) error {
	switch entityType {
	case sync.EntityZone:
		return store.DeleteZone(entityID)
	case sync.EntityRecord:
		// Records need more context to delete - entityID should contain the info
		// Format: zone:name:type:recordID
		return nil // TODO: implement record deletion parsing
	case sync.EntityUser:
		return store.DeleteUser(entityID)
	case sync.EntityTenant:
		return store.DeleteTenant(entityID)
	case sync.EntityDNSSECKeys:
		return store.DeleteDNSSECKeys(entityID)
	case sync.EntityAPIKey:
		return store.DeleteAPIKey(entityID)
	case sync.EntitySession:
		return store.DeleteSession(entityID)
	default:
		log.Printf("[sync] Unknown entity type for delete: %s", entityType)
		return nil
	}
}

// applyCreateOrUpdate handles creation or update of entities
func applyCreateOrUpdate(store *storage.Store, entry *sync.OpLogEntry) error {
	if entry.Data == nil {
		return nil
	}

	// Re-marshal and unmarshal to proper type
	data, err := json.Marshal(entry.Data)
	if err != nil {
		return err
	}

	switch entry.EntityType {
	case sync.EntityZone:
		var zone storage.Zone
		if err := json.Unmarshal(data, &zone); err != nil {
			return err
		}
		// Check if exists
		existing, _ := store.GetZone(zone.Name)
		if existing != nil {
			return store.UpdateZone(&zone)
		}
		return store.CreateZone(&zone)

	case sync.EntityRecord:
		var record storage.Record
		if err := json.Unmarshal(data, &record); err != nil {
			return err
		}
		if entry.Operation == sync.OpCreate {
			return store.CreateRecord(&record)
		}
		return store.UpdateRecord(&record)

	case sync.EntityUser:
		var user storage.User
		if err := json.Unmarshal(data, &user); err != nil {
			return err
		}
		// Check if exists
		existing, _ := store.GetUser(user.ID)
		if existing != nil {
			return store.UpdateUser(&user)
		}
		return store.CreateUser(&user)

	case sync.EntityTenant:
		var tenant storage.Tenant
		if err := json.Unmarshal(data, &tenant); err != nil {
			return err
		}
		existing, _ := store.GetTenant(tenant.ID)
		if existing != nil {
			return store.UpdateTenant(&tenant)
		}
		return store.CreateTenant(&tenant)

	case sync.EntityDNSSECKeys:
		var keys storage.DNSSECKeys
		if err := json.Unmarshal(data, &keys); err != nil {
			return err
		}
		return store.SaveDNSSECKeys(&keys)

	case sync.EntityAPIKey:
		var apiKey storage.APIKey
		if err := json.Unmarshal(data, &apiKey); err != nil {
			return err
		}
		// API keys are synced with their hash so they work across all cluster servers
		existing, _ := store.GetAPIKey(apiKey.ID)
		if existing != nil {
			// Update with the synced data (including hash if provided)
			if apiKey.KeyHash == "" {
				// Preserve existing hash if not provided in sync
				apiKey.KeyHash = existing.KeyHash
			} else if existing.KeyHash == "synced_from_remote_server_key_not_usable_locally" {
				// Repair: existing has placeholder hash, use the real one from sync
				log.Printf("[sync] Repairing API key %s with real hash from sync", apiKey.ID)
			}
			return store.UpdateAPIKey(&apiKey)
		}
		// Create new key with synced hash
		if apiKey.KeyHash == "" {
			log.Printf("[sync] Warning: API key %s synced without hash, key won't work", apiKey.ID)
		} else {
			log.Printf("[sync] Creating synced API key %s (usable on all cluster servers)", apiKey.ID)
		}
		return store.CreateAPIKey(&apiKey)

	case sync.EntitySession:
		var session storage.Session
		if err := json.Unmarshal(data, &session); err != nil {
			return err
		}
		// Sessions are synced so bearer tokens work across all cluster servers
		existing, _ := store.GetSession(session.ID)
		if existing != nil {
			// Session already exists, no need to update (they're immutable except for expiry)
			return nil
		}
		log.Printf("[sync] Creating synced session %s for user %s", session.ID, session.Username)
		return store.CreateSession(&session)

	default:
		log.Printf("[sync] Unknown entity type: %s", entry.EntityType)
		return nil
	}
}

// createFullSyncProvider creates a callback that enumerates all data for full sync
func createFullSyncProvider(store *storage.Store) sync.FullSyncProvider {
	return func() ([]sync.FullSyncDataItem, error) {
		var items []sync.FullSyncDataItem

		// Get all tenants
		tenants, err := store.ListTenants()
		if err != nil {
			log.Printf("[sync] Warning: failed to list tenants: %v", err)
		} else {
			for _, tenant := range tenants {
				items = append(items, sync.FullSyncDataItem{
					EntityType: sync.EntityTenant,
					EntityID:   tenant.ID,
					TenantID:   tenant.ID,
					Data:       tenant,
				})
			}
		}

		// Get all users (for each tenant)
		for _, tenant := range tenants {
			users, err := store.ListUsers(tenant.ID)
			if err != nil {
				log.Printf("[sync] Warning: failed to list users for tenant %s: %v", tenant.ID, err)
				continue
			}
			for _, user := range users {
				// Create a sync-safe version (no password hash)
				syncUser := struct {
					ID          string `json:"id"`
					Username    string `json:"username"`
					TenantID    string `json:"tenant_id"`
					Email       string `json:"email"`
					DisplayName string `json:"display_name"`
					Role        string `json:"role"`
					CreatedAt   string `json:"created_at"`
				}{
					ID:          user.ID,
					Username:    user.Username,
					TenantID:    user.TenantID,
					Email:       user.Email,
					DisplayName: user.DisplayName,
					Role:        user.Role,
					CreatedAt:   user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				}
				items = append(items, sync.FullSyncDataItem{
					EntityType: sync.EntityUser,
					EntityID:   user.ID,
					TenantID:   user.TenantID,
					Data:       syncUser,
				})
			}
		}

		// Get all zones (for each tenant)
		for _, tenant := range tenants {
			zones, err := store.ListZones(tenant.ID)
			if err != nil {
				log.Printf("[sync] Warning: failed to list zones for tenant %s: %v", tenant.ID, err)
				continue
			}
			for _, zone := range zones {
				items = append(items, sync.FullSyncDataItem{
					EntityType: sync.EntityZone,
					EntityID:   zone.Name,
					TenantID:   zone.TenantID,
					Data:       zone,
				})

				// Get all records for this zone
				records, err := store.GetAllZoneRecords(zone.Name)
				if err != nil {
					log.Printf("[sync] Warning: failed to list records for zone %s: %v", zone.Name, err)
					continue
				}
				for _, record := range records {
					items = append(items, sync.FullSyncDataItem{
						EntityType: sync.EntityRecord,
						EntityID:   record.ID,
						TenantID:   zone.TenantID,
						Data:       record,
					})
				}
			}
		}

		// Get all DNSSEC keys
		dnssecKeys, err := store.GetAllDNSSECKeys()
		if err != nil {
			log.Printf("[sync] Warning: failed to list DNSSEC keys: %v", err)
		} else {
			for _, keys := range dnssecKeys {
				items = append(items, sync.FullSyncDataItem{
					EntityType: sync.EntityDNSSECKeys,
					EntityID:   keys.ZoneName,
					TenantID:   "",
					Data:       keys,
				})
			}
		}

		// Get all API keys (including hashes for cluster-wide authentication)
		apiKeys, err := store.ListAPIKeysForSync("")
		if err != nil {
			log.Printf("[sync] Warning: failed to list API keys: %v", err)
		} else {
			for _, apiKey := range apiKeys {
				// Include full API key with hash so keys work on all servers
				items = append(items, sync.FullSyncDataItem{
					EntityType: sync.EntityAPIKey,
					EntityID:   apiKey.ID,
					TenantID:   apiKey.TenantID,
					Data:       apiKey,
				})
			}
		}

		// Get all active sessions (for cluster-wide bearer token support)
		sessions, err := store.ListActiveSessions()
		if err != nil {
			log.Printf("[sync] Warning: failed to list sessions: %v", err)
		} else {
			for _, session := range sessions {
				items = append(items, sync.FullSyncDataItem{
					EntityType: sync.EntitySession,
					EntityID:   session.ID,
					TenantID:   session.TenantID,
					Data:       session,
				})
			}
		}

		// Get all secondary zones
		secondaryZones, err := store.ListSecondaryZones()
		if err != nil {
			log.Printf("[sync] Warning: failed to list secondary zones: %v", err)
		} else {
			for _, zone := range secondaryZones {
				items = append(items, sync.FullSyncDataItem{
					EntityType: sync.EntitySecondaryZone,
					EntityID:   zone.Zone,
					TenantID:   "",
					Data:       zone,
				})
			}
		}

		// Get all settings
		settings, err := store.ListSettings()
		if err != nil {
			log.Printf("[sync] Warning: failed to list settings: %v", err)
		} else {
			for key, value := range settings {
				items = append(items, sync.FullSyncDataItem{
					EntityType: sync.EntitySettings,
					EntityID:   key,
					TenantID:   "",
					Data:       map[string]string{"key": key, "value": value},
				})
			}
		}

		log.Printf("[sync] Full sync provider collected %d items", len(items))
		return items, nil
	}
}
