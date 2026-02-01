package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
)

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

	// Initialize certificate manager with storage
	certMgr := certs.NewManagerWithStorage(store)
	if certMgr != nil {
		log.Printf("Certificate manager initialized")
		api.SetCertManager(certMgr)

		// Initialize ACME manager for Let's Encrypt certificates
		acmeMgr, err := certs.NewACMEManagerWithStorage(certMgr, store)
		if err != nil {
			log.Printf("Warning: Failed to initialize ACME manager: %v", err)
		} else {
			log.Printf("ACME manager initialized")
			api.SetACMEManager(acmeMgr)
			acmeMgr.SetDNSProvider(srv)
			if acmeMgr.GetConfig().AutoRenew {
				acmeMgr.StartAutoRenew()
			}
		}
	}

	// Initialize port manager with storage
	portMgr := ports.NewManagerWithStorage(store)
	if portMgr != nil {
		portMgr.SetDNSHandler(srv)
		if certMgr != nil {
			portMgr.SetTLSProvider(certMgr)
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
		if path != "/" && !hasFileExtension(path) {
			fullPath := filepath.Join(webDir, path)
			if _, err := os.Stat(fullPath); os.IsNotExist(err) {
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
func loadSyncConfig(store *storage.Store) *config.SyncConfig {
	data, err := store.GetSetting("sync")
	if err != nil {
		return nil
	}

	var cfg config.SyncConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		log.Printf("Warning: Failed to parse sync config: %v", err)
		return nil
	}

	return &cfg
}

// initSyncManager initializes the cluster sync manager
func initSyncManager(store *storage.Store, cfg *config.SyncConfig) *sync.Manager {
	// Convert config
	syncCfg := &sync.Config{
		Enabled:      cfg.Enabled,
		ServerID:     cfg.NodeID,
		ListenAddr:   cfg.ListenAddr,
		SharedSecret: cfg.SharedSecret,
	}

	// Add peers
	for _, p := range cfg.Peers {
		syncCfg.Peers = append(syncCfg.Peers, sync.PeerConfig{
			URL: p.Address,
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

	// Set up storage hook to record changes
	storage.SetSyncHook(func(entityType, entityID, tenantID, operation string, data interface{}) error {
		return mgr.RecordChange(entityType, entityID, tenantID, operation, data)
	})

	// Start the sync manager
	if err := mgr.Start(); err != nil {
		log.Printf("Warning: Failed to start sync manager: %v", err)
		return nil
	}

	return mgr
}

// createApplyCallback creates a callback function to apply remote changes to local storage
func createApplyCallback(store *storage.Store) sync.ApplyCallback {
	return func(entry *sync.OpLogEntry) error {
		// Skip if data is empty (tombstone/delete with no data)
		if entry.Operation == sync.OpDelete {
			return applyDelete(store, entry.EntityType, entry.EntityID)
		}

		// Apply create or update
		return applyCreateOrUpdate(store, entry)
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

	default:
		log.Printf("[sync] Unknown entity type: %s", entry.EntityType)
		return nil
	}
}
