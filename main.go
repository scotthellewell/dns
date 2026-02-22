package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scott/dns/api"
	"github.com/scott/dns/auth"
	"github.com/scott/dns/blocklist"
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

// blocklistServerAdapter adapts blocklist.Manager to server.BlocklistChecker interface
type blocklistServerAdapter struct {
	mgr *blocklist.Manager
}

func (a *blocklistServerAdapter) Check(domain string) bool {
	return a.mgr.Check(domain)
}

func (a *blocklistServerAdapter) GetResponse() string {
	cfg := a.mgr.GetConfig()
	if cfg == nil {
		return "nxdomain"
	}
	return cfg.Response
}

func (a *blocklistServerAdapter) GetRedirectIP() string {
	cfg := a.mgr.GetConfig()
	if cfg == nil {
		return ""
	}
	return cfg.RedirectIP
}

func (a *blocklistServerAdapter) GetConfig() *server.BlocklistConfig {
	cfg := a.mgr.GetConfig()
	if cfg == nil {
		return &server.BlocklistConfig{
			Enabled:    false,
			Response:   "nxdomain",
			LogBlocked: true,
		}
	}
	return &server.BlocklistConfig{
		Enabled:    cfg.Enabled,
		Response:   cfg.Response,
		RedirectIP: cfg.RedirectIP,
		LogBlocked: cfg.LogBlocked,
	}
}

// serverStorageAdapter adapts storage.Store to server.StorageInterface for RFC 2136 updates
type serverStorageAdapter struct {
	store      *storage.Store
	apiHandler *api.Handler
}

func (a *serverStorageAdapter) AddRecord(zone string, record interface{}) error {
	rec, ok := record.(map[string]interface{})
	if !ok {
		return fmt.Errorf("record must be map[string]interface{}")
	}

	// Normalize zone name - remove trailing dot if present
	zone = strings.TrimSuffix(zone, ".")

	// Extract record data
	name, _ := rec["name"].(string)
	// Normalize name - remove trailing dot if present
	name = strings.TrimSuffix(name, ".")

	// Strip zone suffix from name if present (RFC 2136 sends full FQDN)
	// e.g., "ddns-test.quicktechresults.com" -> "ddns-test" when zone is "quicktechresults.com"
	zoneSuffix := "." + zone
	if strings.HasSuffix(strings.ToLower(name), strings.ToLower(zoneSuffix)) {
		name = name[:len(name)-len(zoneSuffix)]
	} else if strings.EqualFold(name, zone) {
		// Record at zone apex
		name = "@"
	}

	recordType, _ := rec["type"].(string)
	ttl, _ := rec["ttl"].(int)
	if ttl == 0 {
		ttl = 3600 // Default TTL
	}

	// Create storage record
	storageRec := &storage.Record{
		Zone:      zone,
		Name:      name,
		Type:      recordType,
		TTL:       uint32(ttl),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Marshal data field
	data, err := json.Marshal(rec["data"])
	if err != nil {
		return fmt.Errorf("failed to marshal record data: %w", err)
	}
	storageRec.Data = data

	return a.store.CreateRecord(storageRec)
}

func (a *serverStorageAdapter) DeleteRecord(zone, name string, recordType string) error {
	if recordType == "" {
		// Delete all types for this name - not directly supported, skip
		log.Printf("[storage-adapter] Delete all types not supported for %s.%s", name, zone)
		return nil
	}
	return a.store.DeleteRecordsByType(zone, name, recordType)
}

func (a *serverStorageAdapter) ReloadConfig() error {
	if a.apiHandler == nil {
		return nil // No handler set, skip reload
	}
	return a.apiHandler.UpdateConfigFromStorage()
}

// getKeyNames extracts key names from TSIG key slice
func getKeyNames(keys []storage.TSIGKey) []string {
	names := make([]string, len(keys))
	for i, key := range keys {
		names[i] = key.Name
	}
	return names
}

// fetchCertificateFromPeer attempts to fetch a certificate from a peer server's API
func fetchCertificateFromPeer(peerURL string, domain string) (*storage.TLSCertificate, error) {
	// Build the certificate fetch URL
	// Convert WebSocket URL to HTTPS if needed
	baseURL := peerURL
	baseURL = strings.Replace(baseURL, "wss://", "https://", 1)
	baseURL = strings.Replace(baseURL, "ws://", "http://", 1)
	// Remove any path (like /sync) and add the cert API endpoint
	// Find the third "/" (after https://host) to trim the path
	if len(baseURL) > 8 { // Make sure we have enough characters after "https://"
		remainder := baseURL[8:] // Skip "https://"
		if idx := strings.Index(remainder, "/"); idx > 0 {
			baseURL = baseURL[:8+idx]
		}
	}
	certURL := fmt.Sprintf("%s/api/certs/%s", baseURL, domain)

	log.Printf("[cluster-join] Fetching certificate from peer: %s", certURL)

	// Create HTTP client that accepts self-signed certs (for initial cluster join)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Accept self-signed certs during cluster join
			},
		},
	}

	resp, err := client.Get(certURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cert from peer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("certificate not found on peer")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("peer returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the certificate response
	var certResp struct {
		Domain      string    `json:"domain"`
		Certificate string    `json:"certificate"`
		PrivateKey  string    `json:"private_key"`
		NotBefore   time.Time `json:"not_before"`
		NotAfter    time.Time `json:"not_after"`
		Issuer      string    `json:"issuer"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return nil, fmt.Errorf("failed to decode cert response: %w", err)
	}

	// Check if we got the full certificate with private key
	if certResp.PrivateKey == "" {
		return nil, fmt.Errorf("peer did not return private key (may not support cert sync)")
	}

	return &storage.TLSCertificate{
		Domain:    certResp.Domain,
		CertPEM:   certResp.Certificate,
		KeyPEM:    certResp.PrivateKey,
		NotBefore: certResp.NotBefore,
		NotAfter:  certResp.NotAfter,
		Issuer:    certResp.Issuer,
	}, nil
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

	// Start recursive DNS cache warmup in background
	srv.WarmupRecursionCache()

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
	log.Printf("[init] Creating auth manager...")
	authMgr := auth.NewManagerWithStorage(store)
	log.Printf("[init] Auth manager created")
	if authMgr.IsEnabled() {
		log.Printf("Authentication enabled")
	}

	// Initialize ACME manager first (needed for SNI manager)
	log.Printf("[init] Creating cert manager...")
	certMgr := certs.NewManagerWithStorage(store)
	log.Printf("[init] Cert manager created")
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
		api.SetCertStore(store) // Set store for certificate sync API

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

	// Set callback to clear DNSSEC validation caches when records change
	apiHandler.SetClearDNSSECCacheCallback(func() {
		srv.ClearAllDNSSECCaches()
	})

	// Set up storage adapter for RFC 2136 dynamic updates
	storageAdapter := &serverStorageAdapter{
		store:      store,
		apiHandler: apiHandler,
	}
	srv.SetStorage(storageAdapter)

	// Load and apply dynamic update configuration from storage
	if updateCfg, err := store.GetDynamicUpdateConfig(); err == nil {
		srv.SetUpdateConfig(server.UpdateConfig{
			Enabled:     updateCfg.Enabled,
			AllowedNets: updateCfg.AllowedNets,
			AllowedKeys: getKeyNames(updateCfg.TSIGKeys),
			AutoPTR:     updateCfg.AutoPTR,
		})
		if updateCfg.Enabled {
			log.Printf("RFC 2136 Dynamic Updates enabled (allowed nets: %v)", updateCfg.AllowedNets)
		}
	}

	// Set callback for dynamic update config changes (from API)
	apiHandler.SetUpdateConfigChangeCallback(func(enabled bool, allowedNets, allowedKeys []string, autoPTR bool) {
		srv.SetUpdateConfig(server.UpdateConfig{
			Enabled:     enabled,
			AllowedNets: allowedNets,
			AllowedKeys: allowedKeys,
			AutoPTR:     autoPTR,
		})
		log.Printf("RFC 2136 Dynamic Updates config updated (enabled: %v, allowed nets: %v)", enabled, allowedNets)
	})

	// Initialize blocklist manager with composite storage:
	// - Main database (store) for config, sources, whitelist (synced across cluster)
	// - Blocklist database for domain entries only (local, not synced - too large)
	blocklistDomainStore, err := blocklist.NewBlocklistStore(*dataDir)
	if err != nil {
		log.Printf("Warning: Failed to open blocklist database: %v", err)
	}

	var blocklistMgr *blocklist.Manager
	if blocklistDomainStore != nil {
		// Create adapter for main storage to implement blocklist.MainStorage interface
		mainStorageAdapter := storage.NewBlocklistMainStorageAdapter(store)
		// Create composite store: main db for config/sources/whitelist, blocklist.db for domains only
		compositeStore := blocklist.NewCompositeStore(mainStorageAdapter, blocklistDomainStore)
		blocklistMgr = blocklist.New(compositeStore)

		// Load config from main storage (synced), or use defaults
		blocklistConfig, err := compositeStore.GetBlocklistConfig()
		if err != nil || blocklistConfig == nil {
			// Use default config with default sources
			blocklistConfig = &blocklist.Config{
				Enabled:    true,
				LogBlocked: true,
				Response:   "nxdomain",
			}
			blocklistMgr.SetConfig(blocklistConfig)

			// Add default sources
			for _, source := range blocklist.DefaultSources() {
				if err := blocklistMgr.AddSource(source); err != nil {
					log.Printf("Warning: Failed to add default blocklist source %s: %v", source.ID, err)
				}
			}
		} else {
			blocklistMgr.SetConfig(blocklistConfig)
		}

		// Start the blocklist manager (returns immediately, initializes in background)
		if err := blocklistMgr.Start(); err != nil {
			log.Printf("Warning: Failed to start blocklist manager: %v", err)
		} else if blocklistConfig.Enabled {
			log.Printf("[blocklist] Manager started (initializing in background)")
		}

		// Wire up blocklist to DNS server via adapter
		srv.SetBlocklist(&blocklistServerAdapter{mgr: blocklistMgr})

		// Wire up blocklist to API handler
		apiHandler.SetBlocklistManager(blocklistMgr)
	}

	// Wire up redirect checker to DNS server
	srv.SetRedirectChecker(server.NewStorageRedirectChecker(store))

	// Set up sync manager config refresh callback now that we have the API handler
	if syncMgr != nil {
		syncMgr.SetConfigRefreshCallback(func() {
			if err := apiHandler.UpdateConfigFromStorage(); err != nil {
				log.Printf("[sync] Config refresh failed: %v", err)
			}
		})

		// Set up blocklist reload callbacks for sync
		if blocklistMgr != nil {
			syncMgr.SetBlocklistReloadCallbacks(
				blocklistMgr.ReloadConfig,
				blocklistMgr.ReloadSources,
				blocklistMgr.ReloadWhitelist,
			)
		}
	}

	// Create web mux and start services
	if portMgr != nil && portMgr.GetConfig().Web.Enabled {
		mux := createWebMux(apiHandler, authMgr, store, syncMgr, acmeMgr)

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

func createWebMux(apiHandler *api.Handler, authMgr *auth.Manager, store *storage.Store, syncMgr *sync.Manager, acmeMgr *certs.ACMEManager) *http.ServeMux {
	mux := http.NewServeMux()

	// Set up ACME certificate callback for cluster join
	if authMgr != nil && acmeMgr != nil && store != nil {
		authMgr.SetACMECertCallback(func(req auth.ACMECertRequest) error {
			log.Printf("[cluster-join] Configuring ACME for domain: %s (provider: %s)", req.Domain, req.Provider)

			// Check if we already have a valid certificate for this domain in storage
			existingCert, err := store.GetCertificate(req.Domain)
			if err == nil && existingCert != nil && existingCert.NotAfter.After(time.Now().Add(24*time.Hour)) {
				log.Printf("[cluster-join] Valid certificate already exists for %s (expires %s), skipping ACME request",
					req.Domain, existingCert.NotAfter.Format(time.RFC3339))
				return nil
			}

			// Try to fetch certificate from peer servers first
			if len(req.PeerURLs) > 0 {
				log.Printf("[cluster-join] Checking %d peer(s) for existing certificate for %s", len(req.PeerURLs), req.Domain)
				for _, peerURL := range req.PeerURLs {
					cert, err := fetchCertificateFromPeer(peerURL, req.Domain)
					if err == nil && cert != nil && cert.NotAfter.After(time.Now().Add(24*time.Hour)) {
						log.Printf("[cluster-join] Found valid certificate on peer %s, importing", peerURL)
						if err := store.StoreCertificate(cert); err != nil {
							log.Printf("[cluster-join] Warning: Failed to store peer certificate: %v", err)
						} else {
							log.Printf("[cluster-join] Successfully imported certificate from peer for %s", req.Domain)
							return nil
						}
					} else if err != nil {
						log.Printf("[cluster-join] Could not fetch cert from peer %s: %v", peerURL, err)
					}
				}
			}

			// Set default provider if not specified
			provider := req.Provider
			if provider == "" {
				provider = certs.ACMEProviderLetsEncrypt
			}

			// Update ACME config with provider settings
			acmeConfig := certs.ACMEConfig{
				Enabled:       true,
				Email:         req.Email,
				Domains:       []string{req.Domain},
				Provider:      provider,
				UseStaging:    req.Staging,
				ChallengeType: "http-01",
				AutoRenew:     true,
				RenewBefore:   30,
				EABKeyID:      req.EABKeyID,
				EABHMACKey:    req.EABHMACKey,
			}
			if err := acmeMgr.UpdateConfig(acmeConfig); err != nil {
				return errors.New("failed to configure ACME: " + err.Error())
			}

			// Request the certificate
			log.Printf("[cluster-join] Requesting certificate from %s...", provider)
			if err := acmeMgr.RequestCertificate(req.Email, []string{req.Domain}); err != nil {
				return errors.New("failed to obtain certificate: " + err.Error())
			}

			log.Printf("[cluster-join] Certificate obtained successfully for %s", req.Domain)
			return nil
		})
	}

	// Set up cluster join callback if we have both auth and sync managers
	if authMgr != nil && syncMgr != nil {
		authMgr.SetJoinClusterCallback(func(clusterConfig *auth.ClusterJoinConfig) error {
			log.Printf("[cluster-join] Configuring sync with %d peers", len(clusterConfig.Peers))

			// Build peer configs
			peers := make([]sync.PeerConfig, 0, len(clusterConfig.Peers))
			for _, p := range clusterConfig.Peers {
				peers = append(peers, sync.PeerConfig{
					URL: p.URL,
					ID:  p.ServerID,
				})
			}

			// Update sync config
			newConfig := &sync.Config{
				Enabled:            true,
				ServerID:           clusterConfig.ThisServer.ServerID,
				ServerName:         clusterConfig.ThisServer.Name,
				SharedSecret:       clusterConfig.SharedSecret,
				Peers:              peers,
				BatchSize:          1000,
				ReconnectInterval:  5 * time.Second,
				PingInterval:       30 * time.Second,
				TombstoneRetention: 7 * 24 * time.Hour,
			}

			// Save sync config to storage
			storeCfg := &config.SyncConfig{
				Enabled:                true,
				NodeID:                 clusterConfig.ThisServer.ServerID,
				ServerName:             clusterConfig.ThisServer.Name,
				SharedSecret:           clusterConfig.SharedSecret,
				TombstoneRetentionDays: 7,
			}
			for _, p := range clusterConfig.Peers {
				storeCfg.Peers = append(storeCfg.Peers, config.SyncPeerConfig{
					ID:      p.ServerID,
					Address: p.URL,
				})
			}
			if err := store.SaveSyncConfig(storeCfg); err != nil {
				return errors.New("failed to save sync config: " + err.Error())
			}

			// Apply config to running sync manager
			syncMgr.UpdateConfig(newConfig)

			log.Printf("[cluster-join] Sync configured successfully")
			return nil
		})
	}

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
	// Run in background to avoid blocking server startup
	log.Printf("[init] Starting sync-repair goroutine...")
	go func() {
		log.Printf("[sync-repair] Goroutine started, waiting 2s before repair to let main thread proceed...")
		time.Sleep(2 * time.Second)
		log.Printf("[sync-repair] Starting repair process...")
		repairSyncEntries(mgr, store)
		log.Printf("[sync-repair] Repair process complete")
	}()

	log.Printf("[init] Sync manager initialization complete, returning...")
	return mgr
}

// repairSyncEntries replays oplog entries from remote servers to ensure they're applied
// This handles the case where entity type support was added after entries were synced
func repairSyncEntries(mgr *sync.Manager, store *storage.Store) {
	log.Printf("[sync-repair] repairSyncEntries called")
	localServerID := mgr.ServerID()
	log.Printf("[sync-repair] Local server ID: %s", localServerID)
	repaired := 0
	entryCount := 0

	log.Printf("[sync-repair] Calling ReplayAllEntries...")
	err := mgr.ReplayAllEntries(func(entry *sync.OpLogEntry) error {
		entryCount++
		if entryCount%100 == 0 {
			log.Printf("[sync-repair] Processed %d oplog entries...", entryCount)
		}
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
		// Delete record by content ID - uses content-based matching for consistency across servers
		return store.DeleteRecordByContentID(entityID)
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
	case sync.EntityTLSCert:
		return store.DeleteCertificate(entityID)
	case sync.EntityBlocklistSource:
		return store.DeleteBlocklistSource(entityID)
	default:
		log.Printf("[sync] Unknown entity type for delete: %s", entityType)
		return nil
	}
}

// entityHasChanged compares two entities to determine if they have meaningful differences.
// It ignores timestamp fields (CreatedAt, UpdatedAt) to prevent sync loops.
func entityHasChanged(existing, incoming interface{}) bool {
	// Marshal both to JSON for comparison, but we need to normalize timestamps
	existingData, err := json.Marshal(existing)
	if err != nil {
		return true // Can't compare, assume changed
	}
	incomingData, err := json.Marshal(incoming)
	if err != nil {
		return true // Can't compare, assume changed
	}

	// Unmarshal to maps so we can remove timestamp fields
	var existingMap, incomingMap map[string]interface{}
	if err := json.Unmarshal(existingData, &existingMap); err != nil {
		return true
	}
	if err := json.Unmarshal(incomingData, &incomingMap); err != nil {
		return true
	}

	// Remove timestamp fields that we want to ignore
	timestampFields := []string{"created_at", "updated_at", "CreatedAt", "UpdatedAt", "last_sync_time", "LastSyncTime"}
	for _, field := range timestampFields {
		delete(existingMap, field)
		delete(incomingMap, field)
	}

	// Re-marshal and compare
	existingNorm, _ := json.Marshal(existingMap)
	incomingNorm, _ := json.Marshal(incomingMap)

	return string(existingNorm) != string(incomingNorm)
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
			// Check if anything has actually changed
			if !entityHasChanged(existing, &zone) {
				log.Printf("[sync] Zone %s unchanged, skipping update", zone.Name)
				return nil
			}
			// Use UpdateZonePreserveSerial to preserve the synced serial
			// and prevent triggering further sync events
			return store.UpdateZonePreserveSerial(&zone)
		}
		// Use CreateZonePreserveSerial to preserve the synced serial
		return store.CreateZonePreserveSerial(&zone)

	case sync.EntityRecord:
		var record storage.Record
		if err := json.Unmarshal(data, &record); err != nil {
			return err
		}
		// For records, check if it already exists with same data
		if entry.Operation == sync.OpCreate {
			// Check if record already exists
			existing, err := store.GetRecords(record.Zone, record.Name, record.Type)
			if err == nil {
				for _, r := range existing {
					if r.ID == record.ID {
						// Record already exists, check if changed
						if !entityHasChanged(&r, &record) {
							log.Printf("[sync] Record %s unchanged, skipping create", record.ID)
							return nil
						}
						// Exists but changed, update instead
						return store.UpdateRecord(&record)
					}
				}
			}
			err = store.CreateRecord(&record)
			// Handle duplicate error gracefully - it means the record content already exists
			if err != nil && err.Error() == "duplicate record exists" {
				log.Printf("[sync] Record %s duplicate content, skipping create", record.ID)
				return nil
			}
			return err
		}
		// For updates, check if record has actually changed
		existing, err := store.GetRecords(record.Zone, record.Name, record.Type)
		if err == nil {
			for _, r := range existing {
				if r.ID == record.ID {
					if !entityHasChanged(&r, &record) {
						log.Printf("[sync] Record %s unchanged, skipping update", record.ID)
						return nil
					}
					break
				}
			}
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
			// Preserve existing password hash if incoming is empty
			// This handles stale oplog entries that don't include password hash
			if user.PasswordHash == "" && existing.PasswordHash != "" {
				user.PasswordHash = existing.PasswordHash
			}
			// Check if anything has actually changed
			if !entityHasChanged(existing, &user) {
				log.Printf("[sync] User %s unchanged, skipping update", user.ID)
				return nil
			}
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
			// Check if anything has actually changed
			if !entityHasChanged(existing, &tenant) {
				log.Printf("[sync] Tenant %s unchanged, skipping update", tenant.ID)
				return nil
			}
			return store.UpdateTenant(&tenant)
		}
		return store.CreateTenant(&tenant)

	case sync.EntityDNSSECKeys:
		var keys storage.DNSSECKeys
		if err := json.Unmarshal(data, &keys); err != nil {
			return err
		}
		// Check if DNSSEC keys have changed
		existing, _ := store.GetDNSSECKeys(keys.ZoneName)
		if existing != nil {
			if !entityHasChanged(existing, &keys) {
				log.Printf("[sync] DNSSEC keys for %s unchanged, skipping update", keys.ZoneName)
				return nil
			}
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
			// Check if anything has actually changed
			if !entityHasChanged(existing, &apiKey) {
				log.Printf("[sync] API key %s unchanged, skipping update", apiKey.ID)
				return nil
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

	case sync.EntityTLSCert:
		var cert storage.TLSCertificate
		if err := json.Unmarshal(data, &cert); err != nil {
			return err
		}
		// Only sync if the certificate is valid (not expired)
		if time.Now().After(cert.NotAfter) {
			log.Printf("[sync] Skipping expired certificate for %s", cert.Domain)
			return nil
		}
		// Check if certificate has actually changed
		existing, _ := store.GetCertificate(cert.Domain)
		if existing != nil {
			if !entityHasChanged(existing, &cert) {
				log.Printf("[sync] TLS certificate for %s unchanged, skipping update", cert.Domain)
				return nil
			}
		}
		log.Printf("[sync] Syncing TLS certificate for %s (expires %s)", cert.Domain, cert.NotAfter.Format("2006-01-02"))
		return store.StoreCertificate(&cert)

	case sync.EntityRecursion:
		var cfg storage.RecursionConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
		// Check if recursion config has actually changed
		existing, _ := store.GetRecursionConfig()
		if existing != nil {
			if !entityHasChanged(existing, &cfg) {
				log.Printf("[sync] Recursion config unchanged, skipping update")
				return nil
			}
		}
		log.Printf("[sync] Syncing recursion config (enabled: %v, mode: %s)", cfg.Enabled, cfg.Mode)
		return store.UpdateRecursionConfig(&cfg)

	case sync.EntityBlocklistConfig:
		var cfg storage.BlocklistConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
		log.Printf("[sync] Syncing blocklist config (enabled: %v)", cfg.Enabled)
		return store.SaveBlocklistConfig(&cfg)

	case sync.EntityBlocklistSource:
		var source storage.BlocklistSource
		if err := json.Unmarshal(data, &source); err != nil {
			return err
		}
		existing, _ := store.GetBlocklistSource(source.ID)
		if existing != nil {
			if !entityHasChanged(existing, &source) {
				log.Printf("[sync] Blocklist source %s unchanged, skipping update", source.ID)
				return nil
			}
		}
		log.Printf("[sync] Syncing blocklist source %s (enabled: %v)", source.ID, source.Enabled)
		return store.SaveBlocklistSource(&source)

	case sync.EntityBlocklistWhitelist:
		var entries []string
		if err := json.Unmarshal(data, &entries); err != nil {
			return err
		}
		log.Printf("[sync] Syncing blocklist whitelist (%d entries)", len(entries))
		return store.SaveBlocklistWhitelist(entries)

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

		// Get all users (for each tenant) - include password hash for cluster auth
		for _, tenant := range tenants {
			users, err := store.ListUsers(tenant.ID)
			if err != nil {
				log.Printf("[sync] Warning: failed to list users for tenant %s: %v", tenant.ID, err)
				continue
			}
			for _, user := range users {
				// Include full user data for cluster sync (password hash needed for auth)
				items = append(items, sync.FullSyncDataItem{
					EntityType: sync.EntityUser,
					EntityID:   user.ID,
					TenantID:   user.TenantID,
					Data:       user,
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

		// Get all TLS certificates (for cluster-wide certificate sharing)
		certs, err := store.ListCertificates()
		if err != nil {
			log.Printf("[sync] Warning: failed to list certificates: %v", err)
		} else {
			for _, cert := range certs {
				// Only sync valid (non-expired) certificates
				if time.Now().Before(cert.NotAfter) {
					items = append(items, sync.FullSyncDataItem{
						EntityType: sync.EntityTLSCert,
						EntityID:   cert.Domain,
						TenantID:   "",
						Data:       cert,
					})
				}
			}
		}

		// Get recursion config (for cluster-wide recursion settings)
		recursionCfg, err := store.GetRecursionConfig()
		if err != nil {
			log.Printf("[sync] Warning: failed to get recursion config: %v", err)
		} else {
			items = append(items, sync.FullSyncDataItem{
				EntityType: sync.EntityRecursion,
				EntityID:   storage.ConfigKeyRecursion,
				TenantID:   "",
				Data:       recursionCfg,
			})
		}

		log.Printf("[sync] Full sync provider collected %d items", len(items))
		return items, nil
	}
}
