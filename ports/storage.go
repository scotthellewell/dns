package ports

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/scott/dns/storage"
)

// StorageInterface defines storage methods needed by port manager
type StorageInterface interface {
	GetServerConfig() (*storage.ServerConfig, error)
	UpdateServerConfig(config *storage.ServerConfig) error
}

// WebPortFallbacks defines the ports to try for the web UI in order of preference
// All ports use TLS - non-TLS web UI is not supported
var WebPortFallbacks = []int{443, 8443, 9443}

// getRandomHighPort returns a random port in the range 49152-65535 (dynamic/private ports)
func getRandomHighPort() int {
	return 49152 + int(time.Now().UnixNano()%16383) // Range: 49152-65535
}

// checkPortAvailable tests if a port is available for binding
func checkPortAvailable(address string, port int) bool {
	addr := fmt.Sprintf("%s:%d", address, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

// findAvailableWebPort tries ports in order and returns the first available one
// Falls back to a random high port if all standard ports are taken
func findAvailableWebPort(address string) (int, bool) {
	// Try standard ports first
	for _, port := range WebPortFallbacks {
		if checkPortAvailable(address, port) {
			return port, true
		}
		log.Printf("Port %d is not available, trying next...", port)
	}
	
	// Try random high ports as last resort (try a few times)
	for i := 0; i < 5; i++ {
		port := getRandomHighPort()
		if checkPortAvailable(address, port) {
			log.Printf("Using random high port %d", port)
			return port, true
		}
	}
	
	return 0, false
}

// NewManagerWithStorage creates a port manager backed by storage
func NewManagerWithStorage(store StorageInterface) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		configPath: "", // Not used with storage
		ctx:        ctx,
		cancel:     cancel,
		config: Config{
			DNS: DNSPortConfig{
				Enabled: true,
				Port:    53,
				Address: "",
			},
			DoT: DoTPortConfig{
				Enabled: false,
				Port:    853,
				Address: "",
			},
			DoH: DoHPortConfig{
				Enabled:    false,
				Standalone: false,
				Port:       443,
				Address:    "",
				Path:       "/dns-query",
			},
			Web: WebPortConfig{
				Enabled: true,
				Port:    443,
				Address: "",
				TLS:     true,
			},
		},
		storage: store,
	}

	// Try to load config from storage
	serverConfig, err := store.GetServerConfig()
	if err == nil && serverConfig != nil && serverConfig.Web.Port > 0 {
		// Existing config with port already set - use saved settings
		m.config.DNS.Enabled = serverConfig.DNS.Enabled
		m.config.DNS.Port = serverConfig.DNS.UDPPort
		m.config.DNS.Address = serverConfig.DNS.Address
		if m.config.DNS.Port == 0 {
			m.config.DNS.Port = 53
		}

		m.config.DoT.Enabled = serverConfig.DoT.Enabled
		m.config.DoT.Port = serverConfig.DoT.Port
		m.config.DoT.Address = serverConfig.DoT.Address
		if m.config.DoT.Port == 0 {
			m.config.DoT.Port = 853
		}

		m.config.DoH.Enabled = serverConfig.DoH.Enabled
		m.config.DoH.Standalone = serverConfig.DoH.Standalone
		m.config.DoH.Port = serverConfig.DoH.Port
		m.config.DoH.Address = serverConfig.DoH.Address
		m.config.DoH.Path = serverConfig.DoH.Path
		if m.config.DoH.Port == 0 {
			m.config.DoH.Port = 443
		}
		if m.config.DoH.Path == "" {
			m.config.DoH.Path = "/dns-query"
		}

		m.config.Web.Enabled = serverConfig.Web.Enabled
		m.config.Web.Port = serverConfig.Web.Port
		m.config.Web.Address = serverConfig.Web.Address
		m.config.Web.TLS = true // TLS is always required
		
		log.Printf("Loaded port configuration from storage (Web: %d)", m.config.Web.Port)
	} else {
		// No existing config - auto-detect available web port
		log.Printf("No port configuration found, auto-detecting available web port...")
		
		if port, found := findAvailableWebPort(m.config.Web.Address); found {
			m.config.Web.Port = port
			m.config.Web.TLS = true // TLS is always required
			
			// Log the URL prominently
			hostname := m.config.Web.Address
			if hostname == "" {
				hostname = "localhost"
			}
			log.Printf("╔════════════════════════════════════════════════════════════╗")
			log.Printf("║  Web UI will be available at: https://%s:%d", hostname, port)
			log.Printf("╚════════════════════════════════════════════════════════════╝")
			
			if port != 443 {
				log.Printf("Note: Port 443 was not available. Using port %d instead.", port)
				log.Printf("For SNI proxy configuration, point your hostname to internal port %d", port)
			}
			
			// Save the detected configuration to storage
			newConfig := &storage.ServerConfig{
				DNS: storage.DNSConfig{
					Enabled: m.config.DNS.Enabled,
					UDPPort: m.config.DNS.Port,
					TCPPort: m.config.DNS.Port,
					Address: m.config.DNS.Address,
				},
				DoT: storage.DoTConfig{
					Enabled: m.config.DoT.Enabled,
					Port:    m.config.DoT.Port,
					Address: m.config.DoT.Address,
				},
				DoH: storage.DoHConfig{
					Enabled:    m.config.DoH.Enabled,
					Standalone: m.config.DoH.Standalone,
					Port:       m.config.DoH.Port,
					Address:    m.config.DoH.Address,
					Path:       m.config.DoH.Path,
				},
				Web: storage.WebConfig{
					Enabled: m.config.Web.Enabled,
					Port:    m.config.Web.Port,
					Address: m.config.Web.Address,
					TLS:     m.config.Web.TLS,
				},
			}
			if err := store.UpdateServerConfig(newConfig); err != nil {
				log.Printf("Warning: Could not save auto-detected port configuration: %v", err)
			} else {
				log.Printf("Saved port configuration to storage")
			}
		} else {
			log.Printf("WARNING: No available web ports found! Tried: %v", WebPortFallbacks)
			log.Printf("The web UI may not be accessible. Check if another service is using these ports.")
		}
	}

	return m
}
