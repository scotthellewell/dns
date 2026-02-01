package ports

import (
	"context"
	"log"

	"github.com/scott/dns/storage"
)

// StorageInterface defines storage methods needed by port manager
type StorageInterface interface {
	GetServerConfig() (*storage.ServerConfig, error)
	UpdateServerConfig(config *storage.ServerConfig) error
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
				Port:    8080,
				Address: "",
				TLS:     false,
			},
		},
	}

	// Try to load config from storage
	serverConfig, err := store.GetServerConfig()
	if err == nil && serverConfig != nil {
		// Map storage config to ports config
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
		m.config.Web.TLS = serverConfig.Web.TLS
		if m.config.Web.Port == 0 {
			m.config.Web.Port = 8080
		}
	} else {
		log.Printf("Using default port configuration")
	}

	return m
}
