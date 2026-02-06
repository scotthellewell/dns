package sync

import (
	"time"
)

// Config holds the sync configuration
type Config struct {
	// Enable cluster synchronization
	Enabled bool `json:"enabled"`

	// Unique identifier for this server (auto-generated if empty)
	ServerID string `json:"server_id"`

	// Display name for this server
	ServerName string `json:"server_name"`

	// Peers to connect to
	Peers []PeerConfig `json:"peers"`

	// Shared secret for peer authentication
	SharedSecret string `json:"shared_secret"`

	// OpLog retention period for tombstones (default: 7 days)
	TombstoneRetention time.Duration `json:"tombstone_retention"`

	// Maximum batch size for sync operations (default: 1000)
	BatchSize int `json:"batch_size"`

	// Reconnect interval when peer is unavailable (default: 5 seconds)
	ReconnectInterval time.Duration `json:"reconnect_interval"`

	// Ping interval for keepalive (default: 30 seconds)
	PingInterval time.Duration `json:"ping_interval"`
}

// PeerConfig holds configuration for a sync peer
type PeerConfig struct {
	// ID is a friendly identifier for this peer (e.g., "ns2")
	ID string `json:"id,omitempty"`

	// URL of the peer (e.g., "https://dns2.example.com")
	URL string `json:"url"`

	// API key for authenticating with the peer
	APIKey string `json:"api_key,omitempty"`

	// Optional: Skip TLS verification (for self-signed certs)
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// DefaultConfig returns a Config with default values
func DefaultConfig() *Config {
	return &Config{
		Enabled:            false,
		TombstoneRetention: 7 * 24 * time.Hour,
		BatchSize:          1000,
		ReconnectInterval:  5 * time.Second,
		PingInterval:       30 * time.Second,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.SharedSecret == "" {
		return &ConfigError{"shared_secret is required when sync is enabled"}
	}

	if len(c.Peers) == 0 {
		return &ConfigError{"at least one peer is required when sync is enabled"}
	}

	return nil
}

// ConfigError represents a configuration error
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return "sync config error: " + e.Message
}
