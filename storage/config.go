package storage

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// Config keys
const (
	ConfigKeyServer      = "server"
	ConfigKeyRecursion   = "recursion"
	ConfigKeyRateLimit   = "rate_limit"
	ConfigKeyQueryLog    = "query_log"
	ConfigKeyTransfer    = "transfer"
	ConfigKeyOIDC        = "oidc"
	ConfigKeyWebAuthn    = "webauthn"
	ConfigKeyACME        = "acme"
	ConfigKeyACMEAcctKey = "acme_account_key"
	ConfigKeyACMEState   = "acme_state"
)

// GetServerConfig retrieves the server configuration.
func (s *Store) GetServerConfig() (*ServerConfig, error) {
	var config ServerConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(ConfigKeyServer))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &config)
	})

	if err == ErrNotFound {
		// Return defaults
		return &ServerConfig{
			DNS: DNSConfig{
				Enabled: true,
				UDPPort: 53,
				TCPPort: 53,
				Address: "",
			},
			DoT: DoTConfig{
				Enabled: false,
				Port:    853,
				Address: "",
			},
			DoH: DoHConfig{
				Enabled: false,
				Port:    443,
				Path:    "/dns-query",
			},
			Web: WebConfig{
				Enabled: true,
				Port:    8080,
				TLS:     false,
			},
		}, nil
	}

	return &config, err
}

// UpdateServerConfig saves the server configuration.
func (s *Store) UpdateServerConfig(config *ServerConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(ConfigKeyServer), data)
	})
}

// GetRecursionConfig retrieves the recursion configuration.
func (s *Store) GetRecursionConfig() (*RecursionConfig, error) {
	var config RecursionConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(ConfigKeyRecursion))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &config)
	})

	if err == ErrNotFound {
		// Return defaults
		return &RecursionConfig{
			Enabled:  false,
			Mode:     "partial",
			Upstream: []string{},
			Timeout:  5,
			MaxDepth: 10,
		}, nil
	}

	return &config, err
}

// UpdateRecursionConfig saves the recursion configuration.
func (s *Store) UpdateRecursionConfig(config *RecursionConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(ConfigKeyRecursion), data)
	})
}

// GetRateLimitConfig retrieves the rate limit configuration.
func (s *Store) GetRateLimitConfig() (*RateLimitConfig, error) {
	var config RateLimitConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(ConfigKeyRateLimit))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &config)
	})

	if err == ErrNotFound {
		// Return defaults
		return &RateLimitConfig{
			Enabled:         false,
			ResponsesPerSec: 100,
			SlipRatio:       2,
			WindowSeconds:   1,
			WhitelistCIDRs:  []string{"127.0.0.1/8", "::1/128"},
		}, nil
	}

	return &config, err
}

// UpdateRateLimitConfig saves the rate limit configuration.
func (s *Store) UpdateRateLimitConfig(config *RateLimitConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(ConfigKeyRateLimit), data)
	})
}

// GetQueryLogConfig retrieves the query logging configuration.
func (s *Store) GetQueryLogConfig() (*QueryLogConfig, error) {
	var config QueryLogConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(ConfigKeyQueryLog))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &config)
	})

	if err == ErrNotFound {
		// Return defaults
		return &QueryLogConfig{
			Enabled:     false,
			LogSuccess:  true,
			LogNXDomain: true,
			LogErrors:   true,
			Retention:   7,
		}, nil
	}

	return &config, err
}

// UpdateQueryLogConfig saves the query logging configuration.
func (s *Store) UpdateQueryLogConfig(config *QueryLogConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(ConfigKeyQueryLog), data)
	})
}

// GetTransferConfig retrieves the zone transfer configuration.
func (s *Store) GetTransferConfig() (*TransferConfig, error) {
	var config TransferConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(ConfigKeyTransfer))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &config)
	})

	if err == ErrNotFound {
		// Return defaults
		return &TransferConfig{
			Enabled:       false,
			TSIGKeys:      []TSIGKey{},
			DefaultACL:    []string{},
			NotifyEnabled: false,
		}, nil
	}

	return &config, err
}

// UpdateTransferConfig saves the zone transfer configuration.
func (s *Store) UpdateTransferConfig(config *TransferConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(ConfigKeyTransfer), data)
	})
}

// GetOIDCConfig retrieves the OIDC configuration.
func (s *Store) GetOIDCConfig() (*OIDCConfig, error) {
	var config OIDCConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(ConfigKeyOIDC))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &config)
	})

	if err == ErrNotFound {
		return &OIDCConfig{
			Enabled: false,
		}, nil
	}

	return &config, err
}

// UpdateOIDCConfig saves the OIDC configuration.
func (s *Store) UpdateOIDCConfig(config *OIDCConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(ConfigKeyOIDC), data)
	})
}

// GetWebAuthnConfig retrieves the WebAuthn configuration.
func (s *Store) GetWebAuthnConfig() (*WebAuthnConfig, error) {
	var config WebAuthnConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(ConfigKeyWebAuthn))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &config)
	})

	if err == ErrNotFound {
		return &WebAuthnConfig{
			Enabled: false,
		}, nil
	}

	return &config, err
}

// UpdateWebAuthnConfig saves the WebAuthn configuration.
func (s *Store) UpdateWebAuthnConfig(config *WebAuthnConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(ConfigKeyWebAuthn), data)
	})
}

// GetACMEConfig retrieves the ACME configuration.
func (s *Store) GetACMEConfig() (*ACMEConfig, error) {
	var config ACMEConfig

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(ConfigKeyACME))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &config)
	})

	if err == ErrNotFound {
		return &ACMEConfig{
			Enabled: false,
		}, nil
	}

	return &config, err
}

// UpdateACMEConfig saves the ACME configuration.
func (s *Store) UpdateACMEConfig(config *ACMEConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(ConfigKeyACME), data)
	})
}

// GetACMEAccountKey retrieves the ACME account private key.
func (s *Store) GetACMEAccountKey() ([]byte, error) {
	var key []byte

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(ConfigKeyACMEAcctKey))
		if data == nil {
			return ErrNotFound
		}
		key = make([]byte, len(data))
		copy(key, data)
		return nil
	})

	if err == ErrNotFound {
		return nil, nil
	}

	return key, err
}

// SaveACMEAccountKey saves the ACME account private key.
func (s *Store) SaveACMEAccountKey(key []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		return bucket.Put([]byte(ConfigKeyACMEAcctKey), key)
	})
}

// GetACMEState retrieves the ACME state.
func (s *Store) GetACMEState() (*ACMEState, error) {
	var state ACMEState

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(ConfigKeyACMEState))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &state)
	})

	if err == ErrNotFound {
		return &ACMEState{}, nil
	}

	return &state, err
}

// SaveACMEState saves the ACME state.
func (s *Store) SaveACMEState(state *ACMEState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data, err := json.Marshal(state)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(ConfigKeyACMEState), data)
	})
}

// GetConfigValue retrieves a generic configuration value by key.
func (s *Store) GetConfigValue(key string, v interface{}) error {
	return s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data := bucket.Get([]byte(key))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, v)
	})
}

// SetConfigValue saves a generic configuration value by key.
func (s *Store) SetConfigValue(key string, v interface{}) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), data)
	})
}

// DeleteConfigValue deletes a configuration value by key.
func (s *Store) DeleteConfigValue(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))
		return bucket.Delete([]byte(key))
	})
}

// ListConfigKeys lists all configuration keys.
func (s *Store) ListConfigKeys() ([]string, error) {
	var keys []string

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("config"))

		return bucket.ForEach(func(k, v []byte) error {
			keys = append(keys, string(k))
			return nil
		})
	})

	return keys, err
}

// TLSCertificate storage

// StoreCertificate saves a TLS certificate.
func (s *Store) StoreCertificate(cert *TLSCertificate) error {
	if cert.Domain == "" {
		return fmt.Errorf("certificate domain required")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("certificates"))
		data, err := json.Marshal(cert)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(cert.Domain), data)
	})
}

// GetCertificate retrieves a TLS certificate by domain.
func (s *Store) GetCertificate(domain string) (*TLSCertificate, error) {
	var cert TLSCertificate

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("certificates"))
		data := bucket.Get([]byte(domain))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &cert)
	})

	return &cert, err
}

// DeleteCertificate deletes a TLS certificate.
func (s *Store) DeleteCertificate(domain string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("certificates"))
		return bucket.Delete([]byte(domain))
	})
}

// ListCertificates lists all TLS certificates.
func (s *Store) ListCertificates() ([]TLSCertificate, error) {
	var certs []TLSCertificate

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("certificates"))

		return bucket.ForEach(func(k, v []byte) error {
			var cert TLSCertificate
			if err := json.Unmarshal(v, &cert); err != nil {
				return err
			}
			certs = append(certs, cert)
			return nil
		})
	})

	return certs, err
}
