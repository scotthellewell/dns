package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// ACMEConfig holds ACME/Let's Encrypt configuration
type ACMEConfig struct {
	Enabled       bool     `json:"enabled"`
	Email         string   `json:"email"`
	Domains       []string `json:"domains"`
	UseStaging    bool     `json:"use_staging"`    // Use Let's Encrypt staging for testing
	ChallengeType string   `json:"challenge_type"` // "http-01" or "dns-01"
	AutoRenew     bool     `json:"auto_renew"`
	RenewBefore   int      `json:"renew_before"` // Days before expiry to renew
}

// ACMEState holds the current ACME state
type ACMEState struct {
	Email        string    `json:"email"`
	Domains      []string  `json:"domains"`
	LastRenewal  time.Time `json:"last_renewal"`
	NextRenewal  time.Time `json:"next_renewal"`
	Registration string    `json:"registration_uri"`
}

// ACMEUser implements the acme.User interface
type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}

func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// DNSProvider interface for DNS-01 challenge
type DNSProvider interface {
	// SetTXTRecord sets a TXT record for DNS-01 challenge
	SetTXTRecord(fqdn, value string) error
	// RemoveTXTRecord removes the TXT record after challenge
	RemoveTXTRecord(fqdn string) error
}

// ACMEStorage defines storage methods needed by ACME manager
type ACMEStorage interface {
	GetACMEConfig() (*ACMEConfig, error)
	UpdateACMEConfig(config *ACMEConfig) error
	GetACMEAccountKey() ([]byte, error)
	SaveACMEAccountKey(key []byte) error
}

// ACMEManager handles ACME certificate operations
type ACMEManager struct {
	mu             sync.RWMutex
	config         ACMEConfig
	state          ACMEState
	certManager    *Manager
	dnsProvider    DNSProvider
	httpServer     *http.Server
	httpChallenge  *http01.ProviderServer
	configFile     string
	stateFile      string
	accountKeyFile string
	stopRenew      chan struct{}
	storage        ACMEStorage
}

// NewACMEManager creates a new ACME manager
func NewACMEManager(certManager *Manager) (*ACMEManager, error) {
	m := &ACMEManager{
		certManager:    certManager,
		configFile:     "acme-config.json",
		stateFile:      "acme-state.json",
		accountKeyFile: "acme-account.pem",
		stopRenew:      make(chan struct{}),
	}

	// Load existing config
	if err := m.loadConfig(); err != nil {
		// Use defaults
		m.config = ACMEConfig{
			Enabled:       false,
			UseStaging:    true,
			ChallengeType: "http-01",
			AutoRenew:     true,
			RenewBefore:   30,
		}
	}

	// Load state
	m.loadState()

	return m, nil
}

// loadConfig loads ACME configuration from file
func (m *ACMEManager) loadConfig() error {
	data, err := os.ReadFile(m.configFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &m.config)
}

// saveConfig saves ACME configuration to storage or file
func (m *ACMEManager) saveConfig() error {
	if m.storage != nil {
		return m.storage.UpdateACMEConfig(&m.config)
	}
	// Fall back to file-based storage
	if m.configFile == "" {
		return nil // No storage configured
	}
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.configFile, data, 0644)
}

// loadState loads ACME state from file
func (m *ACMEManager) loadState() error {
	data, err := os.ReadFile(m.stateFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &m.state)
}

// saveState saves ACME state to file
func (m *ACMEManager) saveState() error {
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.stateFile, data, 0644)
}

// GetConfig returns the current ACME configuration
func (m *ACMEManager) GetConfig() ACMEConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// GetState returns the current ACME state
func (m *ACMEManager) GetState() ACMEState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// SetDNSProvider sets the DNS provider for DNS-01 challenges
func (m *ACMEManager) SetDNSProvider(provider DNSProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dnsProvider = provider
}

// UpdateConfig updates the ACME configuration
func (m *ACMEManager) UpdateConfig(config ACMEConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config = config
	return m.saveConfig()
}

// getAccountKey loads or generates the ACME account private key
func (m *ACMEManager) getAccountKey() (crypto.PrivateKey, error) {
	// Try to load existing key from storage first
	if m.storage != nil {
		data, err := m.storage.GetACMEAccountKey()
		if err == nil && len(data) > 0 {
			block, _ := pem.Decode(data)
			if block != nil {
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err == nil {
					return key, nil
				}
			}
		}
	} else if m.accountKeyFile != "" {
		// Fall back to file-based storage
		data, err := os.ReadFile(m.accountKeyFile)
		if err == nil {
			block, _ := pem.Decode(data)
			if block != nil {
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err == nil {
					return key, nil
				}
			}
		}
	}

	// Generate new key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account key: %v", err)
	}

	// Save key
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal account key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Save to storage or file
	if m.storage != nil {
		if err := m.storage.SaveACMEAccountKey(keyPEM); err != nil {
			return nil, fmt.Errorf("failed to save account key: %v", err)
		}
	} else if m.accountKeyFile != "" {
		if err := os.WriteFile(m.accountKeyFile, keyPEM, 0600); err != nil {
			return nil, fmt.Errorf("failed to save account key: %v", err)
		}
	}

	return key, nil
}

// RequestCertificate requests a new certificate from ACME
func (m *ACMEManager) RequestCertificate(email string, domains []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(domains) == 0 {
		return fmt.Errorf("no domains specified")
	}

	if email == "" {
		return fmt.Errorf("email is required")
	}

	// Get or create account key
	accountKey, err := m.getAccountKey()
	if err != nil {
		return err
	}

	user := &ACMEUser{
		Email: email,
		key:   accountKey,
	}

	// Configure ACME client
	config := lego.NewConfig(user)
	if m.config.UseStaging {
		config.CADirURL = lego.LEDirectoryStaging
		log.Printf("ACME: Using Let's Encrypt STAGING environment")
	} else {
		config.CADirURL = lego.LEDirectoryProduction
		log.Printf("ACME: Using Let's Encrypt PRODUCTION environment")
	}
	config.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %v", err)
	}

	// Set up challenge provider based on type
	switch m.config.ChallengeType {
	case "dns-01":
		if m.dnsProvider == nil {
			return fmt.Errorf("DNS provider not configured for DNS-01 challenge")
		}
		// Use our custom DNS provider
		if err := client.Challenge.SetDNS01Provider(&legoDNSProvider{provider: m.dnsProvider}); err != nil {
			return fmt.Errorf("failed to set DNS-01 provider: %v", err)
		}
	case "http-01":
		fallthrough
	default:
		// Start HTTP server for HTTP-01 challenge on port 80
		provider := http01.NewProviderServer("", "80")
		if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
			return fmt.Errorf("failed to set HTTP-01 provider: %v", err)
		}
	}

	// Register account if needed
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("failed to register ACME account: %v", err)
	}
	user.Registration = reg

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	// Upload certificate to our manager
	if err := m.certManager.UploadCertificate(certificates.Certificate, certificates.PrivateKey); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	// Update state
	m.state = ACMEState{
		Email:        email,
		Domains:      domains,
		LastRenewal:  time.Now(),
		NextRenewal:  time.Now().Add(time.Duration(90-m.config.RenewBefore) * 24 * time.Hour),
		Registration: reg.URI,
	}
	m.config.Email = email
	m.config.Domains = domains
	m.config.Enabled = true

	if err := m.saveState(); err != nil {
		log.Printf("Warning: failed to save ACME state: %v", err)
	}
	if err := m.saveConfig(); err != nil {
		log.Printf("Warning: failed to save ACME config: %v", err)
	}

	log.Printf("Successfully obtained ACME certificate for %v", domains)
	return nil
}

// RenewCertificate renews the current ACME certificate
func (m *ACMEManager) RenewCertificate() error {
	m.mu.RLock()
	email := m.config.Email
	domains := m.config.Domains
	m.mu.RUnlock()

	if email == "" || len(domains) == 0 {
		return fmt.Errorf("no ACME certificate configured")
	}

	return m.RequestCertificate(email, domains)
}

// StartAutoRenew starts the auto-renewal background task
func (m *ACMEManager) StartAutoRenew() {
	go func() {
		ticker := time.NewTicker(24 * time.Hour) // Check daily
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.checkAndRenew()
			case <-m.stopRenew:
				return
			}
		}
	}()
}

// StopAutoRenew stops the auto-renewal background task
func (m *ACMEManager) StopAutoRenew() {
	close(m.stopRenew)
}

// checkAndRenew checks if renewal is needed and performs it
func (m *ACMEManager) checkAndRenew() {
	m.mu.RLock()
	if !m.config.Enabled || !m.config.AutoRenew {
		m.mu.RUnlock()
		return
	}
	nextRenewal := m.state.NextRenewal
	m.mu.RUnlock()

	if time.Now().After(nextRenewal) {
		log.Println("ACME certificate renewal needed, starting renewal...")
		if err := m.RenewCertificate(); err != nil {
			log.Printf("Failed to renew ACME certificate: %v", err)
		}
	}
}

// GetHTTPChallengeHandler returns an HTTP handler for ACME HTTP-01 challenges
// This should be mounted at /.well-known/acme-challenge/
func (m *ACMEManager) GetHTTPChallengeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The lego library handles this internally when using http01.ProviderServer
		// This is a fallback handler
		http.NotFound(w, r)
	})
}

// legoDNSProvider wraps our DNSProvider to implement lego's challenge.Provider interface
type legoDNSProvider struct {
	provider DNSProvider
}

func (p *legoDNSProvider) Present(domain, token, keyAuth string) error {
	// ACME DNS-01 challenge requires a TXT record at _acme-challenge.<domain>
	fqdn := "_acme-challenge." + domain + "."
	return p.provider.SetTXTRecord(fqdn, keyAuth)
}

func (p *legoDNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn := "_acme-challenge." + domain + "."
	return p.provider.RemoveTXTRecord(fqdn)
}

// Timeout returns the timeout and interval for DNS propagation
func (p *legoDNSProvider) Timeout() (timeout, interval time.Duration) {
	return 2 * time.Minute, 5 * time.Second
}
