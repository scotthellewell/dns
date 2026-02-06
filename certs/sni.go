package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/scott/dns/storage"
)

// SNIManager provides SNI-based certificate selection with automatic ACME provisioning
type SNIManager struct {
	mu sync.RWMutex

	// Storage for certificates
	store StorageInterface

	// ACME manager for automatic certificate requests
	acme *ACMEManager

	// Cache of loaded TLS certificates by domain
	certCache map[string]*tls.Certificate

	// Track domains with pending ACME requests
	pendingACME map[string]bool
	pendingMu   sync.Mutex

	// Default certificate for fallback
	defaultCert *tls.Certificate

	// ACME configuration
	acmeEmail string

	// Callback when a new certificate is obtained
	onCertObtained func(domain string)
}

// NewSNIManager creates a new SNI-based certificate manager
func NewSNIManager(store StorageInterface, acme *ACMEManager) *SNIManager {
	m := &SNIManager{
		store:       store,
		acme:        acme,
		certCache:   make(map[string]*tls.Certificate),
		pendingACME: make(map[string]bool),
	}

	// Load default certificate
	m.loadDefaultCert()

	// Get ACME email if configured
	if acme != nil {
		cfg := acme.GetConfig()
		m.acmeEmail = cfg.Email
	}

	return m
}

// SetACMEEmail sets the email for ACME certificate requests
func (m *SNIManager) SetACMEEmail(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acmeEmail = email
}

// SetOnCertObtained sets a callback to be called when a new certificate is obtained
func (m *SNIManager) SetOnCertObtained(fn func(domain string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onCertObtained = fn
}

// loadDefaultCert loads or generates the default certificate
func (m *SNIManager) loadDefaultCert() {
	// Try to load from storage
	cert, err := m.store.GetCertificate("default")
	if err == nil && cert != nil {
		tlsCert, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM))
		if err == nil {
			m.defaultCert = &tlsCert
			return
		}
	}

	// Generate self-signed default cert
	tlsCert, err := m.generateSelfSigned("localhost", []string{"localhost"})
	if err != nil {
		log.Printf("Warning: Failed to generate default certificate: %v", err)
		return
	}
	m.defaultCert = tlsCert
}

// GetTLSConfig returns a TLS configuration with SNI-based certificate selection
func (m *SNIManager) GetTLSConfig() (*tls.Config, error) {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}, nil
}

// GetCertificate is the callback for tls.Config.GetCertificate
// It returns the appropriate certificate based on the SNI hostname
func (m *SNIManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := hello.ServerName
	if serverName == "" {
		// No SNI, return default cert
		m.mu.RLock()
		cert := m.defaultCert
		m.mu.RUnlock()
		return cert, nil
	}

	// Normalize server name (lowercase, no trailing dot)
	serverName = strings.ToLower(strings.TrimSuffix(serverName, "."))

	// Check cache first
	m.mu.RLock()
	if cert, ok := m.certCache[serverName]; ok {
		m.mu.RUnlock()
		return cert, nil
	}
	m.mu.RUnlock()

	// Try to load from storage
	storedCert, err := m.store.GetCertificate(serverName)
	if err == nil && storedCert != nil {
		// Check if certificate is valid (not expired)
		if time.Now().Before(storedCert.NotAfter) {
			tlsCert, err := tls.X509KeyPair([]byte(storedCert.CertPEM), []byte(storedCert.KeyPEM))
			if err == nil {
				// Cache and return
				m.mu.Lock()
				m.certCache[serverName] = &tlsCert
				m.mu.Unlock()
				return &tlsCert, nil
			}
		} else {
			log.Printf("Certificate for %s is expired, will request new one", serverName)
		}
	}

	// No valid certificate found - start ACME request in background and return self-signed
	m.startACMERequest(serverName)

	// Generate and return self-signed certificate for immediate use
	selfSigned, err := m.getOrCreateSelfSigned(serverName)
	if err != nil {
		// Fall back to default
		m.mu.RLock()
		cert := m.defaultCert
		m.mu.RUnlock()
		return cert, nil
	}

	return selfSigned, nil
}

// getOrCreateSelfSigned gets a cached self-signed cert or creates a new one
func (m *SNIManager) getOrCreateSelfSigned(domain string) (*tls.Certificate, error) {
	cacheKey := "selfsigned:" + domain

	m.mu.RLock()
	if cert, ok := m.certCache[cacheKey]; ok {
		m.mu.RUnlock()
		return cert, nil
	}
	m.mu.RUnlock()

	// Generate new self-signed certificate
	cert, err := m.generateSelfSigned(domain, []string{domain})
	if err != nil {
		return nil, err
	}

	// Cache it
	m.mu.Lock()
	m.certCache[cacheKey] = cert
	m.mu.Unlock()

	return cert, nil
}

// startACMERequest starts an ACME certificate request in the background
func (m *SNIManager) startACMERequest(domain string) {
	// Check if request is already pending
	m.pendingMu.Lock()
	if m.pendingACME[domain] {
		m.pendingMu.Unlock()
		return
	}
	m.pendingACME[domain] = true
	m.pendingMu.Unlock()

	// Check if we have ACME configured
	m.mu.RLock()
	email := m.acmeEmail
	acme := m.acme
	m.mu.RUnlock()

	if acme == nil || email == "" {
		log.Printf("ACME not configured, cannot request certificate for %s", domain)
		m.pendingMu.Lock()
		delete(m.pendingACME, domain)
		m.pendingMu.Unlock()
		return
	}

	// Start ACME request in background
	go func() {
		defer func() {
			m.pendingMu.Lock()
			delete(m.pendingACME, domain)
			m.pendingMu.Unlock()
		}()

		log.Printf("Starting ACME certificate request for %s", domain)

		// Request certificate
		if err := m.requestCertificateForDomain(email, domain); err != nil {
			log.Printf("Failed to obtain ACME certificate for %s: %v", domain, err)
			return
		}

		log.Printf("Successfully obtained ACME certificate for %s", domain)

		// Load the new certificate into cache
		storedCert, err := m.store.GetCertificate(domain)
		if err == nil && storedCert != nil {
			tlsCert, err := tls.X509KeyPair([]byte(storedCert.CertPEM), []byte(storedCert.KeyPEM))
			if err == nil {
				m.mu.Lock()
				m.certCache[domain] = &tlsCert
				// Remove self-signed from cache so new cert is used
				delete(m.certCache, "selfsigned:"+domain)
				callback := m.onCertObtained
				m.mu.Unlock()

				// Notify callback
				if callback != nil {
					callback(domain)
				}
			}
		}
	}()
}

// requestCertificateForDomain requests a certificate for a single domain
// This is similar to ACMEManager.RequestCertificate but stores with the domain name
func (m *SNIManager) requestCertificateForDomain(email, domain string) error {
	if m.acme == nil {
		return fmt.Errorf("ACME manager not configured")
	}

	// Use a temporary cert manager to get the certificate
	// We'll intercept the upload and store it with the correct domain name
	tempMgr := &domainCertManager{
		domain: domain,
		store:  m.store,
	}

	// Create a modified ACME manager that uses our temp manager
	origMgr := m.acme.GetCertUploader()
	m.acme.SetCertUploader(tempMgr)

	err := m.acme.RequestCertificate(email, []string{domain})

	// Restore original manager
	m.acme.SetCertUploader(origMgr)

	return err
}

// domainCertManager is a temporary cert manager for storing domain-specific certs
type domainCertManager struct {
	domain string
	store  StorageInterface
}

func (d *domainCertManager) UploadCertificate(certPEM, keyPEM []byte) error {
	// Parse certificate to extract metadata
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("invalid certificate: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Extract IP addresses as strings
	var ipAddresses []string
	for _, ip := range x509Cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	// Store with the specific domain name
	return d.store.StoreCertificate(&storage.TLSCertificate{
		Domain:        d.domain,
		CertPEM:       string(certPEM),
		KeyPEM:        string(keyPEM),
		AutoGenerated: false,
		Subject:       x509Cert.Subject.CommonName,
		Issuer:        x509Cert.Issuer.CommonName,
		NotBefore:     x509Cert.NotBefore,
		NotAfter:      x509Cert.NotAfter,
		DNSNames:      x509Cert.DNSNames,
		IPAddresses:   ipAddresses,
	})
}

// generateSelfSigned generates a self-signed certificate for the given domain
func (m *SNIManager) generateSelfSigned(commonName string, dnsNames []string) (*tls.Certificate, error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour) // Short validity for self-signed

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"DNS Server (Self-Signed)"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Load as tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}

	return &cert, nil
}

// ClearCache clears the certificate cache for a domain
func (m *SNIManager) ClearCache(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.certCache, domain)
	delete(m.certCache, "selfsigned:"+domain)
}

// ClearAllCache clears the entire certificate cache
func (m *SNIManager) ClearAllCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certCache = make(map[string]*tls.Certificate)
}

// PreloadCertificates loads all certificates from storage into cache
func (m *SNIManager) PreloadCertificates() error {
	certs, err := m.store.ListCertificates()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, cert := range certs {
		if time.Now().After(cert.NotAfter) {
			continue // Skip expired
		}

		tlsCert, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM))
		if err != nil {
			log.Printf("Warning: Failed to load certificate for %s: %v", cert.Domain, err)
			continue
		}

		m.certCache[cert.Domain] = &tlsCert

		// Also cache by DNS names
		for _, name := range cert.DNSNames {
			name = strings.ToLower(strings.TrimSuffix(name, "."))
			if name != cert.Domain {
				m.certCache[name] = &tlsCert
			}
		}
	}

	log.Printf("Preloaded %d certificates into cache", len(m.certCache))
	return nil
}

// GetCertificateInfo returns information about a cached certificate
func (m *SNIManager) GetCertificateInfo(domain string) *storage.TLSCertificate {
	cert, err := m.store.GetCertificate(domain)
	if err != nil {
		return nil
	}
	return cert
}

// RefreshCertificate refreshes a certificate from storage into cache
func (m *SNIManager) RefreshCertificate(domain string) error {
	cert, err := m.store.GetCertificate(domain)
	if err != nil {
		return err
	}

	tlsCert, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM))
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.certCache[domain] = &tlsCert
	delete(m.certCache, "selfsigned:"+domain)
	m.mu.Unlock()

	return nil
}

// IsPendingACME returns true if an ACME request is pending for the domain
func (m *SNIManager) IsPendingACME(domain string) bool {
	m.pendingMu.Lock()
	defer m.pendingMu.Unlock()
	return m.pendingACME[domain]
}

// GetConfig returns the current certificate configuration (for compatibility)
func (m *SNIManager) GetConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return info about default cert
	if m.defaultCert != nil && len(m.defaultCert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(m.defaultCert.Certificate[0])
		if err == nil {
			var ips []string
			for _, ip := range x509Cert.IPAddresses {
				ips = append(ips, ip.String())
			}
			return Config{
				AutoGenerated: strings.Contains(x509Cert.Issuer.CommonName, "Self-Signed") ||
					x509Cert.Subject.CommonName == x509Cert.Issuer.CommonName,
				Subject:     x509Cert.Subject.CommonName,
				Issuer:      x509Cert.Issuer.CommonName,
				NotBefore:   x509Cert.NotBefore,
				NotAfter:    x509Cert.NotAfter,
				DNSNames:    x509Cert.DNSNames,
				IPAddresses: ips,
			}
		}
	}

	return Config{}
}

// GetCertificatePEM returns the default certificate in PEM format (for compatibility)
func (m *SNIManager) GetCertificatePEM() ([]byte, error) {
	cert, err := m.store.GetCertificate("default")
	if err != nil {
		return nil, err
	}
	return []byte(cert.CertPEM), nil
}

// IsExpiringSoon returns true if the default certificate expires within the given duration
func (m *SNIManager) IsExpiringSoon(within time.Duration) bool {
	cert, err := m.store.GetCertificate("default")
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) < within
}

// IsExpired returns true if the default certificate has expired
func (m *SNIManager) IsExpired() bool {
	cert, err := m.store.GetCertificate("default")
	if err != nil {
		return true
	}
	return time.Now().After(cert.NotAfter)
}

// UploadCertificate uploads a certificate and stores it as the default
func (m *SNIManager) UploadCertificate(certPEM, keyPEM []byte) error {
	// Validate the certificate and key
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("invalid certificate or key: %v", err)
	}

	// Parse certificate to extract metadata
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Extract IP addresses as strings
	var ipAddresses []string
	for _, ip := range x509Cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	// Store as default
	if err := m.store.StoreCertificate(&storage.TLSCertificate{
		Domain:        "default",
		CertPEM:       string(certPEM),
		KeyPEM:        string(keyPEM),
		AutoGenerated: false,
		Subject:       x509Cert.Subject.CommonName,
		Issuer:        x509Cert.Issuer.CommonName,
		NotBefore:     x509Cert.NotBefore,
		NotAfter:      x509Cert.NotAfter,
		DNSNames:      x509Cert.DNSNames,
		IPAddresses:   ipAddresses,
	}); err != nil {
		return err
	}

	// Also store by domain name if it has DNS names
	for _, name := range x509Cert.DNSNames {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if name != "default" && name != "localhost" {
			m.store.StoreCertificate(&storage.TLSCertificate{
				Domain:        name,
				CertPEM:       string(certPEM),
				KeyPEM:        string(keyPEM),
				AutoGenerated: false,
				Subject:       x509Cert.Subject.CommonName,
				Issuer:        x509Cert.Issuer.CommonName,
				NotBefore:     x509Cert.NotBefore,
				NotAfter:      x509Cert.NotAfter,
				DNSNames:      x509Cert.DNSNames,
				IPAddresses:   ipAddresses,
			})
		}
	}

	// Update cache
	m.mu.Lock()
	m.defaultCert = &cert
	for _, name := range x509Cert.DNSNames {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		m.certCache[name] = &cert
		delete(m.certCache, "selfsigned:"+name)
	}
	m.mu.Unlock()

	return nil
}
