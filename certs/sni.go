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

// loadDefaultCert is a no-op - we no longer use a default certificate
// Certificates are selected based on SNI or found by searching all stored certs
func (m *SNIManager) loadDefaultCert() {
	// Legacy function kept for compatibility but no longer creates/loads a default cert
	// Certificate selection now works as follows:
	// 1. If SNI provided: Look for exact match, then search all certs for wildcard/SAN match
	// 2. If no match: Generate self-signed for the specific domain (triggers ACME if configured)
	// 3. If no SNI: Return any valid cert we have, or generate self-signed for localhost
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
		// No SNI - try to find any certificate, or generate self-signed
		cert := m.findAnyValidCert()
		if cert != nil {
			return cert, nil
		}
		// Generate self-signed for localhost as fallback
		return m.getOrCreateSelfSigned("localhost")
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

	// Try to load from storage by exact domain match
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

	// Try to find any cert that covers this domain (wildcards, multi-SAN)
	matchingCert := m.findCertForDomain(serverName)
	if matchingCert != nil {
		return matchingCert, nil
	}

	// No valid certificate found - start ACME request in background and return self-signed
	m.startACMERequest(serverName)

	// Generate and return self-signed certificate for immediate use
	selfSigned, err := m.getOrCreateSelfSigned(serverName)
	if err != nil {
		// Last resort: return any cert we have or generate localhost self-signed
		cert := m.findAnyValidCert()
		if cert != nil {
			return cert, nil
		}
		return m.getOrCreateSelfSigned("localhost")
	}

	return selfSigned, nil
}

// findCertForDomain searches all stored certificates to find one that matches the domain
// This handles wildcards and multi-domain certificates
func (m *SNIManager) findCertForDomain(domain string) *tls.Certificate {
	certs, err := m.store.ListCertificates()
	if err != nil {
		return nil
	}

	now := time.Now()
	for _, cert := range certs {
		// Skip expired certs
		if now.After(cert.NotAfter) {
			continue
		}
		// Skip the "default" placeholder if it exists
		if cert.Domain == "default" {
			continue
		}

		// Check if this cert covers the requested domain
		if m.certMatchesDomain(&cert, domain) {
			tlsCert, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM))
			if err == nil {
				// Cache by the requested domain name for future lookups
				m.mu.Lock()
				m.certCache[domain] = &tlsCert
				m.mu.Unlock()
				return &tlsCert
			}
		}
	}
	return nil
}

// certMatchesDomain checks if a stored certificate covers the given domain
func (m *SNIManager) certMatchesDomain(cert *storage.TLSCertificate, domain string) bool {
	// Check exact domain match
	if strings.EqualFold(cert.Domain, domain) {
		return true
	}

	// Check DNS names in the certificate
	for _, dnsName := range cert.DNSNames {
		dnsName = strings.ToLower(strings.TrimSuffix(dnsName, "."))
		if dnsName == domain {
			return true
		}
		// Check wildcard match
		if strings.HasPrefix(dnsName, "*.") {
			wildcardBase := dnsName[2:] // Remove "*."
			if strings.HasSuffix(domain, "."+wildcardBase) || domain == wildcardBase {
				// domain matches *.example.com (e.g., sub.example.com or example.com)
				return true
			}
		}
	}
	return false
}

// findAnyValidCert returns any valid (non-expired) certificate from storage
// Used as fallback when no SNI is provided or no specific match found
func (m *SNIManager) findAnyValidCert() *tls.Certificate {
	certs, err := m.store.ListCertificates()
	if err != nil {
		return nil
	}

	now := time.Now()
	for _, cert := range certs {
		// Skip expired certs
		if now.After(cert.NotAfter) {
			continue
		}
		// Skip the "default" placeholder and self-signed localhost certs
		if cert.Domain == "default" || cert.Domain == "localhost" {
			continue
		}
		// Skip very short-lived self-signed certs (less than 2 days validity)
		if cert.NotAfter.Sub(cert.NotBefore) < 48*time.Hour {
			continue
		}

		tlsCert, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM))
		if err == nil {
			return &tlsCert
		}
	}
	return nil
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
// Now returns info about the first valid certificate found
func (m *SNIManager) GetConfig() Config {
	// Try to find any valid certificate
	certs, err := m.store.ListCertificates()
	if err != nil || len(certs) == 0 {
		return Config{}
	}

	now := time.Now()
	for _, cert := range certs {
		// Skip expired certs and legacy "default" entries
		if now.After(cert.NotAfter) || cert.Domain == "default" {
			continue
		}
		
		return Config{
			AutoGenerated: cert.AutoGenerated || strings.Contains(cert.Issuer, "Self-Signed"),
			Subject:       cert.Subject,
			Issuer:        cert.Issuer,
			NotBefore:     cert.NotBefore,
			NotAfter:      cert.NotAfter,
			DNSNames:      cert.DNSNames,
			IPAddresses:   cert.IPAddresses,
		}
	}

	return Config{}
}

// GetCertificatePEM returns the first valid certificate in PEM format (for compatibility)
func (m *SNIManager) GetCertificatePEM() ([]byte, error) {
	certs, err := m.store.ListCertificates()
	if err != nil {
		return nil, err
	}
	
	now := time.Now()
	for _, cert := range certs {
		// Skip expired certs and legacy "default" entries
		if now.After(cert.NotAfter) || cert.Domain == "default" {
			continue
		}
		return []byte(cert.CertPEM), nil
	}
	return nil, fmt.Errorf("no valid certificate found")
}

// IsExpiringSoon returns true if any certificate expires within the given duration
func (m *SNIManager) IsExpiringSoon(within time.Duration) bool {
	certs, err := m.store.ListCertificates()
	if err != nil || len(certs) == 0 {
		return true // No certs = expiring soon (need one)
	}
	
	now := time.Now()
	for _, cert := range certs {
		// Skip legacy "default" entries
		if cert.Domain == "default" {
			continue
		}
		// If any valid cert exists that's not expiring soon, return false
		if now.Before(cert.NotAfter) && time.Until(cert.NotAfter) >= within {
			return false
		}
	}
	return true // All certs are expired or expiring soon
}

// IsExpired returns true if there are no valid (non-expired) certificates
func (m *SNIManager) IsExpired() bool {
	certs, err := m.store.ListCertificates()
	if err != nil || len(certs) == 0 {
		return true // No certs = expired
	}
	
	now := time.Now()
	for _, cert := range certs {
		// Skip legacy "default" entries
		if cert.Domain == "default" {
			continue
		}
		// If any valid cert exists, not expired
		if now.Before(cert.NotAfter) {
			return false
		}
	}
	return true // All certs are expired
}

// UploadCertificate uploads a certificate and stores it by its DNS names
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

	// Determine the primary domain name to store under
	// Use the first DNS name if available, otherwise use Subject CN
	primaryDomain := ""
	if len(x509Cert.DNSNames) > 0 {
		primaryDomain = strings.ToLower(strings.TrimSuffix(x509Cert.DNSNames[0], "."))
	} else if x509Cert.Subject.CommonName != "" {
		primaryDomain = strings.ToLower(x509Cert.Subject.CommonName)
	}

	if primaryDomain == "" || primaryDomain == "localhost" {
		return fmt.Errorf("certificate must have at least one DNS name or valid Common Name")
	}

	// Store by the primary domain name
	if err := m.store.StoreCertificate(&storage.TLSCertificate{
		Domain:        primaryDomain,
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

	// Update cache for all DNS names covered by this cert
	m.mu.Lock()
	for _, name := range x509Cert.DNSNames {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		m.certCache[name] = &cert
		delete(m.certCache, "selfsigned:"+name)
	}
	m.mu.Unlock()

	return nil
}
