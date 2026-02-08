package certs

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/scott/dns/storage"
)

// mockStorage implements StorageInterface for testing
type mockStorage struct {
	mu    sync.RWMutex
	certs map[string]*storage.TLSCertificate
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		certs: make(map[string]*storage.TLSCertificate),
	}
}

func (m *mockStorage) GetCertificate(domain string) (*storage.TLSCertificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cert, ok := m.certs[domain]
	if !ok {
		return nil, nil
	}
	return cert, nil
}

func (m *mockStorage) StoreCertificate(cert *storage.TLSCertificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs[cert.Domain] = cert
	return nil
}

func (m *mockStorage) ListCertificates() ([]storage.TLSCertificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var certs []storage.TLSCertificate
	for _, cert := range m.certs {
		certs = append(certs, *cert)
	}
	return certs, nil
}

func (m *mockStorage) GetACMEConfig() (*storage.ACMEConfig, error) {
	return nil, nil
}

func (m *mockStorage) UpdateACMEConfig(config *storage.ACMEConfig) error {
	return nil
}

func (m *mockStorage) GetACMEAccountKey() ([]byte, error) {
	return nil, nil
}

func (m *mockStorage) SaveACMEAccountKey(key []byte) error {
	return nil
}

func (m *mockStorage) GetACMEState() (*storage.ACMEState, error) {
	return nil, nil
}

func (m *mockStorage) SaveACMEState(state *storage.ACMEState) error {
	return nil
}

func TestNewSNIManager(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	if mgr == nil {
		t.Fatal("NewSNIManager returned nil")
	}

	if mgr.certCache == nil {
		t.Error("certCache should be initialized")
	}

	if mgr.pendingACME == nil {
		t.Error("pendingACME should be initialized")
	}

	if mgr.defaultCert == nil {
		t.Error("defaultCert should be initialized")
	}
}

func TestGetCertificate_NoSNI(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	// Request without SNI should return default cert
	hello := &tls.ClientHelloInfo{
		ServerName: "",
	}

	cert, err := mgr.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("Expected default certificate, got nil")
	}

	// Verify it's the default cert
	if cert != mgr.defaultCert {
		t.Error("Expected default certificate")
	}
}

func TestGetCertificate_MultipleDomains(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	domains := []string{
		"example.com",
		"api.example.com",
		"test.example.org",
		"another-domain.net",
	}

	// Request certificates for multiple domains
	certs := make(map[string]*tls.Certificate)
	for _, domain := range domains {
		hello := &tls.ClientHelloInfo{
			ServerName: domain,
		}

		cert, err := mgr.GetCertificate(hello)
		if err != nil {
			t.Fatalf("GetCertificate(%s) failed: %v", domain, err)
		}

		if cert == nil {
			t.Fatalf("GetCertificate(%s) returned nil", domain)
		}

		certs[domain] = cert
	}

	// Verify all domains got cached
	for _, domain := range domains {
		// Should be cached as self-signed
		cacheKey := "selfsigned:" + domain
		mgr.mu.RLock()
		cached, ok := mgr.certCache[cacheKey]
		mgr.mu.RUnlock()

		if !ok {
			t.Errorf("Certificate for %s not cached", domain)
			continue
		}

		if cached != certs[domain] {
			t.Errorf("Cached cert for %s doesn't match returned cert", domain)
		}
	}

	// Request again - should return cached certs
	for _, domain := range domains {
		hello := &tls.ClientHelloInfo{
			ServerName: domain,
		}

		cert, err := mgr.GetCertificate(hello)
		if err != nil {
			t.Fatalf("GetCertificate(%s) second call failed: %v", domain, err)
		}

		if cert != certs[domain] {
			t.Errorf("Second request for %s returned different cert", domain)
		}
	}
}

func TestGetCertificate_CaseInsensitive(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	// Request with mixed case
	hello1 := &tls.ClientHelloInfo{
		ServerName: "Example.COM",
	}
	cert1, err := mgr.GetCertificate(hello1)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	// Request with lowercase - should return same cert
	hello2 := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}
	cert2, err := mgr.GetCertificate(hello2)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert1 != cert2 {
		t.Error("Case-insensitive lookup should return same certificate")
	}
}

func TestGetCertificate_TrailingDot(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	// Request with trailing dot (FQDN)
	hello1 := &tls.ClientHelloInfo{
		ServerName: "example.com.",
	}
	cert1, err := mgr.GetCertificate(hello1)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	// Request without trailing dot - should return same cert
	hello2 := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}
	cert2, err := mgr.GetCertificate(hello2)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert1 != cert2 {
		t.Error("Trailing dot normalization should return same certificate")
	}
}

// Helper to convert certificate to PEM
func certificateToPEM(cert *tls.Certificate) ([]byte, []byte, error) {
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x509Cert.Raw,
	})

	keyBytes, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return certPEM, keyPEM, nil
}

func TestGetCertificate_FromStorage(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	domain := "stored.example.com"

	// Generate a certificate and store it
	selfSigned, err := mgr.generateSelfSigned(domain, []string{domain})
	if err != nil {
		t.Fatalf("Failed to generate self-signed cert: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(selfSigned.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	certPEM, keyPEM, err := certificateToPEM(selfSigned)
	if err != nil {
		t.Fatalf("Failed to convert cert to PEM: %v", err)
	}

	// Store the certificate
	storedCert := &storage.TLSCertificate{
		Domain:    domain,
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM),
		NotBefore: x509Cert.NotBefore,
		NotAfter:  x509Cert.NotAfter,
	}
	store.StoreCertificate(storedCert)

	// Request certificate - should load from storage
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
	}

	cert, err := mgr.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("Expected certificate from storage")
	}

	// Verify it's now cached
	mgr.mu.RLock()
	cached, ok := mgr.certCache[domain]
	mgr.mu.RUnlock()

	if !ok {
		t.Error("Certificate from storage should be cached")
	}

	if cached != cert {
		t.Error("Cached cert should match returned cert")
	}
}

func TestGetTLSConfig(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	tlsConfig, err := mgr.GetTLSConfig()
	if err != nil {
		t.Fatalf("GetTLSConfig failed: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("GetTLSConfig returned nil")
	}

	if tlsConfig.GetCertificate == nil {
		t.Error("GetCertificate callback should be set")
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Error("MinVersion should be TLS 1.2")
	}
}

func TestPreloadCertificates(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	// Store some certificates
	domains := []string{"preload1.example.com", "preload2.example.com", "preload3.example.com"}

	for _, domain := range domains {
		selfSigned, err := mgr.generateSelfSigned(domain, []string{domain})
		if err != nil {
			t.Fatalf("Failed to generate self-signed cert: %v", err)
		}

		x509Cert, _ := x509.ParseCertificate(selfSigned.Certificate[0])
		certPEM, keyPEM, _ := certificateToPEM(selfSigned)

		store.StoreCertificate(&storage.TLSCertificate{
			Domain:    domain,
			CertPEM:   string(certPEM),
			KeyPEM:    string(keyPEM),
			NotBefore: x509Cert.NotBefore,
			NotAfter:  x509Cert.NotAfter,
		})
	}

	// Clear the cache
	mgr.mu.Lock()
	mgr.certCache = make(map[string]*tls.Certificate)
	mgr.mu.Unlock()

	// Preload
	err := mgr.PreloadCertificates()
	if err != nil {
		t.Fatalf("PreloadCertificates failed: %v", err)
	}

	// Verify all certificates are cached
	for _, domain := range domains {
		mgr.mu.RLock()
		_, ok := mgr.certCache[domain]
		mgr.mu.RUnlock()

		if !ok {
			t.Errorf("Certificate for %s should be preloaded", domain)
		}
	}
}

func TestGenerateSelfSigned(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	domain := "self-signed.example.com"
	cert, err := mgr.generateSelfSigned(domain, []string{domain, "alt." + domain})
	if err != nil {
		t.Fatalf("generateSelfSigned failed: %v", err)
	}

	if cert == nil {
		t.Fatal("generateSelfSigned returned nil")
	}

	// Parse and verify
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if x509Cert.Subject.CommonName != domain {
		t.Errorf("CN should be %s, got %s", domain, x509Cert.Subject.CommonName)
	}

	// Check SANs
	foundDomain := false
	foundAlt := false
	for _, san := range x509Cert.DNSNames {
		if san == domain {
			foundDomain = true
		}
		if san == "alt."+domain {
			foundAlt = true
		}
	}

	if !foundDomain {
		t.Error("Domain should be in SANs")
	}
	if !foundAlt {
		t.Error("Alt domain should be in SANs")
	}

	// Check validity period
	if time.Now().Before(x509Cert.NotBefore) {
		t.Error("Certificate should be valid now")
	}
	if time.Now().After(x509Cert.NotAfter) {
		t.Error("Certificate should not be expired")
	}
}

func TestConcurrentAccess(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	domains := []string{
		"concurrent1.example.com",
		"concurrent2.example.com",
		"concurrent3.example.com",
		"concurrent4.example.com",
		"concurrent5.example.com",
	}

	var wg sync.WaitGroup
	errors := make(chan error, len(domains)*10)

	// Concurrent requests for multiple domains
	for i := 0; i < 10; i++ {
		for _, domain := range domains {
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				hello := &tls.ClientHelloInfo{
					ServerName: d,
				}
				cert, err := mgr.GetCertificate(hello)
				if err != nil {
					errors <- err
					return
				}
				if cert == nil {
					errors <- fmt.Errorf("nil certificate for %s", d)
				}
			}(domain)
		}
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestSetACMEEmail(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	email := "test@example.com"
	mgr.SetACMEEmail(email)

	mgr.mu.RLock()
	got := mgr.acmeEmail
	mgr.mu.RUnlock()

	if got != email {
		t.Errorf("Expected email %s, got %s", email, got)
	}
}

func TestOnCertObtained(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	called := false
	calledDomain := ""

	mgr.SetOnCertObtained(func(domain string) {
		called = true
		calledDomain = domain
	})

	// Verify the callback was set
	mgr.mu.RLock()
	hasCallback := mgr.onCertObtained != nil
	mgr.mu.RUnlock()

	if !hasCallback {
		t.Error("onCertObtained callback should be set")
	}

	// The callback is invoked internally when ACME completes.
	// We verify SetOnCertObtained works by checking the function was stored.
	// To fully test the callback, we would need to mock ACME which is complex.
	// Instead we test that the mechanism for storing the callback works.
	domain := "test.example.com"
	mgr.SetOnCertObtained(func(d string) {
		called = true
		calledDomain = d
	})

	// Simulate what happens after ACME by directly manipulating cache and calling callback
	selfSigned, _ := mgr.generateSelfSigned(domain, []string{domain})
	certPEM, keyPEM, _ := certificateToPEM(selfSigned)
	x509Cert, _ := x509.ParseCertificate(selfSigned.Certificate[0])

	// Store the cert so it appears ACME succeeded
	store.StoreCertificate(&storage.TLSCertificate{
		Domain:    domain,
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM),
		NotBefore: x509Cert.NotBefore,
		NotAfter:  x509Cert.NotAfter,
	})

	// Now manually trigger what the ACME completion code does
	mgr.mu.Lock()
	mgr.certCache[domain] = selfSigned
	delete(mgr.certCache, "selfsigned:"+domain)
	callback := mgr.onCertObtained
	mgr.mu.Unlock()

	if callback != nil {
		callback(domain)
	}

	if !called {
		t.Error("onCertObtained callback should have been called")
	}

	if calledDomain != domain {
		t.Errorf("Expected domain %s, got %s", domain, calledDomain)
	}
}

func TestExpiredCertNotUsed(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	domain := "expired.example.com"

	// Store an expired certificate
	selfSigned, _ := mgr.generateSelfSigned(domain, []string{domain})
	certPEM, keyPEM, _ := certificateToPEM(selfSigned)

	expiredCert := &storage.TLSCertificate{
		Domain:    domain,
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM),
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour), // Expired yesterday
	}
	store.StoreCertificate(expiredCert)

	// Request certificate - should NOT use the expired one
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
	}

	cert, err := mgr.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("Expected a certificate (self-signed fallback)")
	}

	// The cert should be a NEW self-signed, not the expired one
	// Check that the expired cert wasn't cached under the domain name
	mgr.mu.RLock()
	_, cachedUnderDomain := mgr.certCache[domain]
	mgr.mu.RUnlock()

	if cachedUnderDomain {
		t.Error("Expired certificate should not be cached under domain name")
	}
}

func TestCacheIsolation(t *testing.T) {
	store := newMockStorage()
	mgr := NewSNIManager(store, nil)

	// Get certificates for two different domains
	hello1 := &tls.ClientHelloInfo{ServerName: "domain1.example.com"}
	hello2 := &tls.ClientHelloInfo{ServerName: "domain2.example.com"}

	cert1, _ := mgr.GetCertificate(hello1)
	cert2, _ := mgr.GetCertificate(hello2)

	// They should be different certificates
	if cert1 == cert2 {
		t.Error("Different domains should get different certificates")
	}

	// Verify the certs have different CNs
	x509Cert1, _ := x509.ParseCertificate(cert1.Certificate[0])
	x509Cert2, _ := x509.ParseCertificate(cert2.Certificate[0])

	if x509Cert1.Subject.CommonName == x509Cert2.Subject.CommonName {
		t.Error("Certificates should have different CNs")
	}
}
