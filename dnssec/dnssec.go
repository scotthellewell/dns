package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// KeyConfig holds DNSSEC key configuration for a zone
type KeyConfig struct {
	Zone       string `json:"zone"`        // Zone name (e.g., "ip6.quicktechresults.com")
	KeyDir     string `json:"key_dir"`     // Directory containing keys
	Algorithm  string `json:"algorithm"`   // "ECDSAP256SHA256" or "ECDSAP384SHA384"
	AutoCreate bool   `json:"auto_create"` // Auto-create keys if missing
}

// Signer handles DNSSEC signing for a zone
type Signer struct {
	zone      string
	ksk       *dns.DNSKEY
	zsk       *dns.DNSKEY
	kskPriv   crypto.PrivateKey
	zskPriv   crypto.PrivateKey
	algorithm uint8
}

// Manager manages DNSSEC signers for multiple zones
type Manager struct {
	signers map[string]*Signer // zone -> signer
}

// NewManager creates a new DNSSEC manager
func NewManager() *Manager {
	return &Manager{
		signers: make(map[string]*Signer),
	}
}

// LoadKey loads or creates DNSSEC keys for a zone
func (m *Manager) LoadKey(cfg KeyConfig) error {
	zone := dns.Fqdn(strings.ToLower(cfg.Zone))

	algorithm := dns.ECDSAP256SHA256
	switch strings.ToUpper(cfg.Algorithm) {
	case "ECDSAP256SHA256", "":
		algorithm = dns.ECDSAP256SHA256
	case "ECDSAP384SHA384":
		algorithm = dns.ECDSAP384SHA384
	default:
		return fmt.Errorf("unsupported algorithm: %s", cfg.Algorithm)
	}

	signer := &Signer{
		zone:      zone,
		algorithm: algorithm,
	}

	// Try to load existing keys
	kskPath := filepath.Join(cfg.KeyDir, zone+"ksk.pem")
	zskPath := filepath.Join(cfg.KeyDir, zone+"zsk.pem")

	kskLoaded := false
	zskLoaded := false

	if key, privKey, err := loadKeyFromFile(kskPath, zone, algorithm, true); err == nil {
		signer.ksk = key
		signer.kskPriv = privKey
		kskLoaded = true
	}

	if key, privKey, err := loadKeyFromFile(zskPath, zone, algorithm, false); err == nil {
		signer.zsk = key
		signer.zskPriv = privKey
		zskLoaded = true
	}

	// Create missing keys if auto_create is enabled
	if cfg.AutoCreate {
		if err := os.MkdirAll(cfg.KeyDir, 0700); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}

		if !kskLoaded {
			key, privKey, err := generateKey(zone, algorithm, true)
			if err != nil {
				return fmt.Errorf("failed to generate KSK: %w", err)
			}
			signer.ksk = key
			signer.kskPriv = privKey
			if err := saveKeyToFile(kskPath, privKey); err != nil {
				return fmt.Errorf("failed to save KSK: %w", err)
			}
		}

		if !zskLoaded {
			key, privKey, err := generateKey(zone, algorithm, false)
			if err != nil {
				return fmt.Errorf("failed to generate ZSK: %w", err)
			}
			signer.zsk = key
			signer.zskPriv = privKey
			if err := saveKeyToFile(zskPath, privKey); err != nil {
				return fmt.Errorf("failed to save ZSK: %w", err)
			}
		}
	}

	if signer.ksk == nil || signer.zsk == nil {
		return fmt.Errorf("DNSSEC keys not found for zone %s", zone)
	}

	m.signers[zone] = signer
	return nil
}

// GetSigner returns the signer for a zone (or parent zone)
func (m *Manager) GetSigner(name string) *Signer {
	name = dns.Fqdn(strings.ToLower(name))

	// Walk up the name hierarchy to find a matching zone
	for {
		if signer, ok := m.signers[name]; ok {
			return signer
		}
		// Move to parent zone
		idx := strings.Index(name, ".")
		if idx == -1 || idx == len(name)-1 {
			return nil
		}
		name = name[idx+1:]
	}
}

// Sign signs the answer section of a DNS message
func (s *Signer) Sign(msg *dns.Msg) error {
	if len(msg.Answer) == 0 {
		return nil
	}

	// Group RRs by name and type for signing
	rrsets := make(map[string][]dns.RR)
	for _, rr := range msg.Answer {
		key := fmt.Sprintf("%s:%d", rr.Header().Name, rr.Header().Rrtype)
		rrsets[key] = append(rrsets[key], rr)
	}

	// Sign each RRset
	now := time.Now().UTC()
	inception := now.Add(-1 * time.Hour)
	expiration := now.Add(7 * 24 * time.Hour) // 7 days

	for _, rrset := range rrsets {
		rrsig := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   rrset[0].Header().Name,
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    rrset[0].Header().Ttl,
			},
			Algorithm:  s.algorithm,
			Labels:     uint8(dns.CountLabel(rrset[0].Header().Name)),
			OrigTtl:    rrset[0].Header().Ttl,
			Expiration: uint32(expiration.Unix()),
			Inception:  uint32(inception.Unix()),
			KeyTag:     s.zsk.KeyTag(),
			SignerName: s.zone,
			TypeCovered: rrset[0].Header().Rrtype,
		}

		if err := rrsig.Sign(s.zskPriv.(crypto.Signer), rrset); err != nil {
			return fmt.Errorf("failed to sign RRset: %w", err)
		}

		msg.Answer = append(msg.Answer, rrsig)
	}

	return nil
}

// GetDNSKEYs returns the DNSKEY records for this zone
func (s *Signer) GetDNSKEYs() []dns.RR {
	return []dns.RR{s.ksk, s.zsk}
}

// GetDS returns the DS record for the KSK
func (s *Signer) GetDS() *dns.DS {
	return s.ksk.ToDS(dns.SHA256)
}

// Zone returns the zone name
func (s *Signer) Zone() string {
	return s.zone
}

func generateKey(zone string, algorithm uint8, isKSK bool) (*dns.DNSKEY, crypto.PrivateKey, error) {
	flags := uint16(256) // ZSK
	if isKSK {
		flags = 257 // KSK
	}

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     flags,
		Protocol:  3,
		Algorithm: algorithm,
	}

	var curve elliptic.Curve
	switch algorithm {
	case dns.ECDSAP256SHA256:
		curve = elliptic.P256()
	case dns.ECDSAP384SHA384:
		curve = elliptic.P384()
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm")
	}

	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	key.PublicKey = publicKeyToBase64(privKey.Public())

	return key, privKey, nil
}

func publicKeyToBase64(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		// For ECDSA, the public key is the X and Y coordinates concatenated
		size := k.Curve.Params().BitSize / 8
		buf := make([]byte, size*2)
		k.X.FillBytes(buf[:size])
		k.Y.FillBytes(buf[size:])
		return base64.StdEncoding.EncodeToString(buf)
	default:
		return ""
	}
}

func loadKeyFromFile(path, zone string, algorithm uint8, isKSK bool) (*dns.DNSKEY, crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	flags := uint16(256)
	if isKSK {
		flags = 257
	}

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     flags,
		Protocol:  3,
		Algorithm: algorithm,
		PublicKey: publicKeyToBase64(privKey.Public()),
	}

	return key, privKey, nil
}

func saveKeyToFile(path string, privKey crypto.PrivateKey) error {
	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("expected ECDSA key")
	}

	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// HasDNSSEC returns true if any DNSSEC keys are configured
func (m *Manager) HasDNSSEC() bool {
	return len(m.signers) > 0
}
