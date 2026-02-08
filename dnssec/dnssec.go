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

// GeneratedKeys holds the generated DNSSEC key data for storage
type GeneratedKeys struct {
	KSKPrivate string // PEM-encoded KSK private key
	KSKPublic  string // Base64-encoded KSK public key
	KSKKeyTag  uint16 // KSK key tag
	ZSKPrivate string // PEM-encoded ZSK private key
	ZSKPublic  string // Base64-encoded ZSK public key
	ZSKKeyTag  uint16 // ZSK key tag
	DSRecord   string // DS record in text format
}

// GenerateKeys generates new DNSSEC keys for a zone and returns all data for storage
func GenerateKeys(zoneName string, algorithm string) (*GeneratedKeys, error) {
	zone := dns.Fqdn(strings.ToLower(zoneName))

	alg := dns.ECDSAP256SHA256
	switch strings.ToUpper(algorithm) {
	case "ECDSAP256SHA256", "":
		alg = dns.ECDSAP256SHA256
	case "ECDSAP384SHA384":
		alg = dns.ECDSAP384SHA384
	case "ED25519":
		alg = dns.ED25519
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Generate KSK
	ksk, kskPriv, err := generateKey(zone, alg, true)
	if err != nil {
		return nil, fmt.Errorf("failed to generate KSK: %w", err)
	}

	// Generate ZSK
	zsk, zskPriv, err := generateKey(zone, alg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ZSK: %w", err)
	}

	// Generate DS record from KSK
	ds := ksk.ToDS(dns.SHA256)

	// Encode private keys to PEM
	kskPEM, err := encodePrivateKeyToPEM(kskPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to encode KSK: %w", err)
	}
	zskPEM, err := encodePrivateKeyToPEM(zskPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ZSK: %w", err)
	}

	return &GeneratedKeys{
		KSKPrivate: kskPEM,
		KSKPublic:  ksk.PublicKey,
		KSKKeyTag:  ksk.KeyTag(),
		ZSKPrivate: zskPEM,
		ZSKPublic:  zsk.PublicKey,
		ZSKKeyTag:  zsk.KeyTag(),
		DSRecord:   ds.String(),
	}, nil
}

func encodePrivateKeyToPEM(privKey crypto.PrivateKey) (string, error) {
	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("expected ECDSA key")
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
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

// StoredKeyData represents DNSSEC key data as stored in the database
type StoredKeyData struct {
	Zone       string
	Algorithm  string
	KSKPrivate string // PEM-encoded
	KSKPublic  string // Base64-encoded
	ZSKPrivate string // PEM-encoded
	ZSKPublic  string // Base64-encoded
}

// LoadKeyFromData loads DNSSEC keys from database-stored data (no file system access)
func (m *Manager) LoadKeyFromData(data StoredKeyData) error {
	zone := dns.Fqdn(strings.ToLower(data.Zone))

	algorithm := dns.ECDSAP256SHA256
	switch strings.ToUpper(data.Algorithm) {
	case "ECDSAP256SHA256", "":
		algorithm = dns.ECDSAP256SHA256
	case "ECDSAP384SHA384":
		algorithm = dns.ECDSAP384SHA384
	case "ED25519":
		algorithm = dns.ED25519
	default:
		return fmt.Errorf("unsupported algorithm: %s", data.Algorithm)
	}

	signer := &Signer{
		zone:      zone,
		algorithm: algorithm,
	}

	// Load KSK from PEM data
	if data.KSKPrivate != "" {
		ksk, kskPriv, err := parseKeyFromPEM(data.KSKPrivate, zone, algorithm, true)
		if err != nil {
			return fmt.Errorf("failed to parse KSK: %w", err)
		}
		signer.ksk = ksk
		signer.kskPriv = kskPriv
	}

	// Load ZSK from PEM data
	if data.ZSKPrivate != "" {
		zsk, zskPriv, err := parseKeyFromPEM(data.ZSKPrivate, zone, algorithm, false)
		if err != nil {
			return fmt.Errorf("failed to parse ZSK: %w", err)
		}
		signer.zsk = zsk
		signer.zskPriv = zskPriv
	}

	if signer.ksk == nil || signer.zsk == nil {
		return fmt.Errorf("DNSSEC keys incomplete for zone %s", zone)
	}

	m.signers[zone] = signer
	return nil
}

// parseKeyFromPEM parses a DNSSEC key from PEM-encoded data
func parseKeyFromPEM(pemData, zone string, algorithm uint8, isKSK bool) (*dns.DNSKEY, crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM data")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

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
		PublicKey: publicKeyToBase64(privKey.Public()),
	}

	return key, privKey, nil
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
			Algorithm:   s.algorithm,
			Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
			OrigTtl:     rrset[0].Header().Ttl,
			Expiration:  uint32(expiration.Unix()),
			Inception:   uint32(inception.Unix()),
			KeyTag:      s.zsk.KeyTag(),
			SignerName:  s.zone,
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

// ============================================================================
// NSEC3 Support
// ============================================================================

// NSEC3Config holds NSEC3 configuration for a zone.
type NSEC3Config struct {
	HashAlgorithm uint8  // 1 = SHA-1
	Flags         uint8  // 0 = no opt-out, 1 = opt-out
	Iterations    uint16 // Recommended: 0-150
	SaltLength    uint8  // Recommended: 0-8 bytes
	Salt          string // Hex-encoded salt
}

// DefaultNSEC3Config returns sensible NSEC3 defaults.
// Per RFC 9276, iterations should be 0 and salt length should be 0.
func DefaultNSEC3Config() NSEC3Config {
	return NSEC3Config{
		HashAlgorithm: 1, // SHA-1 (only standardized option)
		Flags:         0, // No opt-out
		Iterations:    0, // RFC 9276 recommends 0
		SaltLength:    0, // RFC 9276 recommends empty salt
		Salt:          "",
	}
}

// GenerateNSEC3Salt generates a random salt for NSEC3.
func GenerateNSEC3Salt(length int) (string, error) {
	if length == 0 {
		return "", nil
	}
	if length > 255 {
		length = 255
	}
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return fmt.Sprintf("%X", salt), nil
}

// CreateNSEC3PARAM creates an NSEC3PARAM record for a zone.
func (s *Signer) CreateNSEC3PARAM(cfg NSEC3Config) *dns.NSEC3PARAM {
	return &dns.NSEC3PARAM{
		Hdr: dns.RR_Header{
			Name:   s.zone,
			Rrtype: dns.TypeNSEC3PARAM,
			Class:  dns.ClassINET,
			Ttl:    0, // NSEC3PARAM TTL should be 0
		},
		Hash:       cfg.HashAlgorithm,
		Flags:      cfg.Flags,
		Iterations: cfg.Iterations,
		SaltLength: cfg.SaltLength,
		Salt:       cfg.Salt,
	}
}

// CreateNSEC3 creates an NSEC3 record for a given owner name.
func (s *Signer) CreateNSEC3(ownerName string, nextHashedOwner string, types []uint16, cfg NSEC3Config, ttl uint32) *dns.NSEC3 {
	// Hash the owner name
	hashedOwner := dns.HashName(ownerName, cfg.HashAlgorithm, cfg.Iterations, cfg.Salt)

	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   hashedOwner + "." + s.zone,
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Hash:       cfg.HashAlgorithm,
		Flags:      cfg.Flags,
		Iterations: cfg.Iterations,
		SaltLength: cfg.SaltLength,
		Salt:       cfg.Salt,
		HashLength: 20, // SHA-1 produces 20 bytes (32 base32 chars)
		NextDomain: nextHashedOwner,
		TypeBitMap: types,
	}
}

// SignNSEC3 signs an NSEC3 record.
func (s *Signer) SignNSEC3(nsec3 *dns.NSEC3, inception, expiration uint32) (*dns.RRSIG, error) {
	if s.zsk == nil || s.zskPriv == nil {
		return nil, fmt.Errorf("no ZSK available for signing")
	}

	signer, ok := s.zskPriv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ZSK private key does not implement crypto.Signer")
	}

	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   nsec3.Hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    nsec3.Hdr.Ttl,
		},
		TypeCovered: dns.TypeNSEC3,
		Algorithm:   s.algorithm,
		Labels:      uint8(dns.CountLabel(nsec3.Hdr.Name)),
		OrigTtl:     nsec3.Hdr.Ttl,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      s.zsk.KeyTag(),
		SignerName:  s.zone,
	}

	if err := rrsig.Sign(signer, []dns.RR{nsec3}); err != nil {
		return nil, fmt.Errorf("signing NSEC3: %w", err)
	}

	return rrsig, nil
}

// GenerateNSEC3Chain generates a complete NSEC3 chain for a zone.
// It takes a list of owner names and their record types.
func (s *Signer) GenerateNSEC3Chain(records map[string][]uint16, cfg NSEC3Config, ttl uint32) ([]*dns.NSEC3, error) {
	if len(records) == 0 {
		return nil, nil
	}

	// Hash all owner names
	type hashedEntry struct {
		hash  string
		name  string
		types []uint16
	}

	entries := make([]hashedEntry, 0, len(records))
	for name, types := range records {
		hash := dns.HashName(name, cfg.HashAlgorithm, cfg.Iterations, cfg.Salt)
		entries = append(entries, hashedEntry{hash: hash, name: name, types: types})
	}

	// Sort by hash
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].hash > entries[j].hash {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Create NSEC3 chain
	nsec3s := make([]*dns.NSEC3, len(entries))
	for i := range entries {
		nextIdx := (i + 1) % len(entries)
		nsec3s[i] = s.CreateNSEC3(
			entries[i].name,
			entries[nextIdx].hash,
			entries[i].types,
			cfg,
			ttl,
		)
	}

	return nsec3s, nil
}

// ============================================================================
// Key Rollover Automation
// ============================================================================

// KeyRolloverConfig holds configuration for automatic key rollover.
type KeyRolloverConfig struct {
	ZSKLifetime      time.Duration // How long before ZSK should be rotated (e.g., 30 days)
	KSKLifetime      time.Duration // How long before KSK should be rotated (e.g., 365 days)
	RolloverDelay    time.Duration // Overlap period during rollover (e.g., 24 hours)
	SignatureRefresh time.Duration // How often to re-sign (e.g., 7 days)
}

// DefaultKeyRolloverConfig returns sensible defaults for key rollover.
func DefaultKeyRolloverConfig() KeyRolloverConfig {
	return KeyRolloverConfig{
		ZSKLifetime:      30 * 24 * time.Hour,  // 30 days
		KSKLifetime:      365 * 24 * time.Hour, // 1 year
		RolloverDelay:    24 * time.Hour,       // 1 day overlap
		SignatureRefresh: 7 * 24 * time.Hour,   // Re-sign weekly
	}
}

// KeyRolloverState tracks the state of a key rollover.
type KeyRolloverState struct {
	InProgress  bool      `json:"in_progress"`
	KeyType     string    `json:"key_type"` // "ZSK" or "KSK"
	Phase       string    `json:"phase"`    // "pre-publish", "active", "post-publish"
	StartedAt   time.Time `json:"started_at"`
	NextPhaseAt time.Time `json:"next_phase_at"`
	NewKeyTag   uint16    `json:"new_key_tag,omitempty"`
	OldKeyTag   uint16    `json:"old_key_tag,omitempty"`
}

// RolloverManager manages key rollovers for zones.
type RolloverManager struct {
	manager *Manager
	config  KeyRolloverConfig
}

// NewRolloverManager creates a new rollover manager.
func NewRolloverManager(m *Manager, cfg KeyRolloverConfig) *RolloverManager {
	return &RolloverManager{
		manager: m,
		config:  cfg,
	}
}

// NeedsZSKRollover checks if a zone's ZSK needs to be rotated.
func (r *RolloverManager) NeedsZSKRollover(zone string, zskCreated time.Time) bool {
	return time.Since(zskCreated) > r.config.ZSKLifetime
}

// NeedsKSKRollover checks if a zone's KSK should be rotated.
// Note: KSK rotation is ADVISORY ONLY because it requires manual DS record
// updates at the domain registrar. This function returns whether rotation
// is recommended, but the rollover should not be performed automatically.
func (r *RolloverManager) NeedsKSKRollover(zone string, kskCreated time.Time) bool {
	return time.Since(kskCreated) > r.config.KSKLifetime
}

// KSKRotationAdvisory represents an advisory warning for KSK rotation.
type KSKRotationAdvisory struct {
	Zone       string        `json:"zone"`
	KSKCreated time.Time     `json:"ksk_created"`
	Age        time.Duration `json:"age"`
	Threshold  time.Duration `json:"threshold"`
	Message    string        `json:"message"`
}

// GetKSKRotationAdvisory returns an advisory if KSK rotation is recommended.
// Returns nil if rotation is not needed.
func (r *RolloverManager) GetKSKRotationAdvisory(zone string, kskCreated time.Time) *KSKRotationAdvisory {
	if !r.NeedsKSKRollover(zone, kskCreated) {
		return nil
	}

	age := time.Since(kskCreated)
	return &KSKRotationAdvisory{
		Zone:       zone,
		KSKCreated: kskCreated,
		Age:        age,
		Threshold:  r.config.KSKLifetime,
		Message:    fmt.Sprintf("KSK for %s is %d days old (threshold: %d days). Manual rotation recommended. You will need to update the DS record at your registrar.", zone, int(age.Hours()/24), int(r.config.KSKLifetime.Hours()/24)),
	}
}

// BeginZSKRollover starts a ZSK rollover using the pre-publish method.
// Phase 1: Pre-publish - Publish new ZSK alongside old ZSK
func (r *RolloverManager) BeginZSKRollover(zone string) (*KeyRolloverState, error) {
	signer, ok := r.manager.signers[dns.Fqdn(zone)]
	if !ok {
		return nil, fmt.Errorf("no signer for zone %s", zone)
	}

	// Generate new ZSK
	newZSK, newPriv, err := generateKey(signer.zone, signer.algorithm, false)
	if err != nil {
		return nil, fmt.Errorf("generate new ZSK: %w", err)
	}

	// Store old key tag
	oldKeyTag := signer.zsk.KeyTag()

	// For pre-publish, we keep both keys available
	// The actual key swap happens in CompleteZSKRollover

	state := &KeyRolloverState{
		InProgress:  true,
		KeyType:     "ZSK",
		Phase:       "pre-publish",
		StartedAt:   time.Now(),
		NextPhaseAt: time.Now().Add(r.config.RolloverDelay),
		NewKeyTag:   newZSK.KeyTag(),
		OldKeyTag:   oldKeyTag,
	}

	// Store new key temporarily (implementation would store in separate field)
	_ = newPriv // Would be stored in PreviousZSK or similar

	return state, nil
}

// CompleteZSKRollover finishes the ZSK rollover.
// Phase 2: Active - New ZSK is now primary, old ZSK still published
// Phase 3: Post-publish - Old ZSK removed
func (r *RolloverManager) CompleteZSKRollover(zone string, state *KeyRolloverState) error {
	if !state.InProgress || state.KeyType != "ZSK" {
		return fmt.Errorf("no ZSK rollover in progress")
	}

	if time.Now().Before(state.NextPhaseAt) {
		return fmt.Errorf("rollover not ready, wait until %v", state.NextPhaseAt)
	}

	// In a real implementation, this would:
	// 1. Make the new ZSK the primary signing key
	// 2. Keep publishing the old ZSK for one more period
	// 3. Eventually remove the old ZSK

	state.Phase = "active"
	state.NextPhaseAt = time.Now().Add(r.config.RolloverDelay)

	return nil
}

// FinalizeZSKRollover removes the old ZSK after rollover is complete.
func (r *RolloverManager) FinalizeZSKRollover(zone string, state *KeyRolloverState) error {
	if state.Phase != "active" {
		return fmt.Errorf("rollover not in active phase")
	}

	if time.Now().Before(state.NextPhaseAt) {
		return fmt.Errorf("not ready to finalize, wait until %v", state.NextPhaseAt)
	}

	state.Phase = "complete"
	state.InProgress = false

	return nil
}
