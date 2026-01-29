package dnssecval

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Root DNSKEY trust anchors (KSK for the root zone)
// These are the public keys used to validate the root zone
var rootAnchors = []dns.DNSKEY{
	{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 172800},
		Flags:     257, // KSK
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	},
	{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 172800},
		Flags:     257, // KSK
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx1tzM40/1BbpEXGWoJjy8JXSY7GJLNv86cxNnxrA+Yk/F6lGbaPXFtTCpxhEHcfwVPNq5ljN+GGbFmBL9EPE/gFlaxdV6/nWQM7RlrraFmn64DNIM7gWhg2u3dkqYRBKYR03jXomGEPlYnZ94DQqoGb9SM+k+Z8lbXvSyPJJLVEQ0bqhgXYSLGG1LN5E9tGXq8K7Cxmj6N1TYH1mP0V9FqxKZx/mVZhJjp0=",
	},
}

// QueryFunc is a function that queries DNS (used for fetching DNSKEY/DS records)
type QueryFunc func(name string, qtype uint16) (*dns.Msg, error)

// Validator handles DNSSEC validation
type Validator struct {
	trustAnchors map[string][]dns.DNSKEY // Zone -> trusted DNSKEYs
	keyCache     map[string][]*dns.DNSKEY // Cached DNSKEY records
	dsCache      map[string][]*dns.DS     // Cached DS records
	cacheMu      sync.RWMutex
	queryFn      QueryFunc
}

// New creates a new DNSSEC validator with root trust anchors
func New() *Validator {
	v := &Validator{
		trustAnchors: make(map[string][]dns.DNSKEY),
		keyCache:     make(map[string][]*dns.DNSKEY),
		dsCache:      make(map[string][]*dns.DS),
	}
	// Add root trust anchors
	v.trustAnchors["."] = rootAnchors
	return v
}

// SetQueryFunc sets the function used to query DNS for DNSKEY/DS records
func (v *Validator) SetQueryFunc(fn QueryFunc) {
	v.queryFn = fn
}

// ValidationResult holds the result of DNSSEC validation
type ValidationResult struct {
	Secure   bool   // True if DNSSEC validated successfully
	Insecure bool   // True if zone is not signed (no DS record)
	Bogus    bool   // True if validation failed
	Error    error  // Validation error if any
	WhyBogus string // Reason for bogus result
}

// ValidateResponse validates a DNS response using DNSSEC
func (v *Validator) ValidateResponse(resp *dns.Msg, qname string, qtype uint16) ValidationResult {
	// Check if response has DNSSEC records
	var rrsigs []*dns.RRSIG

	for _, rr := range resp.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, sig)
		}
	}

	// No RRSIG records means insecure (or unsigned)
	if len(rrsigs) == 0 {
		// Check if this zone should be signed (has DS in parent)
		if v.queryFn != nil {
			parentZone := getParentZone(qname)
			if parentZone != "" {
				dsResp, err := v.queryFn(qname, dns.TypeDS)
				if err == nil && dsResp != nil {
					for _, rr := range dsResp.Answer {
						if _, ok := rr.(*dns.DS); ok {
							// DS exists but no RRSIG - this is BOGUS
							return ValidationResult{
								Bogus:    true,
								WhyBogus: "DS exists but response is unsigned",
							}
						}
					}
				}
			}
		}
		return ValidationResult{Insecure: true}
	}

	// Get the records to validate (excluding RRSIGs themselves)
	var recordsToValidate []dns.RR
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.RRSIG); !ok {
			recordsToValidate = append(recordsToValidate, rr)
		}
	}

	if len(recordsToValidate) == 0 {
		return ValidationResult{Insecure: true}
	}

	// Find matching RRSIG for the record type
	recordType := recordsToValidate[0].Header().Rrtype
	var matchingSig *dns.RRSIG
	for _, sig := range rrsigs {
		if sig.TypeCovered == recordType {
			matchingSig = sig
			break
		}
	}

	if matchingSig == nil {
		return ValidationResult{
			Bogus:    true,
			WhyBogus: "No RRSIG covering record type",
		}
	}

	// Check signature expiration
	now := time.Now().UTC()
	inception := time.Unix(int64(matchingSig.Inception), 0)
	expiration := time.Unix(int64(matchingSig.Expiration), 0)

	if now.Before(inception) {
		return ValidationResult{
			Bogus:    true,
			WhyBogus: "RRSIG not yet valid",
		}
	}

	if now.After(expiration) {
		return ValidationResult{
			Bogus:    true,
			WhyBogus: "RRSIG expired",
		}
	}

	// If no query function, we can only do basic validation
	if v.queryFn == nil {
		return ValidationResult{Secure: true}
	}

	// Full chain-of-trust validation
	signerName := dns.Fqdn(matchingSig.SignerName)

	// Fetch DNSKEY for the signer zone
	dnskeys, err := v.getDNSKEYs(signerName)
	if err != nil {
		log.Printf("DNSSEC: Failed to get DNSKEYs for %s: %v", signerName, err)
		return ValidationResult{Insecure: true}
	}

	if len(dnskeys) == 0 {
		return ValidationResult{Insecure: true}
	}

	// Find the key that signed this RRSIG
	var signingKey *dns.DNSKEY
	for _, key := range dnskeys {
		if key.KeyTag() == matchingSig.KeyTag && key.Algorithm == matchingSig.Algorithm {
			signingKey = key
			break
		}
	}

	if signingKey == nil {
		return ValidationResult{
			Bogus:    true,
			WhyBogus: fmt.Sprintf("No DNSKEY found for key tag %d", matchingSig.KeyTag),
		}
	}

	// Verify the signature
	err = VerifyRRSIG(matchingSig, signingKey, recordsToValidate)
	if err != nil {
		return ValidationResult{
			Bogus:    true,
			WhyBogus: fmt.Sprintf("RRSIG verification failed: %v", err),
		}
	}

	// Validate the DNSKEY is trusted (chain of trust to root)
	if !v.validateKeyTrust(signerName, dnskeys, 0) {
		return ValidationResult{
			Bogus:    true,
			WhyBogus: "DNSKEY not in chain of trust from root",
		}
	}

	return ValidationResult{Secure: true}
}

// getDNSKEYs fetches and caches DNSKEY records for a zone
func (v *Validator) getDNSKEYs(zone string) ([]*dns.DNSKEY, error) {
	zone = dns.Fqdn(zone)

	v.cacheMu.RLock()
	if keys, ok := v.keyCache[zone]; ok {
		v.cacheMu.RUnlock()
		return keys, nil
	}
	v.cacheMu.RUnlock()

	if v.queryFn == nil {
		return nil, errors.New("no query function set")
	}

	resp, err := v.queryFn(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return nil, errors.New("DNSKEY query failed")
	}

	var keys []*dns.DNSKEY
	for _, rr := range resp.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, key)
		}
	}

	v.cacheMu.Lock()
	v.keyCache[zone] = keys
	v.cacheMu.Unlock()

	return keys, nil
}

// getDS fetches and caches DS records for a zone
func (v *Validator) getDS(zone string) ([]*dns.DS, error) {
	zone = dns.Fqdn(zone)

	v.cacheMu.RLock()
	if ds, ok := v.dsCache[zone]; ok {
		v.cacheMu.RUnlock()
		return ds, nil
	}
	v.cacheMu.RUnlock()

	if v.queryFn == nil {
		return nil, errors.New("no query function set")
	}

	resp, err := v.queryFn(zone, dns.TypeDS)
	if err != nil {
		return nil, err
	}

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return nil, errors.New("DS query failed")
	}

	var dsRecords []*dns.DS
	for _, rr := range resp.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			dsRecords = append(dsRecords, ds)
		}
	}

	v.cacheMu.Lock()
	v.dsCache[zone] = dsRecords
	v.cacheMu.Unlock()

	return dsRecords, nil
}

// validateKeyTrust validates that DNSKEYs are trusted via DS from parent
func (v *Validator) validateKeyTrust(zone string, keys []*dns.DNSKEY, depth int) bool {
	if depth > 10 {
		return false // Prevent infinite loops
	}

	zone = dns.Fqdn(zone)

	// Check if zone is in trust anchors
	if anchors, ok := v.trustAnchors[zone]; ok {
		for _, anchor := range anchors {
			for _, key := range keys {
				if key.KeyTag() == anchor.KeyTag() && key.Algorithm == anchor.Algorithm {
					return true
				}
			}
		}
	}

	// Root zone should have been matched above
	if zone == "." {
		return false
	}

	// Get DS records from parent zone
	dsRecords, err := v.getDS(zone)
	if err != nil || len(dsRecords) == 0 {
		// No DS means zone is not signed (insecure delegation)
		return true // Treat as insecure but not bogus
	}

	// Check if any DNSKEY matches a DS record
	var ksk *dns.DNSKEY
	for _, key := range keys {
		if key.Flags&1 == 1 { // SEP flag (KSK)
			for _, ds := range dsRecords {
				if CheckDS(key, ds) {
					ksk = key
					break
				}
			}
		}
	}

	if ksk == nil {
		log.Printf("DNSSEC: No DNSKEY matches DS for zone %s", zone)
		return false
	}

	// Now validate parent zone's DS is properly signed
	parentZone := getParentZone(zone)
	if parentZone == "" {
		return false
	}

	// Get parent DNSKEY and validate DS was signed by it
	parentKeys, err := v.getDNSKEYs(parentZone)
	if err != nil || len(parentKeys) == 0 {
		// Parent has no DNSKEY - insecure
		return true
	}

	// Recursively validate parent
	return v.validateKeyTrust(parentZone, parentKeys, depth+1)
}

// getParentZone returns the parent zone (e.g., "example.com." -> "com.")
func getParentZone(zone string) string {
	zone = dns.Fqdn(zone)
	if zone == "." {
		return ""
	}
	idx := strings.Index(zone, ".")
	if idx == -1 || idx == len(zone)-1 {
		return "."
	}
	return zone[idx+1:]
}

// VerifyRRSIG verifies an RRSIG against a DNSKEY
func VerifyRRSIG(rrsig *dns.RRSIG, key *dns.DNSKEY, rrset []dns.RR) error {
	if rrsig == nil || key == nil {
		return errors.New("nil rrsig or key")
	}

	// Check key tag matches
	if rrsig.KeyTag != key.KeyTag() {
		return fmt.Errorf("key tag mismatch: sig=%d key=%d", rrsig.KeyTag, key.KeyTag())
	}

	// Check algorithm matches
	if rrsig.Algorithm != key.Algorithm {
		return fmt.Errorf("algorithm mismatch: sig=%d key=%d", rrsig.Algorithm, key.Algorithm)
	}

	// Build the signed data
	signedData, err := buildSignedData(rrsig, rrset)
	if err != nil {
		return fmt.Errorf("failed to build signed data: %w", err)
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(rrsig.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify based on algorithm
	switch rrsig.Algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1:
		return verifyRSASHA1(signedData, signature, key)
	case dns.RSASHA256:
		return verifyRSASHA256(signedData, signature, key)
	case dns.RSASHA512:
		return verifyRSASHA512(signedData, signature, key)
	case dns.ECDSAP256SHA256:
		return verifyECDSAP256(signedData, signature, key)
	case dns.ECDSAP384SHA384:
		return verifyECDSAP384(signedData, signature, key)
	default:
		return fmt.Errorf("unsupported algorithm: %d", rrsig.Algorithm)
	}
}

// buildSignedData constructs the data that was signed
func buildSignedData(rrsig *dns.RRSIG, rrset []dns.RR) ([]byte, error) {
	// RRSIG RDATA without signature
	sigBuf := make([]byte, 1024)
	off := 0

	// Type Covered (2 bytes)
	sigBuf[off] = byte(rrsig.TypeCovered >> 8)
	sigBuf[off+1] = byte(rrsig.TypeCovered)
	off += 2

	// Algorithm (1 byte)
	sigBuf[off] = rrsig.Algorithm
	off++

	// Labels (1 byte)
	sigBuf[off] = rrsig.Labels
	off++

	// Original TTL (4 bytes)
	sigBuf[off] = byte(rrsig.OrigTtl >> 24)
	sigBuf[off+1] = byte(rrsig.OrigTtl >> 16)
	sigBuf[off+2] = byte(rrsig.OrigTtl >> 8)
	sigBuf[off+3] = byte(rrsig.OrigTtl)
	off += 4

	// Signature Expiration (4 bytes)
	sigBuf[off] = byte(rrsig.Expiration >> 24)
	sigBuf[off+1] = byte(rrsig.Expiration >> 16)
	sigBuf[off+2] = byte(rrsig.Expiration >> 8)
	sigBuf[off+3] = byte(rrsig.Expiration)
	off += 4

	// Signature Inception (4 bytes)
	sigBuf[off] = byte(rrsig.Inception >> 24)
	sigBuf[off+1] = byte(rrsig.Inception >> 16)
	sigBuf[off+2] = byte(rrsig.Inception >> 8)
	sigBuf[off+3] = byte(rrsig.Inception)
	off += 4

	// Key Tag (2 bytes)
	sigBuf[off] = byte(rrsig.KeyTag >> 8)
	sigBuf[off+1] = byte(rrsig.KeyTag)
	off += 2

	// Signer's Name (wire format)
	signerName := dns.Fqdn(strings.ToLower(rrsig.SignerName))
	nameBytes := make([]byte, 256)
	n, err := dns.PackDomainName(signerName, nameBytes, 0, nil, false)
	if err != nil {
		return nil, err
	}
	copy(sigBuf[off:], nameBytes[:n])
	off += n

	// Sort and canonicalize RRset
	var rrData []byte
	for _, rr := range rrset {
		// Set TTL to original TTL
		rr.Header().Ttl = rrsig.OrigTtl
		// Lowercase owner name
		rr.Header().Name = strings.ToLower(rr.Header().Name)

		buf := make([]byte, 4096)
		n, err := dns.PackRR(rr, buf, 0, nil, false)
		if err != nil {
			return nil, err
		}
		rrData = append(rrData, buf[:n]...)
	}

	result := make([]byte, off+len(rrData))
	copy(result, sigBuf[:off])
	copy(result[off:], rrData)

	return result, nil
}

func verifyRSASHA1(data, signature []byte, key *dns.DNSKEY) error {
	pubKey, err := parseRSAPublicKey(key.PublicKey)
	if err != nil {
		return err
	}

	hash := sha1.Sum(data)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hash[:], signature)
}

func verifyRSASHA256(data, signature []byte, key *dns.DNSKEY) error {
	pubKey, err := parseRSAPublicKey(key.PublicKey)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
}

func verifyRSASHA512(data, signature []byte, key *dns.DNSKEY) error {
	pubKey, err := parseRSAPublicKey(key.PublicKey)
	if err != nil {
		return err
	}

	hash := sha512.Sum512(data)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, hash[:], signature)
}

func verifyECDSAP256(data, signature []byte, key *dns.DNSKEY) error {
	pubKey, err := parseECDSAPublicKey(key.PublicKey, 256)
	if err != nil {
		return err
	}

	if len(signature) != 64 {
		return errors.New("invalid P256 signature length")
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	hash := sha256.Sum256(data)
	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return errors.New("ECDSA P256 signature verification failed")
	}
	return nil
}

func verifyECDSAP384(data, signature []byte, key *dns.DNSKEY) error {
	pubKey, err := parseECDSAPublicKey(key.PublicKey, 384)
	if err != nil {
		return err
	}

	if len(signature) != 96 {
		return errors.New("invalid P384 signature length")
	}

	r := new(big.Int).SetBytes(signature[:48])
	s := new(big.Int).SetBytes(signature[48:])

	hash := sha512.Sum384(data)
	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return errors.New("ECDSA P384 signature verification failed")
	}
	return nil
}

func parseRSAPublicKey(keyData string) (*rsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, err
	}

	if len(decoded) < 3 {
		return nil, errors.New("key data too short")
	}

	// Parse exponent length
	expLen := int(decoded[0])
	off := 1
	if expLen == 0 {
		expLen = int(decoded[1])<<8 | int(decoded[2])
		off = 3
	}

	if off+expLen > len(decoded) {
		return nil, errors.New("invalid exponent length")
	}

	exp := new(big.Int).SetBytes(decoded[off : off+expLen])
	mod := new(big.Int).SetBytes(decoded[off+expLen:])

	return &rsa.PublicKey{
		N: mod,
		E: int(exp.Int64()),
	}, nil
}

func parseECDSAPublicKey(keyData string, bits int) (*ecdsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, err
	}

	keyLen := bits / 8
	if len(decoded) != keyLen*2 {
		return nil, fmt.Errorf("invalid key length: got %d, expected %d", len(decoded), keyLen*2)
	}

	x := new(big.Int).SetBytes(decoded[:keyLen])
	y := new(big.Int).SetBytes(decoded[keyLen:])

	var curve elliptic.Curve
	if bits == 256 {
		curve = elliptic.P256()
	} else if bits == 384 {
		curve = elliptic.P384()
	} else {
		return nil, fmt.Errorf("unsupported curve size: %d", bits)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// CheckDS verifies that a DNSKEY matches a DS record
func CheckDS(key *dns.DNSKEY, ds *dns.DS) bool {
	if key == nil || ds == nil {
		return false
	}

	// Key tag must match
	if key.KeyTag() != ds.KeyTag {
		return false
	}

	// Algorithm must match
	if key.Algorithm != ds.Algorithm {
		return false
	}

	// Compute digest of DNSKEY and compare
	digest := key.ToDS(ds.DigestType)
	if digest == nil {
		return false
	}

	return strings.EqualFold(digest.Digest, ds.Digest)
}
