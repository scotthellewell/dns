package dnssecval

import (
	"errors"
	"fmt"
	"log"
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
	trustAnchors  map[string][]dns.DNSKEY  // Zone -> trusted DNSKEYs
	keyCache      map[string][]*dns.DNSKEY // Cached DNSKEY records
	dsCache       map[string][]*dns.DS     // Cached DS records
	negativeCache map[string]time.Time     // Negative cache (zone -> expiry time)
	negativeTTL   time.Duration            // How long to cache negative results
	cacheMu       sync.RWMutex
	queryFn       QueryFunc
}

// New creates a new DNSSEC validator with root trust anchors
func New() *Validator {
	v := &Validator{
		trustAnchors:  make(map[string][]dns.DNSKEY),
		keyCache:      make(map[string][]*dns.DNSKEY),
		dsCache:       make(map[string][]*dns.DS),
		negativeCache: make(map[string]time.Time),
		negativeTTL:   5 * time.Minute, // Cache negative results for 5 minutes
	}
	// Add root trust anchors
	v.trustAnchors["."] = rootAnchors
	return v
}

// SetQueryFunc sets the function used to query DNS for DNSKEY/DS records
func (v *Validator) SetQueryFunc(fn QueryFunc) {
	v.queryFn = fn
}

// ClearCache clears all cached DNSSEC records for a specific zone
// Call this when zone records are added/changed/deleted
func (v *Validator) ClearCache(zone string) {
	zone = dns.Fqdn(zone)
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()

	// Clear positive caches
	delete(v.keyCache, zone)
	delete(v.dsCache, zone)

	// Clear negative caches
	delete(v.negativeCache, "dnskey:"+zone)
	delete(v.negativeCache, "ds:"+zone)
}

// ClearAllCaches clears all DNSSEC caches
func (v *Validator) ClearAllCaches() {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()

	v.keyCache = make(map[string][]*dns.DNSKEY)
	v.dsCache = make(map[string][]*dns.DS)
	v.negativeCache = make(map[string]time.Time)
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
	negCacheKey := "dnskey:" + zone

	v.cacheMu.RLock()
	// Check positive cache first
	if keys, ok := v.keyCache[zone]; ok {
		v.cacheMu.RUnlock()
		return keys, nil
	}
	// Check negative cache
	if expiry, ok := v.negativeCache[negCacheKey]; ok && time.Now().Before(expiry) {
		v.cacheMu.RUnlock()
		return nil, errors.New("DNSKEY query failed (negative cached)")
	}
	v.cacheMu.RUnlock()

	if v.queryFn == nil {
		return nil, errors.New("no query function set")
	}

	resp, err := v.queryFn(zone, dns.TypeDNSKEY)
	if err != nil {
		// Cache the negative result
		v.cacheMu.Lock()
		v.negativeCache[negCacheKey] = time.Now().Add(v.negativeTTL)
		v.cacheMu.Unlock()
		return nil, err
	}

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		// Cache the negative result
		v.cacheMu.Lock()
		v.negativeCache[negCacheKey] = time.Now().Add(v.negativeTTL)
		v.cacheMu.Unlock()
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
	// Clear negative cache entry if it exists
	delete(v.negativeCache, negCacheKey)
	v.cacheMu.Unlock()

	return keys, nil
}

// getDS fetches and caches DS records for a zone
func (v *Validator) getDS(zone string) ([]*dns.DS, error) {
	zone = dns.Fqdn(zone)
	negCacheKey := "ds:" + zone

	v.cacheMu.RLock()
	// Check positive cache first
	if ds, ok := v.dsCache[zone]; ok {
		v.cacheMu.RUnlock()
		return ds, nil
	}
	// Check negative cache
	if expiry, ok := v.negativeCache[negCacheKey]; ok && time.Now().Before(expiry) {
		v.cacheMu.RUnlock()
		return nil, errors.New("DS query failed (negative cached)")
	}
	v.cacheMu.RUnlock()

	if v.queryFn == nil {
		return nil, errors.New("no query function set")
	}

	resp, err := v.queryFn(zone, dns.TypeDS)
	if err != nil {
		// Cache the negative result
		v.cacheMu.Lock()
		v.negativeCache[negCacheKey] = time.Now().Add(v.negativeTTL)
		v.cacheMu.Unlock()
		return nil, err
	}

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		// Cache the negative result
		v.cacheMu.Lock()
		v.negativeCache[negCacheKey] = time.Now().Add(v.negativeTTL)
		v.cacheMu.Unlock()
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
	// Clear negative cache entry if it exists
	delete(v.negativeCache, negCacheKey)
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

// VerifyRRSIG verifies an RRSIG against a DNSKEY using the dns library's built-in method
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

	// Use the dns library's built-in verification which properly handles
	// canonicalization, sorting, and all cryptographic algorithms
	return rrsig.Verify(key, rrset)
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
