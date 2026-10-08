package dnssecval

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// QueryFunc is a function that queries DNS (used for fetching DNSKEY/DS records).
// Responses must include DNSSEC records (DO bit set, CD bit set when forwarding).
type QueryFunc func(name string, qtype uint16) (*dns.Msg, error)

// Cache lifetimes for validated chain data
const (
	minCacheTTL = time.Minute
	maxCacheTTL = time.Hour
	bogusTTL    = 30 * time.Second
)

type status int

const (
	statusSecure status = iota
	statusInsecure
	statusBogus
)

// dsKind classifies what the parent says about a name's DS RRset.
type dsKind int

const (
	dsSecure      dsKind = iota // Validated DS RRset with a supported algorithm: secure cut
	dsInsecureCut               // Proven unsigned delegation, unsupported algorithms, or parent insecure
	dsNoCut                     // Proven to exist without being a delegation point
	dsNoName                    // Proven not to exist
	dsBogus                     // Could not be validated
)

type zoneKeysEntry struct {
	status  status
	keys    []*dns.DNSKEY
	why     string
	expires time.Time
}

type dsEntry struct {
	kind    dsKind
	ds      []*dns.DS
	why     string
	expires time.Time
}

// Validator handles DNSSEC validation
type Validator struct {
	anchors  *TrustAnchors
	keyCache map[string]*zoneKeysEntry // zone -> validated DNSKEY RRset
	dsCache  map[string]*dsEntry       // name -> validated DS lookup result
	cacheMu  sync.RWMutex
	flight   singleflight.Group
	queryFn  QueryFunc
	now      func() time.Time
}

// New creates a new DNSSEC validator using the given root trust anchors.
// If anchors is nil, the built-in root anchors are used without persistence.
func New(anchors *TrustAnchors) *Validator {
	if anchors == nil {
		anchors = NewTrustAnchors(BuiltinRootAnchors())
	}
	return &Validator{
		anchors:  anchors,
		keyCache: make(map[string]*zoneKeysEntry),
		dsCache:  make(map[string]*dsEntry),
		now:      time.Now,
	}
}

// SetQueryFunc sets the function used to query DNS for DNSKEY/DS records
func (v *Validator) SetQueryFunc(fn QueryFunc) {
	v.queryFn = fn
}

// ClearCache clears all cached DNSSEC records for a specific zone
// Call this when zone records are added/changed/deleted
func (v *Validator) ClearCache(zone string) {
	zone = canonical(zone)
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	delete(v.keyCache, zone)
	delete(v.dsCache, zone)
}

// ClearAllCaches clears all DNSSEC caches
func (v *Validator) ClearAllCaches() {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	v.keyCache = make(map[string]*zoneKeysEntry)
	v.dsCache = make(map[string]*dsEntry)
}

// ValidationResult holds the result of DNSSEC validation
type ValidationResult struct {
	Secure   bool   // True if DNSSEC validated successfully
	Insecure bool   // True if zone is provably not signed
	Bogus    bool   // True if validation failed
	Error    error  // Validation error if any
	WhyBogus string // Reason for bogus result
}

// ValidateResponse validates every RRset in the answer section of resp.
// Signed RRsets must chain to a trusted root anchor; unsigned RRsets must be
// provably below an insecure delegation. Anything else is bogus.
func (v *Validator) ValidateResponse(resp *dns.Msg, qname string, qtype uint16) ValidationResult {
	if resp == nil || len(resp.Answer) == 0 {
		return ValidationResult{Insecure: true}
	}
	if v.queryFn == nil {
		return bogus("no query function configured for DNSSEC validation")
	}

	type rrsetKey struct {
		name  string
		rtype uint16
	}
	var order []rrsetKey
	rrsets := make(map[rrsetKey][]dns.RR)
	sigs := make(map[rrsetKey][]*dns.RRSIG)
	for _, rr := range resp.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			k := rrsetKey{canonical(sig.Hdr.Name), sig.TypeCovered}
			sigs[k] = append(sigs[k], sig)
			continue
		}
		k := rrsetKey{canonical(rr.Header().Name), rr.Header().Rrtype}
		if _, ok := rrsets[k]; !ok {
			order = append(order, k)
		}
		rrsets[k] = append(rrsets[k], rr)
	}

	// Validate DNAMEs first so CNAMEs synthesized from them can be accepted
	var secureDNAMEs []string
	overall := statusSecure
	var why string
	validate := func(k rrsetKey) {
		var st status
		var w string
		switch {
		case len(sigs[k]) > 0:
			st, w = v.verifyRRset(k.name, rrsets[k], sigs[k])
		case k.rtype == dns.TypeCNAME && synthesizedFrom(k.name, secureDNAMEs):
			st = statusSecure
		default:
			st, w = v.provenInsecure(k.name)
		}
		if st == statusSecure && k.rtype == dns.TypeDNAME {
			secureDNAMEs = append(secureDNAMEs, k.name)
		}
		if st > overall {
			overall, why = st, fmt.Sprintf("%s %s: %s", k.name, dns.TypeToString[k.rtype], w)
		}
	}
	for _, k := range order {
		if k.rtype == dns.TypeDNAME {
			validate(k)
		}
	}
	for _, k := range order {
		if k.rtype != dns.TypeDNAME {
			validate(k)
		}
	}

	switch overall {
	case statusSecure:
		return ValidationResult{Secure: true}
	case statusInsecure:
		return ValidationResult{Insecure: true}
	default:
		return bogus(why)
	}
}

func bogus(why string) ValidationResult {
	return ValidationResult{Bogus: true, WhyBogus: why, Error: errors.New(why)}
}

func synthesizedFrom(name string, dnames []string) bool {
	for _, d := range dnames {
		if name != d && dns.IsSubDomain(d, name) {
			return true
		}
	}
	return false
}

// verifyRRset checks that at least one RRSIG over rrset was made by a
// validated key of its signer zone.
func (v *Validator) verifyRRset(owner string, rrset []dns.RR, sigs []*dns.RRSIG) (status, string) {
	now := v.now()
	why := "no usable RRSIG"
	for _, sig := range sigs {
		signer := canonical(sig.SignerName)
		if !dns.IsSubDomain(signer, owner) {
			why = fmt.Sprintf("RRSIG signer %s is not an ancestor of %s", signer, owner)
			continue
		}
		zk := v.zoneKeys(signer)
		if zk.status == statusInsecure {
			return statusInsecure, ""
		}
		if zk.status == statusBogus {
			why = zk.why
			continue
		}
		if !sig.ValidityPeriod(now) {
			why = fmt.Sprintf("RRSIG by %s/%d outside validity period", signer, sig.KeyTag)
			continue
		}
		found := false
		for _, key := range zk.keys {
			if key.KeyTag() != sig.KeyTag || key.Algorithm != sig.Algorithm ||
				key.Flags&dns.ZONE == 0 || key.Flags&dns.REVOKE != 0 {
				continue
			}
			found = true
			err := sig.Verify(key, rrset)
			if err == nil {
				return statusSecure, ""
			}
			why = fmt.Sprintf("RRSIG by %s/%d failed: %v", signer, sig.KeyTag, err)
		}
		if !found {
			why = fmt.Sprintf("no DNSKEY %s/%d", signer, sig.KeyTag)
		}
	}
	return statusBogus, why
}

// zoneKeys returns the validated DNSKEY RRset for a zone apex.
func (v *Validator) zoneKeys(zone string) *zoneKeysEntry {
	v.cacheMu.RLock()
	e, ok := v.keyCache[zone]
	v.cacheMu.RUnlock()
	if ok && v.now().Before(e.expires) {
		return e
	}
	res, _, _ := v.flight.Do("k:"+zone, func() (interface{}, error) {
		e := v.fetchZoneKeys(zone)
		if e.status == statusBogus {
			log.Printf("DNSSEC: Keys for %s are bogus: %s", zone, e.why)
			e.expires = v.now().Add(bogusTTL)
		}
		v.cacheMu.Lock()
		v.keyCache[zone] = e
		v.cacheMu.Unlock()
		return e, nil
	})
	return res.(*zoneKeysEntry)
}

func (v *Validator) fetchZoneKeys(zone string) *zoneKeysEntry {
	var supported []*dns.DS
	if zone != "." {
		d := v.dsLookup(zone)
		switch d.kind {
		case dsSecure:
			supported = d.ds
		case dsInsecureCut:
			return &zoneKeysEntry{status: statusInsecure, expires: d.expires}
		case dsBogus:
			return &zoneKeysEntry{status: statusBogus, why: d.why}
		default:
			return &zoneKeysEntry{status: statusBogus, why: fmt.Sprintf("signer %s is not a delegated zone", zone)}
		}
	}

	resp, err := v.queryFn(zone, dns.TypeDNSKEY)
	if err != nil || resp == nil {
		return &zoneKeysEntry{status: statusBogus, why: fmt.Sprintf("could not fetch DNSKEY for %s: %v", zone, err)}
	}
	keys, sigs := SplitDNSKEYs(resp.Answer, zone)
	if len(keys) == 0 {
		return &zoneKeysEntry{status: statusBogus, why: fmt.Sprintf("no DNSKEY RRset for %s", zone)}
	}
	expires := v.expiry(keys[0].Hdr.Ttl, sigs)

	if zone == "." {
		if err := v.anchors.VerifyRootKeys(keys, sigs); err != nil {
			return &zoneKeysEntry{status: statusBogus, why: err.Error()}
		}
		return &zoneKeysEntry{status: statusSecure, keys: keys, expires: expires}
	}

	rrset := make([]dns.RR, len(keys))
	for i, k := range keys {
		rrset[i] = k
	}
	now := v.now()
	for _, ds := range supported {
		for _, k := range keys {
			if k.Flags&dns.ZONE == 0 || k.Flags&dns.REVOKE != 0 || !CheckDS(k, ds) {
				continue
			}
			for _, sig := range sigs {
				if sig.KeyTag == k.KeyTag() && sig.Algorithm == k.Algorithm &&
					sig.ValidityPeriod(now) && sig.Verify(k, rrset) == nil {
					return &zoneKeysEntry{status: statusSecure, keys: keys, expires: expires}
				}
			}
		}
	}
	return &zoneKeysEntry{status: statusBogus, why: fmt.Sprintf("no DNSKEY matching a DS signs the DNSKEY RRset of %s", zone)}
}

// dsLookup fetches and validates what the parent zone says about name's DS RRset.
func (v *Validator) dsLookup(name string) *dsEntry {
	v.cacheMu.RLock()
	e, ok := v.dsCache[name]
	v.cacheMu.RUnlock()
	if ok && v.now().Before(e.expires) {
		return e
	}
	res, _, _ := v.flight.Do("d:"+name, func() (interface{}, error) {
		e := v.fetchDS(name)
		if e.kind == dsBogus {
			e.expires = v.now().Add(bogusTTL)
		}
		v.cacheMu.Lock()
		v.dsCache[name] = e
		v.cacheMu.Unlock()
		return e, nil
	})
	return res.(*dsEntry)
}

func (v *Validator) fetchDS(name string) *dsEntry {
	resp, err := v.queryFn(name, dns.TypeDS)
	if err != nil || resp == nil {
		return &dsEntry{kind: dsBogus, why: fmt.Sprintf("could not fetch DS for %s: %v", name, err)}
	}

	var dsSet []dns.RR
	var dsSigs []*dns.RRSIG
	for _, rr := range resp.Answer {
		if canonical(rr.Header().Name) != name {
			continue
		}
		switch r := rr.(type) {
		case *dns.DS:
			dsSet = append(dsSet, r)
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeDS {
				dsSigs = append(dsSigs, r)
			}
		}
	}

	if len(dsSet) > 0 {
		if len(dsSigs) == 0 {
			return v.unsignedDS(name, "unsigned DS RRset")
		}
		st, why := v.verifyRRset(name, dsSet, dsSigs)
		switch {
		case st == statusInsecure:
			return &dsEntry{kind: dsInsecureCut, expires: v.expiry(dsSet[0].Header().Ttl, dsSigs)}
		case st == statusBogus:
			return &dsEntry{kind: dsBogus, why: why}
		}
		for _, s := range dsSigs {
			if canonical(s.SignerName) == name {
				return &dsEntry{kind: dsBogus, why: fmt.Sprintf("DS for %s signed by the child zone", name)}
			}
		}
		var supported []*dns.DS
		for _, rr := range dsSet {
			if ds := rr.(*dns.DS); supportedDS(ds) {
				supported = append(supported, ds)
			}
		}
		expires := v.expiry(dsSet[0].Header().Ttl, dsSigs)
		if len(supported) == 0 {
			// RFC 4035 section 5.2: no supported algorithm means treat as insecure
			return &dsEntry{kind: dsInsecureCut, expires: expires}
		}
		return &dsEntry{kind: dsSecure, ds: supported, expires: expires}
	}

	return v.denialOfDS(name, resp)
}

// unsignedDS handles an unsigned DS answer or denial: acceptable only when an
// ancestor is already proven insecure.
func (v *Validator) unsignedDS(name, what string) *dsEntry {
	if parent := parentName(name); parent != "." {
		if st, _ := v.provenInsecure(parent); st == statusInsecure {
			return &dsEntry{kind: dsInsecureCut, expires: v.now().Add(minCacheTTL)}
		}
	}
	return &dsEntry{kind: dsBogus, why: fmt.Sprintf("%s for %s in a signed zone", what, name)}
}

// denialOfDS validates the NSEC/NSEC3 records proving that name has no DS.
func (v *Validator) denialOfDS(name string, resp *dns.Msg) *dsEntry {
	type rrsetKey struct {
		name  string
		rtype uint16
	}
	rrsets := make(map[rrsetKey][]dns.RR)
	sigs := make(map[rrsetKey][]*dns.RRSIG)
	for _, rr := range resp.Ns {
		switch r := rr.(type) {
		case *dns.NSEC, *dns.NSEC3:
			k := rrsetKey{canonical(rr.Header().Name), rr.Header().Rrtype}
			rrsets[k] = append(rrsets[k], rr)
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeNSEC || r.TypeCovered == dns.TypeNSEC3 {
				k := rrsetKey{canonical(r.Hdr.Name), r.TypeCovered}
				sigs[k] = append(sigs[k], r)
			}
		}
	}
	if len(rrsets) == 0 {
		return v.unsignedDS(name, "unsigned DS denial")
	}

	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	var ttl uint32 = 3600
	var allSigs []*dns.RRSIG
	for k, set := range rrsets {
		if len(sigs[k]) == 0 {
			return v.unsignedDS(name, "unsigned NSEC")
		}
		for _, s := range sigs[k] {
			if signer := canonical(s.SignerName); signer == name || !dns.IsSubDomain(signer, name) {
				return &dsEntry{kind: dsBogus, why: fmt.Sprintf("DS denial for %s signed by %s", name, signer)}
			}
		}
		st, why := v.verifyRRset(k.name, set, sigs[k])
		if st == statusInsecure {
			return &dsEntry{kind: dsInsecureCut, expires: v.expiry(set[0].Header().Ttl, sigs[k])}
		}
		if st == statusBogus {
			return &dsEntry{kind: dsBogus, why: why}
		}
		allSigs = append(allSigs, sigs[k]...)
		for _, rr := range set {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
			switch r := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, r)
			case *dns.NSEC3:
				nsec3s = append(nsec3s, r)
			}
		}
	}
	expires := v.expiry(ttl, allSigs)
	result := func(kind dsKind) *dsEntry { return &dsEntry{kind: kind, expires: expires} }

	for _, n := range nsecs {
		if canonical(n.Hdr.Name) == name {
			return result(classifyBitmap(n.TypeBitMap))
		}
	}
	for _, n := range nsecs {
		if nsecCovers(canonical(n.Hdr.Name), canonical(n.NextDomain), name) {
			return result(dsNoName)
		}
	}

	if len(nsec3s) > 0 {
		for _, n := range nsec3s {
			if n.Match(name) {
				return result(classifyBitmap(n.TypeBitMap))
			}
		}
		// Closest encloser proof (RFC 5155 section 8.6)
		labels := dns.SplitDomainName(name)
		for i := 1; i < len(labels); i++ {
			ce := dns.Fqdn(strings.Join(labels[i:], "."))
			nextCloser := dns.Fqdn(strings.Join(labels[i-1:], "."))
			for _, m := range nsec3s {
				if !m.Match(ce) {
					continue
				}
				for _, c := range nsec3s {
					if c.Cover(nextCloser) {
						if c.Flags&1 == 1 {
							return result(dsInsecureCut) // opt-out span: may be an unsigned delegation
						}
						return result(dsNoName)
					}
				}
			}
		}
	}

	return &dsEntry{kind: dsBogus, why: fmt.Sprintf("NSEC/NSEC3 records do not prove absence of DS for %s", name)}
}

func classifyBitmap(types []uint16) dsKind {
	has := make(map[uint16]bool, len(types))
	for _, t := range types {
		has[t] = true
	}
	switch {
	case has[dns.TypeDS]:
		return dsBogus // DS exists but was not returned
	case has[dns.TypeNS] && !has[dns.TypeSOA]:
		return dsInsecureCut
	default:
		return dsNoCut
	}
}

// provenInsecure walks from the top-level domain down to name, and reports
// insecure only if the chain of trust is proven to stop at an unsigned
// delegation. Names below a TLD that does not exist in the root zone (e.g.
// .lan, .internal) are private namespaces and treated as insecure.
func (v *Validator) provenInsecure(name string) (status, string) {
	labels := dns.SplitDomainName(name)
	for i := len(labels) - 1; i >= 0; i-- {
		n := dns.Fqdn(strings.Join(labels[i:], "."))
		d := v.dsLookup(n)
		switch d.kind {
		case dsInsecureCut:
			return statusInsecure, ""
		case dsBogus:
			return statusBogus, d.why
		case dsNoName:
			if i == len(labels)-1 {
				return statusInsecure, ""
			}
		}
	}
	return statusBogus, "unsigned answer in a signed zone"
}

// expiry returns the cache expiry for data with the given TTL and signatures.
func (v *Validator) expiry(ttl uint32, sigs []*dns.RRSIG) time.Time {
	now := v.now()
	d := time.Duration(ttl) * time.Second
	for _, s := range sigs {
		if left := time.Unix(int64(s.Expiration), 0).Sub(now); left < d {
			d = left
		}
	}
	if d > maxCacheTTL {
		d = maxCacheTTL
	}
	if d < minCacheTTL {
		d = minCacheTTL
	}
	return now.Add(d)
}

func supportedDS(ds *dns.DS) bool {
	switch ds.DigestType {
	case dns.SHA1, dns.SHA256, dns.SHA384:
	default:
		return false
	}
	switch ds.Algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512,
		dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519:
		return true
	}
	return false
}

// nsecCovers reports whether the NSEC span (owner, next) covers name.
func nsecCovers(owner, next, name string) bool {
	if canonicalCompare(owner, name) >= 0 {
		return false
	}
	// The last NSEC in a zone wraps around to the apex
	return canonicalCompare(name, next) < 0 || canonicalCompare(next, owner) <= 0
}

// canonicalCompare orders names per RFC 4034 section 6.1.
func canonicalCompare(a, b string) int {
	la := dns.SplitDomainName(strings.ToLower(a))
	lb := dns.SplitDomainName(strings.ToLower(b))
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := strings.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

func canonical(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}

// parentName returns the name with its first label removed ("." for a TLD).
func parentName(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// CheckDS verifies that a DNSKEY matches a DS record
func CheckDS(key *dns.DNSKEY, ds *dns.DS) bool {
	if key == nil || ds == nil {
		return false
	}
	if key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
		return false
	}
	digest := key.ToDS(ds.DigestType)
	if digest == nil {
		return false
	}
	return strings.EqualFold(digest.Digest, ds.Digest)
}
