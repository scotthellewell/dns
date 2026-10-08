package dnssecval

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Built-in root zone trust anchors, as published by IANA in
// https://data.iana.org/root-anchors/root-anchors.xml
//
//	KSK-2017  key tag 20326  DS SHA-256 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
//	KSK-2024  key tag 38696  DS SHA-256 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
//
// These seed the RFC 5011 state machine. Once a key has been revoked by the
// root zone operator, the persisted state keeps it revoked even though it is
// still listed here.
var builtinRootAnchors = []string{
	". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	". 172800 IN DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
}

// BuiltinRootAnchors returns the compiled-in root KSKs.
func BuiltinRootAnchors() []*dns.DNSKEY {
	keys := make([]*dns.DNSKEY, 0, len(builtinRootAnchors))
	for _, s := range builtinRootAnchors {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(fmt.Sprintf("invalid built-in root anchor: %v", err))
		}
		keys = append(keys, rr.(*dns.DNSKEY))
	}
	return keys
}

// RFC 5011 timers
const (
	addHoldDown    = 30 * 24 * time.Hour // Section 2.4.1
	minRefresh     = time.Hour           // Section 2.3
	maxRefresh     = 15 * 24 * time.Hour // Section 2.3
	maxRetryPeriod = 24 * time.Hour      // Section 2.3
)

// AnchorState is the RFC 5011 state of a trust anchor key.
type AnchorState string

const (
	StateAddPend AnchorState = "AddPend" // Seen in a validated RRset, waiting out the add hold-down
	StateValid   AnchorState = "Valid"   // Trusted
	StateMissing AnchorState = "Missing" // Trusted, but absent from the last validated RRset
	StateRevoked AnchorState = "Revoked" // Revoked by the zone operator; never trusted again
)

// AnchorRecord is the persisted form of one trust anchor key.
type AnchorRecord struct {
	Zone      string      `json:"zone"`
	Key       string      `json:"key"` // DNSKEY in presentation format, REVOKE bit clear
	State     AnchorState `json:"state"`
	FirstSeen time.Time   `json:"first_seen"`
	LastSeen  time.Time   `json:"last_seen"`
	RevokedAt time.Time   `json:"revoked_at,omitempty"`
}

// AnchorStore persists trust anchor state across restarts.
type AnchorStore interface {
	LoadTrustAnchors() ([]AnchorRecord, error)
	SaveTrustAnchors([]AnchorRecord) error
}

type anchorEntry struct {
	key *dns.DNSKEY // REVOKE bit clear
	rec AnchorRecord
}

// TrustAnchors manages the root zone trust anchors, following RFC 5011
// automated updates. It is long-lived and shared by every validator the
// process creates, so state survives resolver reconfiguration.
type TrustAnchors struct {
	mu      sync.RWMutex
	entries map[string]*anchorEntry // keyID -> entry
	store   AnchorStore
	now     func() time.Time
}

// NewTrustAnchors creates a trust anchor set seeded with the given keys
// (normally BuiltinRootAnchors()), all in the Valid state.
func NewTrustAnchors(seed []*dns.DNSKEY) *TrustAnchors {
	t := &TrustAnchors{
		entries: make(map[string]*anchorEntry),
		now:     time.Now,
	}
	t.mergeSeed(seed)
	return t
}

// mergeSeed adds seed keys that are not already known as Valid anchors.
// Keys already in the state (including Revoked ones) are left alone.
func (t *TrustAnchors) mergeSeed(seed []*dns.DNSKEY) bool {
	changed := false
	now := t.now().UTC()
	for _, k := range seed {
		k = withoutRevoke(k)
		id := keyID(k)
		if _, ok := t.entries[id]; ok {
			continue
		}
		t.entries[id] = &anchorEntry{key: k, rec: AnchorRecord{
			Zone:      ".",
			Key:       k.String(),
			State:     StateValid,
			FirstSeen: now,
		}}
		changed = true
	}
	return changed
}

// SetStore loads persisted state from store, merges in the built-in anchors
// and from then on saves every state change.
func (t *TrustAnchors) SetStore(store AnchorStore) error {
	recs, err := store.LoadTrustAnchors()
	if err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	seed := make([]*dns.DNSKEY, 0, len(t.entries))
	for _, e := range t.entries {
		seed = append(seed, e.key)
	}

	t.store = store
	if len(recs) > 0 {
		t.entries = make(map[string]*anchorEntry)
		for _, rec := range recs {
			rr, err := dns.NewRR(rec.Key)
			if err != nil {
				log.Printf("DNSSEC: Ignoring unparseable persisted trust anchor: %v", err)
				continue
			}
			k, ok := rr.(*dns.DNSKEY)
			if !ok {
				continue
			}
			k = withoutRevoke(k)
			t.entries[keyID(k)] = &anchorEntry{key: k, rec: rec}
		}
	}
	if t.mergeSeed(seed) || len(recs) == 0 {
		t.saveLocked()
	}
	t.logStateLocked()
	return nil
}

// Trusted returns the keys currently usable as trust anchors (Valid or Missing).
func (t *TrustAnchors) Trusted() []*dns.DNSKEY {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.trustedLocked()
}

func (t *TrustAnchors) trustedLocked() []*dns.DNSKEY {
	var keys []*dns.DNSKEY
	for _, e := range t.entries {
		if e.rec.State == StateValid || e.rec.State == StateMissing {
			keys = append(keys, e.key)
		}
	}
	return keys
}

// Records returns a snapshot of the trust anchor state, sorted by key tag.
func (t *TrustAnchors) Records() []AnchorRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.recordsLocked()
}

func (t *TrustAnchors) recordsLocked() []AnchorRecord {
	recs := make([]AnchorRecord, 0, len(t.entries))
	for _, e := range t.entries {
		recs = append(recs, e.rec)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Key < recs[j].Key })
	return recs
}

// VerifyRootKeys checks that the root DNSKEY RRset is signed by a trusted
// anchor. On success it also runs the RFC 5011 state machine against the RRset.
func (t *TrustAnchors) VerifyRootKeys(keys []*dns.DNSKEY, sigs []*dns.RRSIG) error {
	if len(keys) == 0 {
		return errors.New("empty root DNSKEY RRset")
	}
	rrset := make([]dns.RR, len(keys))
	for i, k := range keys {
		rrset[i] = k
	}
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.signedByTrustedLocked(keys, rrset, sigs, now) {
		return errors.New("root DNSKEY RRset not signed by any trusted anchor")
	}
	if t.observeLocked(keys, rrset, sigs, now.UTC()) {
		t.saveLocked()
	}
	return nil
}

func (t *TrustAnchors) signedByTrustedLocked(keys []*dns.DNSKEY, rrset []dns.RR, sigs []*dns.RRSIG, now time.Time) bool {
	for _, anchor := range t.trustedLocked() {
		// The anchor must be published, unrevoked, in the RRset it signs
		var published *dns.DNSKEY
		for _, k := range keys {
			if k.Flags&dns.REVOKE == 0 && sameKey(k, anchor) {
				published = k
				break
			}
		}
		if published == nil {
			continue
		}
		tag := published.KeyTag()
		for _, sig := range sigs {
			if sig.KeyTag != tag || sig.Algorithm != published.Algorithm || sig.SignerName != "." {
				continue
			}
			if sig.ValidityPeriod(now) && sig.Verify(published, rrset) == nil {
				return true
			}
		}
	}
	return false
}

// observeLocked applies RFC 5011 section 4 transitions for a validated RRset.
// Returns true if anything changed.
func (t *TrustAnchors) observeLocked(keys []*dns.DNSKEY, rrset []dns.RR, sigs []*dns.RRSIG, now time.Time) bool {
	changed := false
	present := make(map[string]bool)

	for _, k := range keys {
		if k.Flags&dns.SEP == 0 {
			continue
		}
		base := withoutRevoke(k)
		id := keyID(base)
		present[id] = true
		e := t.entries[id]

		if k.Flags&dns.REVOKE != 0 {
			// Unknown revoked keys are ignored; known ones are revoked only if
			// the revoked key itself signed the RRset (section 2.1)
			if e == nil || e.rec.State == StateRevoked || !selfSigned(k, rrset, sigs, now) {
				continue
			}
			e.rec.State = StateRevoked
			e.rec.RevokedAt = now
			e.rec.LastSeen = now
			log.Printf("DNSSEC: Root trust anchor %d revoked by the root zone (RFC 5011)", base.KeyTag())
			changed = true
			continue
		}

		switch {
		case e == nil:
			t.entries[id] = &anchorEntry{key: base, rec: AnchorRecord{
				Zone: ".", Key: base.String(), State: StateAddPend, FirstSeen: now, LastSeen: now,
			}}
			log.Printf("DNSSEC: New root KSK %d seen, trusting it after %v hold-down (RFC 5011)", base.KeyTag(), addHoldDown)
			changed = true
		case e.rec.State == StateAddPend && now.Sub(e.rec.FirstSeen) >= addHoldDown:
			e.rec.State = StateValid
			log.Printf("DNSSEC: Root KSK %d is now a trusted anchor (RFC 5011)", base.KeyTag())
			changed = true
		case e.rec.State == StateMissing:
			e.rec.State = StateValid
			log.Printf("DNSSEC: Root trust anchor %d reappeared", base.KeyTag())
			changed = true
		}
		if e = t.entries[id]; e.rec.State != StateRevoked && now.Sub(e.rec.LastSeen) >= time.Hour {
			e.rec.LastSeen = now
			changed = true
		}
	}

	for id, e := range t.entries {
		if present[id] {
			continue
		}
		switch e.rec.State {
		case StateValid:
			e.rec.State = StateMissing
			log.Printf("DNSSEC: Root trust anchor %d no longer published; still trusted until revoked", e.key.KeyTag())
			changed = true
		case StateAddPend:
			// Section 2.4.1: a pending key that disappears goes back to Start
			delete(t.entries, id)
			log.Printf("DNSSEC: Pending root KSK %d disappeared; hold-down reset", e.key.KeyTag())
			changed = true
		}
	}

	if changed && len(t.trustedLocked()) == 0 {
		log.Printf("DNSSEC: WARNING: no trusted root anchors remain; DNSSEC validation will fail until anchors are updated")
	}
	return changed
}

func selfSigned(k *dns.DNSKEY, rrset []dns.RR, sigs []*dns.RRSIG, now time.Time) bool {
	tag := k.KeyTag()
	for _, sig := range sigs {
		if sig.KeyTag == tag && sig.Algorithm == k.Algorithm && sig.ValidityPeriod(now) && sig.Verify(k, rrset) == nil {
			return true
		}
	}
	return false
}

func (t *TrustAnchors) saveLocked() {
	if t.store == nil {
		return
	}
	if err := t.store.SaveTrustAnchors(t.recordsLocked()); err != nil {
		log.Printf("DNSSEC: Failed to save trust anchor state: %v", err)
	}
}

func (t *TrustAnchors) logStateLocked() {
	var parts []string
	for _, rec := range t.recordsLocked() {
		tag := uint16(0)
		if rr, err := dns.NewRR(rec.Key); err == nil {
			tag = rr.(*dns.DNSKEY).KeyTag()
		}
		parts = append(parts, fmt.Sprintf("%d=%s", tag, rec.State))
	}
	log.Printf("DNSSEC: Root trust anchors: %s", strings.Join(parts, ", "))
}

// RefreshInterval returns how long to wait before the next active refresh
// (RFC 5011 section 2.3), given the root DNSKEY RRset and its signatures.
func RefreshInterval(keys []*dns.DNSKEY, sigs []*dns.RRSIG, now time.Time) time.Duration {
	interval := maxRefresh
	if len(keys) > 0 {
		interval = minDuration(interval, time.Duration(keys[0].Hdr.Ttl)*time.Second/2)
	}
	for _, sig := range sigs {
		left := time.Unix(int64(sig.Expiration), 0).Sub(now)
		interval = minDuration(interval, left/2)
	}
	if interval < minRefresh {
		interval = minRefresh
	}
	return interval
}

// RetryInterval is the wait after a failed refresh (RFC 5011 section 2.3).
func RetryInterval(ttl uint32) time.Duration {
	interval := minDuration(maxRetryPeriod, time.Duration(ttl)*time.Second/10)
	if interval < minRefresh {
		interval = minRefresh
	}
	return interval
}

// ErrRefreshSkipped can be returned by a refresh fetch function to signal that
// refreshing is currently not possible (e.g. recursion disabled).
var ErrRefreshSkipped = errors.New("trust anchor refresh skipped")

// Run actively refreshes the root DNSKEY RRset until ctx is cancelled, so
// RFC 5011 hold-down timers keep advancing even when the validator's caches
// would otherwise not fetch it. fetch must return the root DNSKEY response
// including RRSIGs (DO bit set).
func (t *TrustAnchors) Run(ctx context.Context, fetch func() (*dns.Msg, error)) {
	for {
		wait := t.refresh(fetch)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (t *TrustAnchors) refresh(fetch func() (*dns.Msg, error)) time.Duration {
	resp, err := fetch()
	if err != nil {
		if !errors.Is(err, ErrRefreshSkipped) {
			log.Printf("DNSSEC: Root trust anchor refresh failed: %v", err)
		}
		return RetryInterval(172800)
	}
	keys, sigs := SplitDNSKEYs(resp.Answer, ".")
	if err := t.VerifyRootKeys(keys, sigs); err != nil {
		log.Printf("DNSSEC: Root trust anchor refresh: %v", err)
		ttl := uint32(172800)
		if len(keys) > 0 {
			ttl = keys[0].Hdr.Ttl
		}
		return RetryInterval(ttl)
	}
	return RefreshInterval(keys, sigs, t.now())
}

// SplitDNSKEYs extracts the DNSKEY RRset for zone and the RRSIGs covering it.
func SplitDNSKEYs(rrs []dns.RR, zone string) ([]*dns.DNSKEY, []*dns.RRSIG) {
	var keys []*dns.DNSKEY
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		if !strings.EqualFold(rr.Header().Name, zone) {
			continue
		}
		switch v := rr.(type) {
		case *dns.DNSKEY:
			keys = append(keys, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDNSKEY {
				sigs = append(sigs, v)
			}
		}
	}
	return keys, sigs
}

// keyID identifies a key by algorithm and public key material, ignoring flags.
func keyID(k *dns.DNSKEY) string {
	return fmt.Sprintf("%d/%d/%s", k.Protocol, k.Algorithm, normalizeKey(k.PublicKey))
}

// sameKey reports whether a and b are the same key, ignoring the REVOKE bit.
func sameKey(a, b *dns.DNSKEY) bool {
	return a.Flags&^dns.REVOKE == b.Flags&^dns.REVOKE && keyID(a) == keyID(b)
}

func normalizeKey(pub string) string {
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(pub), ""))
	if err != nil {
		return pub
	}
	return base64.StdEncoding.EncodeToString(b)
}

func withoutRevoke(k *dns.DNSKEY) *dns.DNSKEY {
	c := dns.Copy(k).(*dns.DNSKEY)
	c.Flags &^= dns.REVOKE
	c.Hdr.Name = "."
	return c
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
