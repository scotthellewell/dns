package dnssecval

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

type memAnchorStore struct {
	recs  []AnchorRecord
	saves int
}

func (m *memAnchorStore) LoadTrustAnchors() ([]AnchorRecord, error) { return m.recs, nil }
func (m *memAnchorStore) SaveTrustAnchors(r []AnchorRecord) error {
	m.recs = r
	m.saves++
	return nil
}

// rootRRset builds a root DNSKEY RRset of keys, signed by each of signers.
func rootRRset(t *testing.T, keys []*testKey, signers ...*testKey) ([]*dns.DNSKEY, []*dns.RRSIG) {
	t.Helper()
	var dk []*dns.DNSKEY
	var rrset []dns.RR
	for _, k := range keys {
		dk = append(dk, k.key)
		rrset = append(rrset, k.key)
	}
	var sigs []*dns.RRSIG
	for _, s := range signers {
		sigs = append(sigs, sign(t, s, rrset))
	}
	return dk, sigs
}

func states(ta *TrustAnchors) map[uint16]AnchorState {
	out := map[uint16]AnchorState{}
	for _, rec := range ta.Records() {
		k, _ := dns.NewRR(rec.Key)
		out[k.(*dns.DNSKEY).KeyTag()] = rec.State
	}
	return out
}

func newClockedAnchors(seed ...*testKey) (*TrustAnchors, *time.Time) {
	now := time.Now()
	var keys []*dns.DNSKEY
	for _, k := range seed {
		keys = append(keys, k.key)
	}
	ta := NewTrustAnchors(keys)
	ta.now = func() time.Time { return now }
	return ta, &now
}

func TestRFC5011AddHoldDown(t *testing.T) {
	old := newTestKey(t, ".", 257)
	newK := newTestKey(t, ".", 257)
	ta, now := newClockedAnchors(old)

	// New key published, RRset signed by the old (trusted) key
	keys, sigs := rootRRset(t, []*testKey{old, newK}, old)
	if err := ta.VerifyRootKeys(keys, sigs); err != nil {
		t.Fatal(err)
	}
	if got := states(ta)[newK.key.KeyTag()]; got != StateAddPend {
		t.Fatalf("new key state = %s, want AddPend", got)
	}

	// Not yet trusted: an RRset signed only by the new key fails
	onlyNew, newSigs := rootRRset(t, []*testKey{old, newK}, newK)
	if err := ta.VerifyRootKeys(onlyNew, newSigs); err == nil {
		t.Fatal("pending key trusted before hold-down")
	}

	// After the hold-down it becomes Valid
	*now = now.Add(addHoldDown + time.Hour)
	if err := ta.VerifyRootKeys(keys, sigs); err != nil {
		t.Fatal(err)
	}
	if got := states(ta)[newK.key.KeyTag()]; got != StateValid {
		t.Fatalf("new key state = %s, want Valid", got)
	}

	// The rollover: RRset now signed only by the new key
	if err := ta.VerifyRootKeys(onlyNew, newSigs); err != nil {
		t.Fatalf("rolled RRset rejected: %v", err)
	}
}

func TestRFC5011PendingKeyRemovedResetsHoldDown(t *testing.T) {
	old := newTestKey(t, ".", 257)
	newK := newTestKey(t, ".", 257)
	ta, now := newClockedAnchors(old)

	keys, sigs := rootRRset(t, []*testKey{old, newK}, old)
	if err := ta.VerifyRootKeys(keys, sigs); err != nil {
		t.Fatal(err)
	}

	*now = now.Add(10 * 24 * time.Hour)
	without, wsigs := rootRRset(t, []*testKey{old}, old)
	if err := ta.VerifyRootKeys(without, wsigs); err != nil {
		t.Fatal(err)
	}
	if _, ok := states(ta)[newK.key.KeyTag()]; ok {
		t.Fatal("pending key not discarded when it disappeared")
	}

	// Reappearing restarts the clock: 25 more days is not enough
	if err := ta.VerifyRootKeys(keys, sigs); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(25 * 24 * time.Hour)
	if err := ta.VerifyRootKeys(keys, sigs); err != nil {
		t.Fatal(err)
	}
	if got := states(ta)[newK.key.KeyTag()]; got != StateAddPend {
		t.Fatalf("state = %s, want AddPend", got)
	}
}

func TestRFC5011IgnoresUnvalidatedRRset(t *testing.T) {
	old := newTestKey(t, ".", 257)
	attacker := newTestKey(t, ".", 257)
	ta, _ := newClockedAnchors(old)

	keys, sigs := rootRRset(t, []*testKey{old, attacker}, attacker)
	if err := ta.VerifyRootKeys(keys, sigs); err == nil {
		t.Fatal("RRset signed by unknown key accepted")
	}
	if _, ok := states(ta)[attacker.key.KeyTag()]; ok {
		t.Fatal("key from unvalidated RRset entered the state machine")
	}
}

func TestRFC5011RevocationAndPersistence(t *testing.T) {
	old := newTestKey(t, ".", 257)
	newK := newTestKey(t, ".", 257)
	oldTag := old.key.KeyTag()
	store := &memAnchorStore{}

	ta, _ := newClockedAnchors(old, newK)
	if err := ta.SetStore(store); err != nil {
		t.Fatal(err)
	}

	// Operator revokes the old key: REVOKE bit set, self-signed, plus new key signature
	revoked := &testKey{key: dns.Copy(old.key).(*dns.DNSKEY), priv: old.priv}
	revoked.key.Flags |= dns.REVOKE
	keys, sigs := rootRRset(t, []*testKey{revoked, newK}, revoked, newK)
	if err := ta.VerifyRootKeys(keys, sigs); err != nil {
		t.Fatal(err)
	}
	if got := states(ta)[oldTag]; got != StateRevoked {
		t.Fatalf("old key state = %s, want Revoked", got)
	}
	for _, k := range ta.Trusted() {
		if sameKey(k, old.key) {
			t.Fatal("revoked key still trusted")
		}
	}

	// Restart with the same built-ins: the revoked key must stay revoked
	ta2, _ := newClockedAnchors(old, newK)
	if err := ta2.SetStore(store); err != nil {
		t.Fatal(err)
	}
	if got := states(ta2)[oldTag]; got != StateRevoked {
		t.Fatalf("after restart old key state = %s, want Revoked", got)
	}
	onlyOld, oldSigs := rootRRset(t, []*testKey{old, newK}, old)
	if err := ta2.VerifyRootKeys(onlyOld, oldSigs); err == nil {
		t.Fatal("RRset signed only by revoked key accepted after restart")
	}
}

func TestRFC5011RevocationRequiresSelfSignature(t *testing.T) {
	old := newTestKey(t, ".", 257)
	newK := newTestKey(t, ".", 257)
	ta, _ := newClockedAnchors(old, newK)

	revoked := &testKey{key: dns.Copy(old.key).(*dns.DNSKEY), priv: old.priv}
	revoked.key.Flags |= dns.REVOKE
	keys, sigs := rootRRset(t, []*testKey{revoked, newK}, newK) // not signed by the revoked key
	if err := ta.VerifyRootKeys(keys, sigs); err != nil {
		t.Fatal(err)
	}
	if got := states(ta)[old.key.KeyTag()]; got == StateRevoked {
		t.Fatal("key revoked without its own signature")
	}
}

func TestRFC5011MissingKeyStaysTrusted(t *testing.T) {
	a := newTestKey(t, ".", 257)
	b := newTestKey(t, ".", 257)
	ta, _ := newClockedAnchors(a, b)

	keys, sigs := rootRRset(t, []*testKey{b}, b)
	if err := ta.VerifyRootKeys(keys, sigs); err != nil {
		t.Fatal(err)
	}
	if got := states(ta)[a.key.KeyTag()]; got != StateMissing {
		t.Fatalf("state = %s, want Missing", got)
	}
	if len(ta.Trusted()) != 2 {
		t.Fatal("missing key should remain trusted")
	}
}

func TestRefreshInterval(t *testing.T) {
	now := time.Now()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Ttl: 172800}}
	sig := &dns.RRSIG{Expiration: uint32(now.Add(14 * 24 * time.Hour).Unix())}
	if got := RefreshInterval([]*dns.DNSKEY{k}, []*dns.RRSIG{sig}, now); got != 24*time.Hour {
		t.Errorf("refresh interval = %v, want 24h", got)
	}
	if got := RetryInterval(172800); got != 4*time.Hour+48*time.Minute {
		t.Errorf("retry interval = %v, want 4h48m", got)
	}
	if got := RetryInterval(60); got != time.Hour {
		t.Errorf("retry interval = %v, want 1h minimum", got)
	}
}
