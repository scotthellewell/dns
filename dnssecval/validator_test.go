package dnssecval

import (
	"crypto"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type testKey struct {
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newTestKey(t *testing.T, zone string, flags uint16) *testKey {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return &testKey{key: k, priv: priv.(crypto.Signer)}
}

// sign signs rrset with k, using k's current flags for the key tag.
func sign(t *testing.T, k *testKey, rrset []dns.RR) *dns.RRSIG {
	t.Helper()
	h := rrset[0].Header()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
		TypeCovered: h.Rrtype,
		Algorithm:   k.key.Algorithm,
		OrigTtl:     h.Ttl,
		Inception:   uint32(time.Now().Add(-365 * 24 * time.Hour).Unix()),
		Expiration:  uint32(time.Now().Add(2 * 365 * 24 * time.Hour).Unix()),
		KeyTag:      k.key.KeyTag(),
		SignerName:  k.key.Hdr.Name,
	}
	if err := sig.Sign(k.priv, rrset); err != nil {
		t.Fatal(err)
	}
	return sig
}

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// testTree is a small signed hierarchy:
//
//	.               secure (trust anchor)
//	test.           secure, DS in .
//	example.test.   secure, DS in test.
//	insecure.test.  unsigned delegation, NSEC in test. proves no DS
//	lan.            does not exist in .
type testTree struct {
	t       *testing.T
	keys    map[string]*testKey
	answers map[string]*dns.Msg // "name/type" -> response
}

func key(name string, qtype uint16) string {
	return strings.ToLower(name) + "/" + dns.TypeToString[qtype]
}

func newTestTree(t *testing.T) *testTree {
	tr := &testTree{t: t, keys: map[string]*testKey{}, answers: map[string]*dns.Msg{}}
	for _, z := range []string{".", "test.", "example.test."} {
		tr.keys[z] = newTestKey(t, z, 257)
	}

	// DNSKEY RRsets, self-signed
	for z, k := range tr.keys {
		tr.answer(z, dns.TypeDNSKEY, []dns.RR{k.key}, z, nil)
	}

	// Secure delegations
	tr.answer("test.", dns.TypeDS, []dns.RR{tr.keys["test."].key.ToDS(dns.SHA256)}, ".", nil)
	tr.answer("example.test.", dns.TypeDS, []dns.RR{tr.keys["example.test."].key.ToDS(dns.SHA256)}, "test.", nil)

	// Unsigned delegation: test. proves insecure.test. has NS but no DS
	tr.denial("insecure.test.", dns.RcodeSuccess, "test.",
		rr(t, "insecure.test. 3600 IN NSEC test. NS RRSIG NSEC"))

	// Name inside example.test. that is not a cut
	tr.denial("www.example.test.", dns.RcodeSuccess, "example.test.",
		rr(t, "www.example.test. 3600 IN NSEC example.test. A RRSIG NSEC"))

	// Private TLD: root proves lan. does not exist
	tr.denial("lan.", dns.RcodeNameError, ".",
		rr(t, ". 3600 IN NSEC test. NS SOA RRSIG NSEC DNSKEY"))

	return tr
}

func (tr *testTree) answer(name string, qtype uint16, rrset []dns.RR, signer string, msg *dns.Msg) {
	if msg == nil {
		msg = new(dns.Msg)
		msg.SetQuestion(name, qtype)
	}
	msg.Answer = append(msg.Answer, rrset...)
	if signer != "" {
		msg.Answer = append(msg.Answer, sign(tr.t, tr.keys[signer], rrset))
	}
	tr.answers[key(name, qtype)] = msg
}

func (tr *testTree) denial(name string, rcode int, signer string, nsec dns.RR) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeDS)
	msg.Rcode = rcode
	msg.Ns = []dns.RR{nsec, sign(tr.t, tr.keys[signer], []dns.RR{nsec})}
	tr.answers[key(name, dns.TypeDS)] = msg
}

func (tr *testTree) query(name string, qtype uint16) (*dns.Msg, error) {
	if m, ok := tr.answers[key(name, qtype)]; ok {
		return m.Copy(), nil
	}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Rcode = dns.RcodeServerFailure
	return m, nil
}

func (tr *testTree) validator(anchors ...*dns.DNSKEY) *Validator {
	if len(anchors) == 0 {
		anchors = []*dns.DNSKEY{tr.keys["."].key}
	}
	v := New(NewTrustAnchors(anchors))
	v.SetQueryFunc(tr.query)
	return v
}

func (tr *testTree) aResponse(name, ip, signer string) *dns.Msg {
	a := &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(ip)}
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Answer = []dns.RR{a}
	if signer != "" {
		m.Answer = append(m.Answer, sign(tr.t, tr.keys[signer], []dns.RR{a}))
	}
	return m
}

func TestBuiltinRootAnchors(t *testing.T) {
	want := map[uint16]string{
		20326: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		38696: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
	}
	keys := BuiltinRootAnchors()
	if len(keys) != len(want) {
		t.Fatalf("got %d anchors, want %d", len(keys), len(want))
	}
	for _, k := range keys {
		digest, ok := want[k.KeyTag()]
		if !ok {
			t.Fatalf("unexpected anchor key tag %d", k.KeyTag())
		}
		ds := k.ToDS(dns.SHA256)
		if ds == nil || !strings.EqualFold(ds.Digest, digest) {
			t.Errorf("anchor %d: DS digest mismatch with IANA root-anchors.xml", k.KeyTag())
		}
	}
}

func TestSecureAnswer(t *testing.T) {
	tr := newTestTree(t)
	res := tr.validator().ValidateResponse(tr.aResponse("www.example.test.", "192.0.2.1", "example.test."), "www.example.test.", dns.TypeA)
	if !res.Secure {
		t.Fatalf("want secure, got %+v", res)
	}
}

func TestTamperedAnswerIsBogus(t *testing.T) {
	tr := newTestTree(t)
	resp := tr.aResponse("www.example.test.", "192.0.2.1", "example.test.")
	resp.Answer[0].(*dns.A).A = net.ParseIP("203.0.113.66")
	if res := tr.validator().ValidateResponse(resp, "www.example.test.", dns.TypeA); !res.Bogus {
		t.Fatalf("want bogus, got %+v", res)
	}
}

func TestUntrustedRootIsBogus(t *testing.T) {
	tr := newTestTree(t)
	other := newTestKey(t, ".", 257)
	v := tr.validator(other.key)
	if res := v.ValidateResponse(tr.aResponse("www.example.test.", "192.0.2.1", "example.test."), "www.example.test.", dns.TypeA); !res.Bogus {
		t.Fatalf("want bogus, got %+v", res)
	}
}

func TestUnsignedAnswerInSecureZoneIsBogus(t *testing.T) {
	tr := newTestTree(t)
	if res := tr.validator().ValidateResponse(tr.aResponse("www.example.test.", "192.0.2.1", ""), "www.example.test.", dns.TypeA); !res.Bogus {
		t.Fatalf("want bogus, got %+v", res)
	}
}

func TestStrippedDSIsBogus(t *testing.T) {
	tr := newTestTree(t)
	// Attacker replaces the signed DS with an unsigned NODATA
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeDS)
	tr.answers[key("example.test.", dns.TypeDS)] = m
	if res := tr.validator().ValidateResponse(tr.aResponse("www.example.test.", "192.0.2.1", "example.test."), "www.example.test.", dns.TypeA); !res.Bogus {
		t.Fatalf("want bogus, got %+v", res)
	}
}

func TestInsecureDelegation(t *testing.T) {
	tr := newTestTree(t)
	if res := tr.validator().ValidateResponse(tr.aResponse("host.insecure.test.", "192.0.2.2", ""), "host.insecure.test.", dns.TypeA); !res.Insecure {
		t.Fatalf("want insecure, got %+v", res)
	}
}

func TestPrivateTLDIsInsecure(t *testing.T) {
	tr := newTestTree(t)
	if res := tr.validator().ValidateResponse(tr.aResponse("printer.lan.", "192.168.1.5", ""), "printer.lan.", dns.TypeA); !res.Insecure {
		t.Fatalf("want insecure, got %+v", res)
	}
}

func TestValidationQueryFailureIsBogus(t *testing.T) {
	tr := newTestTree(t)
	delete(tr.answers, key("example.test.", dns.TypeDNSKEY))
	if res := tr.validator().ValidateResponse(tr.aResponse("www.example.test.", "192.0.2.1", "example.test."), "www.example.test.", dns.TypeA); !res.Bogus {
		t.Fatalf("want bogus, got %+v", res)
	}
}

func TestCanonicalOrderAndNSECCover(t *testing.T) {
	if canonicalCompare("a.example.", "z.example.") >= 0 || canonicalCompare("example.", "a.example.") >= 0 {
		t.Fatal("canonical ordering wrong")
	}
	if !nsecCovers(".", "test.", "lan.") || nsecCovers(".", "test.", "zz.") {
		t.Fatal("NSEC cover wrong")
	}
	if !nsecCovers("test.", ".", "zz.") {
		t.Fatal("wrap-around NSEC cover wrong")
	}
}
