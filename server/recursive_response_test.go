package server

import (
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/scott/dns/recurse"
)

func recursiveMX(t *testing.T) *dns.Msg {
	t.Helper()
	resp := new(dns.Msg)
	resp.SetQuestion("isc.org.", dns.TypeMX)
	for _, s := range []string{
		"isc.org. 300 IN MX 10 mx.ams1.isc.org.",
		"isc.org. 300 IN RRSIG MX 13 2 300 20261017160117 20261003155013 27566 isc.org. AAAA",
	} {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		resp.Answer = append(resp.Answer, rr)
	}
	glue, _ := dns.NewRR("mx.ams1.isc.org. 7200 IN A 199.6.1.65")
	resp.Extra = append(resp.Extra, glue)
	resp.SetEdns0(4096, true) // upstream OPT
	return resp
}

func clientReply(do bool) *dns.Msg {
	r := new(dns.Msg)
	r.SetQuestion("isc.org.", dns.TypeMX)
	r.SetEdns0(1232, do)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Extra = append(m.Extra, r.IsEdns0())
	return m
}

func countType(rrs []dns.RR, t uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			n++
		}
	}
	return n
}

func TestAppendRecursiveSingleOPT(t *testing.T) {
	m := clientReply(true)
	appendRecursive(m, recursiveMX(t), nil)

	if got := countType(m.Extra, dns.TypeOPT); got != 1 {
		t.Fatalf("response has %d OPT records, want 1", got)
	}
	if m.Authoritative {
		t.Error("recursive answer marked authoritative")
	}
	if countType(m.Answer, dns.TypeRRSIG) != 1 {
		t.Error("RRSIG dropped although client set DO")
	}
	// Must pack and parse cleanly (the old duplicate OPT made dig report malformed)
	buf, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := new(dns.Msg).Unpack(buf); err != nil {
		t.Fatalf("response does not round-trip: %v", err)
	}
}

func TestAppendRecursiveStripsDNSSECWithoutDO(t *testing.T) {
	m := clientReply(false)
	appendRecursive(m, recursiveMX(t), nil)
	if countType(m.Answer, dns.TypeRRSIG) != 0 {
		t.Error("RRSIG returned to a client that did not set DO")
	}
	if countType(m.Answer, dns.TypeMX) != 1 || countType(m.Extra, dns.TypeA) != 1 {
		t.Error("answer or glue records lost")
	}
}

func TestAppendRecursiveBogusIsServfail(t *testing.T) {
	m := clientReply(true)
	err := fmt.Errorf("%w for dnssec-failed.org.: test", recurse.ErrDNSSECBogus)
	appendRecursive(m, nil, err)
	if m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Error("bogus response carries answers")
	}

	// Ordinary failures stay NOERROR with no answer
	m = clientReply(true)
	appendRecursive(m, nil, errors.New("timeout"))
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
}
