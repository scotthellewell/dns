package server

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/scott/dns/config"
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

// TestBogusRecursiveAnswerIsServfail runs a query end to end through the server
// against an upstream whose signed answers can't be validated (the upstream
// can't supply a root DNSKEY RRset signed by the real root anchors).
func TestBogusRecursiveAnswerIsServfail(t *testing.T) {
	upstream := &dns.Server{Addr: "127.0.0.1:15354", Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA, dns.TypeMX:
			rr, _ := dns.NewRR(q.Name + " 300 IN A 192.0.2.66")
			if q.Qtype == dns.TypeMX {
				rr, _ = dns.NewRR(q.Name + " 300 IN MX 10 mail." + q.Name)
			}
			sig, _ := dns.NewRR(q.Name + " 300 IN RRSIG " + dns.TypeToString[q.Qtype] +
				" 13 2 300 20361017160117 20161003155013 12345 " + q.Name + " AAAA")
			m.Answer = []dns.RR{rr, sig}
		}
		w.WriteMsg(m)
	})}
	go upstream.ListenAndServe()
	defer upstream.Shutdown()

	rawCfg := config.DefaultConfig()
	rawCfg.Recursion.Enabled = true
	rawCfg.Recursion.Mode = "full"
	rawCfg.Recursion.Upstream = []string{"127.0.0.1:15354"}
	rawCfg.Recursion.Timeout = 2
	parsedCfg, err := rawCfg.Parse()
	if err != nil {
		t.Fatal(err)
	}
	srv := New(parsedCfg)
	front := &dns.Server{Addr: "127.0.0.1:15355", Net: "udp", Handler: dns.HandlerFunc(srv.ServeDNS)}
	go front.ListenAndServe()
	defer front.Shutdown()
	time.Sleep(100 * time.Millisecond)

	client := &dns.Client{Timeout: 5 * time.Second}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeMX} {
		for attempt := 0; attempt < 2; attempt++ { // second attempt hits the cache
			msg := new(dns.Msg)
			msg.SetQuestion("bogus.example.", qtype)
			resp, _, err := client.Exchange(msg, "127.0.0.1:15355")
			if err != nil {
				t.Fatalf("%s query: %v", dns.TypeToString[qtype], err)
			}
			if resp.Rcode != dns.RcodeServerFailure {
				t.Errorf("%s attempt %d: rcode = %s, want SERVFAIL", dns.TypeToString[qtype], attempt, dns.RcodeToString[resp.Rcode])
			}
			if len(resp.Answer) != 0 {
				t.Errorf("%s attempt %d: bogus answer returned to client", dns.TypeToString[qtype], attempt)
			}
		}
	}
}
