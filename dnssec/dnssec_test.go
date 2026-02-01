package dnssec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("Expected non-nil Manager")
	}
	if m.signers == nil {
		t.Error("Expected signers map")
	}
}

func TestLoadKey_AutoCreate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dnssec-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	m := NewManager()
	cfg := KeyConfig{Zone: "example.com", KeyDir: tmpDir, Algorithm: "ECDSAP256SHA256", AutoCreate: true}
	if err := m.LoadKey(cfg); err != nil {
		t.Fatalf("LoadKey failed: %v", err)
	}
	signer := m.GetSigner("example.com.")
	if signer == nil {
		t.Fatal("Expected signer")
	}
	kskPath := filepath.Join(tmpDir, "example.com.ksk.pem")
	zskPath := filepath.Join(tmpDir, "example.com.zsk.pem")
	if _, err := os.Stat(kskPath); os.IsNotExist(err) {
		t.Error("Expected KSK file")
	}
	if _, err := os.Stat(zskPath); os.IsNotExist(err) {
		t.Error("Expected ZSK file")
	}
}

func TestLoadKey_UnsupportedAlgorithm(t *testing.T) {
	m := NewManager()
	cfg := KeyConfig{Zone: "example.com", KeyDir: "/tmp", Algorithm: "UNSUPPORTED", AutoCreate: true}
	if err := m.LoadKey(cfg); err == nil {
		t.Error("Expected error for unsupported algorithm")
	}
}

func TestGetSigner_DirectMatch(t *testing.T) {
	m := NewManager()
	m.signers["example.com."] = &Signer{zone: "example.com."}
	if m.GetSigner("example.com.") == nil {
		t.Error("Expected signer")
	}
}

func TestGetSigner_ParentZone(t *testing.T) {
	m := NewManager()
	m.signers["example.com."] = &Signer{zone: "example.com."}
	if m.GetSigner("www.example.com.") == nil {
		t.Error("Expected parent signer")
	}
}

func TestGetSigner_NoMatch(t *testing.T) {
	m := NewManager()
	m.signers["example.com."] = &Signer{zone: "example.com."}
	if m.GetSigner("other.org.") != nil {
		t.Error("Expected no signer")
	}
}

func testPubKeyToBase64(pub interface{}) string {
	k := pub.(*ecdsa.PublicKey)
	size := k.Curve.Params().BitSize / 8
	buf := make([]byte, size*2)
	k.X.FillBytes(buf[:size])
	k.Y.FillBytes(buf[size:])
	return base64.StdEncoding.EncodeToString(buf)
}

func TestSigner_Sign(t *testing.T) {
	zone := "example.com."
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	zsk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: testPubKeyToBase64(privKey.Public()),
	}
	signer := &Signer{zone: zone, zsk: zsk, zskPriv: privKey, algorithm: dns.ECDSAP256SHA256}
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeA)
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 1},
	})
	if err := signer.Sign(msg); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("Expected 2 records")
	}
	hasRRSIG := false
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			hasRRSIG = true
		}
	}
	if !hasRRSIG {
		t.Error("Expected RRSIG")
	}
}

func TestSigner_SignEmptyAnswer(t *testing.T) {
	signer := &Signer{zone: "example.com."}
	msg := new(dns.Msg)
	if err := signer.Sign(msg); err != nil {
		t.Errorf("Should not fail: %v", err)
	}
}

func TestSigner_GetDNSKEYs(t *testing.T) {
	signer := &Signer{zone: "example.com.", ksk: &dns.DNSKEY{}, zsk: &dns.DNSKEY{}}
	if len(signer.GetDNSKEYs()) != 2 {
		t.Error("Expected 2 keys")
	}
}

func TestSigner_GetDS(t *testing.T) {
	zone := "example.com."
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ksk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: testPubKeyToBase64(privKey.Public()),
	}
	signer := &Signer{zone: zone, ksk: ksk}
	ds := signer.GetDS()
	if ds == nil {
		t.Fatal("Expected DS")
	}
	if ds.DigestType != dns.SHA256 {
		t.Errorf("Expected SHA256")
	}
}

func TestSigner_Zone(t *testing.T) {
	signer := &Signer{zone: "example.com."}
	if signer.Zone() != "example.com." {
		t.Errorf("Expected example.com.")
	}
}

func TestGenerateKey(t *testing.T) {
	key, priv, err := generateKey("example.com.", dns.ECDSAP256SHA256, true)
	if err != nil {
		t.Fatalf("generateKey failed: %v", err)
	}
	if key == nil || priv == nil {
		t.Fatal("Expected key and priv")
	}
	if key.Flags != 257 {
		t.Errorf("Expected KSK flags")
	}
	key, _, err = generateKey("example.com.", dns.ECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("generateKey ZSK failed: %v", err)
	}
	if key.Flags != 256 {
		t.Errorf("Expected ZSK flags")
	}
}

func TestGenerateKey_Unsupported(t *testing.T) {
	_, _, err := generateKey("example.com.", 255, false)
	if err == nil {
		t.Error("Expected error")
	}
}

func TestPublicKeyToBase64(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	result := publicKeyToBase64(privKey.Public())
	if result == "" {
		t.Error("Expected base64 string")
	}
}

func TestDefaultNSEC3Config(t *testing.T) {
	cfg := DefaultNSEC3Config()
	if cfg.HashAlgorithm != 1 {
		t.Errorf("Expected HashAlgorithm=1")
	}
	if cfg.Iterations != 0 {
		t.Errorf("Expected Iterations=0")
	}
}

func TestGenerateNSEC3Salt(t *testing.T) {
	salt, err := GenerateNSEC3Salt(8)
	if err != nil {
		t.Fatalf("GenerateNSEC3Salt failed: %v", err)
	}
	if len(salt) != 16 {
		t.Errorf("Expected 16 hex chars for 8 bytes")
	}
	empty, _ := GenerateNSEC3Salt(0)
	if empty != "" {
		t.Error("Expected empty salt")
	}
}

func TestDefaultKeyRolloverConfig(t *testing.T) {
	cfg := DefaultKeyRolloverConfig()
	if cfg.ZSKLifetime == 0 {
		t.Error("Expected ZSKLifetime > 0")
	}
	if cfg.KSKLifetime == 0 {
		t.Error("Expected KSKLifetime > 0")
	}
}

func TestNewRolloverManager(t *testing.T) {
	m := NewManager()
	rm := NewRolloverManager(m, DefaultKeyRolloverConfig())
	if rm == nil {
		t.Fatal("Expected non-nil RolloverManager")
	}
}

func TestHasDNSSEC(t *testing.T) {
	m := NewManager()
	if m.HasDNSSEC() {
		t.Error("Expected no DNSSEC initially")
	}
	m.signers["example.com."] = &Signer{}
	if !m.HasDNSSEC() {
		t.Error("Expected DNSSEC after adding signer")
	}
}
