package zonefile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewParser(t *testing.T) {
	p := NewParser()
	if p == nil {
		t.Fatal("Expected non-nil Parser")
	}
	if p.defaultTTL != 3600 {
		t.Errorf("Expected defaultTTL=3600")
	}
}

func TestParse_ARecord(t *testing.T) {
	p := NewParser()
	result, err := p.Parse(strings.NewReader("www IN A 192.0.2.1"), "example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("Expected 1 record")
	}
	r := result.Records[0]
	if r.Type != "A" {
		t.Errorf("Expected type A")
	}
	if r.Name != "www.example.com." {
		t.Errorf("Expected name www.example.com., got %s", r.Name)
	}
	var data struct {
		IP string `json:"ip"`
	}
	json.Unmarshal(r.Data, &data)
	if data.IP != "192.0.2.1" {
		t.Errorf("Expected IP 192.0.2.1")
	}
}

func TestParse_AAAARecord(t *testing.T) {
	p := NewParser()
	result, err := p.Parse(strings.NewReader("www IN AAAA 2001:db8::1"), "example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("Expected 1 record")
	}
	if result.Records[0].Type != "AAAA" {
		t.Errorf("Expected type AAAA")
	}
}

func TestParse_CNAMERecord(t *testing.T) {
	p := NewParser()
	result, err := p.Parse(strings.NewReader("alias IN CNAME www.example.com."), "example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("Expected 1 record")
	}
	if result.Records[0].Type != "CNAME" {
		t.Errorf("Expected type CNAME")
	}
}

func TestParse_MXRecord(t *testing.T) {
	p := NewParser()
	result, err := p.Parse(strings.NewReader("@ IN MX 10 mail.example.com."), "example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("Expected 1 record")
	}
	var data struct {
		Priority int    `json:"priority"`
		Target   string `json:"target"`
	}
	json.Unmarshal(result.Records[0].Data, &data)
	if data.Priority != 10 {
		t.Errorf("Expected priority 10")
	}
}

func TestParse_TXTRecord(t *testing.T) {
	p := NewParser()
	result, err := p.Parse(strings.NewReader(`@ IN TXT "v=spf1 ~all"`), "example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("Expected 1 record")
	}
	if result.Records[0].Type != "TXT" {
		t.Errorf("Expected type TXT")
	}
}

func TestParse_TTLDirective(t *testing.T) {
	p := NewParser()
	result, err := p.Parse(strings.NewReader("$TTL 7200\nwww IN A 192.0.2.1"), "example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if result.Records[0].TTL != 7200 {
		t.Errorf("Expected TTL 7200, got %d", result.Records[0].TTL)
	}
}

func TestParse_OriginDirective(t *testing.T) {
	p := NewParser()
	result, err := p.Parse(strings.NewReader("$ORIGIN example.com.\nwww IN A 192.0.2.1"), "other.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if result.Records[0].Name != "www.example.com." {
		t.Errorf("Expected name www.example.com.")
	}
}

func TestParse_AtSymbol(t *testing.T) {
	p := NewParser()
	result, err := p.Parse(strings.NewReader("@ IN A 192.0.2.1"), "example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if result.Records[0].Name != "example.com." {
		t.Errorf("Expected name example.com.")
	}
}

func TestParse_Comments(t *testing.T) {
	p := NewParser()
	result, err := p.Parse(strings.NewReader("; comment\nwww IN A 192.0.2.1 ; inline"), "example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Records) != 1 {
		t.Errorf("Expected 1 record")
	}
}

func TestParse_InvalidRecord(t *testing.T) {
	p := NewParser()
	result, err := p.Parse(strings.NewReader("www IN A notanip"), "example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("Expected errors for invalid IP")
	}
}

func TestParseTTL(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
	}{
		{"3600", 3600},
		{"1h", 3600},
		{"30m", 1800},
		{"1d", 86400},
		{"1w", 604800},
	}
	for _, tt := range tests {
		got, err := parseTTL(tt.input)
		if err != nil {
			t.Errorf("parseTTL(%q) failed: %v", tt.input, err)
		}
		if got != tt.expected {
			t.Errorf("parseTTL(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestIsClass(t *testing.T) {
	if !isClass("IN") {
		t.Error("IN should be a class")
	}
	if isClass("A") {
		t.Error("A should not be a class")
	}
}

func TestIsType(t *testing.T) {
	if !isType("A") {
		t.Error("A should be a type")
	}
	if isType("IN") {
		t.Error("IN should not be a type")
	}
}
