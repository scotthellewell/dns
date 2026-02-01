package cache

import (
	"net"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c := New(100)
	if c == nil {
		t.Fatal("New(100) returned nil")
	}
	if c.Size() != 0 {
		t.Errorf("New cache Size() = %d, want 0", c.Size())
	}
}

func TestNew_DefaultSize(t *testing.T) {
	c := New(0)
	if c == nil {
		t.Fatal("New(0) returned nil")
	}
}

func TestNew_NegativeSize(t *testing.T) {
	c := New(-1)
	if c == nil {
		t.Fatal("New(-1) returned nil")
	}
}

func TestKey(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		qtype  uint16
	}{
		{"A record", "example.com", 1},
		{"AAAA record", "example.com", 28},
		{"MX record", "example.com", 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := Key(tt.domain, tt.qtype)
			if key == "" {
				t.Error("Key() returned empty string")
			}
		})
	}
}

func TestKey_Unique(t *testing.T) {
	key1 := Key("example.com", 1)
	key2 := Key("example.com", 28)
	if key1 == key2 {
		t.Error("Different qtypes should produce different keys")
	}

	key3 := Key("example.com", 1)
	key4 := Key("test.com", 1)
	if key3 == key4 {
		t.Error("Different domains should produce different keys")
	}
}

func TestSetAndGet(t *testing.T) {
	c := New(100)
	key := Key("example.com", 1)
	ips := []net.IP{net.ParseIP("192.168.1.1")}
	cnames := []string{}
	ttl := uint32(300)

	c.Set(key, ips, cnames, ttl)

	entry, ok := c.Get(key)
	if !ok {
		t.Fatal("Get() returned not ok for existing key")
	}
	if len(entry.IPs) != 1 {
		t.Errorf("Get() IPs count = %d, want 1", len(entry.IPs))
	}
	if !entry.IPs[0].Equal(ips[0]) {
		t.Errorf("Get() IP = %s, want %s", entry.IPs[0], ips[0])
	}
}

func TestGet_NotFound(t *testing.T) {
	c := New(100)
	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("Get() returned ok for nonexistent key")
	}
}

func TestSet_ZeroTTL(t *testing.T) {
	c := New(100)
	key := Key("example.com", 1)
	ips := []net.IP{net.ParseIP("192.168.1.1")}

	c.Set(key, ips, nil, 0)

	if c.Size() != 0 {
		t.Error("Zero TTL should not be cached")
	}
}

func TestSet_TTLCap(t *testing.T) {
	c := New(100)
	key := Key("example.com", 1)
	ips := []net.IP{net.ParseIP("192.168.1.1")}

	c.Set(key, ips, nil, 86400)

	entry, ok := c.Get(key)
	if !ok {
		t.Fatal("Get() returned not ok")
	}
	if entry.TTL > 3600 {
		t.Errorf("TTL should be capped at 3600, got %d", entry.TTL)
	}
}

func TestGet_Expired(t *testing.T) {
	c := New(100)
	key := Key("example.com", 1)
	ips := []net.IP{net.ParseIP("192.168.1.1")}

	c.Set(key, ips, nil, 1)
	time.Sleep(1100 * time.Millisecond)

	_, ok := c.Get(key)
	if ok {
		t.Error("Get() returned ok for expired entry")
	}
}

func TestGet_TTLDecreases(t *testing.T) {
	c := New(100)
	key := Key("example.com", 1)
	ips := []net.IP{net.ParseIP("192.168.1.1")}

	c.Set(key, ips, nil, 60)

	entry1, _ := c.Get(key)
	ttl1 := entry1.TTL

	time.Sleep(100 * time.Millisecond)

	entry2, _ := c.Get(key)
	ttl2 := entry2.TTL

	if ttl2 > ttl1 {
		t.Errorf("TTL should decrease over time: first=%d, second=%d", ttl1, ttl2)
	}
}

func TestSize(t *testing.T) {
	c := New(100)

	if c.Size() != 0 {
		t.Errorf("Empty cache Size() = %d, want 0", c.Size())
	}

	c.Set(Key("a.com", 1), []net.IP{net.ParseIP("1.1.1.1")}, nil, 300)
	c.Set(Key("b.com", 1), []net.IP{net.ParseIP("2.2.2.2")}, nil, 300)
	c.Set(Key("c.com", 1), []net.IP{net.ParseIP("3.3.3.3")}, nil, 300)

	if c.Size() != 3 {
		t.Errorf("Cache Size() = %d, want 3", c.Size())
	}
}

func TestClear(t *testing.T) {
	c := New(100)

	c.Set(Key("a.com", 1), []net.IP{net.ParseIP("1.1.1.1")}, nil, 300)
	c.Set(Key("b.com", 1), []net.IP{net.ParseIP("2.2.2.2")}, nil, 300)

	c.Clear()

	if c.Size() != 0 {
		t.Errorf("After Clear(), Size() = %d, want 0", c.Size())
	}
}

func TestEviction(t *testing.T) {
	c := New(3)

	c.Set(Key("a.com", 1), []net.IP{net.ParseIP("1.1.1.1")}, nil, 300)
	c.Set(Key("b.com", 1), []net.IP{net.ParseIP("2.2.2.2")}, nil, 300)
	c.Set(Key("c.com", 1), []net.IP{net.ParseIP("3.3.3.3")}, nil, 300)
	c.Set(Key("d.com", 1), []net.IP{net.ParseIP("4.4.4.4")}, nil, 300)

	if c.Size() > 3 {
		t.Errorf("Cache should evict entries when at max size, got %d entries", c.Size())
	}
}

func TestCNAMEs(t *testing.T) {
	c := New(100)
	key := Key("www.example.com", 5)
	cnames := []string{"example.com."}

	c.Set(key, nil, cnames, 300)

	entry, ok := c.Get(key)
	if !ok {
		t.Fatal("Get() returned not ok")
	}
	if len(entry.CNAMEs) != 1 {
		t.Errorf("CNAMEs count = %d, want 1", len(entry.CNAMEs))
	}
	if entry.CNAMEs[0] != "example.com." {
		t.Errorf("CNAME = %s, want example.com.", entry.CNAMEs[0])
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(100)
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			c.Set(Key("test.com", uint16(i%10)), []net.IP{net.ParseIP("1.1.1.1")}, nil, 300)
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			c.Get(Key("test.com", uint16(i%10)))
		}
		done <- true
	}()

	<-done
	<-done
}
