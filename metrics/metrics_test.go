package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("Expected non-nil Collector")
	}
	if c.startTime.IsZero() {
		t.Error("Expected startTime to be set")
	}
}

func TestIncQuery(t *testing.T) {
	c := New()
	c.IncQuery("A", "NOERROR")
	c.IncQuery("A", "NOERROR")
	c.IncQuery("AAAA", "NXDOMAIN")
	if c.queriesTotal != 3 {
		t.Errorf("Expected queriesTotal=3, got %d", c.queriesTotal)
	}
}

func TestRecordResponseTime(t *testing.T) {
	c := New()
	c.RecordResponseTime(500 * time.Microsecond)
	if c.responseTimeBuckets[0] != 1 {
		t.Error("Expected bucket[0]=1 for <1ms")
	}
	c.RecordResponseTime(5 * time.Millisecond)
	if c.responseTimeBuckets[2] != 1 {
		t.Error("Expected bucket[2]=1 for 5-10ms")
	}
	c.RecordResponseTime(1 * time.Second)
	if c.responseTimeBuckets[7] != 1 {
		t.Error("Expected bucket[7]=1 for >=500ms")
	}
}

func TestRRLCounters(t *testing.T) {
	c := New()
	c.IncRRLAllowed()
	c.IncRRLAllowed()
	c.IncRRLSlipped()
	c.IncRRLRefused()
	if c.rrlAllowed != 2 {
		t.Errorf("Expected rrlAllowed=2")
	}
	if c.rrlSlipped != 1 {
		t.Errorf("Expected rrlSlipped=1")
	}
	if c.rrlRefused != 1 {
		t.Errorf("Expected rrlRefused=1")
	}
}

func TestSetZonesTotal(t *testing.T) {
	c := New()
	c.SetZonesTotal(10)
	if c.zonesTotal != 10 {
		t.Errorf("Expected zonesTotal=10")
	}
}

func TestSetRecordsTotal(t *testing.T) {
	c := New()
	c.SetRecordsTotal(100)
	if c.recordsTotal != 100 {
		t.Errorf("Expected recordsTotal=100")
	}
}

func TestWritePrometheus(t *testing.T) {
	c := New()
	c.IncQuery("A", "NOERROR")
	c.IncRRLAllowed()
	c.RecordResponseTime(5 * time.Millisecond)
	c.SetZonesTotal(3)
	c.SetRecordsTotal(50)

	var buf bytes.Buffer
	c.WritePrometheus(&buf)
	output := buf.String()

	expectedMetrics := []string{
		"dns_up 1",
		"dns_queries_total 1",
		"dns_rrl_total{action=\"allowed\"} 1",
		"dns_zones_total 3",
		"dns_records_total 50",
	}
	for _, m := range expectedMetrics {
		if !strings.Contains(output, m) {
			t.Errorf("Expected output to contain %q", m)
		}
	}
}

func TestWritePrometheus_Empty(t *testing.T) {
	c := New()
	var buf bytes.Buffer
	c.WritePrometheus(&buf)
	output := buf.String()
	if !strings.Contains(output, "dns_up 1") {
		t.Error("Expected dns_up metric")
	}
	if !strings.Contains(output, "dns_queries_total 0") {
		t.Error("Expected dns_queries_total 0")
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New()
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				c.IncQuery("A", "NOERROR")
				c.RecordResponseTime(time.Millisecond)
				c.IncRRLAllowed()
			}
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	if c.queriesTotal != 1000 {
		t.Errorf("Expected queriesTotal=1000, got %d", c.queriesTotal)
	}
}
