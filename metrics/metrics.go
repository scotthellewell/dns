// Package metrics provides Prometheus-compatible metrics for DNS server monitoring.
package metrics

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Collector gathers and exposes DNS server metrics.
type Collector struct {
	// Query counters
	queriesTotal   uint64
	queriesByType  sync.Map // map[string]*uint64
	queriesByRcode sync.Map // map[string]*uint64

	// Rate limiting counters
	rrlAllowed uint64
	rrlSlipped uint64
	rrlRefused uint64

	// Response time histogram buckets (in microseconds)
	responseTimeBuckets [8]uint64 // <1ms, <5ms, <10ms, <25ms, <50ms, <100ms, <500ms, >=500ms
	responseTimeSum     uint64    // Total response time in microseconds

	// Zone stats
	zonesTotal   uint64
	recordsTotal uint64

	// Server info
	startTime time.Time
}

// New creates a new metrics collector.
func New() *Collector {
	return &Collector{
		startTime: time.Now(),
	}
}

// IncQuery increments the query counter for a given type and rcode.
func (c *Collector) IncQuery(qtype, rcode string) {
	atomic.AddUint64(&c.queriesTotal, 1)

	// Increment by type
	if counter, ok := c.queriesByType.Load(qtype); ok {
		atomic.AddUint64(counter.(*uint64), 1)
	} else {
		val := uint64(1)
		c.queriesByType.Store(qtype, &val)
	}

	// Increment by rcode
	if counter, ok := c.queriesByRcode.Load(rcode); ok {
		atomic.AddUint64(counter.(*uint64), 1)
	} else {
		val := uint64(1)
		c.queriesByRcode.Store(rcode, &val)
	}
}

// RecordResponseTime records a response time for histogram tracking.
func (c *Collector) RecordResponseTime(d time.Duration) {
	us := uint64(d.Microseconds())
	atomic.AddUint64(&c.responseTimeSum, us)

	// Bucket assignment
	switch {
	case us < 1000: // <1ms
		atomic.AddUint64(&c.responseTimeBuckets[0], 1)
	case us < 5000: // <5ms
		atomic.AddUint64(&c.responseTimeBuckets[1], 1)
	case us < 10000: // <10ms
		atomic.AddUint64(&c.responseTimeBuckets[2], 1)
	case us < 25000: // <25ms
		atomic.AddUint64(&c.responseTimeBuckets[3], 1)
	case us < 50000: // <50ms
		atomic.AddUint64(&c.responseTimeBuckets[4], 1)
	case us < 100000: // <100ms
		atomic.AddUint64(&c.responseTimeBuckets[5], 1)
	case us < 500000: // <500ms
		atomic.AddUint64(&c.responseTimeBuckets[6], 1)
	default: // >=500ms
		atomic.AddUint64(&c.responseTimeBuckets[7], 1)
	}
}

// IncRRLAllowed increments the RRL allowed counter.
func (c *Collector) IncRRLAllowed() {
	atomic.AddUint64(&c.rrlAllowed, 1)
}

// IncRRLSlipped increments the RRL slipped counter.
func (c *Collector) IncRRLSlipped() {
	atomic.AddUint64(&c.rrlSlipped, 1)
}

// IncRRLRefused increments the RRL refused counter.
func (c *Collector) IncRRLRefused() {
	atomic.AddUint64(&c.rrlRefused, 1)
}

// SetZonesTotal sets the total number of zones.
func (c *Collector) SetZonesTotal(n uint64) {
	atomic.StoreUint64(&c.zonesTotal, n)
}

// SetRecordsTotal sets the total number of records.
func (c *Collector) SetRecordsTotal(n uint64) {
	atomic.StoreUint64(&c.recordsTotal, n)
}

// WritePrometheus writes metrics in Prometheus exposition format.
func (c *Collector) WritePrometheus(w io.Writer) {
	// Server info
	fmt.Fprintf(w, "# HELP dns_up Whether the DNS server is up\n")
	fmt.Fprintf(w, "# TYPE dns_up gauge\n")
	fmt.Fprintf(w, "dns_up 1\n\n")

	fmt.Fprintf(w, "# HELP dns_start_time_seconds Unix timestamp of server start\n")
	fmt.Fprintf(w, "# TYPE dns_start_time_seconds gauge\n")
	fmt.Fprintf(w, "dns_start_time_seconds %d\n\n", c.startTime.Unix())

	// Query counters
	fmt.Fprintf(w, "# HELP dns_queries_total Total number of DNS queries received\n")
	fmt.Fprintf(w, "# TYPE dns_queries_total counter\n")
	fmt.Fprintf(w, "dns_queries_total %d\n\n", atomic.LoadUint64(&c.queriesTotal))

	fmt.Fprintf(w, "# HELP dns_queries_by_type_total DNS queries by query type\n")
	fmt.Fprintf(w, "# TYPE dns_queries_by_type_total counter\n")
	c.queriesByType.Range(func(key, value any) bool {
		fmt.Fprintf(w, "dns_queries_by_type_total{type=\"%s\"} %d\n", key, atomic.LoadUint64(value.(*uint64)))
		return true
	})
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# HELP dns_queries_by_rcode_total DNS queries by response code\n")
	fmt.Fprintf(w, "# TYPE dns_queries_by_rcode_total counter\n")
	c.queriesByRcode.Range(func(key, value any) bool {
		fmt.Fprintf(w, "dns_queries_by_rcode_total{rcode=\"%s\"} %d\n", key, atomic.LoadUint64(value.(*uint64)))
		return true
	})
	fmt.Fprintf(w, "\n")

	// Rate limiting
	fmt.Fprintf(w, "# HELP dns_rrl_total Rate limiting decisions\n")
	fmt.Fprintf(w, "# TYPE dns_rrl_total counter\n")
	fmt.Fprintf(w, "dns_rrl_total{action=\"allowed\"} %d\n", atomic.LoadUint64(&c.rrlAllowed))
	fmt.Fprintf(w, "dns_rrl_total{action=\"slipped\"} %d\n", atomic.LoadUint64(&c.rrlSlipped))
	fmt.Fprintf(w, "dns_rrl_total{action=\"refused\"} %d\n\n", atomic.LoadUint64(&c.rrlRefused))

	// Response time histogram
	total := atomic.LoadUint64(&c.queriesTotal)
	sum := atomic.LoadUint64(&c.responseTimeSum)
	fmt.Fprintf(w, "# HELP dns_response_time_seconds DNS response time histogram\n")
	fmt.Fprintf(w, "# TYPE dns_response_time_seconds histogram\n")

	bucketLabels := []string{"0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.5", "+Inf"}
	cumulative := uint64(0)
	for i, label := range bucketLabels {
		if i < len(c.responseTimeBuckets) {
			cumulative += atomic.LoadUint64(&c.responseTimeBuckets[i])
		}
		fmt.Fprintf(w, "dns_response_time_seconds_bucket{le=\"%s\"} %d\n", label, cumulative)
	}
	fmt.Fprintf(w, "dns_response_time_seconds_sum %f\n", float64(sum)/1000000.0)
	fmt.Fprintf(w, "dns_response_time_seconds_count %d\n\n", total)

	// Zone and record stats
	fmt.Fprintf(w, "# HELP dns_zones_total Total number of zones configured\n")
	fmt.Fprintf(w, "# TYPE dns_zones_total gauge\n")
	fmt.Fprintf(w, "dns_zones_total %d\n\n", atomic.LoadUint64(&c.zonesTotal))

	fmt.Fprintf(w, "# HELP dns_records_total Total number of records configured\n")
	fmt.Fprintf(w, "# TYPE dns_records_total gauge\n")
	fmt.Fprintf(w, "dns_records_total %d\n", atomic.LoadUint64(&c.recordsTotal))
}
