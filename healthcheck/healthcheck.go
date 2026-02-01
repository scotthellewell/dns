// Package healthcheck provides health monitoring for DNS record targets.
package healthcheck

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// CheckType defines the type of health check.
type CheckType string

const (
	CheckTypeTCP   CheckType = "tcp"
	CheckTypeHTTP  CheckType = "http"
	CheckTypeHTTPS CheckType = "https"
	CheckTypePing  CheckType = "ping"
)

// Config holds health check configuration.
type Config struct {
	Enabled        bool          `json:"enabled"`
	Interval       time.Duration `json:"interval"`        // How often to check (default: 30s)
	Timeout        time.Duration `json:"timeout"`         // Timeout per check (default: 5s)
	HealthyAfter   int           `json:"healthy_after"`   // Checks before marking healthy (default: 2)
	UnhealthyAfter int           `json:"unhealthy_after"` // Checks before marking unhealthy (default: 3)
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:        false,
		Interval:       30 * time.Second,
		Timeout:        5 * time.Second,
		HealthyAfter:   2,
		UnhealthyAfter: 3,
	}
}

// Target represents a health check target.
type Target struct {
	ID       string    `json:"id"`        // Unique identifier
	Address  string    `json:"address"`   // IP:port or hostname:port
	Type     CheckType `json:"type"`      // Type of check
	Path     string    `json:"path"`      // For HTTP/HTTPS checks
	Zone     string    `json:"zone"`      // Zone this target belongs to
	RecordID string    `json:"record_id"` // Associated record ID
}

// Status represents the health status of a target.
type Status struct {
	Target          Target    `json:"target"`
	Healthy         bool      `json:"healthy"`
	ConsecutivePass int       `json:"consecutive_pass"`
	ConsecutiveFail int       `json:"consecutive_fail"`
	LastCheck       time.Time `json:"last_check"`
	LastError       string    `json:"last_error,omitempty"`
	Latency         int64     `json:"latency_ms"`
}

// Checker performs health checks on targets.
type Checker struct {
	config  Config
	targets map[string]*Target
	status  map[string]*Status
	mu      sync.RWMutex
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Callback when health status changes
	OnStatusChange func(target *Target, healthy bool)
}

// NewChecker creates a new health checker.
func NewChecker(cfg Config) *Checker {
	return &Checker{
		config:  cfg,
		targets: make(map[string]*Target),
		status:  make(map[string]*Status),
		stopCh:  make(chan struct{}),
	}
}

// AddTarget adds a target to monitor.
func (c *Checker) AddTarget(t Target) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.targets[t.ID] = &t
	c.status[t.ID] = &Status{
		Target:  t,
		Healthy: true, // Assume healthy initially
	}
}

// RemoveTarget removes a target from monitoring.
func (c *Checker) RemoveTarget(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.targets, id)
	delete(c.status, id)
}

// GetStatus returns the current status of a target.
func (c *Checker) GetStatus(id string) (*Status, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	s, ok := c.status[id]
	if !ok {
		return nil, false
	}
	// Return a copy
	copy := *s
	return &copy, true
}

// GetAllStatus returns status for all targets.
func (c *Checker) GetAllStatus() []Status {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]Status, 0, len(c.status))
	for _, s := range c.status {
		result = append(result, *s)
	}
	return result
}

// IsHealthy returns whether a target is healthy.
func (c *Checker) IsHealthy(id string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	s, ok := c.status[id]
	if !ok {
		return true // Unknown targets are assumed healthy
	}
	return s.Healthy
}

// GetHealthyTargets returns all healthy target IDs for a zone.
func (c *Checker) GetHealthyTargets(zone string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var healthy []string
	for id, s := range c.status {
		if s.Target.Zone == zone && s.Healthy {
			healthy = append(healthy, id)
		}
	}
	return healthy
}

// Start begins the health check loop.
func (c *Checker) Start() {
	if !c.config.Enabled {
		return
	}

	c.wg.Add(1)
	go c.checkLoop()
}

// Stop stops the health check loop.
func (c *Checker) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

func (c *Checker) checkLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()

	// Initial check
	c.checkAll()

	for {
		select {
		case <-ticker.C:
			c.checkAll()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Checker) checkAll() {
	c.mu.RLock()
	targets := make([]*Target, 0, len(c.targets))
	for _, t := range c.targets {
		targets = append(targets, t)
	}
	c.mu.RUnlock()

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(target *Target) {
			defer wg.Done()
			c.check(target)
		}(t)
	}
	wg.Wait()
}

func (c *Checker) check(t *Target) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()

	var err error

	switch t.Type {
	case CheckTypeTCP:
		err = c.checkTCP(ctx, t.Address)
	case CheckTypeHTTP:
		err = c.checkHTTP(ctx, "http://"+t.Address+t.Path)
	case CheckTypeHTTPS:
		err = c.checkHTTP(ctx, "https://"+t.Address+t.Path)
	default:
		err = c.checkTCP(ctx, t.Address)
	}

	latency := time.Since(start).Milliseconds()

	c.mu.Lock()
	defer c.mu.Unlock()

	s, ok := c.status[t.ID]
	if !ok {
		return
	}

	s.LastCheck = time.Now()
	s.Latency = latency

	wasHealthy := s.Healthy

	if err != nil {
		s.LastError = err.Error()
		s.ConsecutivePass = 0
		s.ConsecutiveFail++

		if s.ConsecutiveFail >= c.config.UnhealthyAfter {
			s.Healthy = false
		}
	} else {
		s.LastError = ""
		s.ConsecutiveFail = 0
		s.ConsecutivePass++

		if s.ConsecutivePass >= c.config.HealthyAfter {
			s.Healthy = true
		}
	}

	// Notify on status change
	if wasHealthy != s.Healthy && c.OnStatusChange != nil {
		go c.OnStatusChange(t, s.Healthy)
	}
}

func (c *Checker) checkTCP(ctx context.Context, addr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp connect failed: %w", err)
	}
	conn.Close()
	return nil
}

func (c *Checker) checkHTTP(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request failed: %w", err)
	}

	client := &http.Client{
		Timeout: c.config.Timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("unhealthy status: %d", resp.StatusCode)
	}

	return nil
}
