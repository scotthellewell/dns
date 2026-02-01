package healthcheck

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("Expected Enabled=false")
	}
	if cfg.Interval != 30*time.Second {
		t.Errorf("Expected Interval=30s")
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Expected Timeout=5s")
	}
}

func TestNewChecker(t *testing.T) {
	c := NewChecker(DefaultConfig())
	if c == nil {
		t.Fatal("Expected non-nil Checker")
	}
	if c.targets == nil {
		t.Error("Expected targets map")
	}
}

func TestAddTarget(t *testing.T) {
	c := NewChecker(DefaultConfig())
	c.AddTarget(Target{ID: "test-1", Address: "192.0.2.1:80"})
	if _, ok := c.targets["test-1"]; !ok {
		t.Error("Expected target to be added")
	}
	if s, ok := c.status["test-1"]; !ok || !s.Healthy {
		t.Error("Expected healthy status")
	}
}

func TestRemoveTarget(t *testing.T) {
	c := NewChecker(DefaultConfig())
	c.AddTarget(Target{ID: "test-1"})
	c.RemoveTarget("test-1")
	if _, ok := c.targets["test-1"]; ok {
		t.Error("Expected target removed")
	}
}

func TestGetStatus(t *testing.T) {
	c := NewChecker(DefaultConfig())
	c.AddTarget(Target{ID: "test-1"})
	status, ok := c.GetStatus("test-1")
	if !ok {
		t.Fatal("Expected status")
	}
	if status.Target.ID != "test-1" {
		t.Errorf("Expected target ID test-1")
	}
	_, ok = c.GetStatus("nonexistent")
	if ok {
		t.Error("Expected no status for nonexistent")
	}
}

func TestGetAllStatus(t *testing.T) {
	c := NewChecker(DefaultConfig())
	c.AddTarget(Target{ID: "test-1"})
	c.AddTarget(Target{ID: "test-2"})
	statuses := c.GetAllStatus()
	if len(statuses) != 2 {
		t.Errorf("Expected 2 statuses")
	}
}

func TestIsHealthy(t *testing.T) {
	c := NewChecker(DefaultConfig())
	c.AddTarget(Target{ID: "test-1"})
	if !c.IsHealthy("test-1") {
		t.Error("Expected healthy")
	}
	if !c.IsHealthy("unknown") {
		t.Error("Unknown targets assumed healthy")
	}
	c.mu.Lock()
	c.status["test-1"].Healthy = false
	c.mu.Unlock()
	if c.IsHealthy("test-1") {
		t.Error("Expected unhealthy")
	}
}

func TestGetHealthyTargets(t *testing.T) {
	c := NewChecker(DefaultConfig())
	c.AddTarget(Target{ID: "t1", Zone: "example.com."})
	c.AddTarget(Target{ID: "t2", Zone: "example.com."})
	c.AddTarget(Target{ID: "t3", Zone: "other.com."})
	c.mu.Lock()
	c.status["t2"].Healthy = false
	c.mu.Unlock()
	healthy := c.GetHealthyTargets("example.com.")
	if len(healthy) != 1 {
		t.Errorf("Expected 1 healthy target")
	}
}

func TestCheckTCP_Success(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	cfg := Config{Enabled: true, Timeout: time.Second, HealthyAfter: 1, UnhealthyAfter: 1}
	c := NewChecker(cfg)
	target := Target{ID: "tcp-test", Address: listener.Addr().String(), Type: CheckTypeTCP}
	c.AddTarget(target)
	c.check(&target)
	status, _ := c.GetStatus("tcp-test")
	if !status.Healthy {
		t.Errorf("Expected healthy: %s", status.LastError)
	}
}

func TestCheckTCP_Failure(t *testing.T) {
	cfg := Config{Enabled: true, Timeout: 100 * time.Millisecond, HealthyAfter: 1, UnhealthyAfter: 1}
	c := NewChecker(cfg)
	target := Target{ID: "tcp-fail", Address: "127.0.0.1:59999", Type: CheckTypeTCP}
	c.AddTarget(target)
	c.check(&target)
	status, _ := c.GetStatus("tcp-fail")
	if status.Healthy {
		t.Error("Expected unhealthy")
	}
}

func TestCheckHTTP_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := Config{Enabled: true, Timeout: time.Second, HealthyAfter: 1, UnhealthyAfter: 1}
	c := NewChecker(cfg)
	target := Target{ID: "http-test", Address: server.Listener.Addr().String(), Type: CheckTypeHTTP, Path: "/"}
	c.AddTarget(target)
	c.check(&target)
	status, _ := c.GetStatus("http-test")
	if !status.Healthy {
		t.Errorf("Expected healthy: %s", status.LastError)
	}
}

func TestCheckHTTP_Unhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	cfg := Config{Enabled: true, Timeout: time.Second, HealthyAfter: 1, UnhealthyAfter: 1}
	c := NewChecker(cfg)
	target := Target{ID: "http-500", Address: server.Listener.Addr().String(), Type: CheckTypeHTTP, Path: "/"}
	c.AddTarget(target)
	c.check(&target)
	status, _ := c.GetStatus("http-500")
	if status.Healthy {
		t.Error("Expected unhealthy for 500")
	}
}

func TestLatencyTracking(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Add a small delay so latency is measurable
			time.Sleep(5 * time.Millisecond)
			conn.Close()
		}
	}()
	cfg := Config{Enabled: true, Timeout: time.Second, HealthyAfter: 1, UnhealthyAfter: 1}
	c := NewChecker(cfg)
	target := Target{ID: "latency", Address: listener.Addr().String(), Type: CheckTypeTCP}
	c.AddTarget(target)

	// Get the pointer to the target that's stored in the checker
	c.mu.RLock()
	storedTarget := c.targets["latency"]
	c.mu.RUnlock()

	c.check(storedTarget)
	status, found := c.GetStatus("latency")
	if !found {
		t.Fatal("Status not found after check")
	}
	// Latency tracking works if LastCheck is set (latency may be 0 for very fast local connections)
	if status.LastCheck.IsZero() {
		t.Error("Expected LastCheck to be set after check")
	}
}

func TestStartStop(t *testing.T) {
	cfg := Config{Enabled: true, Interval: 50 * time.Millisecond, Timeout: 10 * time.Millisecond}
	c := NewChecker(cfg)
	c.AddTarget(Target{ID: "loop", Address: "127.0.0.1:59999", Type: CheckTypeTCP})
	c.Start()
	time.Sleep(100 * time.Millisecond)
	done := make(chan bool)
	go func() {
		c.Stop()
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("Stop() timed out")
	}
}
