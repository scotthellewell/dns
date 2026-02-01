package ports

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Config holds all port configurations
type Config struct {
	DNS DNSPortConfig `json:"dns"`
	DoT DoTPortConfig `json:"dot"`
	DoH DoHPortConfig `json:"doh"`
	Web WebPortConfig `json:"web"`
}

// DNSPortConfig holds DNS server port configuration
type DNSPortConfig struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Address string `json:"address"`
}

// DoTPortConfig holds DNS over TLS port configuration
type DoTPortConfig struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Address string `json:"address"`
}

// DoHPortConfig holds DNS over HTTPS port configuration
type DoHPortConfig struct {
	Enabled    bool   `json:"enabled"`
	Standalone bool   `json:"standalone"` // If true, run on separate port; if false, share with Web
	Port       int    `json:"port"`       // Only used if Standalone is true
	Address    string `json:"address"`
	Path       string `json:"path"` // e.g., "/dns-query"
}

// WebPortConfig holds Web UI port configuration
type WebPortConfig struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Address string `json:"address"`
	TLS     bool   `json:"tls"` // Enable HTTPS
}

// TLSConfigProvider provides TLS configuration
type TLSConfigProvider interface {
	GetTLSConfig() (*tls.Config, error)
}

// Manager handles dynamic port management
type Manager struct {
	mu         sync.RWMutex
	config     Config
	configPath string

	// TLS configuration provider
	tlsProvider TLSConfigProvider

	// DNS servers
	dnsUDP *dns.Server
	dnsTCP *dns.Server

	// DoT server
	dotListener net.Listener
	dotServer   *dns.Server

	// DoH server (standalone mode only)
	dohServer *http.Server

	// Web server (also serves DoH if not standalone)
	webServer *http.Server
	webMux    *http.ServeMux

	// DNS handler
	dnsHandler dns.Handler

	// Shutdown contexts
	ctx    context.Context
	cancel context.CancelFunc
}

// NewManager creates a new port manager
func NewManager(configPath string) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		configPath: configPath,
		ctx:        ctx,
		cancel:     cancel,
		config: Config{
			DNS: DNSPortConfig{
				Enabled: true,
				Port:    53,
				Address: "",
			},
			DoT: DoTPortConfig{
				Enabled: false,
				Port:    853,
				Address: "",
			},
			DoH: DoHPortConfig{
				Enabled:    false,
				Standalone: false,
				Port:       443,
				Address:    "",
				Path:       "/dns-query",
			},
			Web: WebPortConfig{
				Enabled: true,
				Port:    443,
				Address: "",
				TLS:     true,
			},
		},
	}

	// Try to load existing config
	if err := m.loadConfig(); err != nil {
		if os.IsNotExist(err) {
			// Save default config when file doesn't exist
			if saveErr := m.saveConfig(); saveErr != nil {
				log.Printf("Warning: Could not save default ports config: %v", saveErr)
			} else {
				log.Printf("Created default ports config at %s", configPath)
			}
		} else {
			log.Printf("Warning: Could not load ports config: %v", err)
		}
	}

	return m, nil
}

// SetTLSProvider sets the TLS configuration provider
func (m *Manager) SetTLSProvider(provider TLSConfigProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tlsProvider = provider
}

// loadConfig loads port configuration from file
func (m *Manager) loadConfig() error {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}

	m.config = cfg
	return nil
}

// saveConfig saves port configuration to file
func (m *Manager) saveConfig() error {
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.configPath, data, 0644)
}

// GetConfig returns the current port configuration
func (m *Manager) GetConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// SetDNSHandler sets the DNS handler for all DNS services
func (m *Manager) SetDNSHandler(handler dns.Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dnsHandler = handler
}

// SetWebMux sets the HTTP mux for the web server
func (m *Manager) SetWebMux(mux *http.ServeMux) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.webMux = mux
}

// Start starts all enabled services
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []string

	if m.config.DNS.Enabled {
		if err := m.startDNSLocked(); err != nil {
			errs = append(errs, fmt.Sprintf("DNS: %v", err))
		}
	}

	if m.config.DoT.Enabled {
		if err := m.startDoTLocked(); err != nil {
			errs = append(errs, fmt.Sprintf("DoT: %v", err))
		}
	}

	if m.config.DoH.Enabled {
		if err := m.startDoHLocked(); err != nil {
			errs = append(errs, fmt.Sprintf("DoH: %v", err))
		}
	}

	if m.config.Web.Enabled && m.webMux != nil {
		if err := m.startWebLocked(); err != nil {
			errs = append(errs, fmt.Sprintf("Web: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to start services: %s", strings.Join(errs, "; "))
	}

	return nil
}

// Stop stops all services
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cancel()
	m.stopDNSLocked()
	m.stopDoTLocked()
	m.stopDoHLocked()
	m.stopWebLocked()
}

// UpdateDNS updates DNS port configuration
func (m *Manager) UpdateDNS(cfg DNSPortConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop existing DNS servers
	m.stopDNSLocked()

	// Update config
	m.config.DNS = cfg

	// Start if enabled
	if cfg.Enabled {
		if err := m.startDNSLocked(); err != nil {
			return err
		}
	}

	return m.saveConfig()
}

// UpdateDoT updates DoT port configuration
func (m *Manager) UpdateDoT(cfg DoTPortConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop existing DoT server
	m.stopDoTLocked()

	// Update config
	m.config.DoT = cfg

	// Start if enabled
	if cfg.Enabled {
		if err := m.startDoTLocked(); err != nil {
			return err
		}
	}

	return m.saveConfig()
}

// UpdateDoH updates DoH port configuration
func (m *Manager) UpdateDoH(cfg DoHPortConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop existing DoH server
	m.stopDoHLocked()

	// Update config
	m.config.DoH = cfg

	// Start if enabled
	if cfg.Enabled {
		if err := m.startDoHLocked(); err != nil {
			return err
		}
	}

	return m.saveConfig()
}

// UpdateWeb updates Web port configuration
func (m *Manager) UpdateWeb(cfg WebPortConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop existing Web server
	m.stopWebLocked()

	// Update config
	m.config.Web = cfg

	// Start if enabled
	if cfg.Enabled && m.webMux != nil {
		if err := m.startWebLocked(); err != nil {
			return err
		}
	}

	return m.saveConfig()
}

// DNS Server methods

func (m *Manager) startDNSLocked() error {
	if m.dnsHandler == nil {
		return fmt.Errorf("DNS handler not set")
	}

	addr := fmt.Sprintf("%s:%d", m.config.DNS.Address, m.config.DNS.Port)

	// Start UDP server
	m.dnsUDP = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: m.dnsHandler,
	}
	go func() {
		log.Printf("Starting DNS UDP server on %s", addr)
		if err := m.dnsUDP.ListenAndServe(); err != nil {
			log.Printf("DNS UDP server error: %v", err)
		}
	}()

	// Start TCP server
	m.dnsTCP = &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: m.dnsHandler,
	}
	go func() {
		log.Printf("Starting DNS TCP server on %s", addr)
		if err := m.dnsTCP.ListenAndServe(); err != nil {
			log.Printf("DNS TCP server error: %v", err)
		}
	}()

	return nil
}

func (m *Manager) stopDNSLocked() {
	if m.dnsUDP != nil {
		m.dnsUDP.Shutdown()
		m.dnsUDP = nil
	}
	if m.dnsTCP != nil {
		m.dnsTCP.Shutdown()
		m.dnsTCP = nil
	}
}

// DoT Server methods

func (m *Manager) startDoTLocked() error {
	if m.dnsHandler == nil {
		return fmt.Errorf("DNS handler not set")
	}

	if m.tlsProvider == nil {
		return fmt.Errorf("TLS provider not set")
	}

	tlsConfig, err := m.tlsProvider.GetTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to get TLS config: %v", err)
	}
	if tlsConfig == nil {
		return fmt.Errorf("TLS configuration not available")
	}

	addr := fmt.Sprintf("%s:%d", m.config.DoT.Address, m.config.DoT.Port)
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start DoT listener: %v", err)
	}

	m.dotListener = listener
	m.dotServer = &dns.Server{
		Listener: listener,
		Net:      "tcp-tls",
		Handler:  m.dnsHandler,
	}

	go func() {
		log.Printf("Starting DoT server on %s", addr)
		if err := m.dotServer.ActivateAndServe(); err != nil {
			log.Printf("DoT server error: %v", err)
		}
	}()

	return nil
}

func (m *Manager) stopDoTLocked() {
	if m.dotServer != nil {
		m.dotServer.Shutdown()
		m.dotServer = nil
	}
	if m.dotListener != nil {
		m.dotListener.Close()
		m.dotListener = nil
	}
}

// DoH Server methods

func (m *Manager) startDoHLocked() error {
	if m.dnsHandler == nil {
		return fmt.Errorf("DNS handler not set")
	}

	// If not standalone, DoH is served through the web server
	if !m.config.DoH.Standalone {
		log.Printf("DoH will be served through the Web server on path %s", m.config.DoH.Path)
		return nil
	}

	// Standalone DoH server
	if m.tlsProvider == nil {
		return fmt.Errorf("TLS provider not set")
	}

	tlsConfig, err := m.tlsProvider.GetTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to get TLS config: %v", err)
	}
	if tlsConfig == nil {
		return fmt.Errorf("TLS configuration not available")
	}

	addr := fmt.Sprintf("%s:%d", m.config.DoH.Address, m.config.DoH.Port)
	path := m.config.DoH.Path
	if path == "" {
		path = "/dns-query"
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, m.handleDoH)

	m.dohServer = &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	go func() {
		log.Printf("Starting standalone DoH server on %s%s", addr, path)
		if err := m.dohServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("DoH server error: %v", err)
		}
	}()

	return nil
}

func (m *Manager) stopDoHLocked() {
	if m.dohServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.dohServer.Shutdown(ctx)
		m.dohServer = nil
	}
}

// handleDoH handles DNS over HTTPS requests (RFC 8484)
func (m *Manager) handleDoH(w http.ResponseWriter, r *http.Request) {
	var dnsReq []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		// GET request with dns parameter (base64url encoded)
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		dnsReq, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "Invalid base64url encoding", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		// POST request with application/dns-message body
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			http.Error(w, "Invalid content type", http.StatusUnsupportedMediaType)
			return
		}
		dnsReq, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(dnsReq); err != nil {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}

	// Create response writer
	dohWriter := &dohResponseWriter{
		remoteAddr: r.RemoteAddr,
	}

	// Handle the DNS request
	m.dnsHandler.ServeDNS(dohWriter, msg)

	// Get response
	resp := dohWriter.GetResponse()
	if resp == nil {
		http.Error(w, "No DNS response", http.StatusInternalServerError)
		return
	}

	// Pack response
	respBytes, err := resp.Pack()
	if err != nil {
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", getTTL(resp)))
	w.Write(respBytes)
}

// dohResponseWriter implements dns.ResponseWriter for DoH
type dohResponseWriter struct {
	remoteAddr string
	response   *dns.Msg
}

func (w *dohResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}

func (w *dohResponseWriter) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", w.remoteAddr)
	if addr == nil {
		return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	}
	return addr
}

func (w *dohResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.response = msg
	return nil
}

func (w *dohResponseWriter) Write(b []byte) (int, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(b); err != nil {
		return 0, err
	}
	w.response = msg
	return len(b), nil
}

func (w *dohResponseWriter) Close() error {
	return nil
}

func (w *dohResponseWriter) TsigStatus() error {
	return nil
}

func (w *dohResponseWriter) TsigTimersOnly(bool) {}

func (w *dohResponseWriter) Hijack() {}

func (w *dohResponseWriter) GetResponse() *dns.Msg {
	return w.response
}

// getTTL gets the minimum TTL from DNS response for caching
func getTTL(msg *dns.Msg) int {
	minTTL := 3600 // Default 1 hour

	for _, rr := range msg.Answer {
		if ttl := int(rr.Header().Ttl); ttl < minTTL {
			minTTL = ttl
		}
	}

	for _, rr := range msg.Ns {
		if ttl := int(rr.Header().Ttl); ttl < minTTL {
			minTTL = ttl
		}
	}

	for _, rr := range msg.Extra {
		if ttl := int(rr.Header().Ttl); ttl < minTTL {
			minTTL = ttl
		}
	}

	if minTTL < 0 {
		return 0
	}
	return minTTL
}

// Web Server methods

func (m *Manager) startWebLocked() error {
	if m.webMux == nil {
		return fmt.Errorf("web mux not set")
	}

	addr := fmt.Sprintf("%s:%d", m.config.Web.Address, m.config.Web.Port)

	// Create a handler that includes DoH if enabled and not standalone
	var handler http.Handler = m.webMux
	if m.config.DoH.Enabled && !m.config.DoH.Standalone && m.dnsHandler != nil {
		// Wrap the web mux to handle DoH requests
		path := m.config.DoH.Path
		if path == "" {
			path = "/dns-query"
		}
		handler = m.createCombinedHandler(m.webMux, path)
		log.Printf("DoH enabled on Web server at path %s", path)
	}

	m.webServer = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// Use TLS if enabled
	if m.config.Web.TLS {
		if m.tlsProvider == nil {
			return fmt.Errorf("TLS provider not set")
		}
		tlsConfig, err := m.tlsProvider.GetTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to get TLS config: %v", err)
		}
		if tlsConfig == nil {
			return fmt.Errorf("TLS configuration not available")
		}
		m.webServer.TLSConfig = tlsConfig

		go func() {
			log.Printf("Starting Web server (HTTPS) on %s", addr)
			if err := m.webServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Printf("Web server error: %v", err)
			}
		}()
	} else {
		go func() {
			log.Printf("Starting Web server (HTTP) on %s", addr)
			if err := m.webServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("Web server error: %v", err)
			}
		}()
	}

	return nil
}

// createCombinedHandler creates a handler that routes DoH requests to the DNS handler
// and everything else to the web mux
func (m *Manager) createCombinedHandler(webMux *http.ServeMux, dohPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == dohPath {
			m.handleDoH(w, r)
			return
		}
		webMux.ServeHTTP(w, r)
	})
}

func (m *Manager) stopWebLocked() {
	if m.webServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.webServer.Shutdown(ctx)
		m.webServer = nil
	}
}
