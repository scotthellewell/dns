package sync

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	bolt "go.etcd.io/bbolt"
)

// ProtocolVersion is the current sync protocol version
const ProtocolVersion = 1

// Manager coordinates sync operations with peers
type Manager struct {
	config     *Config
	oplog      *OpLog
	db         *bolt.DB
	serverID   string
	serverName string

	// Connected peers
	peers   map[string]*peerConn
	peersMu sync.RWMutex

	// Channel for broadcasting local changes
	changeChan chan *OpLogEntry

	// Callbacks for applying changes
	applyCallback ApplyCallback

	// Full sync data provider
	fullSyncProvider FullSyncProvider

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc

	// WaitGroup for goroutines
	wg sync.WaitGroup

	// WebSocket upgrader for incoming connections
	upgrader websocket.Upgrader
}

// ApplyCallback is called when a remote change needs to be applied locally
type ApplyCallback func(entry *OpLogEntry) error

// FullSyncDataItem represents a single item to be synced during full sync
type FullSyncDataItem struct {
	EntityType string
	EntityID   string
	TenantID   string
	Data       interface{}
}

// FullSyncProvider provides all data for a full sync operation
type FullSyncProvider func() ([]FullSyncDataItem, error)

// peerConn represents a connection to a peer
type peerConn struct {
	serverID   string
	serverName string
	url        string
	conn       *websocket.Conn
	connMu     sync.Mutex
	state      *PeerState
	manager    *Manager

	// Outgoing message queue
	sendChan chan *Message

	// Context for this connection
	ctx    context.Context
	cancel context.CancelFunc
}

// NewManager creates a new sync manager
func NewManager(db *bolt.DB, config *Config) (*Manager, error) {
	if config.ServerID == "" {
		config.ServerID = GenerateServerID()
	}

	oplog, err := NewOpLog(db, config.ServerID)
	if err != nil {
		return nil, fmt.Errorf("create oplog: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:     config,
		oplog:      oplog,
		db:         db,
		serverID:   config.ServerID,
		serverName: config.ServerName,
		peers:      make(map[string]*peerConn),
		changeChan: make(chan *OpLogEntry, 1000),
		ctx:        ctx,
		cancel:     cancel,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // We authenticate via shared secret
			},
		},
	}

	return m, nil
}

// SetApplyCallback sets the callback for applying remote changes
func (m *Manager) SetApplyCallback(cb ApplyCallback) {
	m.applyCallback = cb
}

// SetFullSyncProvider sets the callback for providing full sync data
func (m *Manager) SetFullSyncProvider(provider FullSyncProvider) {
	m.fullSyncProvider = provider
}

// ServerID returns this server's unique ID
func (m *Manager) ServerID() string {
	return m.serverID
}

// ReplayAllEntries replays all entries in the oplog through a callback
// This is useful for repairing entries that weren't properly applied
func (m *Manager) ReplayAllEntries(callback func(entry *OpLogEntry) error) error {
	return m.oplog.ReplayAllEntries(callback)
}

// FullSync broadcasts all local data to connected peers
// This is used for initial sync when a new peer joins the cluster
func (m *Manager) FullSync() (int, error) {
	if !m.config.Enabled {
		return 0, fmt.Errorf("sync is not enabled")
	}

	if m.fullSyncProvider == nil {
		return 0, fmt.Errorf("full sync provider not configured")
	}

	// Get all data from the provider
	items, err := m.fullSyncProvider()
	if err != nil {
		return 0, fmt.Errorf("failed to get full sync data: %w", err)
	}

	log.Printf("[sync] Starting full sync with %d items", len(items))

	// Record each item as a change (OpUpdate so it won't fail if already exists on peer)
	synced := 0
	for _, item := range items {
		entry, err := m.oplog.Append(item.EntityType, item.EntityID, item.TenantID, OpUpdate, item.Data)
		if err != nil {
			log.Printf("[sync] Failed to append item %s/%s: %v", item.EntityType, item.EntityID, err)
			continue
		}

		// Broadcast to connected peers
		select {
		case m.changeChan <- entry:
			synced++
		default:
			log.Printf("[sync] Warning: change channel full, dropping broadcast for %s/%s", item.EntityType, item.EntityID)
		}
	}

	log.Printf("[sync] Full sync complete: %d/%d items broadcast", synced, len(items))
	return synced, nil
}

// Start begins sync operations
func (m *Manager) Start() error {
	if !m.config.Enabled {
		log.Println("[sync] Sync is disabled")
		return nil
	}

	log.Printf("[sync] Starting sync manager (server_id=%s, name=%s)", m.serverID, m.serverName)

	// Start the change broadcaster
	m.wg.Add(1)
	go m.runBroadcaster()

	// Connect to configured peers
	for _, peerCfg := range m.config.Peers {
		m.wg.Add(1)
		go m.connectToPeer(peerCfg)
	}

	// Start tombstone pruner
	m.wg.Add(1)
	go m.runPruner()

	// Start periodic peer state saver (every 30 seconds)
	m.wg.Add(1)
	go m.runPeerStateSaver()

	return nil
}

// Stop shuts down the sync manager
func (m *Manager) Stop() {
	log.Println("[sync] Stopping sync manager")
	m.cancel()

	// Close all peer connections
	m.peersMu.Lock()
	for _, peer := range m.peers {
		peer.close()
	}
	m.peersMu.Unlock()

	close(m.changeChan)
	m.wg.Wait()
}

// UpdateConfig updates the sync configuration at runtime
// Note: Some changes (like listen_addr) may require a restart to take effect
func (m *Manager) UpdateConfig(newConfig *Config) {
	oldEnabled := m.config.Enabled
	oldPeers := make(map[string]bool)
	for _, p := range m.config.Peers {
		oldPeers[p.URL] = true
	}

	// Preserve internal config values that aren't set via API
	if newConfig.PingInterval == 0 {
		newConfig.PingInterval = m.config.PingInterval
	}
	if newConfig.ReconnectInterval == 0 {
		newConfig.ReconnectInterval = m.config.ReconnectInterval
	}
	// Set defaults if still zero (e.g., initial config)
	if newConfig.PingInterval == 0 {
		newConfig.PingInterval = 30 * time.Second
	}
	if newConfig.ReconnectInterval == 0 {
		newConfig.ReconnectInterval = 5 * time.Second
	}

	// Update config
	m.config = newConfig

	// Update server identity if changed
	if newConfig.ServerName != "" {
		m.serverName = newConfig.ServerName
	}
	if newConfig.ServerID != "" && newConfig.ServerID != m.serverID {
		m.serverID = newConfig.ServerID
	}

	// If we're going from disabled to enabled, start the manager
	if !oldEnabled && newConfig.Enabled {
		log.Println("[sync] Sync enabled via config update, starting...")
		m.ctx, m.cancel = context.WithCancel(context.Background())
		m.changeChan = make(chan *OpLogEntry, 1000)
		go m.Start()
		return
	}

	// If going from enabled to disabled, stop connections
	if oldEnabled && !newConfig.Enabled {
		log.Println("[sync] Sync disabled via config update, stopping peer connections...")
		m.peersMu.Lock()
		for _, peer := range m.peers {
			peer.close()
		}
		m.peers = make(map[string]*peerConn)
		m.peersMu.Unlock()
		return
	}

	// If still enabled, check for new peers
	if newConfig.Enabled {
		for _, peerCfg := range newConfig.Peers {
			if !oldPeers[peerCfg.URL] {
				log.Printf("[sync] New peer added: %s", peerCfg.URL)
				m.wg.Add(1)
				go m.connectToPeer(peerCfg)
			}
		}
	}
}

// RecordChange records a local change and broadcasts it to peers
func (m *Manager) RecordChange(entityType, entityID, tenantID, operation string, data interface{}) error {
	if !m.config.Enabled {
		return nil
	}

	entry, err := m.oplog.Append(entityType, entityID, tenantID, operation, data)
	if err != nil {
		return err
	}

	// Broadcast to connected peers
	select {
	case m.changeChan <- entry:
	default:
		log.Println("[sync] Warning: change channel full, dropping broadcast")
	}

	return nil
}

// HandleWebSocket handles incoming peer connections
func (m *Manager) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !m.config.Enabled {
		http.Error(w, "Sync not enabled", http.StatusServiceUnavailable)
		return
	}

	conn, err := m.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[sync] WebSocket upgrade failed: %v", err)
		return
	}

	log.Printf("[sync] Incoming peer connection from %s", r.RemoteAddr)

	// Handle the peer connection
	go m.handleIncomingPeer(conn)
}

// Status returns the current cluster status
func (m *Manager) Status() *ClusterStatus {
	// Get oplog info first, outside the peersMu lock to avoid potential deadlocks
	currentHLC := m.oplog.CurrentHLC()
	// Skip Count() as it can be slow with large oplogs - it's not critical info
	// count, _ := m.oplog.Count()

	m.peersMu.RLock()
	defer m.peersMu.RUnlock()

	status := &ClusterStatus{
		ServerID:     m.serverID,
		ServerName:   m.serverName,
		Enabled:      m.config.Enabled,
		CurrentHLC:   currentHLC,
		OpLogEntries: -1, // Indicate we're not counting
		Peers:        make([]PeerState, 0, len(m.peers)),
	}

	for _, peer := range m.peers {
		if peer.state != nil {
			status.Peers = append(status.Peers, *peer.state)
		}
	}

	return status
}

// runBroadcaster broadcasts local changes to all connected peers
func (m *Manager) runBroadcaster() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case entry, ok := <-m.changeChan:
			if !ok {
				return
			}
			m.broadcastChange(entry)
		}
	}
}

func (m *Manager) broadcastChange(entry *OpLogEntry) {
	msg, err := NewMessage(MsgChange, &ChangePayload{Entry: *entry})
	if err != nil {
		log.Printf("[sync] Failed to create change message: %v", err)
		return
	}

	m.peersMu.RLock()
	defer m.peersMu.RUnlock()

	log.Printf("[sync] Broadcasting change %s to %d peers", entry.ID, len(m.peers))

	for _, peer := range m.peers {
		log.Printf("[sync] Peer %s: state=%v connected=%v", peer.serverID, peer.state != nil, peer.state != nil && peer.state.Connected)
		if peer.state != nil && peer.state.Connected {
			select {
			case peer.sendChan <- msg:
				log.Printf("[sync] Sent change %s to peer %s", entry.ID, peer.serverID)
			default:
				log.Printf("[sync] Send channel full for peer %s", peer.serverID)
			}
		}
	}
}

// connectToPeer establishes a connection to a peer
func (m *Manager) connectToPeer(cfg PeerConfig) {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		err := m.dialPeer(cfg)
		if err != nil {
			log.Printf("[sync] Failed to connect to peer %s: %v", cfg.URL, err)
		}

		// Wait before reconnecting
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(m.config.ReconnectInterval):
		}
	}
}

func (m *Manager) dialPeer(cfg PeerConfig) error {
	// Parse URL and convert to WebSocket URL
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}

	// Convert http(s) to ws(s) scheme
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "wss", "ws":
		// Already a WebSocket URL
	default:
		return fmt.Errorf("unsupported URL scheme: %s", u.Scheme)
	}

	// Add the sync WebSocket path if not present
	if !strings.HasSuffix(u.Path, "/sync") {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/sync"
	}

	// Create dialer with TLS config
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	log.Printf("[sync] Connecting to peer %s", u.String())

	// Set up headers with API key for authentication
	headers := http.Header{}
	if cfg.APIKey != "" {
		headers.Set("X-API-Key", cfg.APIKey)
	}

	conn, _, err := dialer.DialContext(m.ctx, u.String(), headers)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	// Create peer connection
	peerCtx, peerCancel := context.WithCancel(m.ctx)
	peer := &peerConn{
		url:      cfg.URL,
		conn:     conn,
		manager:  m,
		sendChan: make(chan *Message, 100),
		ctx:      peerCtx,
		cancel:   peerCancel,
		state: &PeerState{
			URL:       cfg.URL,
			Connected: false,
		},
	}

	// Perform handshake
	if err := m.performHandshake(peer, true); err != nil {
		conn.Close()
		return fmt.Errorf("handshake: %w", err)
	}

	// Register peer
	m.peersMu.Lock()
	m.peers[peer.serverID] = peer
	m.peersMu.Unlock()

	// Start peer workers
	go peer.readLoop()
	go peer.writeLoop()
	go peer.pingLoop(m.config.PingInterval)

	// Perform initial sync
	go m.performSync(peer)

	// Wait for connection to close
	<-peer.ctx.Done()

	// Cleanup
	m.peersMu.Lock()
	delete(m.peers, peer.serverID)
	m.peersMu.Unlock()

	return nil
}

func (m *Manager) handleIncomingPeer(conn *websocket.Conn) {
	peerCtx, peerCancel := context.WithCancel(m.ctx)
	peer := &peerConn{
		conn:     conn,
		manager:  m,
		sendChan: make(chan *Message, 100),
		ctx:      peerCtx,
		cancel:   peerCancel,
		state: &PeerState{
			Connected: false,
		},
	}

	// Perform handshake
	if err := m.performHandshake(peer, false); err != nil {
		log.Printf("[sync] Incoming handshake failed: %v", err)
		conn.Close()
		return
	}

	// Register peer
	m.peersMu.Lock()
	m.peers[peer.serverID] = peer
	m.peersMu.Unlock()

	// Start peer workers
	go peer.readLoop()
	go peer.writeLoop()
	go peer.pingLoop(m.config.PingInterval)

	// Wait for connection to close
	<-peer.ctx.Done()

	// Cleanup
	m.peersMu.Lock()
	delete(m.peers, peer.serverID)
	m.peersMu.Unlock()
}

func (m *Manager) performHandshake(peer *peerConn, isInitiator bool) error {
	if isInitiator {
		// Send hello
		authTimestamp := time.Now().Unix()
		authToken := m.generateAuthToken(authTimestamp)

		hello := &HelloPayload{
			ServerID:        m.serverID,
			ServerName:      m.serverName,
			CurrentHLC:      m.oplog.CurrentHLC(),
			IsNew:           false, // TODO: detect if this is a new server
			ProtocolVersion: ProtocolVersion,
			AuthToken:       authToken,
			AuthTimestamp:   authTimestamp,
		}

		msg, _ := NewMessage(MsgHello, hello)
		if err := peer.sendMessage(msg); err != nil {
			return fmt.Errorf("send hello: %w", err)
		}

		// Wait for hello ack
		resp, err := peer.readMessage()
		if err != nil {
			return fmt.Errorf("read hello ack: %w", err)
		}

		if resp.Type != MsgHelloAck {
			return fmt.Errorf("expected hello_ack, got %s", resp.Type)
		}

		var ack HelloAckPayload
		if err := resp.ParsePayload(&ack); err != nil {
			return fmt.Errorf("parse hello ack: %w", err)
		}

		if !ack.Accepted {
			return fmt.Errorf("hello rejected: %s", ack.RejectReason)
		}

		peer.serverID = ack.ServerID
		peer.serverName = ack.ServerName
		peer.state.ServerID = ack.ServerID
		peer.state.ServerName = ack.ServerName
		peer.state.Connected = true
		peer.state.LastSyncTime = time.Now()

		// Reject self-connections (can happen with hairpin NAT)
		if peer.serverID == m.serverID {
			log.Printf("[sync] Rejecting self-connection to %s (server_id=%s)", peer.url, peer.serverID)
			return fmt.Errorf("self-connection detected")
		}

		log.Printf("[sync] Connected to peer %s (%s)", peer.serverName, peer.serverID)

	} else {
		// Wait for hello
		msg, err := peer.readMessage()
		if err != nil {
			return fmt.Errorf("read hello: %w", err)
		}

		if msg.Type != MsgHello {
			return fmt.Errorf("expected hello, got %s", msg.Type)
		}

		var hello HelloPayload
		if err := msg.ParsePayload(&hello); err != nil {
			return fmt.Errorf("parse hello: %w", err)
		}

		// Validate auth token
		if !m.validateAuthToken(hello.AuthToken, hello.AuthTimestamp) {
			ack := &HelloAckPayload{
				Accepted:     false,
				RejectReason: "authentication failed",
			}
			ackMsg, _ := NewMessage(MsgHelloAck, ack)
			peer.sendMessage(ackMsg)
			return fmt.Errorf("authentication failed")
		}

		// Check protocol version
		if hello.ProtocolVersion != ProtocolVersion {
			ack := &HelloAckPayload{
				Accepted:     false,
				RejectReason: fmt.Sprintf("protocol version mismatch: expected %d, got %d", ProtocolVersion, hello.ProtocolVersion),
			}
			ackMsg, _ := NewMessage(MsgHelloAck, ack)
			peer.sendMessage(ackMsg)
			return fmt.Errorf("protocol version mismatch")
		}

		// Send hello ack
		ack := &HelloAckPayload{
			ServerID:     m.serverID,
			ServerName:   m.serverName,
			CurrentHLC:   m.oplog.CurrentHLC(),
			Accepted:     true,
			WillSnapshot: hello.IsNew,
		}

		ackMsg, _ := NewMessage(MsgHelloAck, ack)
		if err := peer.sendMessage(ackMsg); err != nil {
			return fmt.Errorf("send hello ack: %w", err)
		}

		peer.serverID = hello.ServerID
		peer.serverName = hello.ServerName
		peer.state.ServerID = hello.ServerID
		peer.state.ServerName = hello.ServerName
		peer.state.Connected = true
		peer.state.LastSyncTime = time.Now()

		// Reject self-connections (can happen with hairpin NAT)
		if peer.serverID == m.serverID {
			log.Printf("[sync] Rejecting self-connection (server_id=%s)", peer.serverID)
			return fmt.Errorf("self-connection detected")
		}

		log.Printf("[sync] Accepted peer %s (%s)", peer.serverName, peer.serverID)
	}

	// Save peer state
	m.oplog.SavePeerState(peer.state)

	return nil
}

func (m *Manager) performSync(peer *peerConn) {
	// Get last known HLC for each server we know about
	lastKnown := make(map[string]HybridLogicalClock)

	// Get saved state for this peer
	savedState, _ := m.oplog.GetPeerState(peer.serverID)
	if savedState != nil {
		lastKnown[peer.serverID] = savedState.LastHLC
	}

	// Request changes
	syncReq := &SyncRequestPayload{
		LastKnownHLC: lastKnown,
		Limit:        m.config.BatchSize,
	}

	msg, _ := NewMessage(MsgSyncRequest, syncReq)
	peer.sendChan <- msg
}

func (m *Manager) generateAuthToken(timestamp int64) string {
	h := hmac.New(sha256.New, []byte(m.config.SharedSecret))
	h.Write([]byte(fmt.Sprintf("%d", timestamp)))
	return hex.EncodeToString(h.Sum(nil))
}

func (m *Manager) validateAuthToken(token string, timestamp int64) bool {
	// Check timestamp is within 5 minutes
	now := time.Now().Unix()
	if timestamp < now-300 || timestamp > now+300 {
		return false
	}

	expected := m.generateAuthToken(timestamp)
	return hmac.Equal([]byte(token), []byte(expected))
}

func (m *Manager) runPruner() {
	defer m.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			pruned, err := m.oplog.PruneTombstones(m.config.TombstoneRetention)
			if err != nil {
				log.Printf("[sync] Failed to prune tombstones: %v", err)
			} else if pruned > 0 {
				log.Printf("[sync] Pruned %d tombstones", pruned)
			}
		}
	}
}

// runPeerStateSaver periodically saves peer state to reduce write frequency
func (m *Manager) runPeerStateSaver() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			// Save final state on shutdown
			m.savePeerStates()
			return
		case <-ticker.C:
			m.savePeerStates()
		}
	}
}

// savePeerStates saves all connected peer states to disk
func (m *Manager) savePeerStates() {
	m.peersMu.RLock()
	defer m.peersMu.RUnlock()

	for _, peer := range m.peers {
		if peer.state != nil && peer.state.Connected {
			if err := m.oplog.SavePeerState(peer.state); err != nil {
				log.Printf("[sync] Failed to save peer state for %s: %v", peer.serverID, err)
			}
		}
	}
}

// peerConn methods

func (p *peerConn) readLoop() {
	defer p.cancel()

	log.Printf("[sync] readLoop started for peer %s (url=%s)", p.serverID, p.url)

	for {
		select {
		case <-p.ctx.Done():
			log.Printf("[sync] readLoop context done for peer %s", p.serverID)
			return
		default:
		}

		msg, err := p.readMessage()
		if err != nil {
			log.Printf("[sync] Read error from %s: %v", p.serverID, err)
			return
		}

		// Only log non-keepalive messages
		if msg.Type != MsgPing && msg.Type != MsgPong {
			log.Printf("[sync] readLoop received message type=%s from peer %s", msg.Type, p.serverID)
		}
		p.handleMessage(msg)
	}
}

func (p *peerConn) writeLoop() {
	defer p.cancel()

	for {
		select {
		case <-p.ctx.Done():
			return
		case msg, ok := <-p.sendChan:
			if !ok {
				return
			}
			// Only log non-keepalive messages
			if msg.Type != MsgPing && msg.Type != MsgPong {
				log.Printf("[sync] writeLoop sending %s to peer %s", msg.Type, p.serverID)
			}
			if err := p.sendMessage(msg); err != nil {
				log.Printf("[sync] Write error to %s: %v", p.serverID, err)
				return
			}
		}
	}
}

func (p *peerConn) pingLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			msg, _ := NewMessage(MsgPing, nil)
			select {
			case p.sendChan <- msg:
			default:
			}
		}
	}
}

func (p *peerConn) handleMessage(msg *Message) {
	switch msg.Type {
	case MsgChange:
		var payload ChangePayload
		if err := msg.ParsePayload(&payload); err != nil {
			log.Printf("[sync] Failed to parse change: %v", err)
			return
		}
		p.handleChange(&payload)

	case MsgChangeAck:
		// Change was acknowledged
		var payload ChangeAckPayload
		if err := msg.ParsePayload(&payload); err != nil {
			return
		}
		if !payload.Applied {
			log.Printf("[sync] Change %s rejected by peer: %s", payload.OpID, payload.Error)
		}

	case MsgSyncRequest:
		var payload SyncRequestPayload
		if err := msg.ParsePayload(&payload); err != nil {
			log.Printf("[sync] Failed to parse sync request: %v", err)
			return
		}
		p.handleSyncRequest(&payload)

	case MsgSyncResponse:
		var payload SyncResponsePayload
		if err := msg.ParsePayload(&payload); err != nil {
			log.Printf("[sync] Failed to parse sync response: %v", err)
			return
		}
		p.handleSyncResponse(&payload)

	case MsgPing:
		pong, _ := NewMessage(MsgPong, nil)
		select {
		case p.sendChan <- pong:
		default:
		}

	case MsgPong:
		// Keepalive acknowledged

	case MsgError:
		var payload ErrorPayload
		if err := msg.ParsePayload(&payload); err == nil {
			log.Printf("[sync] Error from peer %s: %s - %s", p.serverID, payload.Code, payload.Message)
		}
	}
}

func (p *peerConn) handleChange(payload *ChangePayload) {
	entry := &payload.Entry

	log.Printf("[sync] Received change from peer %s: type=%s entity=%s op=%s",
		p.serverID, entry.EntityType, entry.EntityID, entry.Operation)

	// Apply to local oplog
	applied, err := p.manager.oplog.ApplyRemote(entry)
	if err != nil {
		log.Printf("[sync] Failed to apply change %s: %v", entry.ID, err)
		ack, _ := NewMessage(MsgChangeAck, &ChangeAckPayload{
			OpID:    entry.ID,
			Applied: false,
			Error:   err.Error(),
		})
		p.sendChan <- ack
		return
	}

	log.Printf("[sync] Change %s applied=%v, calling callback", entry.ID, applied)

	if applied && p.manager.applyCallback != nil {
		if err := p.manager.applyCallback(entry); err != nil {
			log.Printf("[sync] Apply callback failed for %s: %v", entry.ID, err)
		}
	}

	// Update peer state (in memory only - save periodically, not on every change)
	if applied {
		p.state.LastHLC = entry.HLC
		p.state.LastSyncTime = time.Now()
	}

	// Send ack
	ack, _ := NewMessage(MsgChangeAck, &ChangeAckPayload{
		OpID:    entry.ID,
		Applied: applied,
	})
	p.sendChan <- ack
}

func (p *peerConn) handleSyncRequest(payload *SyncRequestPayload) {
	// Get entries since the last known HLC
	var since HybridLogicalClock
	if hlc, ok := payload.LastKnownHLC[p.manager.serverID]; ok {
		since = hlc
	}

	// Ensure limit is valid (default to 1000 if not set)
	limit := payload.Limit
	if limit <= 0 {
		limit = 1000
	}

	entries, err := p.manager.oplog.GetEntriesSince(since, limit)
	if err != nil {
		log.Printf("[sync] Failed to get entries: %v", err)
		return
	}

	// hasMore is true only if we returned a full batch AND limit was > 0
	hasMore := len(entries) > 0 && len(entries) == limit

	resp, _ := NewMessage(MsgSyncResponse, &SyncResponsePayload{
		Entries:    entries,
		HasMore:    hasMore,
		CurrentHLC: p.manager.oplog.CurrentHLC(),
	})
	p.sendChan <- resp
}

func (p *peerConn) handleSyncResponse(payload *SyncResponsePayload) {
	log.Printf("[sync] Received %d entries from %s", len(payload.Entries), p.serverID)

	appliedCount := 0
	for _, entry := range payload.Entries {
		entryCopy := entry // avoid loop variable capture
		applied, err := p.manager.oplog.ApplyRemote(&entryCopy)
		if err != nil {
			log.Printf("[sync] Failed to apply synced entry %s: %v", entry.ID, err)
			continue
		}

		if applied {
			appliedCount++
			if p.manager.applyCallback != nil {
				if err := p.manager.applyCallback(&entryCopy); err != nil {
					log.Printf("[sync] Apply callback failed for %s: %v", entry.ID, err)
				}
			}
			// Update last HLC only for actually applied entries
			p.state.LastHLC = entry.HLC
		}
	}

	if appliedCount > 0 {
		log.Printf("[sync] Applied %d new entries from %s", appliedCount, p.serverID)
	}

	p.state.LastSyncTime = time.Now()
	// Don't save peer state here - let the periodic saver handle it

	// Request more if available
	if payload.HasMore {
		syncReq := &SyncRequestPayload{
			LastKnownHLC: map[string]HybridLogicalClock{
				p.serverID: p.state.LastHLC,
			},
			Limit: p.manager.config.BatchSize,
		}
		msg, _ := NewMessage(MsgSyncRequest, syncReq)
		p.sendChan <- msg
	}
}

func (p *peerConn) readMessage() (*Message, error) {
	// Note: No mutex here - gorilla/websocket supports one concurrent reader
	// and one concurrent writer. The mutex is only needed for sendMessage
	// to protect against concurrent writes (though our design has one writeLoop).
	_, data, err := p.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal message: %w", err)
	}

	return &msg, nil
}

func (p *peerConn) sendMessage(msg *Message) error {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	err = p.conn.WriteMessage(websocket.TextMessage, data)
	if err != nil {
		log.Printf("[sync] WriteMessage failed for peer %s: %v", p.serverID, err)
	}
	return err
}

func (p *peerConn) close() {
	p.cancel()
	p.connMu.Lock()
	if p.conn != nil {
		p.conn.Close()
	}
	p.connMu.Unlock()
}
