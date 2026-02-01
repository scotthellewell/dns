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

	// Update config
	m.config = newConfig

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
	m.peersMu.RLock()
	defer m.peersMu.RUnlock()

	status := &ClusterStatus{
		ServerID:   m.serverID,
		ServerName: m.serverName,
		Enabled:    m.config.Enabled,
		CurrentHLC: m.oplog.CurrentHLC(),
		Peers:      make([]PeerState, 0, len(m.peers)),
	}

	count, _ := m.oplog.Count()
	status.OpLogEntries = count

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

	for _, peer := range m.peers {
		if peer.state != nil && peer.state.Connected {
			select {
			case peer.sendChan <- msg:
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
	// Parse URL
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}

	// Create dialer with TLS config
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	log.Printf("[sync] Connecting to peer %s", cfg.URL)

	conn, _, err := dialer.DialContext(m.ctx, u.String(), nil)
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

// peerConn methods

func (p *peerConn) readLoop() {
	defer p.cancel()

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		msg, err := p.readMessage()
		if err != nil {
			log.Printf("[sync] Read error from %s: %v", p.serverID, err)
			return
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

	if applied && p.manager.applyCallback != nil {
		if err := p.manager.applyCallback(entry); err != nil {
			log.Printf("[sync] Apply callback failed for %s: %v", entry.ID, err)
		}
	}

	// Update peer state
	p.state.LastHLC = entry.HLC
	p.state.LastSyncTime = time.Now()
	p.manager.oplog.SavePeerState(p.state)

	// Send ack
	ack, _ := NewMessage(MsgChangeAck, &ChangeAckPayload{
		OpID:    entry.ID,
		Applied: true,
	})
	p.sendChan <- ack
}

func (p *peerConn) handleSyncRequest(payload *SyncRequestPayload) {
	// Get entries since the last known HLC
	var since HybridLogicalClock
	if hlc, ok := payload.LastKnownHLC[p.manager.serverID]; ok {
		since = hlc
	}

	entries, err := p.manager.oplog.GetEntriesSince(since, payload.Limit)
	if err != nil {
		log.Printf("[sync] Failed to get entries: %v", err)
		return
	}

	hasMore := len(entries) == payload.Limit

	resp, _ := NewMessage(MsgSyncResponse, &SyncResponsePayload{
		Entries:    entries,
		HasMore:    hasMore,
		CurrentHLC: p.manager.oplog.CurrentHLC(),
	})
	p.sendChan <- resp
}

func (p *peerConn) handleSyncResponse(payload *SyncResponsePayload) {
	log.Printf("[sync] Received %d entries from %s", len(payload.Entries), p.serverID)

	for _, entry := range payload.Entries {
		entryCopy := entry // avoid loop variable capture
		applied, err := p.manager.oplog.ApplyRemote(&entryCopy)
		if err != nil {
			log.Printf("[sync] Failed to apply synced entry %s: %v", entry.ID, err)
			continue
		}

		if applied && p.manager.applyCallback != nil {
			if err := p.manager.applyCallback(&entryCopy); err != nil {
				log.Printf("[sync] Apply callback failed for %s: %v", entry.ID, err)
			}
		}

		// Update last HLC
		p.state.LastHLC = entry.HLC
	}

	p.state.LastSyncTime = time.Now()
	p.manager.oplog.SavePeerState(p.state)

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
	p.connMu.Lock()
	defer p.connMu.Unlock()

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

	return p.conn.WriteMessage(websocket.TextMessage, data)
}

func (p *peerConn) close() {
	p.cancel()
	p.connMu.Lock()
	if p.conn != nil {
		p.conn.Close()
	}
	p.connMu.Unlock()
}
