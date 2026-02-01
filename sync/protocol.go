package sync

import (
	"encoding/json"
	"time"
)

// Message types for the sync protocol
const (
	MsgHello           = "hello"
	MsgHelloAck        = "hello_ack"
	MsgSyncRequest     = "sync_request"
	MsgSyncResponse    = "sync_response"
	MsgChange          = "change"
	MsgChangeAck       = "change_ack"
	MsgSnapshotRequest = "snapshot_req"
	MsgSnapshotBegin   = "snapshot_begin"
	MsgSnapshotData    = "snapshot_data"
	MsgSnapshotEnd     = "snapshot_end"
	MsgPing            = "ping"
	MsgPong            = "pong"
	MsgError           = "error"
)

// Message is the wrapper for all sync protocol messages
type Message struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// HelloPayload is sent during initial handshake
type HelloPayload struct {
	// Server's unique identifier
	ServerID string `json:"server_id"`

	// Human-readable server name
	ServerName string `json:"server_name"`

	// Current HLC of this server
	CurrentHLC HybridLogicalClock `json:"current_hlc"`

	// Whether this is a new server requesting full sync
	IsNew bool `json:"is_new"`

	// Protocol version for compatibility
	ProtocolVersion int `json:"protocol_version"`

	// Authentication token (HMAC of shared secret + timestamp)
	AuthToken string `json:"auth_token"`

	// Timestamp used for auth token
	AuthTimestamp int64 `json:"auth_timestamp"`
}

// HelloAckPayload is the response to a Hello message
type HelloAckPayload struct {
	// Server's unique identifier
	ServerID string `json:"server_id"`

	// Human-readable server name
	ServerName string `json:"server_name"`

	// Current HLC of this server
	CurrentHLC HybridLogicalClock `json:"current_hlc"`

	// Whether the hello was accepted
	Accepted bool `json:"accepted"`

	// Rejection reason if not accepted
	RejectReason string `json:"reject_reason,omitempty"`

	// Whether full snapshot will be sent (for new servers)
	WillSnapshot bool `json:"will_snapshot"`
}

// SyncRequestPayload requests changes since a given HLC
type SyncRequestPayload struct {
	// Request changes after this HLC for the specified server
	// Map of server_id -> last known HLC from that server
	LastKnownHLC map[string]HybridLogicalClock `json:"last_known_hlc"`

	// Maximum number of entries to return
	Limit int `json:"limit,omitempty"`
}

// SyncResponsePayload contains a batch of changes
type SyncResponsePayload struct {
	// The changes
	Entries []OpLogEntry `json:"entries"`

	// Whether there are more entries available
	HasMore bool `json:"has_more"`

	// Current HLC of the sending server
	CurrentHLC HybridLogicalClock `json:"current_hlc"`
}

// ChangePayload contains a single change for real-time sync
type ChangePayload struct {
	// The change
	Entry OpLogEntry `json:"entry"`
}

// ChangeAckPayload acknowledges receipt of a change
type ChangeAckPayload struct {
	// The operation ID being acknowledged
	OpID string `json:"op_id"`

	// Whether the change was applied successfully
	Applied bool `json:"applied"`

	// Error message if not applied
	Error string `json:"error,omitempty"`
}

// SnapshotBeginPayload signals the start of a full snapshot
type SnapshotBeginPayload struct {
	// Estimated total number of entries
	EstimatedEntries int64 `json:"estimated_entries"`

	// HLC at the start of snapshot
	SnapshotHLC HybridLogicalClock `json:"snapshot_hlc"`
}

// SnapshotDataPayload contains a chunk of snapshot data
type SnapshotDataPayload struct {
	// Entity type for this chunk
	EntityType string `json:"entity_type"`

	// The entities (JSON array)
	Entities json.RawMessage `json:"entities"`

	// Sequence number for ordering
	Sequence int `json:"sequence"`
}

// SnapshotEndPayload signals the end of a full snapshot
type SnapshotEndPayload struct {
	// Total entities sent
	TotalEntries int64 `json:"total_entries"`

	// HLC to use as starting point for real-time sync
	FinalHLC HybridLogicalClock `json:"final_hlc"`

	// Checksum of all snapshot data
	Checksum string `json:"checksum"`
}

// ErrorPayload contains an error message
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// PeerState tracks the sync state with a peer
type PeerState struct {
	// Peer's server ID
	ServerID string `json:"server_id"`

	// Peer's server name
	ServerName string `json:"server_name"`

	// Peer's URL
	URL string `json:"url"`

	// Connection status
	Connected bool `json:"connected"`

	// Last HLC received from this peer
	LastHLC HybridLogicalClock `json:"last_hlc"`

	// Last successful sync time
	LastSyncTime time.Time `json:"last_sync_time"`

	// Number of pending operations to send
	PendingOps int64 `json:"pending_ops"`

	// Last error if any
	LastError string `json:"last_error,omitempty"`

	// When the last error occurred
	LastErrorTime time.Time `json:"last_error_time,omitempty"`
}

// ClusterStatus represents the overall cluster sync status
type ClusterStatus struct {
	// This server's ID
	ServerID string `json:"server_id"`

	// This server's name
	ServerName string `json:"server_name"`

	// Whether sync is enabled
	Enabled bool `json:"enabled"`

	// Current HLC
	CurrentHLC HybridLogicalClock `json:"current_hlc"`

	// Total entries in OpLog
	OpLogEntries int64 `json:"oplog_entries"`

	// Connected peers
	Peers []PeerState `json:"peers"`
}

// NewMessage creates a new message with the given type and payload
func NewMessage(msgType string, payload interface{}) (*Message, error) {
	var payloadBytes json.RawMessage
	if payload != nil {
		var err error
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	return &Message{
		Type:    msgType,
		Payload: payloadBytes,
	}, nil
}

// ParsePayload parses the message payload into the given type
func (m *Message) ParsePayload(v interface{}) error {
	return json.Unmarshal(m.Payload, v)
}
