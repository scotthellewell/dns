# DNS Server Cluster Synchronization Design

## Overview

This document describes the design for multi-master synchronization between DNS server instances, allowing any server to accept writes and propagate changes to all peers in real-time.

## Goals

1. **Multi-master writes**: Any server can accept changes (no single primary)
2. **Real-time sync**: Changes propagate immediately via persistent connections
3. **Offline resilience**: Servers catch up when they reconnect
4. **New server bootstrap**: Push full data to new servers joining the cluster
5. **All data types**: Sync zones, records, users, tenants, DNSSEC keys, settings, etc.
6. **Conflict resolution**: Handle concurrent edits gracefully

## Architecture

### High-Level Design

```
┌─────────────────┐     Persistent      ┌─────────────────┐
│   DNS Server A  │◄──── WebSocket ────►│   DNS Server B  │
│                 │      Connections    │                 │
│  ┌───────────┐  │                     │  ┌───────────┐  │
│  │  Storage  │  │                     │  │  Storage  │  │
│  │ (bbolt)   │  │                     │  │ (bbolt)   │  │
│  └───────────┘  │                     │  └───────────┘  │
│  ┌───────────┐  │                     │  ┌───────────┐  │
│  │  OpLog    │  │                     │  │  OpLog    │  │
│  └───────────┘  │                     │  └───────────┘  │
└─────────────────┘                     └─────────────────┘
        ▲                                       ▲
        │         Persistent WebSocket          │
        └──────────────────┬────────────────────┘
                           │
                           ▼
                 ┌─────────────────┐
                 │   DNS Server C  │
                 │                 │
                 │  ┌───────────┐  │
                 │  │  Storage  │  │
                 │  └───────────┘  │
                 │  ┌───────────┐  │
                 │  │  OpLog    │  │
                 │  └───────────┘  │
                 └─────────────────┘
```

### Components

```
sync/
├── manager.go        # Main sync manager, coordinates all sync operations
├── oplog.go          # Operation log storage and retrieval
├── peer.go           # Peer connection management
├── transport.go      # WebSocket transport layer
├── protocol.go       # Sync protocol message types
├── conflict.go       # Conflict resolution strategies
├── snapshot.go       # Full database snapshots for new peers
└── clock.go          # Hybrid logical clock for ordering
```

## Data Model

### Operation Log Entry

Each change to the database is recorded in an operation log:

```go
type OpLogEntry struct {
    // Unique identifier for this operation
    ID string `json:"id"`
    
    // Server that originated this change
    ServerID string `json:"server_id"`
    
    // Hybrid logical clock timestamp for ordering
    HLC HybridLogicalClock `json:"hlc"`
    
    // Wall clock time (for conflict resolution tiebreaker)
    Timestamp time.Time `json:"timestamp"`
    
    // Type of entity: zone, record, user, tenant, dnssec_keys, settings, etc.
    EntityType string `json:"entity_type"`
    
    // Unique identifier for the entity (zone name, record ID, user ID, etc.)
    EntityID string `json:"entity_id"`
    
    // Tenant ID (empty for main tenant)
    TenantID string `json:"tenant_id,omitempty"`
    
    // Operation type: create, update, delete
    Operation string `json:"operation"`
    
    // The actual data (JSON encoded)
    Data json.RawMessage `json:"data"`
    
    // Checksum of data for integrity verification
    Checksum string `json:"checksum"`
}
```

### Hybrid Logical Clock

For ordering events across servers, we use a Hybrid Logical Clock (HLC) that combines physical time with logical counters:

```go
type HybridLogicalClock struct {
    // Physical timestamp (milliseconds since epoch)
    Physical int64 `json:"pt"`
    
    // Logical counter for events at same physical time
    Logical uint32 `json:"lc"`
    
    // Server ID that last updated this clock
    ServerID string `json:"sid"`
}
```

### Peer State

Track sync state with each peer:

```go
type PeerState struct {
    // Peer's server ID
    ServerID string `json:"server_id"`
    
    // Last HLC received from this peer
    LastHLC HybridLogicalClock `json:"last_hlc"`
    
    // Connection status
    Connected bool `json:"connected"`
    
    // Last successful sync time
    LastSyncTime time.Time `json:"last_sync_time"`
    
    // Number of pending operations to send
    PendingOps int64 `json:"pending_ops"`
}
```

## Sync Protocol

### Message Types

```go
// Protocol message wrapper
type SyncMessage struct {
    Type    string          `json:"type"`
    Payload json.RawMessage `json:"payload"`
}

// Message types
const (
    MsgHello           = "hello"           // Initial handshake
    MsgHelloAck        = "hello_ack"       // Handshake response
    MsgSyncRequest     = "sync_request"    // Request changes since HLC
    MsgSyncResponse    = "sync_response"   // Batch of changes
    MsgChange          = "change"          // Real-time change notification
    MsgChangeAck       = "change_ack"      // Acknowledge receipt
    MsgSnapshotRequest = "snapshot_req"    // Request full snapshot
    MsgSnapshotBegin   = "snapshot_begin"  // Start of snapshot stream
    MsgSnapshotData    = "snapshot_data"   // Snapshot data chunk
    MsgSnapshotEnd     = "snapshot_end"    // End of snapshot stream
    MsgPing            = "ping"            // Keepalive
    MsgPong            = "pong"            // Keepalive response
)
```

### Handshake Flow

```
Server A                                Server B
    |                                       |
    |──── Hello(server_id, hlc) ───────────►|
    |                                       |
    |◄─── HelloAck(server_id, hlc) ─────────|
    |                                       |
    |──── SyncRequest(last_hlc_from_B) ────►|
    |                                       |
    |◄─── SyncResponse(changes[]) ──────────|
    |                                       |
    |◄─── SyncRequest(last_hlc_from_A) ─────|
    |                                       |
    |──── SyncResponse(changes[]) ─────────►|
    |                                       |
    |         [Real-time sync mode]         |
    |                                       |
    |──── Change(oplog_entry) ─────────────►|
    |                                       |
    |◄─── ChangeAck(op_id) ─────────────────|
    |                                       |
```

### New Server Bootstrap

```
New Server                           Existing Peer
    |                                       |
    |──── Hello(server_id, is_new=true) ───►|
    |                                       |
    |◄─── HelloAck + SnapshotBegin ─────────|
    |                                       |
    |◄─── SnapshotData(chunk 1) ────────────|
    |◄─── SnapshotData(chunk 2) ────────────|
    |◄─── ... ──────────────────────────────|
    |◄─── SnapshotData(chunk N) ────────────|
    |                                       |
    |◄─── SnapshotEnd(hlc_at_snapshot) ─────|
    |                                       |
    |         [Switch to real-time]         |
    |                                       |
```

## Conflict Resolution

### Strategy: Last-Writer-Wins with HLC

Since we're using Hybrid Logical Clocks, conflicts are resolved by:

1. Compare HLC timestamps - higher HLC wins
2. If HLC physical times are equal, higher logical counter wins
3. If logical counters are equal, use server ID as tiebreaker (deterministic)

### Special Cases

#### Concurrent Creates
- If two servers create the same entity simultaneously, keep the one with higher HLC
- The "loser" is logged for potential manual review

#### Delete vs Update
- Delete operations are "tombstoned" rather than immediately removed
- Tombstones are kept for a configurable retention period (default: 7 days)
- If an update arrives for a tombstoned entity, the tombstone wins if its HLC is higher

#### DNSSEC Keys
- DNSSEC keys require special handling - we don't want key conflicts
- Keys are immutable once created; only the enabled/disabled state can change
- If same zone gets DNSSEC enabled on two servers simultaneously, keep higher HLC

## Configuration

### Sync Configuration

```go
type SyncConfig struct {
    // Enable cluster synchronization
    Enabled bool `json:"enabled"`
    
    // Unique identifier for this server (auto-generated if empty)
    ServerID string `json:"server_id"`
    
    // Display name for this server
    ServerName string `json:"server_name"`
    
    // Address to listen for peer connections (e.g., ":9443")
    ListenAddr string `json:"listen_addr"`
    
    // TLS certificate and key for peer connections
    TLSCert string `json:"tls_cert"`
    TLSKey  string `json:"tls_key"`
    
    // Peers to connect to
    Peers []SyncPeer `json:"peers"`
    
    // Shared secret for peer authentication (will be hashed)
    SharedSecret string `json:"shared_secret"`
    
    // OpLog retention period for tombstones
    TombstoneRetention time.Duration `json:"tombstone_retention"`
    
    // Maximum batch size for sync operations
    BatchSize int `json:"batch_size"`
    
    // Reconnect interval when peer is unavailable
    ReconnectInterval time.Duration `json:"reconnect_interval"`
}

type SyncPeer struct {
    // URL of the peer (e.g., "wss://dns2.example.com:9443/sync")
    URL string `json:"url"`
    
    // Optional: Override TLS verification (for self-signed certs)
    InsecureSkipVerify bool `json:"insecure_skip_verify"`
}
```

### Example Configuration

```json
{
  "sync": {
    "enabled": true,
    "server_name": "dns-primary",
    "listen_addr": ":9443",
    "tls_cert": "/app/certs/sync.crt",
    "tls_key": "/app/certs/sync.key",
    "peers": [
      {"url": "wss://dns-secondary.example.com:9443/sync"},
      {"url": "wss://dns-tertiary.example.com:9443/sync"}
    ],
    "shared_secret": "your-secure-shared-secret"
  }
}
```

## Implementation Phases

### Phase 1: Foundation
- [ ] Implement Hybrid Logical Clock
- [ ] Create OpLog storage in bbolt
- [ ] Hook storage operations to write OpLog entries
- [ ] Basic sync manager structure

### Phase 2: Transport
- [ ] WebSocket server for incoming peer connections
- [ ] WebSocket client for outgoing peer connections
- [ ] TLS configuration
- [ ] Authentication via shared secret

### Phase 3: Protocol
- [ ] Implement all message types
- [ ] Handshake flow
- [ ] Sync request/response
- [ ] Real-time change propagation

### Phase 4: Conflict Resolution
- [ ] HLC-based conflict resolution
- [ ] Tombstone handling
- [ ] Special case handlers (DNSSEC, etc.)

### Phase 5: Bootstrap
- [ ] Full snapshot generation
- [ ] Snapshot streaming
- [ ] New server initialization

### Phase 6: Resilience
- [ ] Automatic reconnection
- [ ] Catch-up sync after reconnect
- [ ] Health monitoring

### Phase 7: UI & Management
- [ ] Cluster status in dashboard
- [ ] Peer connection status
- [ ] Sync lag monitoring
- [ ] Manual sync trigger

## API Endpoints

### Cluster Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/sync/status` | GET | Get sync status and peer states |
| `/api/sync/peers` | GET | List configured peers |
| `/api/sync/peers` | POST | Add a new peer |
| `/api/sync/peers/{id}` | DELETE | Remove a peer |
| `/api/sync/force` | POST | Force full resync with a peer |

### WebSocket Endpoint

| Endpoint | Description |
|----------|-------------|
| `/sync` | WebSocket endpoint for peer-to-peer sync |

## Security Considerations

1. **Authentication**: Peers authenticate using a shared secret (HMAC of handshake)
2. **Transport Security**: All peer connections use TLS
3. **Data Integrity**: Each OpLog entry includes a checksum
4. **Tenant Isolation**: Sync respects tenant boundaries
5. **Audit Trail**: All sync operations are logged

## Monitoring & Observability

### Metrics

- `sync_peers_connected` - Number of connected peers
- `sync_oplog_entries` - Total OpLog entries
- `sync_pending_changes` - Changes waiting to be sent
- `sync_received_changes` - Changes received from peers
- `sync_conflicts_resolved` - Number of conflicts resolved
- `sync_last_sync_timestamp` - Last successful sync per peer

### Health Checks

- Peer connection status
- Sync lag (time since last change received)
- OpLog growth rate

## Future Enhancements

1. **Selective Sync**: Sync only specific tenants or zones
2. **Read Replicas**: Servers that only receive, never originate changes
3. **Geo-Aware Sync**: Prioritize sync to geographically closer peers
4. **Compression**: Compress large payloads
5. **Conflict Dashboard**: UI for reviewing and resolving conflicts manually
