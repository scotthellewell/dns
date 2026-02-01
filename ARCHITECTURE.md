# DNS Server Architecture & Roadmap

## Overview

A modern, multi-tenant authoritative DNS server with recursive resolution capabilities, built in Go with bbolt for persistent storage.

**Design Principles:**
- Single binary, zero-config startup
- Single database file for all data (easy backup)
- Multi-tenant with delegation support
- Low memory footprint (disk-based storage)
- Cross-platform (pure Go, no CGO)

---

## Data Directory

```
~/.dns-server/           # Default location
├── data.db              # bbolt database (all config + data)
└── (no other files)     # Everything in database

# Override with:
./dns-server -data /path/to/dir
```

---

## Database Schema

### Buckets

```
tenants           → {id} → Tenant
users             → {id} → User (includes WebAuthn credentials)
api_keys          → {id} → APIKey
sessions          → {token} → Session

zones             → {name} → Zone
records           → {zone}:{name}:{type} → []Record
dnssec_keys       → {zone} → DNSSECKeys
delegations       → {parent}:{child} → Delegation
secondary_zones   → {zone} → SecondaryZone

views             → {id} → View
blocklist         → {type}:{value} → BlockEntry

config:
  → server        → ServerConfig
  → recursion     → RecursionConfig
  → transfer      → TransferConfig
  → rate_limit    → RateLimitConfig
  → query_log     → QueryLogConfig
  → oidc          → OIDCConfig
  → webauthn      → WebAuthnConfig

certificates:
  → tls           → TLS cert + key
  → acme_config   → ACME configuration
  → acme_state    → ACME state
  → acme_account  → ACME account key

cache             → {key} → CacheEntry (with TTL cleanup)
audit             → {timestamp:id} → AuditEntry
query_log         → {timestamp:id} → QueryLogEntry
metrics           → {key} → Counter/Gauge values

indexes:
  → reverse_zones → {sortable_cidr} → zone_name
  → ptr_sources   → {source_record} → ptr_key
```

### Core Models

```go
type Tenant struct {
    ID          string
    Name        string
    Description string
    IsMain      bool      // Main tenant has super-admin privileges
    CreatedAt   time.Time
    CreatedBy   string
}

type Zone struct {
    Name          string    // "example.com" or "1.168.192.in-addr.arpa"
    TenantID      string
    Type          string    // "forward" or "reverse"
    Subnet        string    // CIDR for reverse zones
    Status        string    // "active", "inactive", "pending_delegation"
    StatusReason  string
    Serial        uint32    // Auto-incremented on changes
    TTL           uint32    // Default TTL
    NotifyTargets []string  // IPs to NOTIFY on change
    AllowTransfer []string  // IPs allowed to AXFR
    CreatedAt     time.Time
    UpdatedAt     time.Time
}

type Record struct {
    Zone         string
    Name         string    // Relative to zone, "@" for apex
    Type         string    // A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, SOA, etc.
    TTL          uint32
    ViewID       string    // Empty = all views
    Weight       int       // For load balancing (0 = no weighting)
    Enabled      bool      // Can disable without deleting
    
    // Auto-PTR management
    AutoPTR      bool      // Create PTR automatically (A/AAAA only)
    AutoManaged  bool      // This PTR was auto-created
    SourceRecord string    // "zone:name:type" that created this PTR
    
    // Type-specific fields stored as JSON
    Data         json.RawMessage
    
    CreatedAt    time.Time
    UpdatedAt    time.Time
}

type Delegation struct {
    ParentZone      string
    ChildZone       string
    Nameservers     []string
    Glue            map[string][]string
    GrantedToTenant string   // Tenant allowed to create child zone
    Active          bool
    CreatedAt       time.Time
    CreatedBy       string
}

type View struct {
    ID          string
    Name        string    // "internal", "external"
    TenantID    string
    MatchCIDRs  []string  // Client IPs that see this view
    Priority    int       // Higher wins on overlap
}
```

---

## PTR Record Lifecycle

| Event | Action |
|-------|--------|
| Create A/AAAA | If matching reverse zone exists & AutoPTR=true → create PTR |
| Update A/AAAA (IP change) | Delete old PTR, create new PTR |
| Delete A/AAAA | Delete corresponding PTR (by SourceRecord) |
| Create reverse zone | Scan all A/AAAA, create PTRs for IPs in range |
| Delete reverse zone | Delete all records in zone |
| Change reverse zone subnet | Recalculate PTRs |

PTRs are only auto-created within the same tenant (delegation grants access to other tenants).

---

## Zone Ownership Rules

1. Zone name must be unique (one owner)
2. For subzone `child.parent.com`:
   - If parent zone exists: requires delegation from parent
   - Creator must be parent tenant OR granted tenant
   - If parent zone doesn't exist: anyone can create
3. Delegation removal with dependent zone: blocked (must delete zone first or admin override to deactivate)

---

## Compact Reverse Zone Transfer (Proposed Extension)

Traditional AXFR for reverse zones transfers every PTR record individually, which is inefficient for large subnets.

**Proposed Format (AXFR Extension):**

```
; Standard AXFR with special TXT record indicating compact format
$ORIGIN 168.192.in-addr.arpa.
@           SOA  ns1.example.com. admin.example.com. (...)
@           NS   ns1.example.com.
@           TXT  "v=dnscompact1" "format=ptr-ranges"

; Compact PTR ranges - single record describes pattern
; Format: start-end:hostname-pattern
; Pattern: {ip} = full IP, {octet} = last octet, {hex} = hex of last octet
_compact    TXT  "1-50:host-{octet}.example.com."
_compact    TXT  "51-100:server-{octet}.internal.example.com."
_compact    TXT  "200:gateway.example.com."  ; Single IP

; Explicit PTR records override compact ranges
150         PTR  special-server.example.com.

; End of zone
@           SOA  ns1.example.com. admin.example.com. (...)
```

**Benefits:**
- 2 TXT records can describe 100 PTR records
- Explicit records override patterns
- Backward compatible (unknown servers just see TXT records)
- Reduces zone size by 95%+ for pattern-based reverse zones

**Implementation:**
- Server recognizes `v=dnscompact1` in AXFR response
- Expands patterns to in-memory PTR records
- On outbound AXFR: detects patterns, generates compact form

---

## Implementation Roadmap

### Phase 1: Storage Foundation
| Task | Status | Notes |
|------|--------|-------|
| Create `storage/` package | ✅ Complete | storage/storage.go |
| bbolt wrapper with auto-init | ✅ Complete | Open() with auto-create |
| Bucket creation and migrations | ✅ Complete | initBuckets() |
| Base models (Tenant, User, Zone, Record) | ✅ Complete | storage/models.go - 17+ models |
| Generic CRUD helpers | ✅ Complete | putJSON, getJSON, delete |

### Phase 2: Core DNS Data
| Task | Status | Notes |
|------|--------|-------|
| Zone CRUD | ✅ Complete | storage/zones.go |
| Record CRUD (all 17 types) | ✅ Complete | storage/records.go |
| PTR auto-sync on record changes | ✅ Complete | createPTRForRecord, syncPTRForRecord |
| PTR population on reverse zone create | ✅ Complete | populatePTRsForReverseZone() |
| Wildcard record support | ✅ Complete | GetWildcardRecords() |
| Zone serial auto-increment | ✅ Complete | Auto-increment on changes |
| Indexes for efficient lookups | ✅ Complete | IndexReverseZones, IndexPTRSources |
| Delegation CRUD | ✅ Complete | CreateDelegation, GetDelegation, etc. |

### Phase 3: Auth & Multi-tenancy
| Task | Status | Notes |
|------|--------|-------|
| Tenant CRUD | ✅ Complete | storage/tenants.go |
| User CRUD + password hashing | ✅ Complete | storage/users.go, bcrypt |
| Session management | ✅ Complete | storage/sessions.go |
| API Key management | ✅ Complete | storage/api_keys.go |
| WebAuthn credential storage | ✅ Complete | auth/webauthn.go |
| OIDC config storage | ✅ Complete | auth/oidc.go |
| Authorization middleware | ✅ Complete | Middleware(), RequireRole() |
| First-run setup flow | ✅ Complete | NeedsSetup(), Setup() |

### Phase 4: Server Integration
| Task | Status | Notes |
|------|--------|-------|
| Update main.go for new startup | ✅ Complete | -data flag, storage.Open() |
| Migrate server.go to use storage | ✅ Complete | Via BuildParsedConfig() adapter |
| Migrate resolver to use storage | ✅ Complete | Via BuildParsedConfig() adapter |
| Migrate API handlers | ✅ Complete | api.NewWithStorage() |
| Remove old file-based config | ✅ Complete | Storage-only mode |

### Phase 5: DNSSEC
| Task | Status | Notes |
|------|--------|-------|
| Key storage in database | ✅ Complete | storage/dnssec.go |
| Signing integration | ✅ Complete | dnssec/dnssec.go Signer |
| NSEC3 for authenticated NXDOMAIN | ✅ Complete | CreateNSEC3, GenerateNSEC3Chain |
| Key rollover automation | ✅ Complete | RolloverManager, BeginZSKRollover |

### Phase 6: Security & Operations (High Priority)
| Task | Status | Notes |
|------|--------|-------|
| Response Rate Limiting (RRL) | ✅ Complete | rrl/rrl.go |
| Query logging | ✅ Complete | querylog/querylog.go |
| Prometheus metrics endpoint | ✅ Complete | metrics/metrics.go, /metrics |
| Audit logging | ✅ Complete | storage/audit.go |
| Zone file import (BIND format) | ✅ Complete | zonefile/zonefile.go |
| Backup/export command | ✅ Complete | storage/backup.go |

### Phase 7: Zone Management (Medium Priority)
| Task | Status | Notes |
|------|--------|-------|
| NOTIFY on zone changes | ✅ Complete | transfer/transfer.go SendNotify |
| Views/Split-horizon DNS | ✅ Complete | storage/adapter.go View CRUD |
| Blocklist/Allowlist | ✅ Complete | storage/adapter.go Blocklist CRUD |
| Weighted records | ✅ Complete | Weight field in Record model |
| Health checks | ✅ Complete | healthcheck/healthcheck.go |

### Phase 8: Advanced Features (In Progress)
| Task | Status | Notes |
|------|--------|-------|
| Dynamic DNS (RFC 2136) | ⬜ Not Started | Client self-updates |
| Response Policy Zones (RPZ) | ⬜ Not Started | DNS firewall |
| EDNS Client Subnet (ECS) | ⬜ Not Started | Geo-aware upstream |
| GeoIP responses | ⬜ Not Started | Uses Views architecture |
| Pattern generation ($GENERATE) | ⬜ Not Started | Bulk record creation |
| Minimal responses | ⬜ Not Started | Omit unnecessary sections |
| Catalog zones | ⬜ Not Started | Auto-configure secondaries |
| Compact reverse zone transfer | ⬜ Not Started | Custom AXFR extension |

---

## Configuration Defaults

```go
// First-run defaults
ServerConfig{
    DNS: DNSConfig{
        Enabled: true,
        UDPPort: 53,
        TCPPort: 53,
        Address: "",  // All interfaces
    },
    DoT: DoTConfig{
        Enabled: true,
        Port:    853,
    },
    DoH: DoHConfig{
        Enabled: true,
        Path:    "/dns-query",
    },
    Web: WebConfig{
        Enabled: true,
        Port:    443,
        TLS:     true,
    },
}

RecursionConfig{
    Enabled:  false,  // Disabled by default (authoritative only)
    Mode:     "partial",
    Upstream: []string{},  // Empty = iterative from root
    Timeout:  5,
    MaxDepth: 10,
}

RateLimitConfig{
    Enabled:         true,
    ResponsesPerSec: 10,
    SlipRatio:       2,
    WindowSeconds:   1,
    WhitelistCIDRs:  []string{"127.0.0.1/8", "::1/128"},
}
```

---

## API Changes

The REST API structure remains similar but now operates on the database:

```
# Zones
GET    /api/zones                    # List zones (filtered by tenant)
POST   /api/zones                    # Create zone
GET    /api/zones/{name}             # Get zone
PUT    /api/zones/{name}             # Update zone
DELETE /api/zones/{name}             # Delete zone

# Records
GET    /api/zones/{zone}/records     # List records
POST   /api/zones/{zone}/records     # Create record (auto-PTR)
PUT    /api/zones/{zone}/records/{id} # Update record
DELETE /api/zones/{zone}/records/{id} # Delete record

# Tenants (super-admin only)
GET    /api/tenants
POST   /api/tenants
...

# Config
GET    /api/config/{section}
PUT    /api/config/{section}

# Operations
POST   /api/zones/{zone}/notify      # Send NOTIFY
POST   /api/zones/{zone}/transfer    # Force AXFR pull (secondary)
POST   /api/export                   # Backup
POST   /api/import                   # Restore

# Metrics
GET    /metrics                      # Prometheus format
```

---

## Migration from JSON Config

For users with existing JSON configs, provide import command:

```bash
./dns-server import --config config.json --auth auth.json
```

This reads old format and populates database.

---

## Notes

- Zone serials use format YYYYMMDDNN (auto-generated)
- All timestamps in UTC
- bbolt provides ACID transactions
- Zone list cached in memory for fast lookups
- Record lookups are direct B+tree access (fast)
