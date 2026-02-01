# Go DNS Server

A full-featured, authoritative DNS server written in Go with DNSSEC, zone transfers, secondary server replication, multi-tenancy, and a modern web administration UI.

## Features

### Core DNS
- **All major record types**: A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA, PTR
- **Forward and reverse zones**: Full support for both lookup types
- **Authoritative responses** for configured zones
- **Recursive resolution** (full or partial mode) for non-authoritative queries
- **DNS over TLS (DoT)** and **DNS over HTTPS (DoH)** support

### Web Administration UI
- **Modern Angular dashboard**: Real-time server status and statistics
- **Zone management**: Create forward and reverse DNS zones
- **Record management**: Full CRUD for all DNS record types
- **Delegation management**: Configure NS and DS records for child zones
- **Settings configuration**: Ports, recursion, zone transfers, DNSSEC
- **User authentication**: Local users, WebAuthn/passkeys, OIDC providers
- **Multi-tenancy**: Isolate zones and records by tenant
- **REST API**: Programmatic access with API key authentication

### Dynamic Reverse DNS
- **IPv4 and IPv6 support**: Automatic PTR record generation for any IP in configured subnets
- **Pattern-based hostnames**: Generate hostnames like `192-168-1-50.ip4.example.com`
- **IPv6 prefix stripping**: Remove common prefix for shorter hostnames
- **Override support**: Custom hostnames for specific IPs take precedence

### DNSSEC
- **Automatic signing**: Sign zones with DNSSEC keys
- **Key management**: Automatic KSK/ZSK generation and rotation
- **Algorithm support**: ECDSAP256SHA256, ECDSAP384SHA384, RSASHA256, RSASHA512, ED25519
- **Key export/import**: Transfer DNSSEC keys between primary and secondary servers
- **Token-based key sharing**: Secure automatic key distribution to secondaries

### Zone Transfers
- **AXFR support**: Full zone transfers for secondaries
- **IXFR support**: Incremental zone transfers
- **NOTIFY**: Immediate notification to secondaries on zone changes
- **TSIG authentication**: Secure transfers with shared secrets
- **ACL control**: Restrict transfers by IP/subnet

### Secondary Server Mode
- **Pull zones from primaries**: AXFR-based zone replication
- **Automatic refresh**: Periodic SOA serial checking
- **NOTIFY handling**: Immediate refresh on primary notification
- **DNSSEC key sync**: Automatic key fetching from primary on zone transfer

### Zone Delegations
- **Child zone support**: Delegate subdomains to other nameservers
- **Glue records**: Automatic glue record generation
- **DS records**: DNSSEC delegation with DS record support

### Multi-Master Cluster Sync
- **Active-active replication**: Edit on any server, changes sync automatically
- **Hybrid Logical Clock (HLC)**: Consistent event ordering across distributed nodes
- **WebSocket transport**: Real-time peer-to-peer synchronization
- **HMAC authentication**: Secure peer connections with shared secret
- **Automatic reconnection**: Resilient to network partitions
- **Operation log**: Track and replay changes for offline peers
- **Last-writer-wins**: Conflict resolution with HLC timestamps

## Quick Start

### Building

```bash
go mod tidy
go build -o dnsserver .
```

### Running

```bash
# Run with web UI on port 8080
./dnsserver -web :8080

# Run with storage backend (recommended - uses bbolt database)
./dnsserver -web :8080 -storage ./data/data.db

# Run without web UI
./dnsserver
```

On first run, visit http://localhost:8080 to set up your admin account.

## Web UI

The web administration interface provides a user-friendly way to manage the DNS server.

### Features

| Section | Description |
|---------|-------------|
| **Dashboard** | Real-time server status, uptime, query statistics |
| **Zones** | Manage forward and reverse DNS zones |
| **Records** | Create and manage all DNS record types |
| **Secondary Zones** | Configure zone replication from primary servers |
| **Zone Transfer** | Configure AXFR/IXFR settings, allowed IPs, TSIG keys |
| **Recursion** | Enable/disable recursive resolution, configure upstreams |
| **DNSSEC** | Manage zone signing, keys, and delegations |
| **Network** | Configure DNS, DoT, DoH, and web ports |
| **Settings** | Server settings and configuration |
| **Profile** | User settings, passkeys, password management |

### REST API

All configuration operations are available via REST API. Authentication is required via session cookie or API key.

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/api/status` | GET | Server status and statistics |
| `/api/zones` | GET, POST | List/create zones |
| `/api/zones/{name}` | GET, PUT, DELETE | Get/update/delete zone |
| `/api/records` | GET, POST | List/create records |
| `/api/records/{type}/{id}` | PUT, DELETE | Update/delete record |
| `/api/delegations` | GET, POST | List/create delegations |
| `/api/delegations/{zone}/{child}` | DELETE | Delete delegation |
| `/api/secondary-zones` | GET, POST | List/create secondary zones |
| `/api/secondary-zones/{zone}` | PUT, DELETE | Update/delete secondary zone |
| `/api/transfer` | GET, PUT | Zone transfer settings |
| `/api/recursion` | GET, PUT | Recursion settings |
| `/api/dnssec` | GET, POST, DELETE | DNSSEC zone management |
| `/api/dnssec/keys/{zone}` | GET, PUT | Export/import DNSSEC keys |
| `/api/dnssec/token/{zone}` | GET, POST, DELETE | Key sharing token management |
| `/api/ports` | GET | Port configuration status |
| `/api/ports/{type}` | GET, PUT | Configure specific port (dns, dot, doh, web) |
| `/api/settings` | GET, PUT | Server settings |
| `/api/auth/...` | Various | Authentication endpoints |

### API Authentication

```bash
# Using API key
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/status

# Using session (after login)
curl -b cookies.txt http://localhost:8080/api/status
```

## Storage

The server uses a bbolt database for persistent storage of all configuration:

- Zones and records
- Users and sessions
- DNSSEC keys
- Audit logs
- Settings

The database file is stored at the path specified by `-storage` flag (default: `./data/data.db`).

### Backup

To backup the DNS server data, copy the database file while the server is stopped, or use file system snapshots.

## Testing

### Query records
```bash
# A record
dig @localhost -p 53 www.example.com A

# Reverse DNS (IPv4)
dig @localhost -p 53 -x 192.168.1.50

# Reverse DNS (IPv6)
dig @localhost -p 53 -x 2001:db8::1

# With DNSSEC
dig @localhost -p 53 www.example.com A +dnssec

# Zone transfer
dig @localhost -p 53 example.com AXFR

# DNS over TLS
kdig @localhost -p 853 +tls www.example.com A

# DNS over HTTPS
curl -H "accept: application/dns-json" "https://localhost:8443/dns-query?name=www.example.com&type=A"
```

### Run tests
```bash
# Unit tests
go test ./... -short

# All tests including integration
go test ./...

# With verbose output
go test ./... -v

# Angular unit tests
cd web && npm run test:run
```

## Architecture

```
├── main.go           # Entry point, CLI flags
├── config/           # Configuration structures
├── server/           # DNS server and request handling
├── resolver/         # Zone and record resolution
├── recurse/          # Recursive DNS resolution
├── dnssec/           # DNSSEC signing and key management
├── dnssecval/        # DNSSEC validation
├── transfer/         # AXFR/IXFR and NOTIFY handling
├── secondary/        # Secondary zone management
├── cache/            # DNS response caching
├── storage/          # bbolt database backend
├── auth/             # Authentication (local, WebAuthn, OIDC)
├── api/              # REST API handlers
├── certs/            # TLS certificate management (ACME)
├── ports/            # Port configuration management
├── metrics/          # Prometheus metrics
├── querylog/         # Query logging
├── rrl/              # Response rate limiting
└── web/              # Angular web administration UI
    ├── src/app/
    │   ├── dashboard/       # Server status dashboard
    │   ├── zones/           # Zone management
    │   ├── records/         # Record management
    │   ├── secondary-zones/ # Secondary zone config
    │   ├── transfer/        # Zone transfer settings
    │   ├── recursion/       # Recursion settings
    │   ├── dnssec/          # DNSSEC settings
    │   ├── network/         # Port configuration
    │   ├── settings/        # Server settings
    │   ├── profile/         # User profile
    │   ├── login/           # Authentication
    │   ├── api-keys/        # API key management
    │   └── services/        # API service
    └── dist/                # Built Angular app
```

### Building the Web UI

The Angular web UI is pre-built in `web/dist`. To rebuild after making changes:

```bash
cd web
npm install
npm run build
```

## Docker Deployment

The DNS server can be deployed as a Docker container with support for both x86_64 (amd64) and ARM64 architectures.

### Building the Docker Image

```bash
# Build for your local architecture
docker build -t dns-server .

# Run locally
docker run -d \
  --name dns-server \
  -p 53:53/udp -p 53:53/tcp \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  dns-server
```

### Multi-Architecture Build

```bash
# Set up buildx for multi-arch builds
docker buildx create --name multiarch-builder --driver docker-container --use

# Build for both amd64 and arm64
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag dns-server:latest \
  .
```

### Docker Compose

```bash
# Start the container
docker-compose up -d

# View logs
docker-compose logs -f
```

### Volume Mounts

| Container Path | Description |
|----------------|-------------|
| `/app/data` | Database file (data.db) |
| `/app/keys` | DNSSEC keys and TLS certificates |

### Exposed Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 53 | UDP/TCP | DNS queries |
| 853 | TCP | DNS over TLS |
| 8080 | TCP | Web UI / REST API (HTTP) |
| 8443 | TCP | Web UI / REST API (HTTPS) |
| 9443 | TCP | Cluster Sync (WebSocket) |

## Cluster Synchronization

Enable multi-master replication between DNS servers for high availability.

### Configure Cluster Sync

Store this configuration in the `settings` store under key `sync`:

```json
{
  "enabled": true,
  "node_id": "dns1",
  "listen_addr": ":9443",
  "shared_secret": "your-secure-shared-secret",
  "peers": [
    {"id": "dns2", "address": "ws://dns2.example.com:9443/sync"},
    {"id": "dns3", "address": "ws://dns3.example.com:9443/sync"}
  ],
  "tombstone_retention_days": 30
}
```

### Sync API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/sync/status` | GET | Get cluster sync status |
| `/api/sync/peers` | GET | List connected peers |
| `/api/sync/peers` | POST | Add a new peer |
| `/api/sync/force` | POST | Force resync with a peer |
| `/sync` | WebSocket | Peer sync connection |

### How It Works

1. **Hybrid Logical Clock (HLC)**: Each change is timestamped with both wall-clock time and a logical counter
2. **Operation Log**: All changes are recorded in an append-only log
3. **Real-time Sync**: Connected peers receive changes immediately via WebSocket
4. **Catch-up**: When a peer reconnects, it requests missed changes since its last known timestamp
5. **Conflict Resolution**: Last-writer-wins based on HLC ordering

## MikroTik RouterOS 7 Deployment

The DNS server can be deployed as a container on MikroTik RouterOS 7 devices.

### Prerequisites

1. RouterOS 7.4+ with container support
2. Sufficient storage space (recommended 256MB+)
3. Container mode enabled on the router

### Deploy to RouterOS

```bash
# Deploy ARM64 image (for ARM-based RouterOS devices)
./scripts/deploy-routeros.sh latest arm64

# Deploy AMD64 image (for x86-based RouterOS devices)
./scripts/deploy-routeros.sh latest amd64
```

### Manual RouterOS Configuration

```routeros
# Enable container mode (requires reboot)
/system/device-mode/update container=yes

# Create bridge and veth for containers
/interface bridge add name=docker
/ip address add address=172.17.0.1/24 interface=docker
/interface veth add name=veth-dns address=172.17.0.2/24 gateway=172.17.0.1
/interface bridge port add bridge=docker interface=veth-dns

# Create mount points
/container mounts
add name="dns-data" src="/container/dns-server/data" dst="/app/data"
add name="dns-keys" src="/container/dns-server/keys" dst="/app/keys"

# NAT rules for DNS
/ip firewall nat
add chain=dstnat dst-port=53 protocol=udp action=dst-nat to-addresses=172.17.0.2 to-ports=53
add chain=dstnat dst-port=53 protocol=tcp action=dst-nat to-addresses=172.17.0.2 to-ports=53
add chain=srcnat src-address=172.17.0.0/24 action=masquerade

# Add container (after uploading the tar.gz)
/container add file=dns-server-arm64.tar.gz interface=veth-dns \
    root-dir=/container/store/dns-server \
    mounts=dns-data,dns-keys \
    start-on-boot=yes logging=yes

# Start container
/container start [find name="dns-server"]
```

## License

MIT

