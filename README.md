# Go DNS Server

A full-featured, authoritative DNS server written in Go with support for dynamic reverse DNS generation, DNSSEC, zone transfers, and secondary server replication.

## Features

### Core DNS
- **All major record types**: A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA, PTR
- **Authoritative responses** for configured zones
- **Recursive resolution** (full or partial mode) for non-authoritative queries
- **Hot-reload configuration** via file watching (fsnotify)

### Dynamic Reverse DNS
- **IPv4 and IPv6 support**: Automatic PTR record generation for any IP in configured subnets
- **Pattern-based hostnames**: Generate hostnames like `192-168-1-50.ip4.example.com`
- **IPv6 prefix stripping**: Remove common prefix for shorter hostnames
- **Override support**: Custom hostnames for specific IPs take precedence

### DNSSEC
- **Automatic signing**: Sign zones with DNSSEC keys
- **Key management**: Auto-create KSK/ZSK pairs
- **Algorithm support**: ECDSAP256SHA256, ECDSAP384SHA384, RSASHA256, RSASHA512, ED25519

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
- **Pattern zone support**: Copy zone patterns for dynamic reverse DNS

## Quick Start

### Building

```bash
go mod tidy
go build -o dnsserver .
```

### Running

```bash
./dnsserver -config config.json
```

## Configuration

### Basic Example

```json
{
  "listen": ":5353",
  "zones": [
    {
      "subnet": "192.168.1.0/24",
      "domain": "ip4.example.com",
      "ttl": 3600
    },
    {
      "subnet": "2001:db8::/32",
      "domain": "ip6.example.com",
      "strip_prefix": true,
      "ttl": 3600
    }
  ],
  "records": {
    "A": [
      {"name": "www.example.com", "ip": "192.168.1.10", "ttl": 300}
    ],
    "MX": [
      {"name": "example.com", "priority": 10, "target": "mail.example.com", "ttl": 3600}
    ],
    "NS": [
      {"name": "example.com", "target": "ns1.example.com", "ttl": 3600}
    ],
    "SOA": [
      {
        "name": "example.com",
        "mname": "ns1.example.com",
        "rname": "hostmaster.example.com",
        "serial": 2024010101,
        "refresh": 3600,
        "retry": 900,
        "expire": 1209600,
        "minimum": 3600,
        "ttl": 3600
      }
    ]
  },
  "recursion": {
    "enabled": true,
    "mode": "partial"
  }
}
```

### Zone Transfer Configuration (Primary)

```json
{
  "transfer": {
    "enabled": true,
    "tsig_keys": [
      {
        "name": "transfer-key.",
        "algorithm": "hmac-sha256",
        "secret": "base64-encoded-secret"
      }
    ],
    "acls": [
      {
        "zone": "example.com",
        "allow_transfer": ["10.0.0.0/8"],
        "allow_notify": ["10.0.0.0/8"],
        "require_tsig": true
      }
    ],
    "notify_targets": [
      {
        "zone": "example.com",
        "targets": ["10.0.0.2:53", "10.0.0.3:53"]
      }
    ]
  }
}
```

### Secondary Server Configuration

```json
{
  "listen": ":5353",
  "zones": [
    {
      "subnet": "192.168.1.0/24",
      "domain": "ip4.example.com",
      "ttl": 3600
    }
  ],
  "secondary_zones": [
    {
      "zone": "example.com",
      "primaries": ["10.0.0.1:53"],
      "refresh_interval": 3600,
      "retry_interval": 900
    }
  ]
}
```

Note: Copy the `zones` array from primary to secondary for pattern-based reverse DNS to work.

### DNSSEC Configuration

```json
{
  "dnssec": [
    {
      "zone": "example.com",
      "key_dir": "./keys",
      "algorithm": "ECDSAP256SHA256",
      "auto_create": true
    }
  ]
}
```

## Testing

### Query records
```bash
# A record
dig @localhost -p 5353 www.example.com A

# Reverse DNS (IPv4)
dig @localhost -p 5353 -x 192.168.1.50

# Reverse DNS (IPv6)
dig @localhost -p 5353 -x 2001:db8::1

# With DNSSEC
dig @localhost -p 5353 www.example.com A +dnssec

# Zone transfer
dig @localhost -p 5353 example.com AXFR
```

### Run tests
```bash
go test ./...
```

## Architecture

```
├── main.go           # Entry point, config watching
├── config/           # Configuration parsing
├── server/           # DNS server and request handling
├── resolver/         # Zone and record resolution
├── recurse/          # Recursive DNS resolution
├── dnssec/           # DNSSEC signing and key management
├── dnssecval/        # DNSSEC validation
├── transfer/         # AXFR/IXFR and NOTIFY handling
├── secondary/        # Secondary zone management
└── cache/            # DNS response caching
```

## License

MIT

