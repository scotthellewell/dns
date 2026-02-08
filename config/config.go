package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// ZoneType represents the type of DNS zone
type ZoneType string

const (
	// ZoneTypeForward is a forward lookup zone (name to IP)
	ZoneTypeForward ZoneType = "forward"
	// ZoneTypeReverse is a reverse lookup zone (IP to name, PTR records)
	ZoneTypeReverse ZoneType = "reverse"
)

// ZoneConfig defines configuration for a DNS zone
// Supports both forward zones (e.g., "example.com") and reverse zones (e.g., "1.168.192.in-addr.arpa")
type ZoneConfig struct {
	// TenantID specifies which tenant owns this zone (empty = main tenant for backward compatibility)
	TenantID string `json:"tenant_id,omitempty"`
	// Name is the zone name (e.g., "example.com" or "1.168.192.in-addr.arpa")
	// For reverse zones, this can be auto-generated from Subnet if not specified
	Name string `json:"name,omitempty"`
	// Type is the zone type: "forward" or "reverse" (default: "forward" if no subnet, "reverse" if subnet specified)
	Type ZoneType `json:"type,omitempty"`
	// Subnet in CIDR notation - only for reverse zones (e.g., "192.168.1.0/24" or "2602:FF29::/40")
	// For reverse zones, this defines the IP range and enables auto-PTR generation
	Subnet string `json:"subnet,omitempty"`
	// Domain suffix for generated hostnames in reverse zones (e.g., "home.local")
	// For forward zones, this is ignored (use Name instead)
	Domain string `json:"domain,omitempty"`
	// StripPrefix - if true, strip the subnet prefix from generated PTR names
	// Only applies to reverse zones with pattern generation
	StripPrefix bool `json:"strip_prefix"`
	// TTL for DNS records in seconds
	TTL uint32 `json:"ttl"`
}

// ARecord defines an A (IPv4) record
type ARecord struct {
	TenantID string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string `json:"name"`                // Hostname (relative to zone, or FQDN for backward compat)
	IP       string `json:"ip"`                  // IPv4 address
	TTL      uint32 `json:"ttl"`                 // TTL in seconds
	// PTR controls auto-creation of PTR record. Default is true if IP is in a configured zone.
	// Set to false to disable PTR creation.
	PTR *bool `json:"ptr,omitempty"`
}

// AAAARecord defines an AAAA (IPv6) record
type AAAARecord struct {
	TenantID string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string `json:"name"`                // Hostname (relative to zone, or FQDN for backward compat)
	IP       string `json:"ip"`                  // IPv6 address
	TTL      uint32 `json:"ttl"`                 // TTL in seconds
	// PTR controls auto-creation of PTR record. Default is true if IP is in a configured zone.
	// Set to false to disable PTR creation.
	PTR *bool `json:"ptr,omitempty"`
}

// CNAMERecord defines a CNAME record
type CNAMERecord struct {
	TenantID string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string `json:"name"`                // Hostname (relative to zone, or FQDN for backward compat)
	Target   string `json:"target"`              // Target hostname (e.g., "example.com")
	TTL      uint32 `json:"ttl"`                 // TTL in seconds
}

// MXRecord defines an MX record
type MXRecord struct {
	TenantID string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string `json:"name"`                // Domain (relative to zone, or FQDN for backward compat)
	Priority uint16 `json:"priority"`            // MX priority
	Target   string `json:"target"`              // Mail server hostname
	TTL      uint32 `json:"ttl"`                 // TTL in seconds
}

// TXTRecord defines a TXT record
type TXTRecord struct {
	TenantID string   `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string   `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string   `json:"name"`                // Hostname (relative to zone, or FQDN for backward compat)
	Values   []string `json:"values"`              // TXT values
	TTL      uint32   `json:"ttl"`                 // TTL in seconds
}

// NSRecord defines an NS record
type NSRecord struct {
	TenantID string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string `json:"name"`                // Zone apex or subdomain (relative to zone, or FQDN for backward compat)
	Target   string `json:"target"`              // Nameserver hostname
	TTL      uint32 `json:"ttl"`                 // TTL in seconds
}

// PTRRecord defines a PTR record explicitly
type PTRRecord struct {
	TenantID string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string `json:"zone,omitempty"`      // Zone name this record belongs to (reverse zone)
	IP       string `json:"ip"`                  // IP address
	Hostname string `json:"hostname"`            // Hostname to return
	TTL      uint32 `json:"ttl"`                 // TTL in seconds
}

// SRVRecord defines an SRV record for service discovery
type SRVRecord struct {
	TenantID string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string `json:"name"`                // Service name (e.g., "_sip._tcp" relative to zone)
	Priority uint16 `json:"priority"`            // Priority (lower = preferred)
	Weight   uint16 `json:"weight"`              // Weight for load balancing
	Port     uint16 `json:"port"`                // Port number
	Target   string `json:"target"`              // Target hostname
	TTL      uint32 `json:"ttl"`                 // TTL in seconds
}

// SOARecord defines an SOA (Start of Authority) record
type SOARecord struct {
	TenantID string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string `json:"name"`                // Zone name (should match zone, or @ for apex)
	MName    string `json:"mname"`               // Primary nameserver
	RName    string `json:"rname"`               // Responsible person email (use . instead of @)
	Serial   uint32 `json:"serial"`              // Serial number (typically YYYYMMDDNN)
	Refresh  uint32 `json:"refresh"`             // Refresh interval in seconds
	Retry    uint32 `json:"retry"`               // Retry interval in seconds
	Expire   uint32 `json:"expire"`              // Expire time in seconds
	Minimum  uint32 `json:"minimum"`             // Minimum TTL (negative cache TTL)
	TTL      uint32 `json:"ttl"`                 // TTL in seconds
}

// ALIASRecord defines an ALIAS/ANAME record (CNAME-like for apex domains)
// Returns the A/AAAA records of the target instead of a CNAME
type ALIASRecord struct {
	TenantID string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string `json:"name"`                // Hostname (relative to zone, or FQDN for backward compat)
	Target   string `json:"target"`              // Target to resolve (e.g., "cdn.example.net")
	TTL      uint32 `json:"ttl"`                 // TTL in seconds
	// PTR controls auto-creation of PTR record for resolved IPs. Default is true if IP is in a configured zone.
	// Set to false to disable PTR creation.
	PTR *bool `json:"ptr,omitempty"`
}

// CAARecord defines a CAA (Certificate Authority Authorization) record
type CAARecord struct {
	TenantID string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string `json:"name"`                // Hostname (relative to zone, or FQDN for backward compat)
	Flag     uint8  `json:"flag"`                // Critical flag (0 or 128)
	Tag      string `json:"tag"`                 // Tag: "issue", "issuewild", or "iodef"
	Value    string `json:"value"`               // CA domain or URL
	TTL      uint32 `json:"ttl"`                 // TTL in seconds
}

// SSHFPRecord defines an SSHFP (SSH Fingerprint) record
type SSHFPRecord struct {
	TenantID    string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone        string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name        string `json:"name"`                // Hostname (relative to zone, or FQDN for backward compat)
	Algorithm   uint8  `json:"algorithm"`           // 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519
	Type        uint8  `json:"type"`                // 1=SHA-1, 2=SHA-256
	Fingerprint string `json:"fingerprint"`         // Hex-encoded fingerprint
	TTL         uint32 `json:"ttl"`                 // TTL in seconds
}

// TLSARecord defines a TLSA (DANE TLS Certificate) record
type TLSARecord struct {
	TenantID     string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone         string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name         string `json:"name"`                // Name (e.g., "_443._tcp" relative to zone)
	Usage        uint8  `json:"usage"`               // 0=CA, 1=Service, 2=Trust anchor, 3=Domain-issued
	Selector     uint8  `json:"selector"`            // 0=Full cert, 1=SubjectPublicKeyInfo
	MatchingType uint8  `json:"matching_type"`       // 0=Exact, 1=SHA-256, 2=SHA-512
	Certificate  string `json:"certificate"`         // Hex-encoded cert data
	TTL          uint32 `json:"ttl"`                 // TTL in seconds
}

// NAPTRRecord defines a NAPTR (Naming Authority Pointer) record
type NAPTRRecord struct {
	TenantID    string `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone        string `json:"zone,omitempty"`      // Zone name this record belongs to
	Name        string `json:"name"`                // Domain name (relative to zone, or FQDN for backward compat)
	Order       uint16 `json:"order"`               // Order (lower = first)
	Preference  uint16 `json:"preference"`          // Preference (lower = preferred)
	Flags       string `json:"flags"`               // Flags (e.g., "s", "a", "u")
	Service     string `json:"service"`             // Service (e.g., "SIP+D2U")
	Regexp      string `json:"regexp"`              // Regular expression
	Replacement string `json:"replacement"`         // Replacement domain
	TTL         uint32 `json:"ttl"`                 // TTL in seconds
}

// SVCBRecord defines an SVCB (Service Binding) record
type SVCBRecord struct {
	TenantID string            `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string            `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string            `json:"name"`                // Name (e.g., "_dns" relative to zone)
	Priority uint16            `json:"priority"`            // Priority (0 = alias mode)
	Target   string            `json:"target"`              // Target name
	Params   map[string]string `json:"params"`              // Parameters (alpn, port, ipv4hint, ipv6hint, etc.)
	TTL      uint32            `json:"ttl"`                 // TTL in seconds
}

// HTTPSRecord defines an HTTPS (HTTPS-specific SVCB) record
type HTTPSRecord struct {
	TenantID string            `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone     string            `json:"zone,omitempty"`      // Zone name this record belongs to
	Name     string            `json:"name"`                // Name (relative to zone, or FQDN for backward compat)
	Priority uint16            `json:"priority"`            // Priority (0 = alias mode)
	Target   string            `json:"target"`              // Target name (. for same name)
	Params   map[string]string `json:"params"`              // Parameters (alpn, port, ipv4hint, ipv6hint, ech, etc.)
	TTL      uint32            `json:"ttl"`                 // TTL in seconds
}

// LOCRecord defines a LOC (Location) record
type LOCRecord struct {
	TenantID  string  `json:"tenant_id,omitempty"` // Tenant ID (empty = main tenant)
	Zone      string  `json:"zone,omitempty"`      // Zone name this record belongs to
	Name      string  `json:"name"`                // Hostname (relative to zone, or FQDN for backward compat)
	Latitude  float64 `json:"latitude"`            // Latitude in decimal degrees
	Longitude float64 `json:"longitude"`           // Longitude in decimal degrees
	Altitude  float64 `json:"altitude"`            // Altitude in meters
	Size      float64 `json:"size"`                // Size/diameter in meters
	HorizPre  float64 `json:"horiz_pre"`           // Horizontal precision in meters
	VertPre   float64 `json:"vert_pre"`            // Vertical precision in meters
	TTL       uint32  `json:"ttl"`                 // TTL in seconds
}

// Records holds all static record definitions
type Records struct {
	A     []ARecord     `json:"A"`
	AAAA  []AAAARecord  `json:"AAAA"`
	CNAME []CNAMERecord `json:"CNAME"`
	MX    []MXRecord    `json:"MX"`
	TXT   []TXTRecord   `json:"TXT"`
	NS    []NSRecord    `json:"NS"`
	PTR   []PTRRecord   `json:"PTR"`
	SRV   []SRVRecord   `json:"SRV"`
	SOA   []SOARecord   `json:"SOA"`
	ALIAS []ALIASRecord `json:"ALIAS"`
	CAA   []CAARecord   `json:"CAA"`
	SSHFP []SSHFPRecord `json:"SSHFP"`
	TLSA  []TLSARecord  `json:"TLSA"`
	NAPTR []NAPTRRecord `json:"NAPTR"`
	SVCB  []SVCBRecord  `json:"SVCB"`
	HTTPS []HTTPSRecord `json:"HTTPS"`
	LOC   []LOCRecord   `json:"LOC"`
}

// DNSSECKeyConfig holds DNSSEC key configuration for a zone
type DNSSECKeyConfig struct {
	// Zone name (e.g., "ip6.quicktechresults.com")
	Zone string `json:"zone"`
	// Directory containing keys
	KeyDir string `json:"key_dir"`
	// Algorithm: "ECDSAP256SHA256" or "ECDSAP384SHA384"
	Algorithm string `json:"algorithm"`
	// Auto-create keys if missing
	AutoCreate bool `json:"auto_create"`
}

// DelegationConfig defines a zone delegation to other nameservers
type DelegationConfig struct {
	// Zone is the zone name to delegate (e.g., "sub.example.com" or "0/26.184.148.23.in-addr.arpa")
	Zone string `json:"zone"`
	// Nameservers are the NS records for this delegation
	Nameservers []string `json:"nameservers"`
	// Addresses are optional glue records (IP addresses for the nameservers)
	// Map of nameserver hostname to IP addresses
	Glue map[string][]string `json:"glue"`
	// Forward enables query forwarding to the delegated servers (acts as a forwarder)
	// If false, only returns NS referrals; if true, queries the NS and returns the answer
	Forward bool `json:"forward"`
	// TTL for the NS records
	TTL uint32 `json:"ttl"`
}

// RecursionConfig defines settings for recursive resolution
type RecursionConfig struct {
	// Enabled turns on recursive resolution for external names
	Enabled bool `json:"enabled"`
	// Mode controls when recursion is used:
	// - "full": Resolve any query (open resolver)
	// - "partial": Only recurse for names we have local records pointing to (CNAME, ALIAS)
	// - "disabled" or "": No recursion
	// Default is "partial" when Enabled is true
	Mode string `json:"mode"`
	// Upstream nameservers to use (e.g., ["8.8.8.8:53", "1.1.1.1:53"])
	// If empty, uses iterative resolution from root servers
	Upstream []string `json:"upstream"`
	// Timeout for upstream queries in seconds (default: 5)
	Timeout int `json:"timeout"`
	// MaxDepth is the maximum CNAME chain depth (default: 10)
	MaxDepth int `json:"max_depth"`
}

// TSIGKey defines a TSIG key for authenticating zone transfers and updates
type TSIGKey struct {
	// Name is the key name (e.g., "transfer-key.")
	Name string `json:"name"`
	// Algorithm is the HMAC algorithm (e.g., "hmac-sha256", "hmac-sha512")
	Algorithm string `json:"algorithm"`
	// Secret is the base64-encoded shared secret
	Secret string `json:"secret"`
}

// TransferACL defines access control for zone transfers
type TransferACL struct {
	// Zone is the zone name this ACL applies to (or "*" for all zones)
	Zone string `json:"zone"`
	// AllowTransfer lists IPs/CIDRs allowed to request zone transfers
	AllowTransfer []string `json:"allow_transfer"`
	// AllowNotify lists IPs/CIDRs allowed to send NOTIFY messages
	AllowNotify []string `json:"allow_notify"`
	// TSIGKey is the required TSIG key name for this zone (optional)
	TSIGKey string `json:"tsig_key"`
}

// NotifyTarget defines a server to notify when a zone changes
type NotifyTarget struct {
	// Zone is the zone name to watch for changes
	Zone string `json:"zone"`
	// Targets are the servers to notify (IP:port)
	Targets []string `json:"targets"`
	// TSIGKey is the TSIG key name to use for NOTIFY (optional)
	TSIGKey string `json:"tsig_key"`
}

// TransferConfig defines zone transfer settings
type TransferConfig struct {
	// Enabled turns on zone transfer support
	Enabled bool `json:"enabled"`
	// TSIGKeys defines shared secrets for authentication
	TSIGKeys []TSIGKey `json:"tsig_keys"`
	// ACLs defines access control for zone transfers
	ACLs []TransferACL `json:"acls"`
	// NotifyTargets defines servers to notify on zone changes
	NotifyTargets []NotifyTarget `json:"notify_targets"`
}

// SecondaryZoneConfig defines a zone to be pulled from a primary server
type SecondaryZoneConfig struct {
	// TenantID specifies which tenant owns this secondary zone (empty = main tenant for backward compatibility)
	TenantID string `json:"tenant_id,omitempty"`
	// Zone is the zone name to transfer (e.g., "example.com")
	Zone string `json:"zone"`
	// Primaries are the primary server addresses to pull from (IP:port)
	Primaries []string `json:"primaries"`
	// TSIGKey is the TSIG key name to use for transfers (optional)
	TSIGKey string `json:"tsig_key"`
	// RefreshInterval overrides the SOA refresh interval (seconds, optional)
	RefreshInterval uint32 `json:"refresh_interval"`
	// RetryInterval overrides the SOA retry interval (seconds, optional)
	RetryInterval uint32 `json:"retry_interval"`
	// DNSSECKeyURL is the URL to fetch DNSSEC keys from primary (optional)
	DNSSECKeyURL string `json:"dnssec_key_url,omitempty"`
	// DNSSECKeyToken is the authentication token for fetching keys (optional)
	DNSSECKeyToken string `json:"dnssec_key_token,omitempty"`
}

// SyncConfig holds cluster synchronization configuration
type SyncConfig struct {
	// Enabled enables cluster synchronization
	Enabled bool `json:"enabled"`
	// NodeID is the unique identifier for this node in the cluster
	NodeID string `json:"node_id"`
	// ServerName is a friendly name for this server in the cluster
	ServerName string `json:"server_name"`
	// SharedSecret is the HMAC secret used for peer authentication
	SharedSecret string `json:"shared_secret"`
	// Peers is the list of peer nodes to synchronize with
	Peers []SyncPeerConfig `json:"peers,omitempty"`
	// OpLogRetentionDays is how long to keep operation log entries (default: 7)
	OpLogRetentionDays int `json:"oplog_retention_days,omitempty"`
	// TombstoneRetentionDays is how long to keep tombstones for deleted entities (default: 30)
	TombstoneRetentionDays int `json:"tombstone_retention_days,omitempty"`
}

// SyncPeerConfig holds configuration for a sync peer
type SyncPeerConfig struct {
	// ID is the unique identifier for this peer
	ID string `json:"id"`
	// Address is the WebSocket address of the peer (e.g., "ws://peer1.example.com:8444/sync")
	Address string `json:"address"`
	// APIKey is the API key for authenticating with this peer
	APIKey string `json:"api_key,omitempty"`
	// InsecureSkipVerify skips TLS certificate verification (for self-signed certs)
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// Config holds the complete server configuration
type Config struct {
	// Listen address (e.g., ":5353" or "127.0.0.1:53")
	Listen string `json:"listen"`
	// Zones defines subnets for forward/reverse DNS
	Zones []ZoneConfig `json:"zones"`
	// Static records
	Records Records `json:"records"`
	// DNSSEC key configurations
	DNSSEC []DNSSECKeyConfig `json:"dnssec"`
	// Recursion settings for following CNAMEs and external lookups
	Recursion RecursionConfig `json:"recursion"`
	// Delegations for subdomains or child zones
	Delegations []DelegationConfig `json:"delegations"`
	// Transfer settings for AXFR/IXFR and NOTIFY
	Transfer TransferConfig `json:"transfer"`
	// SecondaryZones are zones to pull via AXFR from primary servers
	SecondaryZones []SecondaryZoneConfig `json:"secondary_zones"`
}

// ParsedZone holds a parsed zone configuration
type ParsedZone struct {
	Name        string     // Zone name (e.g., "example.com" or generated in-addr.arpa)
	Type        ZoneType   // "forward" or "reverse"
	Network     *net.IPNet // For reverse zones only
	Domain      string     // For reverse zones - domain suffix
	StripPrefix bool
	PrefixLen   int // Number of bits in the prefix (reverse zones)
	TTL         uint32
	IsIPv6      bool // For reverse zones
}

// ParsedARecord holds a parsed A record
type ParsedARecord struct {
	Name string
	IP   net.IP
	TTL  uint32
}

// ParsedAAAARecord holds a parsed AAAA record
type ParsedAAAARecord struct {
	Name string
	IP   net.IP
	TTL  uint32
}

// ParsedCNAMERecord holds a parsed CNAME record
type ParsedCNAMERecord struct {
	Name   string
	Target string
	TTL    uint32
}

// ParsedMXRecord holds a parsed MX record
type ParsedMXRecord struct {
	Name     string
	Priority uint16
	Target   string
	TTL      uint32
}

// ParsedTXTRecord holds a parsed TXT record
type ParsedTXTRecord struct {
	Name   string
	Values []string
	TTL    uint32
}

// ParsedNSRecord holds a parsed NS record
type ParsedNSRecord struct {
	Name   string
	Target string
	TTL    uint32
}

// ParsedPTRRecord holds a parsed PTR record
type ParsedPTRRecord struct {
	IP       net.IP
	Hostname string
	TTL      uint32
}

// ParsedSRVRecord holds a parsed SRV record
type ParsedSRVRecord struct {
	Name     string
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
	TTL      uint32
}

// ParsedSOARecord holds a parsed SOA record
type ParsedSOARecord struct {
	Name    string
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
	TTL     uint32
}

// ParsedALIASRecord holds a parsed ALIAS record
type ParsedALIASRecord struct {
	Name   string
	Target string
	TTL    uint32
	PTR    *bool // nil = auto (create if IP in zone), false = don't create, true = always create
}

// ParsedCAARecord holds a parsed CAA record
type ParsedCAARecord struct {
	Name  string
	Flag  uint8
	Tag   string
	Value string
	TTL   uint32
}

// ParsedSSHFPRecord holds a parsed SSHFP record
type ParsedSSHFPRecord struct {
	Name        string
	Algorithm   uint8
	Type        uint8
	Fingerprint string
	TTL         uint32
}

// ParsedTLSARecord holds a parsed TLSA record
type ParsedTLSARecord struct {
	Name         string
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string
	TTL          uint32
}

// ParsedNAPTRRecord holds a parsed NAPTR record
type ParsedNAPTRRecord struct {
	Name        string
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string
	TTL         uint32
}

// ParsedSVCBRecord holds a parsed SVCB record
type ParsedSVCBRecord struct {
	Name     string
	Priority uint16
	Target   string
	Params   map[string]string
	TTL      uint32
}

// ParsedHTTPSRecord holds a parsed HTTPS record
type ParsedHTTPSRecord struct {
	Name     string
	Priority uint16
	Target   string
	Params   map[string]string
	TTL      uint32
}

// ParsedLOCRecord holds a parsed LOC record
type ParsedLOCRecord struct {
	Name      string
	Latitude  float64
	Longitude float64
	Altitude  float64
	Size      float64
	HorizPre  float64
	VertPre   float64
	TTL       uint32
}

// ParsedRecursion holds parsed recursion configuration
// ParsedDelegation holds a parsed zone delegation
type ParsedDelegation struct {
	Zone        string              // Zone name (FQDN with trailing dot)
	Nameservers []string            // NS hostnames (FQDN with trailing dot)
	Glue        map[string][]net.IP // Nameserver hostname -> IP addresses
	Forward     bool                // Whether to forward queries or just refer
	TTL         uint32
}

// RecursionMode constants
const (
	RecursionModeDisabled = "disabled"
	RecursionModePartial  = "partial"
	RecursionModeFull     = "full"
)

type ParsedRecursion struct {
	Enabled  bool
	Mode     string // "disabled", "partial", or "full"
	Upstream []string
	Timeout  int
	MaxDepth int
}

// ParsedTSIGKey holds a parsed TSIG key
type ParsedTSIGKey struct {
	Name      string // Key name (FQDN)
	Algorithm string // dns package algorithm constant name
	Secret    string // Base64-encoded secret
}

// ParsedTransferACL holds a parsed transfer ACL
type ParsedTransferACL struct {
	Zone          string       // Zone name (FQDN) or "*"
	AllowTransfer []*net.IPNet // Networks allowed to request transfers
	AllowNotify   []*net.IPNet // Networks allowed to send NOTIFY
	TSIGKey       string       // Required TSIG key name (optional)
}

// ParsedNotifyTarget holds a parsed notify target
type ParsedNotifyTarget struct {
	Zone    string   // Zone name (FQDN)
	Targets []string // Server addresses (IP:port)
	TSIGKey string   // TSIG key name to use (optional)
}

// ParsedTransfer holds parsed transfer configuration
type ParsedTransfer struct {
	Enabled       bool
	TSIGKeys      map[string]ParsedTSIGKey // Key name -> key
	ACLs          []ParsedTransferACL
	NotifyTargets []ParsedNotifyTarget
}

// ParsedSecondaryZone holds parsed secondary zone configuration
type ParsedSecondaryZone struct {
	Zone            string
	Primaries       []string
	TSIGKeyName     string
	TSIGSecret      string
	TSIGAlgorithm   string
	RefreshInterval uint32
	RetryInterval   uint32
	// DNSSEC key sharing for secondary signing
	DNSSECKeyURL   string // URL to fetch DNSSEC keys from primary
	DNSSECKeyToken string // Authentication token for key fetch
}

// ParsedConfig holds the parsed configuration
// RateLimitConfig holds rate limiting settings for DDoS protection.
type RateLimitConfig struct {
	Enabled         bool     // Whether rate limiting is enabled
	ResponsesPerSec int      // Max responses per second per client
	SlipRatio       int      // 1-in-N responses sent when rate limited (0 = refuse all)
	WindowSeconds   int      // Time window for rate tracking
	WhitelistCIDRs  []string // CIDRs exempt from rate limiting
}

// QueryLogConfig holds query logging settings.
type QueryLogConfig struct {
	Enabled     bool // Whether query logging is enabled
	LogSuccess  bool // Log successful queries
	LogNXDomain bool // Log NXDOMAIN responses
	LogErrors   bool // Log error responses
}

type ParsedConfig struct {
	Listen         string
	Zones          []ParsedZone          // Sorted by prefix length (most specific first)
	DNSSEC         []DNSSECKeyConfig     // DNSSEC configurations
	Recursion      ParsedRecursion       // Recursion settings
	Delegations    []ParsedDelegation    // Zone delegations
	Transfer       ParsedTransfer        // Zone transfer settings
	SecondaryZones []ParsedSecondaryZone // Secondary zones to pull via AXFR
	RateLimit      RateLimitConfig       // Response rate limiting
	QueryLog       QueryLogConfig        // Query logging settings

	// Static records
	ARecords     map[string][]ParsedARecord     // Name -> A records
	AAAARecords  map[string][]ParsedAAAARecord  // Name -> AAAA records
	CNAMERecords map[string]ParsedCNAMERecord   // Name -> CNAME record
	MXRecords    map[string][]ParsedMXRecord    // Name -> MX records
	TXTRecords   map[string][]ParsedTXTRecord   // Name -> TXT records
	NSRecords    map[string][]ParsedNSRecord    // Name -> NS records
	PTRRecords   map[string]ParsedPTRRecord     // IP -> PTR record
	SRVRecords   map[string][]ParsedSRVRecord   // Name -> SRV records
	SOARecords   map[string]ParsedSOARecord     // Name -> SOA record
	ALIASRecords map[string]ParsedALIASRecord   // Name -> ALIAS record
	CAARecords   map[string][]ParsedCAARecord   // Name -> CAA records
	SSHFPRecords map[string][]ParsedSSHFPRecord // Name -> SSHFP records
	TLSARecords  map[string][]ParsedTLSARecord  // Name -> TLSA records
	NAPTRRecords map[string][]ParsedNAPTRRecord // Name -> NAPTR records
	SVCBRecords  map[string][]ParsedSVCBRecord  // Name -> SVCB records
	HTTPSRecords map[string][]ParsedHTTPSRecord // Name -> HTTPS records
	LOCRecords   map[string][]ParsedLOCRecord   // Name -> LOC records
}

// Load reads and parses a configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadOrCreate reads a configuration file, or creates a default one if it doesn't exist
func LoadOrCreate(path string) (*Config, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default config
			cfg := DefaultConfig()
			if err := SaveConfig(path, cfg); err != nil {
				return nil, false, err
			}
			return cfg, true, nil
		}
		return nil, false, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, false, err
	}

	return &cfg, false, nil
}

// DefaultConfig returns a minimal default configuration
func DefaultConfig() *Config {
	return &Config{
		Listen: ":53",
		Zones:  []ZoneConfig{},
		Records: Records{
			A:     []ARecord{},
			AAAA:  []AAAARecord{},
			CNAME: []CNAMERecord{},
			MX:    []MXRecord{},
			TXT:   []TXTRecord{},
			NS:    []NSRecord{},
			SOA:   []SOARecord{},
			SRV:   []SRVRecord{},
			CAA:   []CAARecord{},
			PTR:   []PTRRecord{},
		},
		Recursion: RecursionConfig{
			Enabled:  false,
			Mode:     RecursionModeDisabled,
			Upstream: []string{"1.1.1.1:53", "8.8.8.8:53"},
			Timeout:  5,
			MaxDepth: 10,
		},
		DNSSEC: []DNSSECKeyConfig{},
	}
}

// SaveConfig writes a configuration to a file
func SaveConfig(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Parse validates and parses the configuration
func (c *Config) Parse() (*ParsedConfig, error) {
	// Set recursion defaults
	timeout := c.Recursion.Timeout
	if timeout == 0 {
		timeout = 5
	}
	maxDepth := c.Recursion.MaxDepth
	if maxDepth == 0 {
		maxDepth = 10
	}

	// Determine recursion mode
	recursionMode := c.Recursion.Mode
	if recursionMode == "" {
		if c.Recursion.Enabled {
			recursionMode = RecursionModePartial // Default to partial when enabled
		} else {
			recursionMode = RecursionModeDisabled
		}
	}

	parsed := &ParsedConfig{
		Listen:      c.Listen,
		Zones:       make([]ParsedZone, 0),
		DNSSEC:      c.DNSSEC,
		Delegations: make([]ParsedDelegation, 0),
		Recursion: ParsedRecursion{
			Enabled:  c.Recursion.Enabled,
			Mode:     recursionMode,
			Upstream: c.Recursion.Upstream,
			Timeout:  timeout,
			MaxDepth: maxDepth,
		},
		ARecords:     make(map[string][]ParsedARecord),
		AAAARecords:  make(map[string][]ParsedAAAARecord),
		CNAMERecords: make(map[string]ParsedCNAMERecord),
		MXRecords:    make(map[string][]ParsedMXRecord),
		TXTRecords:   make(map[string][]ParsedTXTRecord),
		NSRecords:    make(map[string][]ParsedNSRecord),
		PTRRecords:   make(map[string]ParsedPTRRecord),
		SRVRecords:   make(map[string][]ParsedSRVRecord),
		SOARecords:   make(map[string]ParsedSOARecord),
		ALIASRecords: make(map[string]ParsedALIASRecord),
		CAARecords:   make(map[string][]ParsedCAARecord),
		SSHFPRecords: make(map[string][]ParsedSSHFPRecord),
		TLSARecords:  make(map[string][]ParsedTLSARecord),
		NAPTRRecords: make(map[string][]ParsedNAPTRRecord),
		SVCBRecords:  make(map[string][]ParsedSVCBRecord),
		HTTPSRecords: make(map[string][]ParsedHTTPSRecord),
		LOCRecords:   make(map[string][]ParsedLOCRecord),
	}

	// Parse zones
	for _, s := range c.Zones {
		// Determine zone type
		zoneType := s.Type
		if zoneType == "" {
			// Infer from fields
			if s.Subnet != "" {
				zoneType = ZoneTypeReverse
			} else {
				zoneType = ZoneTypeForward
			}
		}

		if zoneType == ZoneTypeReverse {
			// Reverse zone - parse subnet
			_, network, err := net.ParseCIDR(s.Subnet)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR for reverse zone: %w", err)
			}
			prefixLen, _ := network.Mask.Size()
			isIPv6 := network.IP.To4() == nil

			// Generate zone name from subnet if not provided
			zoneName := s.Name
			if zoneName == "" {
				zoneName = generateReverseZoneName(network, isIPv6)
			}

			parsed.Zones = append(parsed.Zones, ParsedZone{
				Name:        zoneName,
				Type:        ZoneTypeReverse,
				Network:     network,
				Domain:      s.Domain,
				StripPrefix: s.StripPrefix,
				PrefixLen:   prefixLen,
				TTL:         s.TTL,
				IsIPv6:      isIPv6,
			})
		} else {
			// Forward zone - just needs name
			parsed.Zones = append(parsed.Zones, ParsedZone{
				Name: s.Name,
				Type: ZoneTypeForward,
				TTL:  s.TTL,
			})
		}
	}

	// Sort zones by prefix length (most specific first)
	sort.Slice(parsed.Zones, func(i, j int) bool {
		return parsed.Zones[i].PrefixLen > parsed.Zones[j].PrefixLen
	})

	// Parse delegations
	for _, del := range c.Delegations {
		zone := normalizeName(del.Zone)

		// Parse nameservers
		nameservers := make([]string, 0, len(del.Nameservers))
		for _, ns := range del.Nameservers {
			nameservers = append(nameservers, normalizeName(ns))
		}

		// Parse glue records
		glue := make(map[string][]net.IP)
		for hostname, ips := range del.Glue {
			normalizedHost := normalizeName(hostname)
			for _, ipStr := range ips {
				if ip := net.ParseIP(ipStr); ip != nil {
					glue[normalizedHost] = append(glue[normalizedHost], ip)
				}
			}
		}

		ttl := del.TTL
		if ttl == 0 {
			ttl = 3600
		}

		parsed.Delegations = append(parsed.Delegations, ParsedDelegation{
			Zone:        zone,
			Nameservers: nameservers,
			Glue:        glue,
			Forward:     del.Forward,
			TTL:         ttl,
		})
	}

	// Sort delegations by zone length (most specific first - longest names first)
	sort.Slice(parsed.Delegations, func(i, j int) bool {
		return len(parsed.Delegations[i].Zone) > len(parsed.Delegations[j].Zone)
	})

	// Parse transfer configuration
	parsed.Transfer = ParsedTransfer{
		Enabled:  c.Transfer.Enabled,
		TSIGKeys: make(map[string]ParsedTSIGKey),
	}

	// Parse TSIG keys
	for _, key := range c.Transfer.TSIGKeys {
		keyName := normalizeName(key.Name)
		parsed.Transfer.TSIGKeys[keyName] = ParsedTSIGKey{
			Name:      keyName,
			Algorithm: key.Algorithm,
			Secret:    key.Secret,
		}
	}

	// Parse transfer ACLs
	for _, acl := range c.Transfer.ACLs {
		zone := acl.Zone
		if zone != "*" {
			zone = normalizeName(zone)
		}

		parsedACL := ParsedTransferACL{
			Zone:    zone,
			TSIGKey: acl.TSIGKey,
		}

		// Parse allow_transfer networks
		for _, cidr := range acl.AllowTransfer {
			if !strings.Contains(cidr, "/") {
				// Single IP - add /32 or /128
				if strings.Contains(cidr, ":") {
					cidr += "/128"
				} else {
					cidr += "/32"
				}
			}
			_, network, err := net.ParseCIDR(cidr)
			if err == nil {
				parsedACL.AllowTransfer = append(parsedACL.AllowTransfer, network)
			}
		}

		// Parse allow_notify networks
		for _, cidr := range acl.AllowNotify {
			if !strings.Contains(cidr, "/") {
				if strings.Contains(cidr, ":") {
					cidr += "/128"
				} else {
					cidr += "/32"
				}
			}
			_, network, err := net.ParseCIDR(cidr)
			if err == nil {
				parsedACL.AllowNotify = append(parsedACL.AllowNotify, network)
			}
		}

		parsed.Transfer.ACLs = append(parsed.Transfer.ACLs, parsedACL)
	}

	// Parse notify targets
	for _, notify := range c.Transfer.NotifyTargets {
		zone := normalizeName(notify.Zone)
		targets := make([]string, 0, len(notify.Targets))
		for _, t := range notify.Targets {
			if !strings.Contains(t, ":") {
				t += ":53" // Default port
			}
			targets = append(targets, t)
		}
		parsed.Transfer.NotifyTargets = append(parsed.Transfer.NotifyTargets, ParsedNotifyTarget{
			Zone:    zone,
			Targets: targets,
			TSIGKey: notify.TSIGKey,
		})
	}

	// Parse secondary zones
	for _, sz := range c.SecondaryZones {
		zone := normalizeName(sz.Zone)
		primaries := make([]string, 0, len(sz.Primaries))
		for _, p := range sz.Primaries {
			if !strings.Contains(p, ":") {
				p += ":53" // Default port
			}
			primaries = append(primaries, p)
		}

		parsedSZ := ParsedSecondaryZone{
			Zone:            zone,
			Primaries:       primaries,
			RefreshInterval: sz.RefreshInterval,
			RetryInterval:   sz.RetryInterval,
			DNSSECKeyURL:    sz.DNSSECKeyURL,
			DNSSECKeyToken:  sz.DNSSECKeyToken,
		}

		// Look up TSIG key details if specified
		if sz.TSIGKey != "" {
			keyName := normalizeName(sz.TSIGKey)
			if key, ok := parsed.Transfer.TSIGKeys[keyName]; ok {
				parsedSZ.TSIGKeyName = key.Name
				parsedSZ.TSIGSecret = key.Secret
				parsedSZ.TSIGAlgorithm = key.Algorithm
			}
		}

		parsed.SecondaryZones = append(parsed.SecondaryZones, parsedSZ)
	}

	// Parse A records
	for _, rec := range c.Records.A {
		ip := net.ParseIP(rec.IP)
		if ip == nil || ip.To4() == nil {
			continue
		}
		ip = ip.To4()
		name := normalizeName(rec.Name)
		parsed.ARecords[name] = append(parsed.ARecords[name], ParsedARecord{
			Name: name,
			IP:   ip,
			TTL:  rec.TTL,
		})
		// Create PTR if: ptr is nil (auto) and IP is in a zone, or ptr is explicitly true
		if shouldCreatePTR(rec.PTR, ip, parsed.Zones) {
			parsed.PTRRecords[ip.String()] = ParsedPTRRecord{
				IP:       ip,
				Hostname: name,
				TTL:      rec.TTL,
			}
		}
	}

	// Parse AAAA records
	for _, rec := range c.Records.AAAA {
		ip := net.ParseIP(rec.IP)
		if ip == nil {
			continue
		}
		// Make sure it's IPv6
		if ip.To4() != nil {
			continue
		}
		ip = ip.To16()
		name := normalizeName(rec.Name)
		parsed.AAAARecords[name] = append(parsed.AAAARecords[name], ParsedAAAARecord{
			Name: name,
			IP:   ip,
			TTL:  rec.TTL,
		})
		// Create PTR if: ptr is nil (auto) and IP is in a zone, or ptr is explicitly true
		if shouldCreatePTR(rec.PTR, ip, parsed.Zones) {
			parsed.PTRRecords[ip.String()] = ParsedPTRRecord{
				IP:       ip,
				Hostname: name,
				TTL:      rec.TTL,
			}
		}
	}

	// Parse CNAME records
	for _, rec := range c.Records.CNAME {
		name := normalizeName(rec.Name)
		parsed.CNAMERecords[name] = ParsedCNAMERecord{
			Name:   name,
			Target: normalizeName(rec.Target),
			TTL:    rec.TTL,
		}
	}

	// Parse MX records
	for _, rec := range c.Records.MX {
		name := normalizeName(rec.Name)
		parsed.MXRecords[name] = append(parsed.MXRecords[name], ParsedMXRecord{
			Name:     name,
			Priority: rec.Priority,
			Target:   normalizeName(rec.Target),
			TTL:      rec.TTL,
		})
	}

	// Parse TXT records
	for _, rec := range c.Records.TXT {
		name := normalizeName(rec.Name)
		parsed.TXTRecords[name] = append(parsed.TXTRecords[name], ParsedTXTRecord{
			Name:   name,
			Values: rec.Values,
			TTL:    rec.TTL,
		})
	}

	// Parse NS records
	for _, rec := range c.Records.NS {
		name := normalizeName(rec.Name)
		parsed.NSRecords[name] = append(parsed.NSRecords[name], ParsedNSRecord{
			Name:   name,
			Target: normalizeName(rec.Target),
			TTL:    rec.TTL,
		})
	}

	// Parse explicit PTR records
	for _, rec := range c.Records.PTR {
		ip := net.ParseIP(rec.IP)
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		} else {
			ip = ip.To16()
		}
		parsed.PTRRecords[ip.String()] = ParsedPTRRecord{
			IP:       ip,
			Hostname: normalizeName(rec.Hostname),
			TTL:      rec.TTL,
		}
	}

	// Parse SRV records
	for _, rec := range c.Records.SRV {
		name := normalizeName(rec.Name)
		parsed.SRVRecords[name] = append(parsed.SRVRecords[name], ParsedSRVRecord{
			Name:     name,
			Priority: rec.Priority,
			Weight:   rec.Weight,
			Port:     rec.Port,
			Target:   normalizeName(rec.Target),
			TTL:      rec.TTL,
		})
	}

	// Parse SOA records
	for _, rec := range c.Records.SOA {
		name := normalizeName(rec.Name)
		parsed.SOARecords[name] = ParsedSOARecord{
			Name:    name,
			MName:   normalizeName(rec.MName),
			RName:   normalizeName(rec.RName),
			Serial:  rec.Serial,
			Refresh: rec.Refresh,
			Retry:   rec.Retry,
			Expire:  rec.Expire,
			Minimum: rec.Minimum,
			TTL:     rec.TTL,
		}
	}

	// Parse ALIAS records
	for _, rec := range c.Records.ALIAS {
		name := normalizeName(rec.Name)
		parsed.ALIASRecords[name] = ParsedALIASRecord{
			Name:   name,
			Target: normalizeName(rec.Target),
			TTL:    rec.TTL,
			PTR:    rec.PTR,
		}
	}

	// Parse CAA records
	for _, rec := range c.Records.CAA {
		name := normalizeName(rec.Name)
		parsed.CAARecords[name] = append(parsed.CAARecords[name], ParsedCAARecord{
			Name:  name,
			Flag:  rec.Flag,
			Tag:   rec.Tag,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	// Parse SSHFP records
	for _, rec := range c.Records.SSHFP {
		name := normalizeName(rec.Name)
		parsed.SSHFPRecords[name] = append(parsed.SSHFPRecords[name], ParsedSSHFPRecord{
			Name:        name,
			Algorithm:   rec.Algorithm,
			Type:        rec.Type,
			Fingerprint: rec.Fingerprint,
			TTL:         rec.TTL,
		})
	}

	// Parse TLSA records
	for _, rec := range c.Records.TLSA {
		name := normalizeName(rec.Name)
		parsed.TLSARecords[name] = append(parsed.TLSARecords[name], ParsedTLSARecord{
			Name:         name,
			Usage:        rec.Usage,
			Selector:     rec.Selector,
			MatchingType: rec.MatchingType,
			Certificate:  rec.Certificate,
			TTL:          rec.TTL,
		})
	}

	// Parse NAPTR records
	for _, rec := range c.Records.NAPTR {
		name := normalizeName(rec.Name)
		parsed.NAPTRRecords[name] = append(parsed.NAPTRRecords[name], ParsedNAPTRRecord{
			Name:        name,
			Order:       rec.Order,
			Preference:  rec.Preference,
			Flags:       rec.Flags,
			Service:     rec.Service,
			Regexp:      rec.Regexp,
			Replacement: normalizeName(rec.Replacement),
			TTL:         rec.TTL,
		})
	}

	// Parse SVCB records
	for _, rec := range c.Records.SVCB {
		name := normalizeName(rec.Name)
		target := rec.Target
		if target != "" && target != "." {
			target = normalizeName(target)
		}
		parsed.SVCBRecords[name] = append(parsed.SVCBRecords[name], ParsedSVCBRecord{
			Name:     name,
			Priority: rec.Priority,
			Target:   target,
			Params:   rec.Params,
			TTL:      rec.TTL,
		})
	}

	// Parse HTTPS records
	for _, rec := range c.Records.HTTPS {
		name := normalizeName(rec.Name)
		target := rec.Target
		if target != "" && target != "." {
			target = normalizeName(target)
		}
		parsed.HTTPSRecords[name] = append(parsed.HTTPSRecords[name], ParsedHTTPSRecord{
			Name:     name,
			Priority: rec.Priority,
			Target:   target,
			Params:   rec.Params,
			TTL:      rec.TTL,
		})
	}

	// Parse LOC records
	for _, rec := range c.Records.LOC {
		name := normalizeName(rec.Name)
		parsed.LOCRecords[name] = append(parsed.LOCRecords[name], ParsedLOCRecord{
			Name:      name,
			Latitude:  rec.Latitude,
			Longitude: rec.Longitude,
			Altitude:  rec.Altitude,
			Size:      rec.Size,
			HorizPre:  rec.HorizPre,
			VertPre:   rec.VertPre,
			TTL:       rec.TTL,
		})
	}

	return parsed, nil
}

// generateReverseZoneName creates the in-addr.arpa or ip6.arpa zone name from a network
func generateReverseZoneName(network *net.IPNet, isIPv6 bool) string {
	if isIPv6 {
		// For IPv6, generate ip6.arpa format based on prefix length
		prefixLen, _ := network.Mask.Size()
		nibbles := prefixLen / 4
		ip := network.IP.To16()
		var parts []string
		for i := 0; i < nibbles; i++ {
			byteIdx := i / 2
			if i%2 == 0 {
				parts = append([]string{fmt.Sprintf("%x", ip[byteIdx]>>4)}, parts...)
			} else {
				parts = append([]string{fmt.Sprintf("%x", ip[byteIdx]&0xf)}, parts...)
			}
		}
		// Reverse the parts for proper ip6.arpa format
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		return strings.Join(parts, ".") + ".ip6.arpa"
	}
	// For IPv4, generate in-addr.arpa format
	ip := network.IP.To4()
	prefixLen, _ := network.Mask.Size()
	octets := prefixLen / 8
	var parts []string
	for i := octets - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%d", ip[i]))
	}
	return strings.Join(parts, ".") + ".in-addr.arpa"
}

// normalizeName ensures a hostname ends with a dot (FQDN format)
func normalizeName(name string) string {
	if name == "" {
		return name
	}
	if name[len(name)-1] != '.' {
		return name + "."
	}
	return name
}

// shouldCreatePTR determines whether to create a PTR record
// - If ptr is explicitly false, return false
// - If ptr is explicitly true, return true
// - If ptr is nil (default), return true only if the IP is in a configured zone
func shouldCreatePTR(ptr *bool, ip net.IP, zones []ParsedZone) bool {
	// Explicit false - don't create
	if ptr != nil && !*ptr {
		return false
	}
	// Explicit true - create
	if ptr != nil && *ptr {
		return true
	}
	// Auto (nil) - create only if IP is in a configured zone
	return isIPInZone(ip, zones)
}

// isIPInZone checks if an IP address falls within any configured reverse zone
func isIPInZone(ip net.IP, zones []ParsedZone) bool {
	isIPv6 := ip.To4() == nil
	for _, zone := range zones {
		// Skip forward zones - they don't have networks
		if zone.Type == ZoneTypeForward || zone.Network == nil {
			continue
		}
		if zone.IsIPv6 != isIPv6 {
			continue
		}
		if zone.Network.Contains(ip) {
			return true
		}
	}
	return false
}

// ShouldCreatePTR is the exported version for use by other packages
func ShouldCreatePTR(ptr *bool, ip net.IP, zones []ParsedZone) bool {
	return shouldCreatePTR(ptr, ip, zones)
}

// IsIPInZone is the exported version for use by other packages
func IsIPInZone(ip net.IP, zones []ParsedZone) bool {
	return isIPInZone(ip, zones)
}

// FindDelegation finds a delegation for the given query name
// Returns the delegation and true if found, nil and false otherwise
func (p *ParsedConfig) FindDelegation(name string) (*ParsedDelegation, bool) {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	// Delegations are sorted by zone length (most specific first)
	for i := range p.Delegations {
		del := &p.Delegations[i]
		// Check if name is at or under the delegated zone
		if name == del.Zone || strings.HasSuffix(name, "."+del.Zone) {
			return del, true
		}
	}
	return nil, false
}
