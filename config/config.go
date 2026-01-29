package config

import (
	"encoding/json"
	"net"
	"os"
	"sort"
	"strings"
)

// ZoneConfig defines configuration for an IPv4 or IPv6 zone
// This handles both forward DNS pattern generation and reverse DNS
type ZoneConfig struct {
	// Subnet in CIDR notation (e.g., "2602:FF29::/40" or "23.148.184.0/24")
	Subnet string `json:"subnet"`
	// Domain suffix for generated hostnames (e.g., "ip6.example.com")
	Domain string `json:"domain"`
	// StripPrefix - if true, strip the subnet prefix from generated names
	// For IPv6: 2602:ff29:0001::1 with /40 becomes 01-0001-0000-0000-0000-0001
	// For IPv4: 23.148.184.5 with /24 becomes 5
	StripPrefix bool `json:"strip_prefix"`
	// TTL for DNS records in seconds
	TTL uint32 `json:"ttl"`
}

// ARecord defines an A (IPv4) record
type ARecord struct {
	Name string `json:"name"` // Hostname (e.g., "gateway.example.com")
	IP   string `json:"ip"`   // IPv4 address
	TTL  uint32 `json:"ttl"`  // TTL in seconds
	// PTR controls auto-creation of PTR record. Default is true if IP is in a configured zone.
	// Set to false to disable PTR creation.
	PTR *bool `json:"ptr,omitempty"`
}

// AAAARecord defines an AAAA (IPv6) record
type AAAARecord struct {
	Name string `json:"name"` // Hostname (e.g., "gateway.example.com")
	IP   string `json:"ip"`   // IPv6 address
	TTL  uint32 `json:"ttl"`  // TTL in seconds
	// PTR controls auto-creation of PTR record. Default is true if IP is in a configured zone.
	// Set to false to disable PTR creation.
	PTR *bool `json:"ptr,omitempty"`
}

// CNAMERecord defines a CNAME record
type CNAMERecord struct {
	Name   string `json:"name"`   // Hostname (e.g., "www.example.com")
	Target string `json:"target"` // Target hostname (e.g., "example.com")
	TTL    uint32 `json:"ttl"`    // TTL in seconds
}

// MXRecord defines an MX record
type MXRecord struct {
	Name     string `json:"name"`     // Domain (e.g., "example.com")
	Priority uint16 `json:"priority"` // MX priority
	Target   string `json:"target"`   // Mail server hostname
	TTL      uint32 `json:"ttl"`      // TTL in seconds
}

// TXTRecord defines a TXT record
type TXTRecord struct {
	Name   string   `json:"name"`   // Hostname (e.g., "example.com")
	Values []string `json:"values"` // TXT values
	TTL    uint32   `json:"ttl"`    // TTL in seconds
}

// NSRecord defines an NS record
type NSRecord struct {
	Name   string `json:"name"`   // Zone (e.g., "example.com")
	Target string `json:"target"` // Nameserver hostname
	TTL    uint32 `json:"ttl"`    // TTL in seconds
}

// PTRRecord defines a PTR record explicitly
type PTRRecord struct {
	IP       string `json:"ip"`       // IP address
	Hostname string `json:"hostname"` // Hostname to return
	TTL      uint32 `json:"ttl"`      // TTL in seconds
}

// SRVRecord defines an SRV record for service discovery
type SRVRecord struct {
	Name     string `json:"name"`     // Service name (e.g., "_sip._tcp.example.com")
	Priority uint16 `json:"priority"` // Priority (lower = preferred)
	Weight   uint16 `json:"weight"`   // Weight for load balancing
	Port     uint16 `json:"port"`     // Port number
	Target   string `json:"target"`   // Target hostname
	TTL      uint32 `json:"ttl"`      // TTL in seconds
}

// SOARecord defines an SOA (Start of Authority) record
type SOARecord struct {
	Name    string `json:"name"`    // Zone name (e.g., "example.com")
	MName   string `json:"mname"`   // Primary nameserver
	RName   string `json:"rname"`   // Responsible person email (use . instead of @)
	Serial  uint32 `json:"serial"`  // Serial number (typically YYYYMMDDNN)
	Refresh uint32 `json:"refresh"` // Refresh interval in seconds
	Retry   uint32 `json:"retry"`   // Retry interval in seconds
	Expire  uint32 `json:"expire"`  // Expire time in seconds
	Minimum uint32 `json:"minimum"` // Minimum TTL (negative cache TTL)
	TTL     uint32 `json:"ttl"`     // TTL in seconds
}

// ALIASRecord defines an ALIAS/ANAME record (CNAME-like for apex domains)
// Returns the A/AAAA records of the target instead of a CNAME
type ALIASRecord struct {
	Name   string `json:"name"`   // Hostname (typically apex like "example.com")
	Target string `json:"target"` // Target to resolve (e.g., "cdn.example.net")
	TTL    uint32 `json:"ttl"`    // TTL in seconds
	// PTR controls auto-creation of PTR record for resolved IPs. Default is true if IP is in a configured zone.
	// Set to false to disable PTR creation.
	PTR *bool `json:"ptr,omitempty"`
}

// CAARecord defines a CAA (Certificate Authority Authorization) record
type CAARecord struct {
	Name  string `json:"name"`  // Hostname
	Flag  uint8  `json:"flag"`  // Critical flag (0 or 128)
	Tag   string `json:"tag"`   // Tag: "issue", "issuewild", or "iodef"
	Value string `json:"value"` // CA domain or URL
	TTL   uint32 `json:"ttl"`   // TTL in seconds
}

// SSHFPRecord defines an SSHFP (SSH Fingerprint) record
type SSHFPRecord struct {
	Name        string `json:"name"`        // Hostname
	Algorithm   uint8  `json:"algorithm"`   // 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519
	Type        uint8  `json:"type"`        // 1=SHA-1, 2=SHA-256
	Fingerprint string `json:"fingerprint"` // Hex-encoded fingerprint
	TTL         uint32 `json:"ttl"`         // TTL in seconds
}

// TLSARecord defines a TLSA (DANE TLS Certificate) record
type TLSARecord struct {
	Name         string `json:"name"`          // Name (e.g., "_443._tcp.example.com")
	Usage        uint8  `json:"usage"`         // 0=CA, 1=Service, 2=Trust anchor, 3=Domain-issued
	Selector     uint8  `json:"selector"`      // 0=Full cert, 1=SubjectPublicKeyInfo
	MatchingType uint8  `json:"matching_type"` // 0=Exact, 1=SHA-256, 2=SHA-512
	Certificate  string `json:"certificate"`   // Hex-encoded cert data
	TTL          uint32 `json:"ttl"`           // TTL in seconds
}

// NAPTRRecord defines a NAPTR (Naming Authority Pointer) record
type NAPTRRecord struct {
	Name        string `json:"name"`        // Domain name
	Order       uint16 `json:"order"`       // Order (lower = first)
	Preference  uint16 `json:"preference"`  // Preference (lower = preferred)
	Flags       string `json:"flags"`       // Flags (e.g., "s", "a", "u")
	Service     string `json:"service"`     // Service (e.g., "SIP+D2U")
	Regexp      string `json:"regexp"`      // Regular expression
	Replacement string `json:"replacement"` // Replacement domain
	TTL         uint32 `json:"ttl"`         // TTL in seconds
}

// SVCBRecord defines an SVCB (Service Binding) record
type SVCBRecord struct {
	Name     string            `json:"name"`     // Name (e.g., "_dns.example.com")
	Priority uint16            `json:"priority"` // Priority (0 = alias mode)
	Target   string            `json:"target"`   // Target name
	Params   map[string]string `json:"params"`   // Parameters (alpn, port, ipv4hint, ipv6hint, etc.)
	TTL      uint32            `json:"ttl"`      // TTL in seconds
}

// HTTPSRecord defines an HTTPS (HTTPS-specific SVCB) record
type HTTPSRecord struct {
	Name     string            `json:"name"`     // Name (e.g., "example.com")
	Priority uint16            `json:"priority"` // Priority (0 = alias mode)
	Target   string            `json:"target"`   // Target name (. for same name)
	Params   map[string]string `json:"params"`   // Parameters (alpn, port, ipv4hint, ipv6hint, ech, etc.)
	TTL      uint32            `json:"ttl"`      // TTL in seconds
}

// LOCRecord defines a LOC (Location) record
type LOCRecord struct {
	Name      string  `json:"name"`      // Hostname
	Latitude  float64 `json:"latitude"`  // Latitude in decimal degrees
	Longitude float64 `json:"longitude"` // Longitude in decimal degrees
	Altitude  float64 `json:"altitude"`  // Altitude in meters
	Size      float64 `json:"size"`      // Size/diameter in meters
	HorizPre  float64 `json:"horiz_pre"` // Horizontal precision in meters
	VertPre   float64 `json:"vert_pre"`  // Vertical precision in meters
	TTL       uint32  `json:"ttl"`       // TTL in seconds
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
	Network     *net.IPNet
	Domain      string
	StripPrefix bool
	PrefixLen   int // Number of bits in the prefix
	TTL         uint32
	IsIPv6      bool
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
	Zone        string            // Zone name (FQDN with trailing dot)
	Nameservers []string          // NS hostnames (FQDN with trailing dot)
	Glue        map[string][]net.IP // Nameserver hostname -> IP addresses
	Forward     bool              // Whether to forward queries or just refer
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
	Zone          string     // Zone name (FQDN) or "*"
	AllowTransfer []*net.IPNet // Networks allowed to request transfers
	AllowNotify   []*net.IPNet // Networks allowed to send NOTIFY
	TSIGKey       string     // Required TSIG key name (optional)
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
}

// ParsedConfig holds the parsed configuration
type ParsedConfig struct {
	Listen         string
	Zones          []ParsedZone           // Sorted by prefix length (most specific first)
	DNSSEC         []DNSSECKeyConfig      // DNSSEC configurations
	Recursion      ParsedRecursion        // Recursion settings
	Delegations    []ParsedDelegation     // Zone delegations
	Transfer       ParsedTransfer         // Zone transfer settings
	SecondaryZones []ParsedSecondaryZone  // Secondary zones to pull via AXFR
	
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
		_, network, err := net.ParseCIDR(s.Subnet)
		if err != nil {
			return nil, err
		}
		prefixLen, _ := network.Mask.Size()
		isIPv6 := network.IP.To4() == nil

		parsed.Zones = append(parsed.Zones, ParsedZone{
			Network:     network,
			Domain:      s.Domain,
			StripPrefix: s.StripPrefix,
			PrefixLen:   prefixLen,
			TTL:         s.TTL,
			IsIPv6:      isIPv6,
		})
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

// isIPInZone checks if an IP address falls within any configured zone
func isIPInZone(ip net.IP, zones []ParsedZone) bool {
	isIPv6 := ip.To4() == nil
	for _, zone := range zones {
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
