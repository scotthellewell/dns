package storage

import (
	"encoding/json"
	"time"
)

// MainTenantID is the ID of the main/system tenant.
const MainTenantID = "main"

// ZoneType represents the type of DNS zone.
type ZoneType string

const (
	ZoneTypeForward ZoneType = "forward"
	ZoneTypeReverse ZoneType = "reverse"
)

// ZoneStatus represents the status of a zone.
type ZoneStatus string

const (
	ZoneStatusActive            ZoneStatus = "active"
	ZoneStatusInactive          ZoneStatus = "inactive"
	ZoneStatusPendingDelegation ZoneStatus = "pending_delegation"
)

// Role constants
const (
	RoleSuperAdmin  = "super_admin"
	RoleTenantAdmin = "tenant_admin"
	RoleUser        = "user"
	RoleReadonly    = "readonly"
)

// Tenant represents an organization in the multi-tenant system.
type Tenant struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	IsMain      bool      `json:"is_main,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
}

// User represents a user account.
type User struct {
	ID                  string               `json:"id"`
	Username            string               `json:"username"`
	PasswordHash        string               `json:"password_hash"`
	Email               string               `json:"email,omitempty"`
	DisplayName         string               `json:"display_name,omitempty"`
	TenantID            string               `json:"tenant_id"`
	Role                string               `json:"role"`
	CreatedAt           time.Time            `json:"created_at"`
	LastLogin           time.Time            `json:"last_login,omitempty"`
	WebAuthnCredentials []WebAuthnCredential `json:"webauthn_credentials,omitempty"`
}

// WebAuthnCredential represents a stored passkey credential.
type WebAuthnCredential struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	CredentialID    []byte     `json:"credential_id"`
	PublicKey       []byte     `json:"public_key"`
	AttestationType string     `json:"attestation_type"`
	AAGUID          []byte     `json:"aaguid"`
	SignCount       uint32     `json:"sign_count"`
	BackupEligible  bool       `json:"backup_eligible"`
	BackupState     bool       `json:"backup_state"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsed        *time.Time `json:"last_used,omitempty"`
}

// Session represents an authenticated session.
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	TenantID     string    `json:"tenant_id"`
	TenantName   string    `json:"tenant_name,omitempty"`
	Role         string    `json:"role"`
	IsSuperAdmin bool      `json:"is_super_admin"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	AuthMethod   string    `json:"auth_method"`
}

// APIKey represents an API key for programmatic access.
type APIKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	KeyHash     string     `json:"key_hash"`
	KeyPrefix   string     `json:"key_prefix"`
	TenantID    string     `json:"tenant_id"`
	Permissions []string   `json:"permissions"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
	CreatedBy   string     `json:"created_by"`
}

// Zone represents a DNS zone.
type Zone struct {
	Name         string     `json:"name"`
	TenantID     string     `json:"tenant_id"`
	Type         ZoneType   `json:"type"`
	Subnet       string     `json:"subnet,omitempty"`
	Domain       string     `json:"domain,omitempty"`
	Status       ZoneStatus `json:"status"`
	StatusReason string     `json:"status_reason,omitempty"`
	Serial       uint32     `json:"serial"`
	TTL          uint32     `json:"ttl"`
	// SOA fields
	PrimaryNS     string    `json:"primary_ns,omitempty"`
	AdminEmail    string    `json:"admin_email,omitempty"`
	Refresh       uint32    `json:"refresh,omitempty"`
	Retry         uint32    `json:"retry,omitempty"`
	Expire        uint32    `json:"expire,omitempty"`
	Minimum       uint32    `json:"minimum,omitempty"`
	NotifyTargets []string  `json:"notify_targets,omitempty"`
	AllowTransfer []string  `json:"allow_transfer,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Record represents a DNS record.
type Record struct {
	ID           string          `json:"id"`
	Zone         string          `json:"zone"`
	Name         string          `json:"name"`
	Type         string          `json:"type"`
	TTL          uint32          `json:"ttl"`
	ViewID       string          `json:"view_id,omitempty"`
	Weight       int             `json:"weight,omitempty"`
	Enabled      bool            `json:"enabled"`
	AutoPTR      bool            `json:"auto_ptr,omitempty"`
	AutoManaged  bool            `json:"auto_managed,omitempty"`
	SourceRecord string          `json:"source_record,omitempty"`
	Data         json.RawMessage `json:"data"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// Record data types for each DNS record type

// ARecordData holds A record data.
type ARecordData struct {
	IP string `json:"ip"`
}

// AAAARecordData holds AAAA record data.
type AAAARecordData struct {
	IP string `json:"ip"`
}

// CNAMERecordData holds CNAME record data.
type CNAMERecordData struct {
	Target string `json:"target"`
}

// MXRecordData holds MX record data.
type MXRecordData struct {
	Priority uint16 `json:"priority"`
	Target   string `json:"target"`
}

// TXTRecordData holds TXT record data.
type TXTRecordData struct {
	Values []string `json:"values"`
}

// NSRecordData holds NS record data.
type NSRecordData struct {
	Target string `json:"target"`
}

// PTRRecordData holds PTR record data.
type PTRRecordData struct {
	Target string `json:"target"`
}

// SRVRecordData holds SRV record data.
type SRVRecordData struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

// SOARecordData holds SOA record data.
type SOARecordData struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// ALIASRecordData holds ALIAS record data.
type ALIASRecordData struct {
	Target string `json:"target"`
}

// CAARecordData holds CAA record data.
type CAARecordData struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// SSHFPRecordData holds SSHFP record data.
type SSHFPRecordData struct {
	Algorithm   uint8  `json:"algorithm"`
	Type        uint8  `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// TLSARecordData holds TLSA record data.
type TLSARecordData struct {
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
	Certificate  string `json:"certificate"`
}

// NAPTRRecordData holds NAPTR record data.
type NAPTRRecordData struct {
	Order       uint16 `json:"order"`
	Preference  uint16 `json:"preference"`
	Flags       string `json:"flags"`
	Service     string `json:"service"`
	Regexp      string `json:"regexp"`
	Replacement string `json:"replacement"`
}

// SVCBRecordData holds SVCB record data.
type SVCBRecordData struct {
	Priority uint16            `json:"priority"`
	Target   string            `json:"target"`
	Params   map[string]string `json:"params"`
}

// HTTPSRecordData holds HTTPS record data.
type HTTPSRecordData struct {
	Priority uint16            `json:"priority"`
	Target   string            `json:"target"`
	Params   map[string]string `json:"params"`
}

// LOCRecordData holds LOC record data.
type LOCRecordData struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Altitude  float64 `json:"altitude"`
	Size      float64 `json:"size"`
	HorizPre  float64 `json:"horiz_pre"`
	VertPre   float64 `json:"vert_pre"`
}

// DSRecordData holds DS (Delegation Signer) record data for DNSSEC.
type DSRecordData struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
}

// DNSKEYRecordData holds DNSKEY record data for DNSSEC.
type DNSKEYRecordData struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// Delegation represents a zone delegation.
type Delegation struct {
	ParentZone      string              `json:"parent_zone"`
	ChildZone       string              `json:"child_zone"`
	Nameservers     []string            `json:"nameservers"`
	Glue            map[string][]string `json:"glue,omitempty"`
	DSRecords       []DSRecordData      `json:"ds_records,omitempty"` // DS records for DNSSEC chain of trust
	GrantedToTenant string              `json:"granted_to_tenant,omitempty"`
	Active          bool                `json:"active"`
	TTL             uint32              `json:"ttl"`
	CreatedAt       time.Time           `json:"created_at"`
	CreatedBy       string              `json:"created_by"`
}

// SecondaryZone represents a zone to be pulled from a primary server.
type SecondaryZone struct {
	Zone            string    `json:"zone"`
	TenantID        string    `json:"tenant_id"`
	Primaries       []string  `json:"primaries"`
	TSIGKey         string    `json:"tsig_key,omitempty"`
	RefreshInterval uint32    `json:"refresh_interval,omitempty"`
	RetryInterval   uint32    `json:"retry_interval,omitempty"`
	LastSync        time.Time `json:"last_sync,omitempty"`
	NextSync        time.Time `json:"next_sync,omitempty"`
	SyncError       string    `json:"sync_error,omitempty"`
	Serial          uint32    `json:"serial,omitempty"`
	// DNSSEC key sharing
	DNSSECKeyToken string `json:"dnssec_key_token,omitempty"` // Token to fetch keys from primary
	DNSSECKeyURL   string `json:"dnssec_key_url,omitempty"`   // URL of primary server's key endpoint
}

// View represents a DNS view for split-horizon.
type View struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	TenantID   string   `json:"tenant_id"`
	MatchCIDRs []string `json:"match_cidrs"`
	Priority   int      `json:"priority"`
}

// BlockEntry represents a blocklist entry.
type BlockEntry struct {
	Type      string     `json:"type"`
	Value     string     `json:"value"`
	Action    string     `json:"action"`
	Reason    string     `json:"reason,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy string     `json:"created_by"`
}

// DNSSECKeys holds the DNSSEC keys for a zone.
type DNSSECKeys struct {
	ZoneName           string    `json:"zone_name"`
	Algorithm          string    `json:"algorithm"`
	Enabled            bool      `json:"enabled"`
	KSKPrivate         string    `json:"ksk_private"`
	KSKPublic          string    `json:"ksk_public"`
	KSKKeyTag          uint16    `json:"ksk_key_tag"`
	KSKCreated         time.Time `json:"ksk_created"`
	ZSKPrivate         string    `json:"zsk_private"`
	ZSKPublic          string    `json:"zsk_public"`
	ZSKKeyTag          uint16    `json:"zsk_key_tag"`
	ZSKCreated         time.Time `json:"zsk_created"`
	PreviousZSKPrivate string    `json:"previous_zsk_private,omitempty"`
	PreviousZSKPublic  string    `json:"previous_zsk_public,omitempty"`
	PreviousZSKKeyTag  uint16    `json:"previous_zsk_key_tag,omitempty"`
	DSRecord           string    `json:"ds_record,omitempty"`
	KeyToken           string    `json:"key_token,omitempty"`        // Token for secondary servers to fetch keys
	KSKRotationDue     bool      `json:"ksk_rotation_due,omitempty"` // Advisory flag when KSK should be rotated
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID         string          `json:"id"`
	Timestamp  time.Time       `json:"timestamp"`
	UserID     string          `json:"user_id"`
	Username   string          `json:"username"`
	TenantID   string          `json:"tenant_id"`
	Action     string          `json:"action"`
	Resource   string          `json:"resource"`
	ResourceID string          `json:"resource_id"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
	IPAddress  string          `json:"ip_address,omitempty"`
}

// QueryLogEntry represents a DNS query log entry.
type QueryLogEntry struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"client_ip"`
	QueryName    string    `json:"query_name"`
	QueryType    string    `json:"query_type"`
	ResponseCode string    `json:"response_code"`
	ResponseTime int64     `json:"response_time_us"`
	Cached       bool      `json:"cached"`
	ViewID       string    `json:"view_id,omitempty"`
}

// Config models

// ServerConfig holds server configuration.
type ServerConfig struct {
	DNS DNSConfig `json:"dns"`
	DoT DoTConfig `json:"dot"`
	DoH DoHConfig `json:"doh"`
	Web WebConfig `json:"web"`
}

// DNSConfig holds DNS server configuration.
type DNSConfig struct {
	Enabled bool   `json:"enabled"`
	UDPPort int    `json:"udp_port"`
	TCPPort int    `json:"tcp_port"`
	Address string `json:"address"`
}

// DoTConfig holds DNS over TLS configuration.
type DoTConfig struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Address string `json:"address"`
}

// DoHConfig holds DNS over HTTPS configuration.
type DoHConfig struct {
	Enabled    bool   `json:"enabled"`
	Standalone bool   `json:"standalone"`
	Port       int    `json:"port"`
	Address    string `json:"address"`
	Path       string `json:"path"`
}

// WebConfig holds web UI configuration.
type WebConfig struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Address string `json:"address"`
	TLS     bool   `json:"tls"`
}

// RecursionConfig holds recursion settings.
type RecursionConfig struct {
	Enabled  bool     `json:"enabled"`
	Mode     string   `json:"mode"`
	Upstream []string `json:"upstream"`
	Timeout  int      `json:"timeout"`
	MaxDepth int      `json:"max_depth"`
}

// RateLimitConfig holds rate limiting settings.
type RateLimitConfig struct {
	Enabled         bool     `json:"enabled"`
	ResponsesPerSec int      `json:"responses_per_sec"`
	SlipRatio       int      `json:"slip_ratio"`
	WindowSeconds   int      `json:"window_seconds"`
	WhitelistCIDRs  []string `json:"whitelist_cidrs"`
}

// QueryLogConfig holds query logging settings.
type QueryLogConfig struct {
	Enabled     bool `json:"enabled"`
	LogSuccess  bool `json:"log_success"`
	LogNXDomain bool `json:"log_nxdomain"`
	LogErrors   bool `json:"log_errors"`
	Retention   int  `json:"retention_days"`
}

// TransferConfig holds zone transfer settings.
type TransferConfig struct {
	Enabled       bool      `json:"enabled"`
	TSIGKeys      []TSIGKey `json:"tsig_keys"`
	DefaultACL    []string  `json:"default_acl"`
	NotifyEnabled bool      `json:"notify_enabled"`
}

// TSIGKey represents a TSIG key for zone transfers.
type TSIGKey struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Secret    string `json:"secret"`
}

// OIDCConfig holds OpenID Connect configuration.
type OIDCConfig struct {
	Enabled       bool     `json:"enabled"`
	ProviderURL   string   `json:"provider_url"`
	ProviderName  string   `json:"provider_name"`
	ProviderIcon  string   `json:"provider_icon,omitempty"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURL   string   `json:"redirect_url"`
	Scopes        []string `json:"scopes"`
	AdminGroups   []string `json:"admin_groups,omitempty"`
	AllowedGroups []string `json:"allowed_groups,omitempty"`
}

// WebAuthnConfig holds WebAuthn/Passkey configuration.
type WebAuthnConfig struct {
	Enabled       bool     `json:"enabled"`
	RPDisplayName string   `json:"rp_display_name"`
	RPID          string   `json:"rp_id"`
	RPOrigins     []string `json:"rp_origins"`
}

// TLSCertificate holds TLS certificate data.
type TLSCertificate struct {
	Domain        string    `json:"domain"`
	CertPEM       string    `json:"cert_pem"`
	KeyPEM        string    `json:"key_pem"`
	AutoGenerated bool      `json:"auto_generated"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DNSNames      []string  `json:"dns_names"`
	IPAddresses   []string  `json:"ip_addresses"`
}

// ACMEConfig holds ACME configuration.
type ACMEConfig struct {
	Enabled       bool     `json:"enabled"`
	Email         string   `json:"email"`
	Domains       []string `json:"domains"`
	UseStaging    bool     `json:"use_staging"`
	ChallengeType string   `json:"challenge_type"`
	AutoRenew     bool     `json:"auto_renew"`
	RenewBefore   int      `json:"renew_before_days"`
}

// ACMEState holds ACME state.
type ACMEState struct {
	Email           string    `json:"email"`
	Domains         []string  `json:"domains"`
	LastRenewal     time.Time `json:"last_renewal"`
	NextRenewal     time.Time `json:"next_renewal"`
	RegistrationURI string    `json:"registration_uri"`
}
