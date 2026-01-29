package resolver

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/scott/dns/config"
)

// Resolver handles DNS resolution for configured subnets
type Resolver struct {
	config *config.ParsedConfig
}

// New creates a new Resolver with the given configuration
func New(cfg *config.ParsedConfig) *Resolver {
	return &Resolver{config: cfg}
}

// IPv6ToReverseName converts an IPv6 address to its reverse DNS name
func IPv6ToReverseName(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}

	var parts []string
	for i := 15; i >= 0; i-- {
		b := ip[i]
		parts = append(parts, fmt.Sprintf("%x", b&0x0f))
		parts = append(parts, fmt.Sprintf("%x", (b>>4)&0x0f))
	}
	return strings.Join(parts, ".") + ".ip6.arpa."
}

// IPv4ToReverseName converts an IPv4 address to its reverse DNS name
func IPv4ToReverseName(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip[3], ip[2], ip[1], ip[0])
}

// ReverseNameToIPv6 converts a reverse DNS name to an IPv6 address
func ReverseNameToIPv6(name string) net.IP {
	name = strings.TrimSuffix(strings.ToLower(name), ".ip6.arpa.")
	if name == "" {
		return nil
	}

	parts := strings.Split(name, ".")
	if len(parts) != 32 {
		return nil
	}

	ip := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		highIdx := 31 - (i * 2)
		lowIdx := 30 - (i * 2)

		high := hexCharToNibble(parts[highIdx])
		low := hexCharToNibble(parts[lowIdx])
		if high < 0 || low < 0 {
			return nil
		}
		ip[i] = byte(high<<4 | low)
	}

	return ip
}

// ReverseNameToIPv4 converts a reverse DNS name to an IPv4 address
func ReverseNameToIPv4(name string) net.IP {
	name = strings.TrimSuffix(strings.ToLower(name), ".in-addr.arpa.")
	if name == "" {
		return nil
	}

	parts := strings.Split(name, ".")
	if len(parts) != 4 {
		return nil
	}

	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		val, err := strconv.Atoi(parts[3-i])
		if err != nil || val < 0 || val > 255 {
			return nil
		}
		ip[i] = byte(val)
	}

	return ip
}

func hexCharToNibble(s string) int {
	if len(s) != 1 {
		return -1
	}
	c := s[0]
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// IPv6ToDashedExpanded returns the fully expanded IPv6 with dashes instead of colons
func IPv6ToDashedExpanded(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}

	groups := make([]string, 8)
	for i := 0; i < 8; i++ {
		groups[i] = fmt.Sprintf("%02x%02x", ip[i*2], ip[i*2+1])
	}
	return strings.Join(groups, "-")
}

// IPv6ToDashedStripped returns the IPv6 with dashes, stripping the prefix portion
func IPv6ToDashedStripped(ip net.IP, prefixLen int) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}

	nibblesToSkip := prefixLen / 4

	var fullHex strings.Builder
	for _, b := range ip {
		fmt.Fprintf(&fullHex, "%02x", b)
	}
	hex := fullHex.String()

	remaining := hex[nibblesToSkip:]

	var result strings.Builder
	pos := 0

	startOffset := nibblesToSkip % 4
	if startOffset > 0 {
		firstGroupLen := 4 - startOffset
		if firstGroupLen > len(remaining) {
			firstGroupLen = len(remaining)
		}
		result.WriteString(remaining[:firstGroupLen])
		pos = firstGroupLen
	}

	for pos < len(remaining) {
		if result.Len() > 0 {
			result.WriteString("-")
		}
		end := pos + 4
		if end > len(remaining) {
			end = len(remaining)
		}
		result.WriteString(remaining[pos:end])
		pos = end
	}

	return result.String()
}

// IPv4ToHostPart returns just the host portion of an IPv4 address given the prefix length
func IPv4ToHostPart(ip net.IP, prefixLen int) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}

	fullOctets := prefixLen / 8
	remainingBits := prefixLen % 8

	var parts []string

	if remainingBits > 0 && fullOctets < 4 {
		mask := byte(0xff >> remainingBits)
		hostPart := ip[fullOctets] & mask
		parts = append(parts, strconv.Itoa(int(hostPart)))
		fullOctets++
	}

	for i := fullOctets; i < 4; i++ {
		parts = append(parts, strconv.Itoa(int(ip[i])))
	}

	return strings.Join(parts, "-")
}

// GenerateHostname creates a hostname for an IP address using the zone configuration
func GenerateHostname(ip net.IP, zone config.ParsedZone) string {
	var hostPart string

	if zone.IsIPv6 {
		if zone.StripPrefix {
			hostPart = IPv6ToDashedStripped(ip, zone.PrefixLen)
		} else {
			hostPart = IPv6ToDashedExpanded(ip)
		}
	} else {
		if zone.StripPrefix {
			hostPart = IPv4ToHostPart(ip, zone.PrefixLen)
		} else {
			ip4 := ip.To4()
			hostPart = fmt.Sprintf("%d-%d-%d-%d", ip4[0], ip4[1], ip4[2], ip4[3])
		}
	}

	domain := zone.Domain
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}

	return hostPart + domain
}

// LookupPTR resolves a reverse DNS query
func (r *Resolver) LookupPTR(reverseName string) (hostname string, ttl uint32, found bool) {
	reverseName = strings.ToLower(reverseName)

	var ip net.IP
	var isIPv6 bool

	if strings.HasSuffix(reverseName, ".ip6.arpa.") {
		ip = ReverseNameToIPv6(reverseName)
		isIPv6 = true
	} else if strings.HasSuffix(reverseName, ".in-addr.arpa.") {
		ip = ReverseNameToIPv4(reverseName)
		isIPv6 = false
	} else {
		return "", 0, false
	}

	if ip == nil {
		return "", 0, false
	}

	lookupIP := ip
	if !isIPv6 {
		lookupIP = ip.To4()
	}

	// Check static PTR records first (from Records.PTR and A/AAAA with ptr)
	if ptr, ok := r.config.PTRRecords[lookupIP.String()]; ok {
		return ptr.Hostname, ptr.TTL, true
	}

	for _, zone := range r.config.Zones {
		if zone.IsIPv6 != isIPv6 {
			continue
		}
		if zone.Network.Contains(ip) {
			hostname := GenerateHostname(ip, zone)
			return hostname, zone.TTL, true
		}
	}

	return "", 0, false
}

// LookupA resolves a forward DNS query for A records (IPv4)
func (r *Resolver) LookupA(hostname string) (ip net.IP, ttl uint32, found bool) {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	// Check static A records first
	if records, ok := r.config.ARecords[hostname]; ok && len(records) > 0 {
		// Return the first record (caller can use LookupAAll for all)
		return records[0].IP, records[0].TTL, true
	}

	for _, zone := range r.config.Zones {
		if zone.IsIPv6 {
			continue
		}
		if ip, ok := r.matchHostnameToIP(hostname, zone); ok {
			if zone.Network.Contains(ip) {
				return ip, zone.TTL, true
			}
		}
	}

	return nil, 0, false
}

// LookupAAll returns all A records for a hostname
func (r *Resolver) LookupAAll(hostname string) []config.ParsedARecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.ARecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupAAAA resolves a forward DNS query for AAAA records (IPv6)
func (r *Resolver) LookupAAAA(hostname string) (ip net.IP, ttl uint32, found bool) {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	// Check static AAAA records first
	if records, ok := r.config.AAAARecords[hostname]; ok && len(records) > 0 {
		return records[0].IP, records[0].TTL, true
	}

	for _, zone := range r.config.Zones {
		if !zone.IsIPv6 {
			continue
		}
		if ip, ok := r.matchHostnameToIP(hostname, zone); ok {
			if zone.Network.Contains(ip) {
				return ip, zone.TTL, true
			}
		}
	}

	return nil, 0, false
}

// LookupAAAAAll returns all AAAA records for a hostname
func (r *Resolver) LookupAAAAAll(hostname string) []config.ParsedAAAARecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.AAAARecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupCNAME resolves a CNAME query
func (r *Resolver) LookupCNAME(hostname string) (target string, ttl uint32, found bool) {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if record, ok := r.config.CNAMERecords[hostname]; ok {
		return record.Target, record.TTL, true
	}
	return "", 0, false
}

// LookupMX resolves MX records for a domain
func (r *Resolver) LookupMX(hostname string) []config.ParsedMXRecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.MXRecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupTXT resolves TXT records for a hostname
func (r *Resolver) LookupTXT(hostname string) []config.ParsedTXTRecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.TXTRecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupNS resolves NS records for a zone
func (r *Resolver) LookupNS(hostname string) []config.ParsedNSRecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.NSRecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupSRV resolves SRV records for a service
func (r *Resolver) LookupSRV(hostname string) []config.ParsedSRVRecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.SRVRecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupSOA resolves SOA record for a zone
func (r *Resolver) LookupSOA(hostname string) (config.ParsedSOARecord, bool) {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if record, ok := r.config.SOARecords[hostname]; ok {
		return record, true
	}
	return config.ParsedSOARecord{}, false
}

// LookupALIAS resolves ALIAS record and returns the target's A/AAAA records
// Returns the target hostname for the caller to resolve
func (r *Resolver) LookupALIAS(hostname string) (target string, ttl uint32, found bool) {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if record, ok := r.config.ALIASRecords[hostname]; ok {
		return record.Target, record.TTL, true
	}
	return "", 0, false
}

// LookupCAA resolves CAA records for a hostname
func (r *Resolver) LookupCAA(hostname string) []config.ParsedCAARecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.CAARecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupSSHFP returns SSHFP records for a hostname
func (r *Resolver) LookupSSHFP(hostname string) []config.ParsedSSHFPRecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.SSHFPRecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupTLSA returns TLSA records for a hostname (e.g., _443._tcp.example.com)
func (r *Resolver) LookupTLSA(hostname string) []config.ParsedTLSARecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.TLSARecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupNAPTR returns NAPTR records for a hostname
func (r *Resolver) LookupNAPTR(hostname string) []config.ParsedNAPTRRecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.NAPTRRecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupSVCB returns SVCB records for a hostname
func (r *Resolver) LookupSVCB(hostname string) []config.ParsedSVCBRecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.SVCBRecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupHTTPS returns HTTPS records for a hostname
func (r *Resolver) LookupHTTPS(hostname string) []config.ParsedHTTPSRecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.HTTPSRecords[hostname]; ok {
		return records
	}
	return nil
}

// LookupLOC returns LOC records for a hostname
func (r *Resolver) LookupLOC(hostname string) []config.ParsedLOCRecord {
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if records, ok := r.config.LOCRecords[hostname]; ok {
		return records
	}
	return nil
}

// matchHostnameToIP attempts to extract an IP from a hostname using a zone's configuration
func (r *Resolver) matchHostnameToIP(hostname string, zone config.ParsedZone) (net.IP, bool) {
	domain := zone.Domain
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	if !strings.HasSuffix(hostname, domain) {
		return nil, false
	}

	hostPart := strings.TrimSuffix(hostname, domain)

	if zone.IsIPv6 {
		return r.parseIPv6HostPart(hostPart, zone)
	}
	return r.parseIPv4HostPart(hostPart, zone)
}

// parseIPv6HostPart parses an IPv6 host part back to an IP
func (r *Resolver) parseIPv6HostPart(hostPart string, zone config.ParsedZone) (net.IP, bool) {
	hex := strings.ReplaceAll(hostPart, "-", "")

	var fullHex string

	if zone.StripPrefix {
		nibblesToSkip := zone.PrefixLen / 4
		prefixHex := ipToFullHex(zone.Network.IP)[:nibblesToSkip]
		fullHex = prefixHex + hex
	} else {
		fullHex = hex
	}

	if len(fullHex) != 32 {
		return nil, false
	}

	ip := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		high := hexCharToNibble(string(fullHex[i*2]))
		low := hexCharToNibble(string(fullHex[i*2+1]))
		if high < 0 || low < 0 {
			return nil, false
		}
		ip[i] = byte(high<<4 | low)
	}
	return ip, true
}

// parseIPv4HostPart parses an IPv4 host part back to an IP
func (r *Resolver) parseIPv4HostPart(hostPart string, zone config.ParsedZone) (net.IP, bool) {
	parts := strings.Split(hostPart, "-")

	if zone.StripPrefix {
		fullOctets := zone.PrefixLen / 8
		remainingBits := zone.PrefixLen % 8

		ip := make(net.IP, 4)
		copy(ip, zone.Network.IP.To4())

		partIdx := 0

		if remainingBits > 0 && fullOctets < 4 {
			if partIdx >= len(parts) {
				return nil, false
			}
			val, err := strconv.Atoi(parts[partIdx])
			if err != nil || val < 0 || val > 255 {
				return nil, false
			}
			mask := byte(0xff << (8 - remainingBits))
			ip[fullOctets] = (ip[fullOctets] & mask) | byte(val)
			partIdx++
			fullOctets++
		}

		for i := fullOctets; i < 4; i++ {
			if partIdx >= len(parts) {
				return nil, false
			}
			val, err := strconv.Atoi(parts[partIdx])
			if err != nil || val < 0 || val > 255 {
				return nil, false
			}
			ip[i] = byte(val)
			partIdx++
		}

		return ip, true
	}

	if len(parts) != 4 {
		return nil, false
	}

	ip := make(net.IP, 4)
	for i, part := range parts {
		val, err := strconv.Atoi(part)
		if err != nil || val < 0 || val > 255 {
			return nil, false
		}
		ip[i] = byte(val)
	}
	return ip, true
}

// ipToFullHex returns the full 32-character hex representation of an IPv6 address
func ipToFullHex(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	var sb strings.Builder
	for _, b := range ip {
		fmt.Fprintf(&sb, "%02x", b)
	}
	return sb.String()
}
