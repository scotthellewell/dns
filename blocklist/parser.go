package blocklist

import (
	"bufio"
	"regexp"
	"strings"
)

// Parser handles parsing of different blocklist formats.
type Parser struct{}

// NewParser creates a new blocklist parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseResult contains the result of parsing a blocklist.
type ParseResult struct {
	Domains    []string
	LineCount  int
	ErrorCount int
	Errors     []string
}

// Parse parses blocklist content based on the specified format.
func (p *Parser) Parse(content string, format string) *ParseResult {
	switch format {
	case "hosts":
		return p.ParseHosts(content)
	case "domains":
		return p.ParseDomains(content)
	default:
		// Auto-detect format
		return p.ParseAuto(content)
	}
}

// ParseHosts parses a hosts file format.
// Format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
func (p *Parser) ParseHosts(content string) *ParseResult {
	result := &ParseResult{}
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		result.LineCount++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split by whitespace
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// First field should be IP (0.0.0.0, 127.0.0.1, ::, etc.)
		ip := fields[0]
		if !isBlockIP(ip) {
			continue
		}

		// Second field is the domain
		domain := normalizeDomain(fields[1])

		// Skip invalid or local domains
		if !isValidDomain(domain) {
			continue
		}

		// Skip duplicates
		if seen[domain] {
			continue
		}
		seen[domain] = true

		result.Domains = append(result.Domains, domain)
	}

	return result
}

// ParseDomains parses a simple domain list format.
// Format: one domain per line
func (p *Parser) ParseDomains(content string) *ParseResult {
	result := &ParseResult{}
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		result.LineCount++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Handle inline comments
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		domain := normalizeDomain(line)

		// Skip invalid or local domains
		if !isValidDomain(domain) {
			continue
		}

		// Skip duplicates
		if seen[domain] {
			continue
		}
		seen[domain] = true

		result.Domains = append(result.Domains, domain)
	}

	return result
}

// ParseAuto auto-detects the format and parses accordingly.
func (p *Parser) ParseAuto(content string) *ParseResult {
	// Sample first few non-comment lines to detect format
	scanner := bufio.NewScanner(strings.NewReader(content))
	hostsLines := 0
	domainLines := 0
	sampleSize := 0

	for scanner.Scan() && sampleSize < 50 {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		sampleSize++
		fields := strings.Fields(line)

		if len(fields) >= 2 && isBlockIP(fields[0]) {
			hostsLines++
		} else if len(fields) == 1 && isValidDomain(fields[0]) {
			domainLines++
		}
	}

	// Decide format based on sample
	if hostsLines > domainLines {
		return p.ParseHosts(content)
	}
	return p.ParseDomains(content)
}

// isBlockIP returns true if the IP is a block destination.
func isBlockIP(ip string) bool {
	blockIPs := []string{
		"0.0.0.0",
		"127.0.0.1",
		"::",
		"::1",
		"0.0.0.0",
	}
	for _, bip := range blockIPs {
		if ip == bip {
			return true
		}
	}
	return false
}

// isValidDomain returns true if the string looks like a valid domain.
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

func isValidDomain(domain string) bool {
	// Basic validation
	if domain == "" || len(domain) > 253 {
		return false
	}

	// Skip localhost and local domains
	skipDomains := []string{
		"localhost",
		"localhost.localdomain",
		"local",
		"broadcasthost",
		"ip6-localhost",
		"ip6-loopback",
		"ip6-localnet",
		"ip6-mcastprefix",
		"ip6-allnodes",
		"ip6-allrouters",
		"ip6-allhosts",
	}
	for _, skip := range skipDomains {
		if domain == skip {
			return false
		}
	}

	// Must have at least one dot (no single-label domains)
	if !strings.Contains(domain, ".") {
		return false
	}

	// Regex validation
	return domainRegex.MatchString(domain)
}

// ParseStats returns statistics about a parsed blocklist.
type ParseStats struct {
	TotalLines  int
	ValidCount  int
	SkippedCount int
	Format      string
}
