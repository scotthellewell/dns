// Package zonefile implements BIND zone file parsing and import.
package zonefile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/scott/dns/storage"
)

// Parser parses BIND zone files.
type Parser struct {
	origin     string
	defaultTTL uint32
}

// NewParser creates a new zone file parser.
func NewParser() *Parser {
	return &Parser{
		defaultTTL: 3600,
	}
}

// ParsedZone contains the result of parsing a zone file.
type ParsedZone struct {
	Zone    *storage.Zone
	Records []*storage.Record
	Errors  []string
}

// Parse reads a zone file from a reader and returns parsed data.
func (p *Parser) Parse(r io.Reader, zoneName string) (*ParsedZone, error) {
	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}
	p.origin = zoneName

	result := &ParsedZone{
		Zone: &storage.Zone{
			Name:    zoneName,
			Type:    "forward",
			TTL:     p.defaultTTL,
			Serial:  uint32(time.Now().Unix()),
			Refresh: 3600,
			Retry:   600,
			Expire:  604800,
			Minimum: 3600,
		},
		Records: make([]*storage.Record, 0),
	}

	scanner := bufio.NewScanner(r)
	lineNum := 0
	var currentName string

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if idx := strings.Index(line, ";"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "$") {
			p.handleDirective(line, result)
			continue
		}

		record, name, err := p.parseRecord(line, currentName)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("line %d: %v", lineNum, err))
			continue
		}

		if name != "" {
			currentName = name
		}

		if record != nil {
			record.Zone = zoneName
			result.Records = append(result.Records, record)

			if record.Type == "SOA" {
				p.extractSOAToZone(record, result.Zone)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return result, nil
}

func (p *Parser) handleDirective(line string, result *ParsedZone) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	switch strings.ToUpper(parts[0]) {
	case "$ORIGIN":
		origin := parts[1]
		if !strings.HasSuffix(origin, ".") {
			origin += "."
		}
		p.origin = origin
	case "$TTL":
		if ttl, err := parseTTL(parts[1]); err == nil {
			p.defaultTTL = ttl
			result.Zone.TTL = ttl
		}
	}
}

func (p *Parser) parseRecord(line, prevName string) (*storage.Record, string, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil, "", fmt.Errorf("too few fields")
	}

	var name string
	var ttl uint32 = p.defaultTTL
	var rtype string
	var dataStart int

	if !isNumeric(fields[0]) && !isClass(fields[0]) && !isType(fields[0]) {
		name = fields[0]
		dataStart = 1
	} else {
		name = prevName
		dataStart = 0
	}

	if name == "@" {
		name = p.origin
	}

	if name != "" && !strings.HasSuffix(name, ".") {
		name = name + "." + p.origin
	}

	for i := dataStart; i < len(fields); i++ {
		f := fields[i]
		if isNumeric(f) {
			if t, err := parseTTL(f); err == nil {
				ttl = t
			}
		} else if isClass(f) {
			// Skip class
		} else if isType(f) {
			rtype = strings.ToUpper(f)
			dataStart = i + 1
			break
		}
	}

	if rtype == "" {
		return nil, name, fmt.Errorf("no record type found")
	}

	data := fields[dataStart:]
	if len(data) == 0 {
		return nil, name, fmt.Errorf("no record data")
	}

	record, err := p.buildRecord(name, ttl, rtype, data)
	if err != nil {
		return nil, name, err
	}

	return record, name, nil
}

func (p *Parser) buildRecord(name string, ttl uint32, rtype string, data []string) (*storage.Record, error) {
	record := &storage.Record{
		Name: name,
		Type: rtype,
		TTL:  ttl,
	}

	switch rtype {
	case "A":
		if len(data) < 1 {
			return nil, fmt.Errorf("A record needs IP")
		}
		ip := net.ParseIP(data[0])
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %s", data[0])
		}
		record.Data = []byte(fmt.Sprintf(`{"ip":"%s"}`, data[0]))

	case "AAAA":
		if len(data) < 1 {
			return nil, fmt.Errorf("AAAA record needs IP")
		}
		ip := net.ParseIP(data[0])
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", data[0])
		}
		record.Data = []byte(fmt.Sprintf(`{"ip":"%s"}`, data[0]))

	case "CNAME", "NS", "PTR":
		if len(data) < 1 {
			return nil, fmt.Errorf("%s record needs target", rtype)
		}
		target := p.expandName(data[0])
		record.Data = []byte(fmt.Sprintf(`{"target":"%s"}`, target))

	case "MX":
		if len(data) < 2 {
			return nil, fmt.Errorf("MX record needs priority and target")
		}
		priority, err := strconv.Atoi(data[0])
		if err != nil {
			return nil, fmt.Errorf("invalid MX priority: %s", data[0])
		}
		target := p.expandName(data[1])
		record.Data = []byte(fmt.Sprintf(`{"priority":%d,"target":"%s"}`, priority, target))

	case "TXT":
		text := strings.Join(data, " ")
		text = strings.Trim(text, "\"")
		record.Data = []byte(fmt.Sprintf(`{"values":["%s"]}`, escapeJSON(text)))

	case "SRV":
		if len(data) < 4 {
			return nil, fmt.Errorf("SRV record needs priority weight port target")
		}
		priority, _ := strconv.Atoi(data[0])
		weight, _ := strconv.Atoi(data[1])
		port, _ := strconv.Atoi(data[2])
		target := p.expandName(data[3])
		record.Data = []byte(fmt.Sprintf(`{"priority":%d,"weight":%d,"port":%d,"target":"%s"}`,
			priority, weight, port, target))

	case "SOA":
		if len(data) < 7 {
			return nil, fmt.Errorf("SOA record needs all fields")
		}
		mname := p.expandName(data[0])
		rname := p.expandName(data[1])
		serial, _ := strconv.ParseUint(strings.Trim(data[2], "()"), 10, 32)
		refresh, _ := parseTTL(strings.Trim(data[3], "()"))
		retry, _ := parseTTL(strings.Trim(data[4], "()"))
		expire, _ := parseTTL(strings.Trim(data[5], "()"))
		minimum, _ := parseTTL(strings.Trim(data[6], "()"))
		record.Data = []byte(fmt.Sprintf(`{"mname":"%s","rname":"%s","serial":%d,"refresh":%d,"retry":%d,"expire":%d,"minimum":%d}`,
			mname, rname, serial, refresh, retry, expire, minimum))

	case "CAA":
		if len(data) < 3 {
			return nil, fmt.Errorf("CAA record needs flags tag value")
		}
		flags, _ := strconv.Atoi(data[0])
		tag := data[1]
		value := strings.Trim(strings.Join(data[2:], " "), "\"")
		record.Data = []byte(fmt.Sprintf(`{"flags":%d,"tag":"%s","value":"%s"}`, flags, tag, value))

	default:
		return nil, fmt.Errorf("unsupported record type: %s", rtype)
	}

	return record, nil
}

func (p *Parser) expandName(name string) string {
	if name == "@" {
		return p.origin
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "." + p.origin
}

func (p *Parser) extractSOAToZone(record *storage.Record, zone *storage.Zone) {
	var soa struct {
		MName   string `json:"mname"`
		RName   string `json:"rname"`
		Serial  uint32 `json:"serial"`
		Refresh uint32 `json:"refresh"`
		Retry   uint32 `json:"retry"`
		Expire  uint32 `json:"expire"`
		Minimum uint32 `json:"minimum"`
	}

	if err := json.Unmarshal(record.Data, &soa); err == nil {
		zone.PrimaryNS = soa.MName
		zone.AdminEmail = soa.RName
		zone.Serial = soa.Serial
		zone.Refresh = soa.Refresh
		zone.Retry = soa.Retry
		zone.Expire = soa.Expire
		zone.Minimum = soa.Minimum
	}
}

func parseTTL(s string) (uint32, error) {
	s = strings.ToLower(s)
	multiplier := uint32(1)

	if strings.HasSuffix(s, "s") {
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "m") {
		s = s[:len(s)-1]
		multiplier = 60
	} else if strings.HasSuffix(s, "h") {
		s = s[:len(s)-1]
		multiplier = 3600
	} else if strings.HasSuffix(s, "d") {
		s = s[:len(s)-1]
		multiplier = 86400
	} else if strings.HasSuffix(s, "w") {
		s = s[:len(s)-1]
		multiplier = 604800
	}

	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}

	return uint32(val) * multiplier, nil
}

func isNumeric(s string) bool {
	_, err := parseTTL(s)
	return err == nil
}

func isClass(s string) bool {
	upper := strings.ToUpper(s)
	return upper == "IN" || upper == "CH" || upper == "HS" || upper == "CS"
}

func isType(s string) bool {
	types := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true,
		"PTR": true, "SOA": true, "SRV": true, "TXT": true, "CAA": true,
		"SSHFP": true, "TLSA": true, "NAPTR": true, "LOC": true,
	}
	return types[strings.ToUpper(s)]
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}
