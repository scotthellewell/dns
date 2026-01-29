package recurse

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/scott/dns/cache"
	"github.com/scott/dns/config"
	"github.com/scott/dns/dnssecval"
)

// Root DNS servers (IANA root servers)
var rootServers = []string{
	"198.41.0.4:53",     // a.root-servers.net
	"170.247.170.2:53",  // b.root-servers.net
	"192.33.4.12:53",    // c.root-servers.net
	"199.7.91.13:53",    // d.root-servers.net
	"192.203.230.10:53", // e.root-servers.net
	"192.5.5.241:53",    // f.root-servers.net
	"192.112.36.4:53",   // g.root-servers.net
	"198.97.190.53:53",  // h.root-servers.net
	"192.36.148.17:53",  // i.root-servers.net
	"192.58.128.30:53",  // j.root-servers.net
	"193.0.14.129:53",   // k.root-servers.net
	"199.7.83.42:53",    // l.root-servers.net
	"202.12.27.33:53",   // m.root-servers.net
}

// Resolver handles recursive DNS queries
type Resolver struct {
	config    config.ParsedRecursion
	client    *dns.Client
	servers   []string
	iterative bool               // true if doing iterative resolution from root
	cache     *cache.Cache       // TTL-based response cache
	validator *dnssecval.Validator // DNSSEC validator
}

// New creates a new recursive resolver
func New(cfg config.ParsedRecursion) *Resolver {
	servers := cfg.Upstream
	iterative := false

	if len(servers) == 0 {
		// No upstream configured - use iterative resolution from root
		servers = rootServers
		iterative = true
	} else {
		// Ensure all servers have port
		for i, s := range servers {
			if !strings.Contains(s, ":") {
				servers[i] = s + ":53"
			}
		}
	}

	r := &Resolver{
		config:    cfg,
		client:    &dns.Client{Timeout: time.Duration(cfg.Timeout) * time.Second},
		servers:   servers,
		iterative: iterative,
		cache:     cache.New(10000),    // 10k entry cache
		validator: dnssecval.New(),     // DNSSEC validator
	}

	// Set the query function for DNSSEC validation
	r.validator.SetQueryFunc(r.queryForValidation)

	return r
}

// queryForValidation performs iterative resolution for DNSSEC validation (DNSKEY/DS)
func (r *Resolver) queryForValidation(name string, qtype uint16) (*dns.Msg, error) {
	name = dns.Fqdn(name)

	// If we have upstream resolvers configured, use them
	if !r.iterative && len(r.servers) > 0 {
		return r.queryForValidationForward(name, qtype)
	}

	// Do iterative resolution from root servers
	return r.queryForValidationIterative(name, qtype, rootServers, 0)
}

// queryForValidationForward queries upstream resolvers for DNSKEY/DS
func (r *Resolver) queryForValidationForward(name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)
	m.CheckingDisabled = true

	for _, server := range r.servers {
		if !strings.Contains(server, ":") {
			server = server + ":53"
		}
		resp, _, err := r.client.Exchange(m, server)
		if err != nil {
			continue
		}
		if resp != nil && resp.Rcode == dns.RcodeSuccess {
			return resp, nil
		}
	}

	return nil, errors.New("query failed")
}

// queryForValidationIterative does iterative resolution for DNSKEY/DS queries
func (r *Resolver) queryForValidationIterative(name string, qtype uint16, servers []string, depth int) (*dns.Msg, error) {
	if depth > 15 {
		return nil, errors.New("max depth exceeded")
	}

	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false
	m.SetEdns0(4096, true)

	for _, server := range servers {
		if !strings.Contains(server, ":") {
			server = server + ":53"
		}

		resp, _, err := r.client.Exchange(m, server)
		if err != nil {
			continue
		}
		if resp == nil {
			continue
		}

		// Got authoritative answer
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			return resp, nil
		}

		// NXDOMAIN or no data
		if resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}

		// Check for delegation
		if len(resp.Ns) > 0 {
			nextServers := r.extractDelegationAddrs(resp)
			if len(nextServers) > 0 {
				return r.queryForValidationIterative(name, qtype, nextServers, depth+1)
			}

			// No glue records - need to resolve NS names
			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					// Resolve NS name to get IP
					nsIPs, _, _, found := r.queryIterative(ns.Ns, dns.TypeA, rootServers, depth+1)
					if found && len(nsIPs) > 0 {
						nsServer := nsIPs[0].String() + ":53"
						return r.queryForValidationIterative(name, qtype, []string{nsServer}, depth+1)
					}
				}
			}
		}

		// No answer, no delegation - try to use SOA for negative response
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
			return resp, nil // NODATA response
		}
	}

	return nil, errors.New("query failed")
}

// extractDelegationAddrs extracts just the IP addresses from glue records
func (r *Resolver) extractDelegationAddrs(resp *dns.Msg) []string {
	var nsNames []string
	var servers []string

	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsNames = append(nsNames, ns.Ns)
		}
	}

	// Get glue records - prefer IPv4
	for _, rr := range resp.Extra {
		if a, ok := rr.(*dns.A); ok {
			for _, nsName := range nsNames {
				if strings.EqualFold(a.Hdr.Name, nsName) {
					servers = append(servers, a.A.String()+":53")
					break
				}
			}
		}
	}

	return servers
}

// Result holds the result of a recursive query
type Result struct {
	IPs          []net.IP // Resolved IP addresses
	CNAMEs       []string // CNAME chain followed
	TTL          uint32   // Minimum TTL from the chain
	Found        bool     // Whether resolution succeeded
	FromLocal    bool     // Whether result came from local resolution
	Secure       bool     // DNSSEC validated
	Insecure     bool     // Zone not signed
	Bogus        bool     // DNSSEC validation failed
	WhyBogus     string   // Reason for bogus result
}

// ResolveA resolves A records, following CNAMEs if necessary
// localLookup is called to check local records first
func (r *Resolver) ResolveA(name string, depth int, localLookup func(string) (net.IP, uint32, bool), localCNAME func(string) (string, uint32, bool)) Result {
	return r.resolve(name, dns.TypeA, depth, false, localLookup, localCNAME)
}

// ResolveAAAA resolves AAAA records, following CNAMEs if necessary
func (r *Resolver) ResolveAAAA(name string, depth int, localLookup func(string) (net.IP, uint32, bool), localCNAME func(string) (string, uint32, bool)) Result {
	return r.resolve(name, dns.TypeAAAA, depth, false, localLookup, localCNAME)
}

// ResolveAExternal resolves A records, always allowing external queries (for ALIAS)
// This bypasses partial mode restrictions
func (r *Resolver) ResolveAExternal(name string, localLookup func(string) (net.IP, uint32, bool), localCNAME func(string) (string, uint32, bool)) Result {
	return r.resolve(name, dns.TypeA, 0, true, localLookup, localCNAME)
}

// ResolveAAAAExternal resolves AAAA records, always allowing external queries (for ALIAS)
func (r *Resolver) ResolveAAAAExternal(name string, localLookup func(string) (net.IP, uint32, bool), localCNAME func(string) (string, uint32, bool)) Result {
	return r.resolve(name, dns.TypeAAAA, 0, true, localLookup, localCNAME)
}

func (r *Resolver) resolve(name string, qtype uint16, depth int, forceExternal bool, localLookup func(string) (net.IP, uint32, bool), localCNAME func(string) (string, uint32, bool)) Result {
	result := Result{TTL: 0xFFFFFFFF}

	if depth > r.config.MaxDepth {
		return result
	}

	// Normalize name
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	// First, try local A/AAAA lookup
	if ip, ttl, found := localLookup(name); found {
		result.IPs = append(result.IPs, ip)
		if ttl < result.TTL {
			result.TTL = ttl
		}
		result.Found = true
		result.FromLocal = true
		return result
	}

	// Check for local CNAME
	if target, ttl, found := localCNAME(name); found {
		result.CNAMEs = append(result.CNAMEs, name)
		if ttl < result.TTL {
			result.TTL = ttl
		}
		// Recursively resolve the CNAME target - allow external since we're following a CNAME
		subResult := r.resolve(target, qtype, depth+1, true, localLookup, localCNAME)
		result.CNAMEs = append(result.CNAMEs, subResult.CNAMEs...)
		result.IPs = append(result.IPs, subResult.IPs...)
		if subResult.TTL < result.TTL {
			result.TTL = subResult.TTL
		}
		result.Found = subResult.Found
		result.FromLocal = subResult.FromLocal
		return result
	}

	// Not found locally, check if we should do external resolution
	if !r.config.Enabled {
		return result
	}
	
	// In partial mode, only recurse if:
	// - We're following a CNAME chain (depth > 0), or
	// - External resolution was explicitly requested (forceExternal, e.g., for ALIAS)
	// This prevents us from being an open resolver for arbitrary queries
	if r.config.Mode == config.RecursionModePartial && depth == 0 && !forceExternal {
		// Not following a CNAME and not explicitly allowed - don't recurse
		return result
	}

	// Check cache first
	cacheKey := cache.Key(name, qtype)
	if entry, ok := r.cache.Get(cacheKey); ok {
		result.IPs = entry.IPs
		result.CNAMEs = entry.CNAMEs
		result.TTL = entry.TTL
		result.Found = true
		result.FromLocal = false
		return result
	}

	// Query upstream servers
	ips, cnames, ttl, found := r.queryExternal(name, qtype, depth)
	if found {
		result.IPs = ips
		result.CNAMEs = append(result.CNAMEs, cnames...)
		if ttl < result.TTL {
			result.TTL = ttl
		}
		result.Found = true
		result.FromLocal = false

		// Cache the result
		r.cache.Set(cacheKey, ips, cnames, ttl)
	}

	return result
}

// queryExternal queries upstream DNS servers
func (r *Resolver) queryExternal(name string, qtype uint16, depth int) ([]net.IP, []string, uint32, bool) {
	if depth > r.config.MaxDepth {
		return nil, nil, 0, false
	}

	if r.iterative {
		return r.queryIterative(name, qtype, r.servers, depth)
	}
	return r.queryForward(name, qtype, depth)
}

// queryForward queries upstream resolvers (forwarding mode)
func (r *Resolver) queryForward(name string, qtype uint16, depth int) ([]net.IP, []string, uint32, bool) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true

	// Set DNSSEC OK (DO) bit to request DNSSEC records
	m.SetEdns0(4096, true)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.config.Timeout)*time.Second)
	defer cancel()

	for _, server := range r.servers {
		resp, _, err := r.client.ExchangeContext(ctx, m, server)
		if err != nil {
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			continue
		}

		// Validate DNSSEC if records are signed
		valResult := r.validator.ValidateResponse(resp, name, qtype)
		if valResult.Bogus {
			// DNSSEC validation failed - return failure
			log.Printf("DNSSEC: Validation BOGUS for %s: %s", name, valResult.WhyBogus)
			return nil, nil, 0, false
		}
		if valResult.Secure {
			log.Printf("DNSSEC: Validated SECURE for %s", name)
		}

		ips, cnames, ttl, found := r.extractRecords(resp, qtype)
		if found {
			return ips, cnames, ttl, true
		}

		// If we only got CNAMEs, follow them
		if len(cnames) > 0 {
			finalTarget := r.getFinalCNAMETarget(resp)
			if finalTarget != "" {
				moreIPs, moreCNAMEs, moreTTL, found := r.queryForward(finalTarget, qtype, depth+1)
				if found {
					cnames = append(cnames, moreCNAMEs...)
					if moreTTL < ttl {
						ttl = moreTTL
					}
					return moreIPs, cnames, ttl, true
				}
			}
		}
	}

	return nil, nil, 0, false
}

// queryIterative does iterative resolution starting from the given nameservers
// Queries all servers in parallel and uses the first successful response
func (r *Resolver) queryIterative(name string, qtype uint16, nameservers []string, depth int) ([]net.IP, []string, uint32, bool) {
	if depth > r.config.MaxDepth {
		return nil, nil, 0, false
	}

	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false // Iterative - don't ask for recursion

	// Set DNSSEC OK (DO) bit to request DNSSEC records
	m.SetEdns0(4096, true)

	// Query result from parallel queries
	type queryResult struct {
		resp   *dns.Msg
		server string
		err    error
	}

	// Query all servers in parallel
	results := make(chan queryResult, len(nameservers))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for _, server := range nameservers {
		go func(srv string) {
			if !strings.Contains(srv, ":") {
				srv = srv + ":53"
			}
			resp, _, err := r.client.ExchangeContext(ctx, m, srv)
			results <- queryResult{resp: resp, server: srv, err: err}
		}(server)
	}

	// Collect results, use first successful one
	var lastResp *dns.Msg
	received := 0
	for received < len(nameservers) {
		select {
		case result := <-results:
			received++
			if result.err != nil {
				continue
			}
			if result.resp == nil {
				continue
			}

			// Check for authoritative answer with records
			if result.resp.Rcode == dns.RcodeSuccess && len(result.resp.Answer) > 0 {
				cancel() // Cancel other pending queries

				// Validate DNSSEC if records are signed
				valResult := r.validator.ValidateResponse(result.resp, name, qtype)
				if valResult.Bogus {
					// DNSSEC validation failed - do NOT return results
					log.Printf("DNSSEC: Validation BOGUS for %s: %s", name, valResult.WhyBogus)
					return nil, nil, 0, false // Return failure, not just continue
				}
				if valResult.Secure {
					log.Printf("DNSSEC: Validated SECURE for %s", name)
				} else if valResult.Insecure {
					log.Printf("DNSSEC: Zone %s is INSECURE (not signed)", name)
				}

				ips, cnames, ttl, found := r.extractRecords(result.resp, qtype)
				if found {
					return ips, cnames, ttl, true
				}

				// If we got CNAMEs, follow them
				if len(cnames) > 0 {
					finalTarget := r.getFinalCNAMETarget(result.resp)
					if finalTarget != "" {
						moreIPs, moreCNAMEs, moreTTL, found := r.queryIterative(finalTarget, qtype, rootServers, depth+1)
						if found {
							cnames = append(cnames, moreCNAMEs...)
							if moreTTL < ttl {
								ttl = moreTTL
							}
							return moreIPs, cnames, ttl, true
						}
					}
				}
			}

			// Check for delegation (NS records in authority section)
			if len(result.resp.Ns) > 0 {
				nextServers := r.extractDelegation(result.resp)
				if len(nextServers) > 0 {
					cancel() // Cancel other pending queries
					return r.queryIterative(name, qtype, nextServers, depth+1)
				}
			}

			// NXDOMAIN - authoritative negative answer
			if result.resp.Rcode == dns.RcodeNameError {
				cancel()
				return nil, nil, 0, false
			}

			// Keep track of last response for fallback
			lastResp = result.resp

		case <-ctx.Done():
			// Timeout waiting for responses
			break
		}
	}

	// If we got a response but couldn't use it, try delegation from last response
	if lastResp != nil && len(lastResp.Ns) > 0 {
		nextServers := r.extractDelegation(lastResp)
		if len(nextServers) > 0 {
			return r.queryIterative(name, qtype, nextServers, depth+1)
		}
	}

	return nil, nil, 0, false
}

// extractDelegation extracts nameserver IPs from a delegation response
// Returns IPv4 servers first, then IPv6 servers (for fallback)
func (r *Resolver) extractDelegation(resp *dns.Msg) []string {
	var nsNames []string
	var ipv4Servers []string
	var ipv6Servers []string

	// Get NS record names from authority section
	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsNames = append(nsNames, ns.Ns)
		}
	}

	// Try to find glue records in additional section
	for _, rr := range resp.Extra {
		switch v := rr.(type) {
		case *dns.A:
			for _, nsName := range nsNames {
				if strings.EqualFold(v.Hdr.Name, nsName) {
					ipv4Servers = append(ipv4Servers, v.A.String()+":53")
					break
				}
			}
		case *dns.AAAA:
			for _, nsName := range nsNames {
				if strings.EqualFold(v.Hdr.Name, nsName) {
					ipv6Servers = append(ipv6Servers, "["+v.AAAA.String()+"]:53")
					break
				}
			}
		}
	}

	// Return IPv4 first, then IPv6 as fallback
	servers := append(ipv4Servers, ipv6Servers...)

	// If no glue records, resolve the NS names
	if len(servers) == 0 && len(nsNames) > 0 {
		// Try to resolve the first NS name (avoid infinite recursion)
		for _, nsName := range nsNames {
			ips, _, _, found := r.queryIterative(nsName, dns.TypeA, rootServers, 0)
			if found && len(ips) > 0 {
				for _, ip := range ips {
					servers = append(servers, ip.String()+":53")
				}
				break
			}
		}
	}

	return servers
}

// extractRecords extracts IPs and CNAMEs from a response
func (r *Resolver) extractRecords(resp *dns.Msg, qtype uint16) ([]net.IP, []string, uint32, bool) {
	var ips []net.IP
	var cnames []string
	var minTTL uint32 = 0xFFFFFFFF

	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ips = append(ips, v.A)
				if v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ips = append(ips, v.AAAA)
				if v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			}
		case *dns.CNAME:
			cnames = append(cnames, v.Hdr.Name)
			if v.Hdr.Ttl < minTTL {
				minTTL = v.Hdr.Ttl
			}
		}
	}

	return ips, cnames, minTTL, len(ips) > 0
}

// getFinalCNAMETarget gets the final CNAME target from a response
func (r *Resolver) getFinalCNAMETarget(resp *dns.Msg) string {
	var target string
	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			target = cname.Target
		}
	}
	return target
}
