package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type DNSFailure struct {
	Kind  string
	Retry time.Duration
}

func (e *DNSFailure) Error() string { return "DNS " + e.Kind }

type DNSAnswer struct {
	Addresses []netip.Addr
	TTL       time.Duration
}
type Resolver struct {
	Servers   []string
	Timeout   time.Duration
	Now       func() time.Time
	mu        sync.Mutex
	semaphore chan struct{}
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
func (r *Resolver) servers() ([]string, error) {
	servers := slices.Clone(r.Servers)
	if len(servers) == 0 {
		b, e := os.ReadFile("/etc/resolv.conf")
		if e != nil {
			return nil, e
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				servers = append(servers, f[1])
			}
		}
	}
	if len(servers) == 0 || len(servers) > 8 {
		return nil, fmt.Errorf("configure 1..8 DNS nameservers")
	}
	for i, s := range servers {
		if _, _, e := net.SplitHostPort(s); e != nil {
			a, e := netip.ParseAddr(s)
			if e != nil {
				return nil, fmt.Errorf("DNS server must be numeric IP[:port]")
			}
			s = net.JoinHostPort(a.String(), "53")
		}
		host, _, _ := net.SplitHostPort(s)
		if _, e := netip.ParseAddr(host); e != nil {
			return nil, fmt.Errorf("DNS server must be numeric")
		}
		servers[i] = s
	}
	return servers, nil
}
func (r *Resolver) Lookup(ctx context.Context, host, family, iface string) (DNSAnswer, error) {
	r.mu.Lock()
	if r.semaphore == nil {
		r.semaphore = make(chan struct{}, 16)
	}
	semaphore := r.semaphore
	r.mu.Unlock()
	select {
	case semaphore <- struct{}{}:
		defer func() { <-semaphore }()
	case <-ctx.Done():
		return DNSAnswer{}, ctx.Err()
	}
	servers, e := r.servers()
	if e != nil {
		return DNSAnswer{}, e
	}
	qtype := dnsmessage.TypeA
	if family == "ipv6" {
		qtype = dnsmessage.TypeAAAA
	}
	seen := map[string]bool{}
	ttl := uint32(3600)
	name := strings.TrimSuffix(strings.ToLower(host), ".") + "."
	for depth := 0; depth < 8; depth++ {
		if seen[name] {
			return DNSAnswer{}, &DNSFailure{"CNAME loop", time.Second}
		}
		seen[name] = true
		qname, e := dnsmessage.NewName(name)
		if e != nil {
			return DNSAnswer{}, e
		}
		var id [2]byte
		if _, e = rand.Read(id[:]); e != nil {
			return DNSAnswer{}, e
		}
		request := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: qname, Type: qtype, Class: dnsmessage.ClassINET}}}
		wire, e := request.Pack()
		if e != nil {
			return DNSAnswer{}, e
		}
		var response dnsmessage.Message
		var failure error
		for _, server := range servers {
			response, e = r.exchange(ctx, server, iface, wire)
			if e == nil {
				break
			}
			failure = e
		}
		if e != nil {
			return DNSAnswer{}, fmt.Errorf("DNS query failed: %w", failure)
		}
		if response.ID != request.ID || !response.Response || len(response.Questions) != 1 || !strings.EqualFold(response.Questions[0].Name.String(), name) || response.Questions[0].Type != qtype {
			return DNSAnswer{}, fmt.Errorf("DNS response identity mismatch")
		}
		negative := uint32(5)
		for _, rr := range response.Authorities {
			if soa, ok := rr.Body.(*dnsmessage.SOAResource); ok {
				negative = min(rr.Header.TTL, soa.MinTTL, 300)
			}
		}
		if response.RCode == dnsmessage.RCodeNameError {
			return DNSAnswer{}, &DNSFailure{"NXDOMAIN", time.Duration(negative) * time.Second}
		}
		if response.RCode != dnsmessage.RCodeSuccess {
			return DNSAnswer{}, &DNSFailure{"SERVFAIL", time.Second}
		}
		cnames := map[string]string{}
		addresses := map[string][]netip.Addr{}
		for _, rr := range response.Answers {
			rrname := strings.ToLower(rr.Header.Name.String())
			ttl = min(ttl, rr.Header.TTL)
			switch body := rr.Body.(type) {
			case *dnsmessage.AResource:
				if qtype == dnsmessage.TypeA {
					addresses[rrname] = append(addresses[rrname], netip.AddrFrom4(body.A))
				}
			case *dnsmessage.AAAAResource:
				if qtype == dnsmessage.TypeAAAA {
					addresses[rrname] = append(addresses[rrname], netip.AddrFrom16(body.AAAA))
				}
			case *dnsmessage.CNAMEResource:
				cnames[rrname] = strings.ToLower(body.CNAME.String())
			}
		}
		current := name
		inReply := map[string]bool{}
		for steps := 0; steps < 8; steps++ {
			if inReply[current] {
				return DNSAnswer{}, &DNSFailure{"CNAME loop", time.Second}
			}
			inReply[current] = true
			if ips := addresses[current]; len(ips) > 0 {
				slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
				ips = slices.Compact(ips)
				if len(ips) > 64 {
					return DNSAnswer{}, fmt.Errorf("DNS answer exceeds 64 address bound")
				}
				return DNSAnswer{ips, time.Duration(ttl) * time.Second}, nil
			}
			if next := cnames[current]; next != "" {
				current = next
				continue
			}
			break
		}
		if current == name {
			return DNSAnswer{}, &DNSFailure{"NODATA", time.Duration(negative) * time.Second}
		}
		name = current
	}
	return DNSAnswer{}, &DNSFailure{"CNAME depth exceeded", time.Second}
}
func (r *Resolver) exchange(ctx context.Context, server, iface string, query []byte) (dnsmessage.Message, error) {
	var response dnsmessage.Message
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 700 * time.Millisecond
	}
	for _, network := range []string{"udp", "tcp"} {
		dial := net.Dialer{Timeout: timeout}
		if iface != "" {
			dial.Control = socketInterface(iface)
		}
		conn, e := dial.DialContext(ctx, network, server)
		if e != nil {
			return response, e
		}
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)
		out := query
		if network == "tcp" {
			out = append([]byte{byte(len(query) >> 8), byte(len(query))}, query...)
		}
		if _, e = conn.Write(out); e != nil {
			conn.Close()
			return response, e
		}
		buf := make([]byte, 4096)
		if network == "udp" {
			var n int
			n, e = conn.Read(buf)
			buf = buf[:n]
		} else {
			var size [2]byte
			_, e = io.ReadFull(conn, size[:])
			if e == nil {
				n := int(binary.BigEndian.Uint16(size[:]))
				if n < 12 || n > 16384 {
					e = fmt.Errorf("DNS TCP response exceeds bound")
				} else {
					buf = make([]byte, n)
					_, e = io.ReadFull(conn, buf)
				}
			}
		}
		conn.Close()
		if e != nil {
			return response, e
		}
		if e = response.Unpack(buf); e != nil {
			return response, e
		}
		if !response.Truncated {
			return response, nil
		}
	}
	return response, fmt.Errorf("DNS response remains truncated after TCP fallback")
}

func (r *Resolver) Resolve(ctx context.Context, s Spec) (Spec, error) {
	if !s.Advanced() || s.Deleted {
		return s, nil
	}
	options := *s.AdvancedOptions
	s.AdvancedOptions = &options
	now := r.now().UnixMilli()
	old := s.Runtime
	current := map[string]ResolvedTarget{}
	families := map[string]bool{}
	for _, l := range s.Listeners {
		families[l.Family] = true
	}
	for _, p := range old.Targets {
		if p.RetiredAt == 0 {
			current[p.Origin+"/"+p.Family] = p
		}
	}
	next := now + 3600000
	newPaths := []ResolvedTarget{}
	errors := []string{}
	hasDNS := false
	// Resolve independent origins/families together. One slow nameserver must
	// not consume the entire refresh deadline before later origins are tried.
	type lookupResult struct {
		answer DNSAnswer
		err    error
	}
	answers := map[string]lookupResult{}
	var lookups sync.WaitGroup
	var answerMu sync.Mutex
	for _, origin := range s.Targets {
		if origin.Endpoint.Kind == "ip" {
			continue
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			if !families[family] {
				continue
			}
			key := origin.Endpoint.String() + "/" + family
			lookups.Add(1)
			go func(origin Target, family, key string) {
				defer lookups.Done()
				answer, err := r.Lookup(ctx, origin.Endpoint.Host, family, s.Egress.Interface)
				answerMu.Lock()
				answers[key] = lookupResult{answer, err}
				answerMu.Unlock()
			}(origin, family, key)
		}
	}
	lookups.Wait()
	for _, origin := range s.Targets {
		for _, family := range []string{"ipv4", "ipv6"} {
			if !families[family] || origin.Endpoint.Kind == "ip" && origin.Endpoint.Family != family {
				continue
			}
			key := origin.Endpoint.String() + "/" + family
			prior, exists := current[key]
			path := prior
			path.Origin = origin.Endpoint.String()
			path.Family = family
			path.Port = origin.Endpoint.Port
			path.Weight = origin.Weight
			path.RetiredAt = 0
			if origin.Endpoint.Kind == "ip" {
				path.Host = origin.Endpoint.Host
				path.AcceptNew = true
				path.FreshUntil = 0
			} else {
				hasDNS = true
				lookup := answers[key]
				answer, e := lookup.answer, lookup.err
				if e != nil {
					errors = append(errors, key+": "+e.Error())
					retry := int64(1000)
					kind := "temporary"
					if failure, ok := e.(*DNSFailure); ok {
						retry = max(250, failure.Retry.Milliseconds())
						kind = failure.Kind
					}
					next = min(next, now+retry)
					if exists {
						path.AcceptNew = !s.DNS.FailClosed && kind != "NXDOMAIN" && kind != "NODATA" && now < path.FreshUntil+s.DNS.StaleMillis
						newPaths = append(newPaths, path)
					}
					continue
				}
				valid := []netip.Addr{}
				for _, ip := range answer.Addresses {
					if !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() {
						valid = append(valid, ip)
					}
				}
				if len(valid) == 0 {
					errors = append(errors, key+": no allowed unicast address")
					next = min(next, now+1000)
					if exists {
						path.AcceptNew = false
						newPaths = append(newPaths, path)
					}
					continue
				}
				path.Host = valid[0].String()
				for _, ip := range valid {
					if ip.String() == prior.Host {
						path.Host = prior.Host
						break
					}
				}
				path.FreshUntil = now + answer.TTL.Milliseconds()
				path.AcceptNew = true
				refresh := max(250, answer.TTL.Milliseconds()*9/10)
				next = min(next, now+refresh)
			}
			if !exists || path.Host != prior.Host {
				path.Healthy = s.Health.Protocol == ""
				path.Successes = 0
				path.Failures = 0
				path.NextProbeAt = 0
			}
			newPaths = append(newPaths, path)
		}
	}
	present := map[string]bool{}
	for _, p := range newPaths {
		present[p.Origin+"/"+p.Key()] = true
	}
	retiring := 0
	for _, p := range old.Targets {
		if present[p.Origin+"/"+p.Key()] {
			continue
		}
		if p.RetiredAt == 0 {
			p.RetiredAt = now
		}
		p.AcceptNew = false
		if now-p.RetiredAt < s.DNS.DrainMillis {
			newPaths = append(newPaths, p)
			retiring++
		}
	}
	if retiring > 32 {
		return s, fmt.Errorf("retiring target capacity reached; wait for old connections to drain")
	}
	s.Runtime = ResolutionState{Generation: old.Generation, ResolvedAt: now, NextResolveAt: next, Targets: newPaths, Status: "ready"}
	if !hasDNS {
		s.Runtime.NextResolveAt = 0
	}
	if len(errors) > 0 {
		s.Runtime.Status = "partial"
		s.Runtime.Error = strings.Join(errors, "; ")
		if len(s.Runtime.Error) > 2048 {
			s.Runtime.Error = s.Runtime.Error[:2048]
		}
	}
	usable := false
	for _, p := range newPaths {
		if p.RetiredAt == 0 && p.AcceptNew {
			usable = true
		}
	}
	if !usable {
		s.Runtime.Status = "failed"
	}
	return s, nil
}

func (r *Resolver) Probe(ctx context.Context, s Spec) Spec {
	if !s.Advanced() || s.Health.Protocol == "" || s.Deleted {
		return s
	}
	options := *s.AdvancedOptions
	options.Runtime.Targets = slices.Clone(s.Runtime.Targets)
	s.AdvancedOptions = &options
	now := r.now().UnixMilli()
	probes := 0
	indices := make([]int, len(s.Runtime.Targets))
	for i := range indices {
		indices[i] = i
	}
	slices.SortStableFunc(indices, func(i, j int) int {
		a, b := s.Runtime.Targets[i].NextProbeAt, s.Runtime.Targets[j].NextProbeAt
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	})
	for _, i := range indices {
		p := s.Runtime.Targets[i]
		if ctx.Err() != nil || probes >= 4 {
			break
		}
		if p.RetiredAt != 0 || now < p.NextProbeAt {
			continue
		}
		port := p.Port
		if s.Health.Port != 0 {
			port = s.Health.Port
		}
		dial := net.Dialer{Timeout: time.Duration(s.Health.TimeoutMillis) * time.Millisecond}
		if s.Egress.Interface != "" {
			mark := uint32(0)
			if s.Runtime.EgressGroup > 0 {
				mark = flowMark(s) | 0x80 | uint32(s.Runtime.EgressGroup)
			}
			dial.Control = socketPolicy(s.Egress.Interface, mark)
			source := s.Egress.SourceIPv4
			if p.Family == "ipv6" {
				source = s.Egress.SourceIPv6
			}
			if source != "" {
				if s.Health.Protocol == "tcp" {
					dial.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
				} else {
					dial.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source)}
				}
			}
		}
		probeCtx, cancel := context.WithTimeout(ctx, time.Duration(s.Health.TimeoutMillis)*time.Millisecond)
		probes++
		conn, e := dial.DialContext(probeCtx, s.Health.Protocol, (Endpoint{Host: p.Host, Port: port}).String())
		if e == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Duration(s.Health.TimeoutMillis) * time.Millisecond))
			if s.Health.Protocol == "udp" {
				payload, _ := base64.StdEncoding.DecodeString(s.Health.Payload)
				expected, _ := base64.StdEncoding.DecodeString(s.Health.Expected)
				_, e = conn.Write(payload)
				if e == nil {
					b := make([]byte, 65)
					var n int
					n, e = conn.Read(b)
					if e == nil && string(b[:n]) != string(expected) {
						e = fmt.Errorf("health response mismatch")
					}
				}
			}
			conn.Close()
		}
		cancel()
		if ctx.Err() != nil {
			break
		}
		if e == nil {
			p.Successes = min(p.Successes+1, s.Health.Rise)
			p.Failures = 0
			if p.Successes >= s.Health.Rise {
				p.Healthy = true
			}
		} else {
			p.Failures = min(p.Failures+1, s.Health.Fall)
			p.Successes = 0
			if p.Failures >= s.Health.Fall {
				p.Healthy = false
			}
		}
		p.NextProbeAt = now + s.Health.IntervalMillis
		s.Runtime.Targets[i] = p
	}
	return s
}
