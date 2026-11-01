package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const protocolTable = "FP_PROTOCOL"
const protocolOwner = "flux-protocol:v1"
const protocolQueue = 41600
const protocolMask = uint32(0x1f)

type queuedProtocolPacket struct {
	id, mark, ctid uint32
	tuple          uint64
	family         byte
	data           []byte
	truncated      bool
}
type protocolKey struct {
	id, mark uint32
	tuple    uint64
}
type protocolRule struct {
	ID     string
	Policy ProtocolFilter
}
type protocolQueueIO interface {
	verdict(queuedProtocolPacket, byte, bool, bool) error
	close()
	start()
}
type protocolFlow struct {
	start    uint32
	known    bool
	data     []byte
	have     []bool
	ids      []queuedProtocolPacket
	at, last time.Time
	class    byte
	blocked  bool
}
type protocolStats struct {
	Decisions uint64            `json:"decisions"`
	Blocked   uint64            `json:"blocked"`
	HTTP      uint64            `json:"http"`
	TLS       uint64            `json:"tls"`
	SOCKS     uint64            `json:"socks"`
	UNKNOWN   uint64            `json:"unknown"`
	Reasons   map[string]uint64 `json:"unknownReasons"`
}
type protocolEngine struct {
	udpMu     sync.Mutex
	udpAt     time.Time
	udpCounts map[uint32]uint64
	udpError  string
	bodies    int
	held      int
	parent    *IPTables
	rules     atomic.Pointer[map[uint32]protocolRule]
	mu        sync.Mutex
	io        protocolQueueIO
	flows     map[protocolKey]*protocolFlow
	stats     map[string]*protocolStats
	epoch     string
	err       string
	ready     bool
	shape     string
	lastGC    time.Time
}

func (k *IPTables) protocolEngine() *protocolEngine {
	if k.DPI == nil {
		k.DPI = &protocolEngine{parent: k, flows: map[protocolKey]*protocolFlow{}, stats: map[string]*protocolStats{}, epoch: identity(), shape: "uninitialized"}
		r := map[uint32]protocolRule{}
		k.DPI.rules.Store(&r)
	}
	return k.DPI
}
func (p *protocolEngine) prepare(rules map[string]Spec) map[string]Spec {
	wanted := map[uint32]protocolRule{}
	for _, s := range rules {
		if !s.Deleted && s.Enabled && s.protocolPolicy().Enabled() {
			wanted[flowMark(s)] = protocolRule{s.ID, s.protocolPolicy()}
		}
	}
	if len(wanted) > 0 {
		if p.io == nil {
			e := p.auditMarks()
			p.mu.Lock()
			p.err = ""
			if e != nil {
				p.err = e.Error()
				p.ready = false
			}
			p.mu.Unlock()
		}
		p.mu.Lock()
		need := !p.ready && p.io == nil && p.err == ""
		p.mu.Unlock()
		if need {
			io, e := startProtocolQueue(p)
			p.mu.Lock()
			if e != nil {
				p.err = e.Error()
			} else {
				p.io = io
				p.ready = true
				p.err = ""
			}
			p.mu.Unlock()
			if e == nil {
				io.start()
			}
		}
	}
	p.mu.Lock()
	ready := p.ready
	err := p.err
	p.mu.Unlock()
	if len(wanted) > 0 && !ready {
		for id, s := range rules {
			if s.protocolPolicy().Enabled() && !s.Deleted {
				p.parent.P1.runtimeErrors[id] = "protocol classifier unavailable: " + err
				s = cloneSpec(s)
				s.Enabled = false
				rules[id] = s
			}
		}
		wanted = map[uint32]protocolRule{}
	}
	old := p.rules.Load()
	p.mu.Lock()
	for k, f := range p.flows {
		r, ok := wanted[k.mark]
		prior, was := (*old)[k.mark]
		if !ok || !was || r != prior {
			for _, pkt := range f.ids {
				_ = p.io.verdict(pkt, 1, true, false)
			}
			p.held -= len(f.ids)
			if f.data != nil {
				p.bodies--
			}
			delete(p.flows, k)
		}
	}
	p.rules.Store(&wanted)
	p.mu.Unlock()
	return rules
}
func (p *protocolEngine) apply() error {
	rules := p.rules.Load()
	if rules == nil {
		return nil
	}
	values := []string{}
	for _, m := range nativeNames(func() map[string]uint32 {
		v := map[string]uint32{}
		for mark := range *rules {
			v[fmt.Sprintf("%08x", mark)] = mark
		}
		return v
	}()) {
		values = append(values, "0x"+m)
	}
	shape := strings.Join(values, ",")
	if shape == p.shape {
		return nil
	}
	saved, e := p.parent.run("nft", "", "-j", "list", "tables")
	if e != nil {
		return e
	}
	exists := strings.Contains(saved, `"`+protocolTable+`"`)
	var b strings.Builder
	if !exists && len(values) == 0 {
		p.shape = shape
		return nil
	}
	if exists {
		saved, e = p.parent.run("nft", "", "-j", "list", "table", "inet", protocolTable)
		if e != nil {
			return e
		}
		if !protocolOwned(saved) {
			return fmt.Errorf("protocol table has foreign ownership")
		}
		if len(values) == 0 {
			_, e = p.parent.run("nft", "", "delete", "table", "inet", protocolTable)
			if e == nil {
				p.shape = shape
			}
			return e
		}
		fmt.Fprintf(&b, "flush set inet %s filtered\nflush map inet %s udp_counts\n", protocolTable, protocolTable)
	} else {
		fmt.Fprintf(&b, "add table inet %s { comment %q; }\nadd set inet %s filtered { type mark; }\nadd map inet %s udp_counts { type mark : counter; }\n", protocolTable, protocolOwner, protocolTable, protocolTable)
	}
	// Rebuild our small static chains on takeover too, upgrading v5.4's table
	// without replacing counters or changing the checkpoint/wire schema.
	for _, name := range []string{"empty4", "empty6"} {
		present := false
		if exists {
			var d nativeDocument
			_ = json.Unmarshal([]byte(saved), &d)
			for _, o := range d.NFT {
				var set struct{ Name string }
				if v := o["set"]; v != nil {
					_ = json.Unmarshal(v, &set)
					present = present || set.Name == name
				}
			}
		}
		if !present {
			b.WriteString(protocolEmptySet(name))
		}
	}
	for _, hook := range []string{"forward", "input", "output"} {
		if exists {
			fmt.Fprintf(&b, "flush chain inet %s %s\n", protocolTable, hook)
		} else {
			fmt.Fprintf(&b, "add chain inet %s %s { type filter hook %s priority -6; policy accept; }\n", protocolTable, hook, hook)
		}
		fmt.Fprintf(&b, "add rule inet %s %s ct mark & 0x18 == 0x10 return\n", protocolTable, hook)
		fmt.Fprintf(&b, "add rule inet %s %s ct mark & 0xffffff00 != @filtered return\n", protocolTable, hook)
		fmt.Fprintf(&b, "add rule inet %s %s ct mark & 0x18 == 0x18 drop\n", protocolTable, hook)
		fmt.Fprintf(&b, "add rule inet %s %s ct direction original meta l4proto udp counter name ct mark & 0xffffff00 map @udp_counts ct mark set ct mark | 0x11 return\n", protocolTable, hook)
		// Keep SYN for sequence tracking (including SYN-data/TFO). Only a proven
		// empty non-SYN can bypass userspace. Extensions use the conservative path.
		fmt.Fprintf(&b, "add rule inet %s %s meta nfproto ipv4 tcp flags & syn == 0 ip hdrlength . tcp doff . meta length @empty4 return\n", protocolTable, hook)
		fmt.Fprintf(&b, "add rule inet %s %s meta nfproto ipv6 ip6 nexthdr tcp tcp flags & syn == 0 tcp doff . meta length @empty6 return\n", protocolTable, hook)
		fmt.Fprintf(&b, "add rule inet %s %s ct direction original meta l4proto tcp queue num %d\n", protocolTable, hook, protocolQueue)
	}

	if len(values) > 0 {
		existing := map[string]bool{}
		if exists {
			var d struct {
				NFT []struct {
					Counter *struct{ Name, Comment string } `json:"counter"`
				} `json:"nftables"`
			}
			_ = json.Unmarshal([]byte(saved), &d)
			for _, v := range d.NFT {
				if v.Counter != nil && v.Counter.Comment == protocolOwner {
					existing[v.Counter.Name] = true
				}
			}
		}
		// Retired diagnostic counters must not be inherited when a token is
		// eventually reused by another business rule.
		for name := range existing {
			var mark uint32
			if _, e := fmt.Sscanf(name, "u_%08x", &mark); e == nil {
				if _, ok := (*rules)[mark]; !ok {
					fmt.Fprintf(&b, "delete counter inet %s %s\n", protocolTable, name)
				}
			}
		}
		for mark := range *rules {
			name := fmt.Sprintf("u_%08x", mark)
			if existing[name] && p.shape == "uninitialized" {
				fmt.Fprintf(&b, "reset counter inet %s %s\n", protocolTable, name)
			}
			if !existing[name] {
				fmt.Fprintf(&b, "add counter inet %s %s { comment %q; }\n", protocolTable, name, protocolOwner)
			}
			fmt.Fprintf(&b, "add element inet %s udp_counts { 0x%x : \"%s\" }\n", protocolTable, mark, name)
		}
	}
	if len(values) > 0 {
		fmt.Fprintf(&b, "add element inet %s filtered { %s }\n", protocolTable, strings.Join(values, ", "))
	}
	if _, e = p.parent.run("nft", b.String(), "-c", "-f", "-"); e != nil {
		return e
	}
	if _, e = p.parent.run("nft", b.String(), "-f", "-"); e != nil {
		return e
	}
	p.shape = shape
	p.udpMu.Lock()
	p.udpAt = time.Time{}
	p.udpMu.Unlock()
	return nil
}
func (p *protocolEngine) handle(pkt queuedProtocolPacket) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	key := protocolKey{pkt.ctid, pkt.mark & 0xffffff00, pkt.tuple}
	rules := p.rules.Load()
	rule, ok := (*rules)[key.mark]
	if !ok {
		_ = p.io.verdict(pkt, 1, true, false)
		return
	}
	f := p.flows[key]
	if f != nil && f.class != 0 {
		f.last = now
		_ = p.io.verdict(pkt, f.class, f.blocked, true)
		return
	}
	packet := inspectPacket(pkt.data)
	if f == nil {
		f = &protocolFlow{last: now}
		if packet.syn {
			f.start = packet.seq
			f.known = true
		}
		if len(p.flows) < 32768 {
			p.flows[key] = f
		}
	}
	f.last = now
	if packet.tcp && len(packet.payload) == 0 && !packet.unsupported {
		if packet.syn {
			f.start = packet.seq
			f.known = true
		}
		_ = p.io.verdict(pkt, 0, false, false)
		return
	}
	p.held++
	f.ids = append(f.ids, queuedProtocolPacket{id: pkt.id, mark: pkt.mark, ctid: pkt.ctid, family: pkt.family})
	reason := ""
	class := byte(0)
	if packet.unsupported {
		class = 1
		reason = "unsupported-or-truncated"
	} else if !packet.tcp {
		class = 1
		reason = "udp"
	} else {
		// The usual case is decidable in one prefix. Allocate reassembly storage
		// only for ambiguity or a gap relative to the SYN's sequence number.
		if f.data == nil && (!f.known || packet.seq == f.start) {
			class = recognizeProtocol(packet.payload)
			if class == 1 {
				reason = "unrecognized"
			}
		}
		if class == 0 && f.data == nil {
			if p.bodies >= 4096 || len(p.flows) >= 32768 {
				class = recognizeProtocol(packet.payload)
				if class == 0 {
					class = 1
				}
				reason = "capacity"
			} else {
				p.bodies++
				f.data = make([]byte, 4096)
				f.have = make([]bool, 4096)
				f.at = now
				if !f.known {
					f.start = packet.seq
					f.known = true
				}
			}
		}
		if class == 0 {
			offset := int(int32(packet.seq - f.start))
			if offset < 0 || offset >= len(f.data) {
				class = 1
				reason = "prefix-bound"
			} else {
				prefix := packet.payload
				if len(prefix) > len(f.data)-offset {
					prefix = prefix[:len(f.data)-offset]
				}
				for i, v := range prefix {
					at := offset + i
					if f.have[at] && f.data[at] != v {
						class = 1
						reason = "overlap"
						break
					}
					f.have[at] = true
					f.data[at] = v
				}
				if class == 0 {
					end := 0
					for end < len(f.have) && f.have[end] {
						end++
					}
					class = recognizeProtocol(f.data[:end])
					if class == 1 {
						reason = "unrecognized"
					}
				}
			}
		}
	}
	if class == 0 && pkt.truncated {
		class = 1
		reason = "truncated-prefix"
	}
	if class == 0 && p.held >= 2048 {
		class = 1
		reason = "queue-pressure"
	}
	if class == 0 && len(f.ids) >= 16 {
		class = 1
		reason = "packet-bound"
	}
	if class != 0 {
		p.decide(key, f, rule, class, reason)
	}
}
func (p *protocolEngine) decide(key protocolKey, f *protocolFlow, rule protocolRule, class byte, reason string) {
	f.class = class
	f.blocked = rule.Policy.blocked(class)
	s := p.stats[rule.ID]
	if s == nil {
		s = &protocolStats{Reasons: map[string]uint64{}}
		p.stats[rule.ID] = s
	}
	s.Decisions++
	if f.blocked {
		s.Blocked++
	}
	switch class {
	case 2:
		s.HTTP++
	case 3:
		s.TLS++
	case 4:
		s.SOCKS++
	default:
		s.UNKNOWN++
		s.Reasons[reason]++
	}
	for _, pkt := range f.ids {
		if e := p.io.verdict(pkt, class, f.blocked, true); e != nil {
			p.err = e.Error()
			p.ready = false
		}
	}
	p.held -= len(f.ids)
	if f.data != nil {
		p.bodies--
	}
	f.ids = nil
	f.data = nil
	f.have = nil
}
func (p *protocolEngine) tick() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if now.Sub(p.lastGC) < 50*time.Millisecond {
		return
	}
	p.lastGC = now
	rules := p.rules.Load()
	for k, f := range p.flows {
		r, ok := (*rules)[k.mark]
		if !ok {
			for _, pkt := range f.ids {
				_ = p.io.verdict(pkt, 1, true, false)
			}
			p.held -= len(f.ids)
			if f.data != nil {
				p.bodies--
			}
			delete(p.flows, k)
			continue
		}
		if f.class == 0 && len(f.ids) > 0 && now.Sub(f.at) >= 500*time.Millisecond {
			p.decide(k, f, r, 1, "inspection-timeout")
		}
		if now.Sub(f.last) > time.Minute {
			delete(p.flows, k)
		}
	}
}
func (p *protocolEngine) status(id string) map[string]any {
	var selected uint32
	rules := p.rules.Load()
	for mark, r := range *rules {
		if r.ID == id {
			selected = mark
			break
		}
	}
	p.udpMu.Lock()
	if selected != 0 && time.Since(p.udpAt) >= time.Second {
		counts, e := readCounterObjectsTable(protocolTable)
		p.udpError = ""
		p.udpAt = time.Now()
		if e != nil {
			p.udpError = e.Error()
		} else {
			p.udpCounts = map[uint32]uint64{}
			for _, c := range counts {
				var mark uint32
				if c.Comment == protocolOwner {
					if _, e := fmt.Sscanf(c.Name, "u_%08x", &mark); e == nil {
						p.udpCounts[mark] = c.Packets
					}
				}
			}
		}
	}
	var udp uint64
	counterError := ""
	if selected != 0 {
		udp = p.udpCounts[selected]
		counterError = p.udpError
	}

	p.udpMu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats[id]
	if s == nil {
		s = &protocolStats{Reasons: map[string]uint64{}}
	}
	copy := *s
	copy.Decisions += udp
	copy.UNKNOWN += udp
	copy.Reasons = map[string]uint64{}
	copy.Reasons["udp"] = udp
	for k, v := range s.Reasons {
		copy.Reasons[k] = v
	}
	return map[string]any{"counterError": counterError, "epoch": p.epoch, "ready": p.ready, "error": p.err, "unknownPolicy": "allow", "statistics": copy, "classificationScope": "bounded-client-prefix", "maximumPrefixBytes": 4096, "maximumWaitMillis": 500}
}
func protocolOwned(saved string) bool {
	var d nativeDocument
	if json.Unmarshal([]byte(saved), &d) != nil {
		return false
	}
	for _, item := range d.NFT {
		if b := item["table"]; b != nil {
			var t struct{ Family, Name, Comment string }
			if json.Unmarshal(b, &t) == nil && t.Family == "inet" && t.Name == protocolTable {
				return t.Comment == protocolOwner
			}
		}
	}
	return false
}
func (p *protocolEngine) auditMarks() error {
	// Existing forwarding tokens occupy the upper bits. DPI additionally owns
	// five low connmark bits; refuse to overwrite a host policy using them.
	for _, name := range []string{"iptables-nft-save", "iptables-legacy-save", "ip6tables-nft-save", "ip6tables-legacy-save"} {
		if saved, e := p.parent.run(name, ""); e == nil {
			if e = validateMarkBits(saved, uint64(protocolMask)); e != nil {
				return fmt.Errorf("protocol connmark conflict: %w", e)
			}
		}
	}
	return nil
}
func (p *protocolEngine) cleanup() error {
	tables, e := p.parent.run("nft", "", "-j", "list", "tables")
	if e != nil {
		return e
	}
	if !strings.Contains(tables, `"`+protocolTable+`"`) {
		return nil
	}
	saved, e := p.parent.run("nft", "", "-j", "list", "table", "inet", protocolTable)
	if e != nil {
		return e
	}
	if !protocolOwned(saved) {
		return fmt.Errorf("foreign protocol table")
	}
	_, e = p.parent.run("nft", "", "delete", "table", "inet", protocolTable)
	return e
}

// Exact header-length tuples, not an approximate small-packet threshold.
func protocolEmptySet(name string) string {
	values := []string{}
	typ := "tcp doff . meta length"
	if name == "empty4" {
		typ = "ip hdrlength . tcp doff . meta length"
		for ip := 5; ip <= 15; ip++ {
			for tcp := 5; tcp <= 15; tcp++ {
				values = append(values, fmt.Sprintf("%d . %d . %d", ip, tcp, 4*(ip+tcp)))
			}
		}
	} else {
		for tcp := 5; tcp <= 15; tcp++ {
			values = append(values, fmt.Sprintf("%d . %d", tcp, 40+4*tcp))
		}
	}
	return fmt.Sprintf("add set inet %s %s { typeof %s; elements = { %s }; }\n", protocolTable, name, typ, strings.Join(values, ", "))
}
