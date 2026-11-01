package engine

// NativeNFT owns one inet table. Configuration updates replace maps and rules
// in a single netlink transaction; named counters survive every such update.
// No iptables rule translation or global ruleset flush is involved.
import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const nativeTable = "FP_NATIVE"
const nativeOwner = "flux-native:v1"
const nativeOwned = "ct mark & 0xff000000 { 0xf1000000, 0xf2000000 }"

type NativeNFT struct {
	parent       *IPTables
	ready        bool
	shape        string
	controlShape string
	bindings     string
	rules        map[string]Spec
}
type nativeDocument struct {
	NFT []map[string]json.RawMessage `json:"nftables"`
}
type nativeCounter struct {
	Name, Comment  string
	Bytes, Packets uint64
}

func (k *IPTables) EnableNative(path string) {
	k.EnableAdvanced(path)
	k.Native = &NativeNFT{parent: k, rules: map[string]Spec{}}
}
func (n *NativeNFT) run(input string, args ...string) (string, error) {
	return n.parent.run("nft", input, args...)
}
func (n *NativeNFT) batch(input string) error {
	if input == "" {
		return nil
	}
	if _, e := n.run(input, "-c", "-f", "-"); e != nil {
		return e
	}
	_, e := n.run(input, "-f", "-")
	return e
}
func (n *NativeNFT) document() (nativeDocument, error) {
	var d nativeDocument
	b, e := n.run("", "-j", "list", "table", "inet", nativeTable)
	if e == nil {
		e = json.Unmarshal([]byte(b), &d)
	}
	return d, e
}
func (n *NativeNFT) ensure() error {
	if n.ready {
		return nil
	}
	text, e := n.run("", "-j", "list", "tables")
	if e != nil {
		return e
	}
	var d nativeDocument
	if e = json.Unmarshal([]byte(text), &d); e != nil {
		return e
	}
	exists := false
	for _, item := range d.NFT {
		if b := item["table"]; b != nil {
			var t struct{ Family, Name string }
			if e = json.Unmarshal(b, &t); e != nil {
				return e
			}
			exists = exists || t.Family == "inet" && t.Name == nativeTable
		}
	}
	if exists {
		d, e = n.document()
		if e != nil {
			return e
		}
		owned := false
		for _, item := range d.NFT {
			if b := item["table"]; b != nil {
				var t struct{ Comment string }
				_ = json.Unmarshal(b, &t)
				owned = t.Comment == nativeOwner
			}
		}
		if !owned {
			return fmt.Errorf("native table exists without exact ownership")
		}
	} else {
		input := fmt.Sprintf("add table inet %s { comment %q; }\n", nativeTable, nativeOwner)
		for _, h := range []struct{ name, kind, hook, priority string }{{"mark_pre", "filter", "prerouting", "-150"}, {"mark_out", "route", "output", "-150"}, {"dnat_pre", "nat", "prerouting", "-100"}, {"dnat_out", "nat", "output", "-100"}, {"snat_post", "nat", "postrouting", "100"}, {"snat_input", "nat", "input", "100"}, {"filter_forward", "filter", "forward", "-1"}, {"filter_input", "filter", "input", "-1"}, {"filter_output", "filter", "output", "-1"}} {
			input += fmt.Sprintf("add chain inet %s %s { type %s hook %s priority %s; policy accept; }\n", nativeTable, h.name, h.kind, h.hook, h.priority)
		}
		if e = n.batch(input); e != nil {
			return e
		}
	}
	existingChains := map[string]bool{}
	for _, item := range d.NFT {
		if raw := item["chain"]; raw != nil {
			var c struct{ Name string }
			_ = json.Unmarshal(raw, &c)
			existingChains[c.Name] = true
		}
	}
	control := ""
	for _, name := range []string{"control4", "control6"} {
		if !existingChains[name] {
			control += fmt.Sprintf("add chain inet %s %s\n", nativeTable, name)
		}
	}
	if e = n.batch(control); e != nil {
		return e
	}
	n.ready = true
	return nil
}
func (n *NativeNFT) configured() (bool, error) {
	d, e := n.document()
	if e != nil {
		return false, e
	}
	for _, item := range d.NFT {
		if b := item["map"]; b != nil {
			var m struct {
				Name string
				Elem []json.RawMessage
			}
			if e = json.Unmarshal(b, &m); e != nil {
				return false, e
			}
			if strings.HasPrefix(m.Name, "bind") && len(m.Elem) > 0 {
				return true, nil
			}
		}
	}
	return false, nil
}
func (n *NativeNFT) claim(epoch string, rotate bool) (string, error) {
	if len(epoch) != 32 {
		return "", fmt.Errorf("invalid native ledger epoch")
	}
	d, e := n.document()
	if e != nil {
		return "", e
	}
	old := ""
	for _, item := range d.NFT {
		if b := item["chain"]; b != nil {
			var c struct{ Name string }
			_ = json.Unmarshal(b, &c)
			if strings.HasPrefix(c.Name, "ledger_") {
				parts := strings.Split(c.Name, "_")
				if len(parts) != 3 || parts[1] != epoch || len(parts[2]) != 32 {
					return "", fmt.Errorf("native ledger epoch mismatch")
				}
				if !rotate {
					return parts[2], nil
				}
				old = c.Name
			}
		}
	}
	id := identity()
	input := ""
	if old != "" {
		input = fmt.Sprintf("delete chain inet %s %s\n", nativeTable, old)
	}
	input += fmt.Sprintf("add chain inet %s ledger_%s_%s\n", nativeTable, epoch, id)
	if e = n.batch(input); e != nil {
		return "", e
	}
	n.parent.P1.epoch = epoch
	return id, nil
}
func nativeCounterName(r counterRecord) string {
	s := sha256.Sum256([]byte(r.Set + "|" + r.Key + "|" + r.Comment))
	return "c_" + hex.EncodeToString(s[:16])
}
func encodeNativeCounter(r counterRecord) string {
	return r.Set + "|" + r.Key + "|" + r.Comment
}
func decodeNativeCounter(c nativeCounter) (counterRecord, error) {
	parts := strings.Split(c.Comment, "|")
	if len(parts) != 3 {
		return counterRecord{}, fmt.Errorf("foreign native counter")
	}
	r := counterRecord{parts[0], parts[1], parts[2], c.Bytes, c.Packets}
	comment := strings.Split(r.Comment, ":")
	if !accountingSet(r.Set) || !serviceID.MatchString(counterID(r)) || len(comment) != 4 || (comment[3] != "up" && comment[3] != "down") || !strings.HasSuffix(strings.ToLower(r.Set), comment[3]) || c.Name != nativeCounterName(r) {
		return r, fmt.Errorf("native counter identity mismatch")
	}
	if _, e := nativeTuple(r.Key); e != nil {
		return r, e
	}
	return r, nil
}
func (n *NativeNFT) counters() (map[string]counterRecord, error) {
	objects, e := n.readCounterObjects()
	if e != nil {
		return nil, e
	}
	out := make(map[string]counterRecord, len(objects))
	for _, c := range objects {
		r, e := decodeNativeCounter(c)
		if e != nil {
			return nil, e
		}
		if _, exists := out[c.Name]; exists {
			return nil, fmt.Errorf("duplicate nft counter identity")
		}
		out[c.Name] = r
	}
	return out, nil
}
func (n *NativeNFT) snapshot() (map[string]uint64, []counterRecord, error) {
	objects, e := n.counters()
	if e != nil {
		return nil, nil, e
	}
	totals := map[string]uint64{}
	records := []counterRecord{}
	for _, name := range nativeNames(objects) {
		r := objects[name]
		p := strings.Split(r.Comment, ":")
		totals[counterBaseline(r.Set, counterID(r), p[3])] += r.Bytes
		records = append(records, r)
	}
	return totals, records, nil
}
func nativeRecord(s Spec, host, family, direction string) counterRecord {
	set := map[string]string{"ipv4": "FP4_", "ipv6": "FP6_"}[family] + strings.ToUpper(direction)
	if !s.Advanced() {
		set = map[string]string{"up": upSet, "down": downSet}[direction]
	}
	return counterRecord{Set: set, Key: fmt.Sprintf("%s,0x%x", host, flowMark(s)), Comment: "flux:v2:" + s.ID + ":" + direction}
}
func nativeTuple(key string) (string, error) {
	i := strings.LastIndex(key, ",")
	if i < 1 {
		return "", fmt.Errorf("invalid native tuple")
	}
	ip, e := netip.ParseAddr(key[:i])
	if e != nil {
		return "", e
	}
	mark, e := strconv.ParseUint(key[i+1:], 0, 32)
	if e != nil {
		return "", e
	}
	if mark&0xff != 0 || mark&0xffff00 == 0 || (mark&0xff000000 != 0xf1000000 && mark&0xff000000 != 0xf2000000) {
		return "", fmt.Errorf("invalid native flow mark")
	}
	return fmt.Sprintf("%s . 0x%x", ip, mark), nil
}
func (n *NativeNFT) restore(records []counterRecord, remove bool) error {
	objects, e := n.counters()
	if e != nil {
		return e
	}
	var b strings.Builder
	for _, r := range records {
		if !accountingSet(r.Set) || counterID(r) == "" {
			return fmt.Errorf("invalid native journal counter")
		}
		if _, e = nativeTuple(r.Key); e != nil {
			return e
		}
		name := nativeCounterName(r)
		old, ok := objects[name]
		if remove {
			if !ok {
				continue
			}
			if old != r {
				return fmt.Errorf("native counter changed during GC")
			}
			fmt.Fprintf(&b, "delete counter inet %s %s\n", nativeTable, name)
		} else if !ok {
			fmt.Fprintf(&b, "add counter inet %s %s { packets %d bytes %d; comment %q; }\n", nativeTable, name, r.Packets, r.Bytes, encodeNativeCounter(r))
		}
	}
	return n.batch(b.String())
}

func nativeNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Native table operations are emitted only from validated typed specs.
func (n *NativeNFT) apply(plan []Spec) error {
	rules := map[string]Spec{}
	for _, s := range plan {
		rules[s.ID] = s
	}
	addresses, e := localAddresses()
	if e != nil {
		return e
	}
	a := n.parent.P1
	for _, r := range rules {
		for _, l := range r.ListenerList() {
			if e = a.ensurePlane(l.Family); e != nil {
				return e
			}
		}
	}
	prepared := a.prepareRuntimeRules(advancedRules(mapSpecs(rules)), addresses)
	for id, r := range prepared {
		rules[id] = r
	}
	advanced, e := a.prepareAux(advancedRules(mapSpecs(rules)))
	if e != nil {
		return e
	}
	for id, s := range advanced {
		rules[id] = s
	}
	objects, e := n.counters()
	if e != nil {
		return e
	}
	input, e := compileNative(rules, addresses, objects)
	if e != nil {
		return e
	}
	d, e := n.document()
	if e != nil {
		return e
	}
	existing := map[string]bool{}
	for _, item := range d.NFT {
		if raw := item["chain"]; raw != nil {
			var c struct{ Name string }
			_ = json.Unmarshal(raw, &c)
			existing[c.Name] = true
		}
	}
	var pools strings.Builder
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, s := range rules {
			count := 0
			for _, p := range s.Paths() {
				if p.Family == family && p.RetiredAt == 0 && p.AcceptNew && p.Healthy {
					count++
				}
			}
			if !s.Deleted && count > 1 && s.Selection != "fifo" {
				name := fmt.Sprintf("pool%s_%04x", map[string]string{"ipv4": "4", "ipv6": "6"}[family], s.Token)
				if !existing[name] {
					fmt.Fprintf(&pools, "add chain inet %s %s\n", nativeTable, name)
					existing[name] = true
				}
			}
		}
	}
	for _, name := range nativeNames(existing) {
		if strings.HasPrefix(name, "pool") {
			fmt.Fprintf(&pools, "flush chain inet %s %s\n", nativeTable, name)
		}
	}
	input = pools.String() + input
	// Keep the transaction guard outside this replaceable configuration graph.
	if digest(input) != n.shape {
		if e = n.batch(input); e != nil {
			return e
		}
		n.shape = digest(input)
		n.controlShape = ""
	}
	if e = a.applyAux(advancedRules(mapSpecs(rules))); e != nil {
		return e
	}
	if n.bindings, e = nativeBindingIdentity(rules, addresses); e != nil {
		return e
	}
	n.rules = rules
	a.last = advancedRules(mapSpecs(rules))
	return nil
}

// Netlink starts with a dirty notification even when the initial apply already
// bound the same addresses. Cache the relevant inventory, not just that flag:
// rebuilding a 10k graph behind a global gate would interrupt a live transfer.
func nativeBindingIdentity(rules map[string]Spec, addresses map[string][]string) (string, error) {
	interfaces := map[string]bool{}
	all, local := false, false
	for _, s := range rules {
		if s.Deleted || !s.Advanced() {
			continue
		}
		if s.Egress.Interface != "" {
			interfaces[s.Egress.Interface] = true
		}
		all = all || s.Bandwidth.Enabled()
		local = local || s.localTraffic()
	}
	type link struct {
		Name  string
		Index int
		Flags net.Flags
		MTU   int
	}
	links := []link{}
	if all || len(interfaces) > 0 {
		entries, e := net.Interfaces()
		if e != nil {
			return "", e
		}
		for _, i := range entries {
			if i.Name == shapingDevice || i.Name == localProbeDevice || i.Name == localPrepareDevice {
				continue
			}
			if interfaces[i.Name] || all && (i.Flags&net.FlagLoopback == 0 || local) {
				links = append(links, link{i.Name, i.Index, i.Flags, i.MTU})
			}
		}
	}
	return digest([]any{addresses, links}), nil
}

func (n *NativeNFT) updateControl(s State) error {
	objects, e := n.parent.P1.quota.snapshot()
	if e != nil {
		return e
	}
	type entry struct {
		mark    uint32
		timeout int64
	}
	entries := make([]entry, 0, len(s.Rules))
	identity := make([]byte, 0, 20*len(s.Rules))
	now, boot := time.Now().UnixMilli(), bootMillis()
	for _, id := range keys(s.Rules) {
		r := s.Rules[id]
		if r.Deleted || !r.Enabled || (r.ExpiresAt > 0 && r.ExpiresAt <= now) || n.parent.P1.runtimeErrors[id] != "" {
			continue
		}
		ms, deadline := int64(0), int64(0)
		if r.ExpiresAt > 0 {
			ms = r.ExpiresAt - now
		}
		if r.LeaseRequired {
			l, ok := s.Leases[id]
			q, exists := objects[quotaName(r, l)]
			if !ok || l.Closed || l.DeadlineBootMillis <= boot || !exists || q.Used >= q.Bytes {
				continue
			}
			deadline = l.DeadlineBootMillis
			remaining := deadline - boot
			if ms == 0 || remaining < ms {
				ms = remaining
			}
		}
		value := flowMark(r)
		entries = append(entries, entry{value, ms})
		identity = binary.LittleEndian.AppendUint32(identity, value)
		identity = binary.LittleEndian.AppendUint64(identity, uint64(r.ExpiresAt))
		identity = binary.LittleEndian.AppendUint64(identity, uint64(deadline))
	}
	sum := sha256.Sum256(identity)
	shape := hex.EncodeToString(sum[:])
	if shape == n.controlShape {
		return nil
	}
	// Do not format a 10k-element transaction on unchanged sampling ticks.
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s live_control\n", nativeTable)
	for _, v := range entries {
		timeout := ""
		if v.timeout > 0 {
			timeout = fmt.Sprintf(" timeout %dms", v.timeout)
		}
		fmt.Fprintf(&b, "add element inet %s live_control { 0x%x%s }\n", nativeTable, v.mark, timeout)
	}
	_, e = n.run(b.String(), "-f", "-")
	if e == nil {
		n.controlShape = shape
	}
	return e
}

func (n *NativeNFT) references() (map[string]bool, error) {
	out := map[string]bool{}
	for _, family := range []string{"ipv4", "ipv6"} {
		text, e := n.parent.run("conntrack", "", "-L", "-f", family, "--mark", "0xf0000000/0xf0000000")
		if e != nil && !strings.Contains(e.Error(), "0 flow entries") {
			return nil, e
		}
		for _, line := range strings.Split(text, "\n") {
			target := ""
			srcs := 0
			var value uint64
			for _, f := range strings.Fields(line) {
				if strings.HasPrefix(f, "src=") {
					srcs++
					if srcs == 2 {
						target = strings.TrimPrefix(f, "src=")
					}
				}
				if strings.HasPrefix(f, "mark=") {
					value, _ = strconv.ParseUint(strings.TrimPrefix(f, "mark="), 0, 32)
				}
			}
			m := uint32(value) & 0xffffff00
			if target != "" && (m&0xff000000 == 0xf1000000 || m&0xff000000 == 0xf2000000) {
				out[fmt.Sprintf("%s,0x%x", target, m)] = true
				out[fmt.Sprintf("mark:0x%x", m)] = true
			}
		}
	}
	return out, nil
}

func (n *NativeNFT) cleanup() error {
	if n.parent.DPI != nil {
		if e := n.parent.DPI.cleanup(); e != nil {
			return e
		}
	}
	if e := n.gate(nil, false, false); e != nil {
		return e
	}
	if data, e := os.ReadFile(n.parent.P1.StatePath); e == nil {
		var s State
		if e = json.Unmarshal(data, &s); e != nil {
			return e
		}
		n.parent.P1.epoch = s.Epoch
	}
	if _, e := os.Stat(n.parent.P1.StatePath + ".aux.json"); e == nil {
		x, e := n.parent.P1.auxiliary()
		if e != nil {
			return e
		}
		if e = x.apply(map[string]Spec{}); e != nil {
			return e
		}
		if e = os.Remove(n.parent.P1.StatePath + ".aux.json"); e != nil {
			return e
		}
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, mark := range []string{"0xf1000000/0xff000000", advancedMark} {
			if _, e := n.parent.run("conntrack", "", "-D", "-f", family, "--mark", mark); e != nil && !strings.Contains(e.Error(), "0 flow entries") {
				return e
			}
		}
	}
	if e := n.ensure(); e != nil {
		return e
	}
	if _, e := n.run("", "delete", "table", "inet", nativeTable); e != nil {
		return e
	}
	if text, e := n.run("", "-j", "list", "table", "inet", quotaTable); e == nil {
		if !strings.Contains(text, advancedOwner) {
			return fmt.Errorf("foreign quota table")
		}
		if _, e = n.run("", "delete", "table", "inet", quotaTable); e != nil {
			return e
		}
	}
	n.ready = false
	n.shape = ""
	n.rules = map[string]Spec{}
	n.parent.P1.quota = &SharedQuota{parent: n.parent}
	return nil
}
func mapSpecs(rules map[string]Spec) []Spec {
	out := []Spec{}
	for _, id := range keys(rules) {
		out = append(out, rules[id])
	}
	return out
}

func (n *NativeNFT) gate(tokens []uint32, newOnly, remove bool) error {
	if remove && !n.ready {
		return nil
	}
	if e := n.ensure(); e != nil {
		return e
	}
	d, e := n.document()
	if e != nil {
		return e
	}
	chains := map[string]bool{}
	for _, item := range d.NFT {
		if b := item["chain"]; b != nil {
			var c struct{ Name string }
			_ = json.Unmarshal(b, &c)
			chains[c.Name] = true
		}
	}
	var b strings.Builder
	for _, hook := range []string{"forward", "input", "output"} {
		name := "transaction_" + hook
		if remove {
			if chains[name] {
				fmt.Fprintf(&b, "flush chain inet %s %s\ndelete chain inet %s %s\n", nativeTable, name, nativeTable, name)
			}
			continue
		}
		if chains[name] {
			fmt.Fprintf(&b, "flush chain inet %s %s\n", nativeTable, name)
		} else {
			fmt.Fprintf(&b, "add chain inet %s %s { type filter hook %s priority -10; policy accept; }\n", nativeTable, name, hook)
		}
		condition := ""
		if newOnly {
			condition = " ct status & confirmed == 0"
		}
		if len(tokens) == 0 || len(tokens) > 16 {
			fmt.Fprintf(&b, "add rule inet %s %s %s%s drop\n", nativeTable, name, nativeOwned, condition)
		} else {
			for _, token := range tokens {
				if token < 1 || token > 65535 {
					return fmt.Errorf("invalid gate token")
				}
				for _, prefix := range []uint32{0xf1000000, 0xf2000000} {
					fmt.Fprintf(&b, "add rule inet %s %s ct mark & 0xffffff00 == 0x%x%s drop\n", nativeTable, name, prefix|(token<<8), condition)
				}
			}
		}
	}
	return n.batch(b.String())
}

func (n *NativeNFT) preflight() (PreflightResult, error) {
	r := PreflightResult{MarkMask: markMask}
	var e error
	r.Kernel, e = n.parent.run("uname", "", "-r")
	if e != nil {
		return r, e
	}
	r.Backend, e = n.run("", "--version")
	if e != nil {
		return r, e
	}
	v, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	r.Forwarding = e == nil && strings.TrimSpace(string(v)) == "1"
	if !r.Forwarding {
		return r, fmt.Errorf("IPv4 forwarding must already be enabled")
	}
	// Inspect both xtables implementations. Native mode never takes over their
	// live Flux state; an explicit settled migration is required.
	for _, binary := range []string{"iptables-nft-save", "iptables-legacy-save", "ip6tables-nft-save", "ip6tables-legacy-save"} {
		if text, e := n.parent.run(binary, ""); e == nil {
			if strings.Contains(text, "flux-owner:") {
				return r, fmt.Errorf("live iptables Flux rules require a settled migration")
			}
			if e = validateExternalMarks(text); e != nil {
				return r, e
			}
			if e = validateMarkBits(text, 0xffffffff); e != nil {
				return r, fmt.Errorf("native backend reserves mark bits on its packets: %w", e)
			}
		}
	}
	text, e := n.run("", "-j", "list", "ruleset")
	if e != nil {
		return r, e
	}
	owners := map[string]map[string]bool{"inet:" + nativeTable: {}}
	var d nativeDocument
	if e = json.Unmarshal([]byte(text), &d); e != nil {
		return r, e
	}
	for _, item := range d.NFT {
		if b := item["chain"]; b != nil {
			var c struct{ Family, Table, Name string }
			_ = json.Unmarshal(b, &c)
			if c.Family == "inet" && c.Table == nativeTable {
				owners["inet:"+nativeTable][c.Name] = true
			}
		}
	}
	if e = validateNativeRules(text, owners); e != nil {
		return r, e
	}
	r.Probes = []string{"native map compiler; exact table ownership; no live xtables takeover; flow-offload audit"}
	return r, nil
}
