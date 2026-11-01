package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

const advancedOwner = "flux-owner:v4"
const advancedMark = "0xf2000000/0xff000000"
const advancedGate = "flux-advanced-transaction:v4"

type AdvancedKernel struct {
	parent            *IPTables
	StatePath         string
	ready             map[string]bool
	trafficReady      map[string]bool
	shape             map[string]string
	control           map[string]string
	last              map[string]Spec
	bindings          map[string]string
	addressDirty      atomic.Bool
	quota             *SharedQuota
	aux               *Auxiliary
	epoch             string
	runtimeErrors     map[string]string
	udpContracts      map[string]string
	localShapeWatch   bool
	localShapePrereq  string
	localProbeChecked bool
	localProbeError   string
}
type advancedPlane struct{ family, prefix, binary, sentinel string }

func (k *IPTables) EnableAdvanced(path string) {
	k.P1 = &AdvancedKernel{parent: k, StatePath: path, ready: map[string]bool{}, trafficReady: map[string]bool{}, shape: map[string]string{}, control: map[string]string{}, last: map[string]Spec{}, bindings: map[string]string{}}
	k.P1.quota = &SharedQuota{parent: k}
}
func (a *AdvancedKernel) plane(family string) advancedPlane {
	if family == "ipv6" {
		return advancedPlane{family, "FP6", strings.Replace(a.parent.Binary, "iptables", "ip6tables", 1), "2001:db8::ffff"}
	}
	return advancedPlane{"ipv4", "FP4", a.parent.Binary, "192.0.2.255"}
}
func (p advancedPlane) set(suffix string) string { return p.prefix + "_" + suffix }
func (p advancedPlane) chains(table string) []string {
	switch table {
	case "mangle":
		return []string{p.set("MARK"), p.set("AUX"), p.set("OMARK")}
	case "nat":
		return []string{p.set("PRE"), p.set("POST"), p.set("LOCAL")}
	default:
		return []string{p.set("FWD"), p.set("INPUT"), p.set("OUTPUT"), p.set("ICMP"), p.set("IROOT")}
	}
}
func (p advancedPlane) hooks(local bool) []Hook {
	hooks := []Hook{{"filter", "FORWARD", p.set("FWD")}, {"filter", "INPUT", p.set("INPUT")}, {"nat", "PREROUTING", p.set("PRE")}, {"nat", "POSTROUTING", p.set("POST")}, {"mangle", "PREROUTING", p.set("MARK")}}
	if local {
		hooks = append(hooks, p.localHooks()...)
	}
	return hooks
}
func (p advancedPlane) localHooks() []Hook {
	return []Hook{{"mangle", "OUTPUT", p.set("OMARK")}, {"nat", "OUTPUT", p.set("PRE")}, {"nat", "INPUT", p.set("LOCAL")}, {"filter", "OUTPUT", p.set("OUTPUT")}}
}
func (p advancedPlane) sentinelKey(binding bool) string {
	if binding {
		return p.sentinel + ",tcp:0"
	}
	return p.sentinel + ",0x0"
}
func (a *AdvancedKernel) initializeFromState() error {
	var state State
	if b, e := os.ReadFile(a.StatePath); e == nil {
		if e = json.Unmarshal(b, &state); e != nil {
			return e
		}
		for _, s := range state.Rules {
			if s.Advanced() {
				for _, l := range s.ListenerList() {
					if e = a.ensurePlane(l.Family); e != nil {
						return e
					}
				}
			}
		}
	}
	names, e := a.parent.run("ipset", "", "list", "-name")
	if e != nil {
		return e
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		p := a.plane(family)
		if strings.Contains("\n"+names+"\n", "\n"+p.set("UP")+"\n") {
			if e = a.ensurePlane(family); e != nil {
				return e
			}
		}
	}
	return nil
}
func (a *AdvancedKernel) ensurePlane(family string) error {
	if a.parent.Native != nil {
		if family == "ipv6" {
			b, e := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
			if e != nil || strings.TrimSpace(string(b)) != "1" {
				return fmt.Errorf("IPv6 forwarding must already be enabled")
			}
		}
		return nil
	}
	if a.ready[family] {
		return nil
	}
	p := a.plane(family)
	if family == "ipv6" {
		b, e := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
		if e != nil || strings.TrimSpace(string(b)) != "1" {
			return fmt.Errorf("IPv6 forwarding must already be enabled in this namespace")
		}
	}
	fam := "inet"
	if family == "ipv6" {
		fam = "inet6"
	}
	names, e := a.parent.run("ipset", "", "list", "-name")
	if e != nil {
		return e
	}
	existing := map[string]bool{}
	for _, name := range strings.Fields(names) {
		existing[name] = true
	}
	suffixes := []string{"BIND", "BNEW", "ALLOW", "ANEW", "UP", "DOWN", "ROUTES", "RNEW"}
	if a.trafficReady[family] || existing[p.set("OBIND")] {
		a.trafficReady[family] = true
		suffixes = append(suffixes, "OBIND", "ONEW", "NOSNAT", "SNEW", "LORIG", "LONEW", "LTARG", "LTNEW")
	}
	for _, suffix := range suffixes {
		name := p.set(suffix)
		binding := suffix == "BIND" || suffix == "BNEW" || suffix == "OBIND" || suffix == "ONEW"
		typ := "hash:ip,mark"
		options := []string{"family", fam, "markmask", "0xffffff00", "hashsize", "4096", "maxelem", "262144", "comment"}
		if binding {
			typ = "hash:ip,port"
			options = []string{"family", fam, "hashsize", "4096", "maxelem", "1048576", "comment", "skbinfo"}
		}
		if suffix == "ROUTES" || suffix == "RNEW" {
			options = append(options, "skbinfo")
		}
		if suffix == "UP" || suffix == "DOWN" {
			options = append(options, "counters")
		}
		if existing[name] {
			saved, e := a.parent.readSet(name)
			if e != nil {
				return e
			}
			header := strings.Split(saved, "\n")[0]
			marker := parseSet(saved)[canonicalSetKey(p.sentinelKey(binding))]
			if !strings.HasPrefix(header, "create "+name+" "+typ+" ") || !strings.Contains(header, "family "+fam+" ") || marker.Comment != advancedOwner {
				return fmt.Errorf("advanced set %s exists without compatible ownership", name)
			}
		} else {
			args := append([]string{"create", name, typ}, options...)
			if _, e = a.parent.run("ipset", "", args...); e != nil {
				return e
			}
			if _, e = a.parent.run("ipset", "", "add", name, p.sentinelKey(binding), "comment", advancedOwner); e != nil {
				return e
			}
		}
	}
	for _, table := range []string{"mangle", "nat", "filter"} {
		saved, e := a.parent.run(p.binary+"-save", "", "-t", table)
		if e != nil {
			return e
		}
		owners := markOwners(saved)
		for _, line := range strings.Split(saved, "\n") {
			if strings.HasPrefix(line, ":"+p.prefix+"_") {
				name := strings.Fields(line)[0][1:]
				if !owners[name] {
					return fmt.Errorf("advanced chain %s has foreign ownership", name)
				}
			}
		}
	}
	a.ready[family] = true
	return nil
}
func advancedRules(plan []Spec) map[string]Spec {
	r := map[string]Spec{}
	for _, s := range plan {
		if s.Advanced() {
			r[s.ID] = s
		}
	}
	return r
}
func legacyRules(plan []Spec) map[string]Spec {
	r := map[string]Spec{}
	for _, s := range plan {
		if !s.Advanced() {
			r[s.ID] = s
		}
	}
	return r
}
func (a *AdvancedKernel) validate(s Spec) error {
	if !s.Advanced() {
		return a.parent.validateBaseSpec(s)
	}
	if s.Deleted || !s.Enabled {
		return nil
	}
	addresses, e := localAddresses()
	if e != nil {
		return e
	}
	for _, l := range s.Listeners {
		if l.Host != "0.0.0.0" && l.Host != "::" && !slices.Contains(addresses[l.Family], l.Host) && !(s.trafficPolicy().LocalOutput && netip.MustParseAddr(l.Host).IsLoopback()) {
			return fmt.Errorf("listener address is not assigned and usable in this namespace")
		}
		for _, proto := range []string{l.Protocol} {
			network := proto + "4"
			if l.Family == "ipv6" {
				network = proto + "6"
			}
			address := (Endpoint{Host: l.Host, Port: l.Port}).String()
			if proto == "tcp" {
				listener, e := net.Listen(network, address)
				if e != nil {
					return fmt.Errorf("TCP listen port occupied: %w", e)
				}
				listener.Close()
			} else {
				listener, e := net.ListenPacket(network, address)
				if e != nil {
					return fmt.Errorf("UDP listen port occupied: %w", e)
				}
				listener.Close()
			}
		}
	}
	if problem := s.localPathProblem(addresses, routeLocalnetEnabled()); problem != "" {
		return fmt.Errorf("%s", problem)
	}
	for _, target := range s.Paths() {
		ip := netip.MustParseAddr(target.Host)
		local := ip.IsLoopback() || slices.Contains(addresses[target.Family], target.Host)
		// Do not redirect a local service into another engine listener or itself.
		for _, l := range s.Listeners {
			if local && l.Port == target.Port && l.Family == target.Family {
				return fmt.Errorf("local target overlaps listener port")
			}
		}
	}
	if s.Egress.Interface != "" {
		if _, e = net.InterfaceByName(s.Egress.Interface); e != nil {
			return fmt.Errorf("egress interface unavailable")
		}
	}
	if e = a.validateAux(s); e != nil {
		return e
	}
	for _, l := range s.Listeners {
		if e = a.ensurePlane(l.Family); e != nil {
			return e
		}
	}
	return nil
}
func localAddresses() (map[string][]string, error) {
	result := map[string][]string{"ipv4": {}, "ipv6": {}}
	blocked := map[string]bool{}
	if data, e := os.ReadFile("/proc/net/if_inet6"); e == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) != 6 {
				continue
			}
			flags, _ := strconv.ParseUint(f[4], 16, 32)
			if flags&(0x40|0x08) == 0 {
				continue
			}
			if len(f[0]) == 32 {
				parts := []string{}
				for i := 0; i < 32; i += 4 {
					parts = append(parts, f[0][i:i+4])
				}
				if ip, e := netip.ParseAddr(strings.Join(parts, ":")); e == nil {
					blocked[ip.String()] = true
				}
			}
		}
	}
	interfaces, e := net.Interfaces()
	if e != nil {
		return nil, e
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Name == shapingDevice || iface.Name == localProbeDevice || iface.Name == localPrepareDevice {
			continue
		}
		addresses, e := iface.Addrs()
		if e != nil {
			return nil, e
		}
		for _, address := range addresses {
			ip, _, e := net.ParseCIDR(address.String())
			if e != nil {
				continue
			}
			parsed, e := netip.ParseAddr(ip.String())
			if e != nil || parsed.IsUnspecified() || parsed.IsMulticast() || parsed.IsLinkLocalUnicast() {
				continue
			}
			if blocked[parsed.String()] {
				continue
			}
			family := "ipv6"
			if parsed.Is4() {
				family = "ipv4"
			}
			result[family] = append(result[family], parsed.String())
		}
	}
	for family, ips := range result {
		slices.Sort(ips)
		result[family] = slices.Compact(ips)
	}
	return result, nil
}
func (a *AdvancedKernel) apply(plan []Spec) error {
	rules := advancedRules(plan)
	addresses, e := localAddresses()
	if e != nil {
		return e
	}
	rules = a.prepareRuntimeRules(rules, addresses)
	rules, e = a.prepareAux(rules)
	if e != nil {
		return e
	}
	for _, s := range rules {
		if s.Deleted {
			continue
		}
		for _, l := range s.Listeners {
			if e = a.ensurePlane(l.Family); e != nil {
				return e
			}
		}
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !a.ready[family] {
			continue
		}
		p := a.plane(family)
		for _, s := range rules {
			if !s.Deleted && s.needsTrafficSets() {
				for _, l := range s.Listeners {
					if l.Family == family {
						if e = a.ensureTrafficPlane(family); e != nil {
							return e
						}
						break
					}
				}
			}
		}
		tables, bindings, allowed, e := compileAdvancedPlane(p, rules, addresses[family])
		if e != nil {
			return e
		}
		if e = a.prepareCounters(p, rules); e != nil {
			return e
		}
		shape := digest(tables)
		full := shape != a.shape[family]
		if e = a.stage(p, "BNEW", bindings, true); e != nil {
			return e
		}
		if full {
			a.control[family] = ""
			tables["nat"], e = a.stale(p, tables["nat"], "nat")
			if e != nil {
				return e
			}
			for _, table := range []string{"filter", "nat", "mangle"} {
				if _, e = a.parent.run(p.binary+"-restore", tables[table], "--test", "--noflush", "--wait", "2"); e != nil {
					return e
				}
			}
			for _, table := range []string{"filter", "nat", "mangle"} {
				if _, e = a.parent.run(p.binary+"-restore", tables[table], "--noflush", "--wait", "2"); e != nil {
					return e
				}
			}
			local := false
			for _, rule := range rules {
				if !rule.Deleted && rule.localTraffic() {
					for _, l := range rule.Listeners {
						if l.Family == family {
							local = true
						}
					}
				}
			}
			if !local {
				for _, hook := range p.localHooks() {
					args := []string{"--wait", "2", "-t", hook.Table, "-C", hook.Parent, "-m", "comment", "--comment", "flux-advanced-hook:v4", "-j", hook.Child}
					if _, err := a.parent.run(p.binary, "", args...); err == nil {
						args[4] = "-D"
						if _, err = a.parent.run(p.binary, "", args...); err != nil {
							return err
						}
					}
				}
			}
			for _, hook := range p.hooks(local) {
				args := []string{"--wait", "2", "-t", hook.Table, "-C", hook.Parent, "-m", "comment", "--comment", "flux-advanced-hook:v4", "-j", hook.Child}
				if _, e = a.parent.run(p.binary, "", args...); e != nil {
					args[4] = "-I"
					position := 1
					if hook.Table == "filter" && hook.Parent == "FORWARD" {
						position, e = transactionGatePosition(a.parent, p.binary)
						if e != nil {
							return e
						}
					}
					args = append(args[:6], append([]string{strconv.Itoa(position)}, args[6:]...)...)
					if _, e = a.parent.run(p.binary, "", args...); e != nil {
						return e
					}
				}
			}
			a.shape[family] = shape
		}
		if _, e = a.parent.run("ipset", "", "swap", p.set("BNEW"), p.set("BIND")); e != nil {
			return e
		}
		a.bindings[family] = digest(bindings)
		if a.trafficReady[family] {
			outputBindings, noSNAT := trafficSets(p, rules, addresses[family])
			a.bindings[family] = digest([]any{bindings, outputBindings})
			for _, set := range []struct {
				stage, live string
				entries     map[string]string
				binding     bool
			}{{"ONEW", "OBIND", outputBindings, true}, {"SNEW", "NOSNAT", noSNAT, false}, {"LONEW", "LORIG", localHookTargets(p, rules, true, addresses[family]), false}, {"LTNEW", "LTARG", localHookTargets(p, rules, false, addresses[family]), false}} {
				if e = a.stage(p, set.stage, set.entries, set.binding); e != nil {
					return e
				}
				if _, e = a.parent.run("ipset", "", "swap", p.set(set.stage), p.set(set.live)); e != nil {
					return e
				}
			}
		}
		if e = a.stage(p, "ANEW", allowed, false); e != nil {
			return e
		}
		routes := map[string]string{}
		for _, s := range rules {
			if s.Deleted || s.Egress.Interface == "" {
				continue
			}
			for _, l := range s.Listeners {
				if l.Family != family {
					continue
				}
				ips := []string{l.Host}
				if l.Host == "0.0.0.0" || l.Host == "::" {
					ips = append([]string{}, addresses[family]...)
					if s.trafficPolicy().LocalOutput {
						ips = append(ips, map[string]string{"ipv4": "127.0.0.1", "ipv6": "::1"}[family])
					}
				}
				for _, ip := range ips {
					routes[fmt.Sprintf("%s,0x%x", ip, flowMark(s))] = fmt.Sprintf("skbmark 0x%x/0x3f comment flux:v4:%s:egress", s.Runtime.EgressGroup, s.ID)
				}
			}
		}
		if e = a.stage(p, "RNEW", routes, false); e != nil {
			return e
		}
		if _, e = a.parent.run("ipset", "", "swap", p.set("RNEW"), p.set("ROUTES")); e != nil {
			return e
		}
		if _, e = a.parent.run("ipset", "", "swap", p.set("ANEW"), p.set("ALLOW")); e != nil {
			return e
		}
	}
	if e = a.applyAux(rules); e != nil {
		return e
	}
	a.last = rules
	return nil
}

func (k *IPTables) RuntimeFailure(id string) string {
	if k.P1 != nil {
		return k.P1.runtimeErrors[id]
	}
	return ""
}
func (a *AdvancedKernel) stage(p advancedPlane, suffix string, entries map[string]string, binding bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "flush %s\nadd %s %s comment %s\n", p.set(suffix), p.set(suffix), p.sentinelKey(binding), advancedOwner)
	names := make([]string, 0, len(entries))
	for key := range entries {
		names = append(names, key)
	}
	slices.Sort(names)
	for _, key := range names {
		fmt.Fprintf(&b, "add %s %s %s\n", p.set(suffix), key, entries[key])
	}
	_, e := a.parent.run("ipset", b.String(), "restore")
	return e
}
func (a *AdvancedKernel) prepareCounters(p advancedPlane, rules map[string]Spec) error {
	var b strings.Builder
	for _, direction := range []string{"UP", "DOWN"} {
		name := p.set(direction)
		saved, e := a.parent.readSet(name)
		if e != nil {
			return e
		}
		existing := parseSet(saved)
		for _, id := range keys(rules) {
			s := rules[id]
			if s.Deleted {
				continue
			}
			for _, target := range s.Paths() {
				if target.Family != p.family {
					continue
				}
				key := fmt.Sprintf("%s,0x%x", target.Host, flowMark(s))
				comment := "flux:v2:" + id + ":" + strings.ToLower(direction)
				if old, ok := existing[key]; ok {
					if old.Comment != comment {
						return fmt.Errorf("advanced counter owner mismatch")
					}
					continue
				}
				fmt.Fprintf(&b, "add %s %s comment %s\n", name, key, comment)
				existing[key] = setElement{Comment: comment}
			}
		}
	}
	if b.Len() == 0 {
		return nil
	}
	_, e := a.parent.run("ipset", b.String(), "restore")
	return e
}
func (a *AdvancedKernel) snapshot() (map[string]uint64, []counterRecord, error) {
	totals := map[string]uint64{}
	records := []counterRecord{}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !a.ready[family] {
			continue
		}
		p := a.plane(family)
		for _, direction := range []string{"UP", "DOWN"} {
			name := p.set(direction)
			saved, e := a.parent.readSet(name)
			if e != nil {
				return nil, nil, e
			}
			for _, v := range parseSet(saved) {
				record := counterRecord{name, v.Key, v.Comment, v.Bytes, v.Packets}
				id := counterID(record)
				if id == "" {
					continue
				}
				baseline := counterBaseline(name, id, strings.ToLower(direction))
				totals[baseline] += v.Bytes
				records = append(records, record)
			}
		}
	}
	return totals, records, nil
}
func counterBaseline(set, id, direction string) string {
	family := "all"
	if strings.HasPrefix(set, "FP6_") {
		family = "ipv6"
	}
	return "flux:v2:" + id + ":" + family + ":" + direction
}
func accountingSet(name string) bool {
	return name == upSet || name == downSet || name == "FP4_UP" || name == "FP4_DOWN" || name == "FP6_UP" || name == "FP6_DOWN"
}
func (a *AdvancedKernel) references() (map[string]bool, error) {
	out := map[string]bool{}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !a.ready[family] {
			continue
		}
		text, e := a.parent.run("conntrack", "", "-L", "-f", family, "--mark", advancedMark)
		if e != nil && !strings.Contains(e.Error(), "0 flow entries") {
			return nil, e
		}
		for _, line := range strings.Split(text, "\n") {
			target := ""
			srcs := 0
			var value uint64
			for _, field := range strings.Fields(line) {
				if strings.HasPrefix(field, "src=") {
					srcs++
					if srcs == 2 {
						target = strings.TrimPrefix(field, "src=")
					}
				}
				if strings.HasPrefix(field, "mark=") {
					value, _ = strconv.ParseUint(strings.TrimPrefix(field, "mark="), 0, 32)
				}
			}
			if target != "" && uint32(value)&0xff000000 == 0xf2000000 {
				out[fmt.Sprintf("%s,0x%x", target, uint32(value)&0xffffff00)] = true
				out[fmt.Sprintf("mark:0x%x", uint32(value)&0xffffff00)] = true
			}
		}
	}
	return out, nil
}
func (a *AdvancedKernel) gate(tokens []uint32, newOnly, remove bool) error {
	var nftError error
	if !remove && (a.ready["ipv4"] || a.ready["ipv6"]) {
		nftError = a.quota.transactionGate(tokens, newOnly, false)
	}
	marks := []string{advancedMark}
	if len(tokens) > 0 && len(tokens) <= 16 {
		marks = nil
		for _, token := range tokens {
			if token == 0 || token > 65535 {
				return fmt.Errorf("invalid advanced gate token")
			}
			marks = append(marks, fmt.Sprintf("0x%08x/%s", uint32(0xf2000000)|(token<<8), markMask))
		}
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !a.ready[family] && family == "ipv6" {
			continue
		}
		p := a.plane(family)
		if remove {
			saved, e := a.parent.run(p.binary+"-save", "", "-t", "filter")
			if e != nil {
				return e
			}
			for _, line := range strings.Split(saved, "\n") {
				if !strings.HasPrefix(line, "-A FORWARD ") || !strings.Contains(line, advancedGate) {
					continue
				}
				fields := strings.Fields(strings.ReplaceAll(line, "\"", ""))
				fields[0] = "-D"
				if _, e = a.parent.run(p.binary, "", append([]string{"--wait", "2", "-t", "filter"}, fields...)...); e != nil {
					return e
				}
			}
			continue
		}
		for _, value := range marks {
			args := []string{"--wait", "2", "-t", "filter", "-C", "FORWARD", "-m", "connmark", "--mark", value}
			if newOnly {
				args = append(args, "-m", "conntrack", "!", "--ctstatus", "CONFIRMED")
			}
			args = append(args, "-m", "comment", "--comment", advancedGate, "-j", "DROP")
			if _, e := a.parent.run(p.binary, "", args...); e == nil {
				continue
			}
			args[4] = "-I"
			args = append(args[:6], append([]string{"1"}, args[6:]...)...)
			if _, e := a.parent.run(p.binary, "", args...); e != nil {
				return e
			}
		}
	}
	if remove && a.quota.ready {
		if e := a.quota.transactionGate(nil, false, true); e != nil {
			return e
		}
	}
	return nftError
}
func (a *AdvancedKernel) forget(s Spec) error {
	for _, family := range []string{"ipv4", "ipv6"} {
		if !a.ready[family] {
			continue
		}
		_, e := a.parent.run("conntrack", "", "-D", "-f", family, "--mark", fullMark(s))
		if e != nil && !strings.Contains(e.Error(), "0 flow entries") {
			return e
		}
	}
	return nil
}
func (a *AdvancedKernel) stale(p advancedPlane, desired, table string) (string, error) {
	saved, e := a.parent.run(p.binary+"-save", "", "-t", table)
	if e != nil {
		return "", e
	}
	wanted := map[string]bool{}
	for _, line := range strings.Split(desired, "\n") {
		if strings.HasPrefix(line, ":"+p.prefix+"_") {
			wanted[strings.Fields(line)[0][1:]] = true
		}
	}
	stale := []string{}
	owners := markOwners(saved)
	filterNode := regexp.MustCompile(`^` + p.prefix + `_I[0-9a-f]{1,3}$`)
	for _, line := range strings.Split(saved, "\n") {
		if !strings.HasPrefix(line, ":"+p.prefix+"_") {
			continue
		}
		name := strings.Fields(line)[0][1:]
		if table == "filter" && !filterNode.MatchString(name) {
			continue
		}
		if wanted[name] {
			continue
		}
		if !owners[name] {
			return "", fmt.Errorf("foreign advanced chain")
		}
		stale = append(stale, name)
	}
	sort.Strings(stale)
	declarations, removal := "", ""
	for _, name := range stale {
		declarations += ":" + name + " - [0:0]\n"
		removal += "-X " + name + "\n"
	}
	desired = strings.Replace(desired, "*"+table+"\n", "*"+table+"\n"+declarations, 1)
	return strings.Replace(desired, "COMMIT\n", removal+"COMMIT\n", 1), nil
}
func transactionGatePosition(k *IPTables, binary string) (int, error) {
	saved, e := k.run(binary+"-save", "", "-t", "filter")
	if e != nil {
		return 0, e
	}
	n := 1
	for _, line := range strings.Split(saved, "\n") {
		if strings.HasPrefix(line, "-A FORWARD ") && (strings.Contains(line, gateComment) || strings.Contains(line, advancedGate)) {
			n++
		}
	}
	return n, nil
}

func (a *AdvancedKernel) ensureTrafficPlane(family string) error {
	if a.trafficReady[family] {
		return nil
	}
	a.trafficReady[family] = true
	a.ready[family] = false
	return a.ensurePlane(family)
}

func routeLocalnetEnabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/route_localnet")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

func (s Spec) localPathProblem(addresses map[string][]string, routeLocal bool) string {
	for _, target := range s.Paths() {
		ip := netip.MustParseAddr(target.Host)
		local := ip.IsLoopback() || slices.Contains(addresses[target.Family], target.Host)
		if local && !s.trafficPolicy().LocalTargets {
			return "local target requires explicit localTargets mode"
		}
		if local && s.preserveSource() && slices.Contains(s.Protocols, "udp") {
			if problem := localUDPSourceProblem(target); problem != "" {
				return problem
			}
		}
		if local && s.Egress.Interface != "" {
			return "a local target has no selectable physical egress; remove the egress policy"
		}
		if !ip.IsLoopback() && !s.trafficPolicy().LocalOutput {
			continue
		}
		for _, l := range s.Listeners {
			if l.Family != target.Family {
				continue
			}
			listenerLoop := netip.MustParseAddr(l.Host).IsLoopback()
			if ip.Is6() && ip.IsLoopback() && !listenerLoop {
				return "external IPv6 loopback targets are not supported; use an assigned local address"
			}
			if ip.Is4() && ip.IsLoopback() && !listenerLoop && !routeLocal {
				return "IPv4 loopback target with external listeners requires preconfigured route_localnet; use an assigned local address instead"
			}
			if !local && s.trafficPolicy().LocalOutput && listenerLoop && (target.Family == "ipv6" || !routeLocal) {
				return "loopback listener to remote target requires a prepared IPv4 route_localnet path; use an assigned listener address"
			}
		}
	}
	return ""
}

func (a *AdvancedKernel) runtimeContractsChanged(rules map[string]Spec) bool {
	if p := a.parent.DPI; p != nil {
		p.mu.Lock()
		ready := p.ready
		p.mu.Unlock()
		if !ready {
			for id, s := range rules {
				if s.Enabled && s.protocolPolicy().Enabled() && a.runtimeErrors[id] == "" {
					return true
				}
			}
		}
	}
	if a.aux != nil && a.aux.shapeReady {
		iface, e := net.InterfaceByName(shapingDevice)
		if e != nil || iface.Flags&net.FlagUp == 0 || iface.Index != a.aux.shapeIndex {
			a.aux.shapeReady = false
			return true
		}
	}
	if a.localShapeWatch && localShapingProblem() != a.localShapePrereq {
		return true
	}
	if len(a.udpContracts) == 0 {
		return false
	}
	addresses, err := localAddresses()
	if err != nil {
		return true
	}
	for id, old := range a.udpContracts {
		if s, ok := rules[id]; ok && !s.Deleted {
			if s.localPathProblem(addresses, routeLocalnetEnabled()) != old {
				return true
			}
		}
	}
	return false
}
