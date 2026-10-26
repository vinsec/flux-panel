package engine

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

func compileAdvancedPlane(p advancedPlane, rules map[string]Spec, addresses []string) (map[string]string, map[string]string, map[string]string, error) {
	bindings, allowed := map[string]string{}, map[string]string{}
	included := map[string]Spec{}
	targets := map[string][]ResolvedTarget{}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Deleted {
			continue
		}
		hasFamily := false
		for _, l := range s.Listeners {
			if l.Family != p.family {
				continue
			}
			hasFamily = true
			ips := []string{l.Host}
			if l.Host == "0.0.0.0" || l.Host == "::" {
				ips = addresses
			} else if !slices.Contains(addresses, l.Host) {
				ips = nil
			}
			for _, ip := range ips {
				bindings[fmt.Sprintf("%s,%s:%d", ip, l.Protocol, l.Port)] = fmt.Sprintf("skbmark 0x%x/%s comment flux:v4:%s:binding", flowMark(s), markMask, id)
				if len(bindings) > 1048575 {
					return nil, nil, nil, fmt.Errorf("listener binding capacity exceeded")
				}
			}
		}
		if !hasFamily {
			continue
		}
		included[id] = s
		for _, t := range s.Paths() {
			if t.Family != p.family {
				continue
			}
			if s.Active() {
				allowed[fmt.Sprintf("%s,0x%x", t.Host, flowMark(s))] = "comment flux:v4:" + id + ":active"
			}
			if t.RetiredAt == 0 && t.AcceptNew && t.Healthy {
				targets[id] = append(targets[id], t)
			}
		}
		if s.trafficPolicy().LocalOutput && s.Active() {
			for _, ip := range listenerAliases(s, p.family, addresses) {
				allowed[fmt.Sprintf("%s,0x%x", ip, flowMark(s))] = "comment flux:v5:" + id + ":local-reply"
				if len(allowed) > 262143 {
					return nil, nil, nil, fmt.Errorf("local reply allowance capacity exceeded")
				}
			}
		}
		if s.Selection == "fifo" && len(targets[id]) > 1 {
			targets[id] = targets[id][:1]
		}
	}
	if len(allowed) > 262143 {
		return nil, nil, nil, fmt.Errorf("local reply allowance capacity exceeded")
	}
	result := map[string]string{}
	for _, table := range []string{"filter", "nat", "mangle"} {
		chains := append([]string{}, p.chains(table)...)
		nodes := map[string]bool{}
		sourceNodes := map[string]bool{}
		if table == "nat" {
			for _, s := range included {
				token := fmt.Sprintf("%04x", s.Token)
				for depth := 1; depth <= 3; depth++ {
					nodes[token[:depth]] = true
					if s.trafficPolicy().LocalTargets && !s.preserveSource() {
						sourceNodes[token[:depth]] = true
					}
				}
				if len(targets[s.ID]) > 1 {
					chains = append(chains, p.prefix+"_T"+token)
				}
			}
			names := []string{}
			for node := range nodes {
				names = append(names, node)
			}
			sort.Strings(names)
			for _, node := range names {
				chains = append(chains, p.prefix+"_N"+node)
			}
		}
		if table == "nat" && len(sourceNodes) > 0 {
			chains = append(chains, p.set("SROOT"))
			for _, node := range sortedNames(sourceNodes) {
				chains = append(chains, p.prefix+"_S"+node)
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "*%s\n", table)
		for _, chain := range chains {
			fmt.Fprintf(&b, ":%s - [0:0]\n", chain)
		}
		switch table {
		case "mangle":
			local := false
			for _, s := range included {
				if s.localTraffic() {
					local = true
				}
			}
			if local {
				renderMarkChain(&b, p, "OMARK", "OBIND")
			}
			fmt.Fprintf(&b, "-A %s -m connmark --mark %s -j CONNMARK --restore-mark --nfmask %s --ctmask %s\n", p.set("MARK"), advancedMark, markMask, markMask)
			fmt.Fprintf(&b, "-A %s -m connmark --mark %s -j %s\n-A %s -m connmark --mark %s -j RETURN\n", p.set("MARK"), advancedMark, p.set("AUX"), p.set("MARK"), advancedMark)
			fmt.Fprintf(&b, "-A %s -m conntrack --ctdir ORIGINAL -m addrtype --dst-type LOCAL -m set --match-set %s dst,dst -j SET --map-set %s dst,dst --map-mark\n", p.set("MARK"), p.set("BIND"), p.set("BIND"))
			fmt.Fprintf(&b, "-A %s -m mark --mark %s -j CONNMARK --save-mark --nfmask %s --ctmask %s\n-A %s -m connmark --mark %s -j %s\n", p.set("MARK"), advancedMark, markMask, markMask, p.set("MARK"), advancedMark, p.set("AUX"))
			aux := false
			route := false
			for _, s := range included {
				if s.Egress.Interface != "" || s.Bandwidth.Enabled() {
					aux = true
				}
				if s.Egress.Interface != "" {
					route = true
				}
			}
			if aux {
				mask := "0xffffff3f"
				if route {
					mask = "0xffffff00"
				}
				fmt.Fprintf(&b, "-A %s -j MARK --and-mark %s\n-A %s -m conntrack --ctdir ORIGINAL -j MARK --or-mark 0x80\n", p.set("AUX"), mask, p.set("AUX"))
				if route {
					fmt.Fprintf(&b, "-A %s -m conntrack --ctdir ORIGINAL -m set --match-set %s dst,dst -j SET --map-set %s dst,dst --map-mark\n", p.set("AUX"), p.set("ROUTES"), p.set("ROUTES"))
				}
			}
		case "filter":
			icmp := "icmp"
			if p.family == "ipv6" {
				icmp = "ipv6-icmp"
			}
			fmt.Fprintf(&b, "-A %s -p %s -m connmark --mark %s -j %s\n", p.set("FWD"), icmp, advancedMark, p.set("ICMP"))
			fmt.Fprintf(&b, "-A %s -m connmark --mark %s -m conntrack --ctdir ORIGINAL -m set --match-set %s dst,dst -m set --match-set %s dst,dst -j ACCEPT\n", p.set("FWD"), advancedMark, p.set("ALLOW"), p.set("UP"))
			fmt.Fprintf(&b, "-A %s -m connmark --mark %s -m conntrack --ctdir REPLY -m set --match-set %s src,src -m set --match-set %s src,src -j ACCEPT\n", p.set("FWD"), advancedMark, p.set("ALLOW"), p.set("DOWN"))
			fmt.Fprintf(&b, "-A %s -m connmark --mark %s -j DROP\n", p.set("FWD"), advancedMark)
			local := false
			for _, s := range included {
				if s.localTraffic() {
					local = true
				}
			}
			if local {
				// Local-to-local traffic is metered in OUTPUT, before reverse DNAT.
				// Its loopback INPUT pass only checks admission again, without billing.
				for _, chain := range []string{"INPUT", "OUTPUT"} {
					fmt.Fprintf(&b, "-A %s -p %s -m connmark --mark %s -j %s\n", p.set(chain), icmp, advancedMark, p.set("ICMP"))
					if chain == "INPUT" {
						fmt.Fprintf(&b, "-A %s -i lo -m connmark --mark %s -m conntrack --ctdir ORIGINAL --ctstate DNAT -m set --match-set %s dst,dst -m set --match-set %s dst,dst -j ACCEPT\n", p.set(chain), advancedMark, p.set("LTARG"), p.set("ALLOW"))
						fmt.Fprintf(&b, "-A %s -i lo -m connmark --mark %s -m conntrack --ctdir REPLY --ctstate DNAT -m set --match-set %s src,src -m set --match-set %s src,src -j ACCEPT\n", p.set(chain), advancedMark, p.set("LORIG"), p.set("ALLOW"))
						fmt.Fprintf(&b, "-A %s -i lo -m connmark --mark %s -j DROP\n", p.set(chain), advancedMark)
					} else {
						fmt.Fprintf(&b, "-A %s -m connmark --mark %s -m conntrack --ctdir ORIGINAL -m addrtype --dst-type LOCAL -m set ! --match-set %s dst,dst -j DROP\n", p.set(chain), advancedMark, p.set("LTARG"))
					}
					upPolicy, downPolicy := "LTARG", "LORIG"
					if chain == "OUTPUT" {
						upPolicy, downPolicy = "LORIG", "LTARG"
					}
					fmt.Fprintf(&b, "-A %s -m connmark --mark %s -m conntrack --ctdir ORIGINAL --ctstate DNAT -m set --match-set %s dst,dst -m set --match-set %s dst,dst -m set --match-set %s dst,dst -j ACCEPT\n", p.set(chain), advancedMark, p.set(upPolicy), p.set("ALLOW"), p.set("UP"))
					fmt.Fprintf(&b, "-A %s -m connmark --mark %s -m conntrack --ctdir REPLY --ctstate DNAT -m set --match-set %s src,src -m set --match-set %s src,src -m set --match-set %s src,src -j ACCEPT\n", p.set(chain), advancedMark, p.set(downPolicy), p.set("ALLOW"), p.set("DOWN"))
					fmt.Fprintf(&b, "-A %s -m connmark --mark %s -j DROP\n", p.set(chain), advancedMark)
				}
			} else {
				fmt.Fprintf(&b, "-A %s -m connmark --mark %s -j DROP\n", p.set("INPUT"), advancedMark)
			}
		case "nat":
			if len(sourceNodes) > 0 {
				fmt.Fprintf(&b, "-A %s -m connmark --mark %s -m conntrack --ctdir ORIGINAL --ctstate DNAT -j %s\n", p.set("LOCAL"), advancedMark, p.set("SROOT"))
				for _, node := range sortedNames(sourceNodes) {
					parent := p.set("SROOT")
					if len(node) > 1 {
						parent = p.prefix + "_S" + node[:len(node)-1]
					}
					var value uint32
					fmt.Sscanf(node, "%x", &value)
					mask := uint32(0xffffffff) << uint(24-len(node)*4)
					value = 0xf2000000 | (value << uint(24-len(node)*4))
					fmt.Fprintf(&b, "-A %s -m connmark --mark 0x%08x/0x%08x -j %s_S%s\n", parent, value, mask, p.prefix, node)
				}
				for _, id := range keys(included) {
					s := included[id]
					if !s.trafficPolicy().LocalTargets || s.preserveSource() {
						continue
					}
					seen := map[string]bool{}
					token := fmt.Sprintf("%04x", s.Token)
					for _, target := range s.Paths() {
						if target.Family != p.family || seen[target.Host] {
							continue
						}
						seen[target.Host] = true
						for _, proto := range s.Protocols {
							fmt.Fprintf(&b, "-A %s_S%s -p %s -d %s -m connmark --mark %s -j SNAT --to-source %s\n", p.prefix, token[:3], proto, target.Host, fullMark(s), target.Host)
						}
					}
				}
			}
			names := []string{}
			for node := range nodes {
				names = append(names, node)
			}
			sort.Strings(names)
			for _, node := range names {
				parent := p.set("PRE")
				if len(node) > 1 {
					parent = p.prefix + "_N" + node[:len(node)-1]
				}
				var value uint32
				fmt.Sscanf(node, "%x", &value)
				mask := uint32(0xffffffff) << uint(24-len(node)*4)
				value = 0xf2000000 | (value << uint(24-len(node)*4))
				fmt.Fprintf(&b, "-A %s -m connmark --mark 0x%08x/0x%08x -j %s_N%s\n", parent, value, mask, p.prefix, node)
			}
			local, preserve := false, false
			for _, s := range included {
				local = local || s.localTraffic()
				preserve = preserve || s.preserveSource()
			}
			if len(sourceNodes) > 0 {
				fmt.Fprintf(&b, "-A %s -m connmark --mark %s -m conntrack --ctdir ORIGINAL --ctstate DNAT -m addrtype --dst-type LOCAL -j %s\n", p.set("POST"), advancedMark, p.set("SROOT"))
			}
			if local {
				fmt.Fprintf(&b, "-A %s -m connmark --mark %s -m addrtype --dst-type LOCAL -j RETURN\n", p.set("POST"), advancedMark)
			}
			if preserve {
				fmt.Fprintf(&b, "-A %s -m connmark --mark %s -m set --match-set %s dst,dst -j RETURN\n", p.set("POST"), advancedMark, p.set("NOSNAT"))
			}
			sources := map[uint8]string{}
			for _, id := range keys(included) {
				s := included[id]
				token := fmt.Sprintf("%04x", s.Token)
				pool := targets[id]
				if len(pool) <= 1 {
					if len(pool) == 1 {
						destination := net.JoinHostPort(pool[0].Host, fmt.Sprint(pool[0].Port))
						for _, protocol := range s.Protocols {
							fmt.Fprintf(&b, "-A %s_N%s -p %s -m connmark --mark %s -j DNAT --to-destination %s\n", p.prefix, token[:3], protocol, fullMark(s), destination)
						}
					}
				} else {
					leaf := p.prefix + "_T" + token
					for _, protocol := range s.Protocols {
						fmt.Fprintf(&b, "-A %s_N%s -p %s -m connmark --mark %s -j %s\n", p.prefix, token[:3], protocol, fullMark(s), leaf)
					}
					total := 0
					for _, target := range pool {
						total += target.Weight
					}
					slot := 0
					for index, target := range pool {
						destination := net.JoinHostPort(target.Host, fmt.Sprint(target.Port))
						match := ""
						switch s.Selection {
						case "hash":
							mask := uint32(0)
							for n := 0; n < target.Weight; n++ {
								mask |= 1 << uint(slot+n)
							}
							slot += target.Weight
							match = fmt.Sprintf(" -m cluster --cluster-total-nodes %d --cluster-local-nodemask 0x%x --cluster-hash-seed 0xf204", total, mask)
						case "random":
							if index < len(pool)-1 {
								match = fmt.Sprintf(" -m statistic --mode random --probability %.10f", float64(target.Weight)/float64(total-slot))
							}
							slot += target.Weight
						case "round":
							for n := 0; n < target.Weight; n++ {
								remaining := total - slot
								selector := ""
								if remaining > 1 {
									selector = fmt.Sprintf(" -m statistic --mode nth --every %d --packet 0", remaining)
								}
								for _, protocol := range s.Protocols {
									fmt.Fprintf(&b, "-A %s -p %s%s -j DNAT --to-destination %s\n", leaf, protocol, selector, destination)
								}
								slot++
							}
							continue
						}
						for _, protocol := range s.Protocols {
							fmt.Fprintf(&b, "-A %s -p %s%s -j DNAT --to-destination %s\n", leaf, protocol, match, destination)
						}
					}
				}
				source := s.Egress.SourceIPv4
				if p.family == "ipv6" {
					source = s.Egress.SourceIPv6
				}
				if source != "" {
					sources[s.Runtime.EgressGroup] = source
				}
			}
			groups := []int{}
			for group := range sources {
				groups = append(groups, int(group))
			}
			sort.Ints(groups)
			for _, group := range groups {
				fmt.Fprintf(&b, "-A %s -m mark --mark 0x%x/0xff0000bf -m conntrack --ctdir ORIGINAL -j SNAT --to-source %s\n", p.set("POST"), uint32(0xf2000080)|uint32(group), sources[uint8(group)])
			}
			fmt.Fprintf(&b, "-A %s -m connmark --mark %s -m conntrack --ctdir ORIGINAL -j MASQUERADE\n", p.set("POST"), advancedMark)
		}
		for _, chain := range chains {
			fmt.Fprintf(&b, "-A %s -m comment --comment %s -j RETURN\n", chain, advancedOwner)
		}
		b.WriteString("COMMIT\n")
		result[table] = b.String()
	}
	return result, bindings, allowed, nil
}

func (a *AdvancedKernel) updateControl(s State) error {
	quota, e := a.quota.snapshot()
	if e != nil {
		return e
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !a.ready[family] {
			continue
		}
		p := a.plane(family)
		rules := map[string]Spec{}
		allowed := map[uint32]bool{}
		for _, id := range keys(s.Rules) {
			rule := s.Rules[id]
			if !rule.Advanced() || rule.Deleted {
				continue
			}
			present := false
			for _, target := range rule.Paths() {
				if target.Family == family {
					present = true
					break
				}
			}
			if !present {
				continue
			}
			rules[id] = rule
			live := rule.Active() && a.runtimeErrors[rule.ID] == ""
			if live && rule.LeaseRequired {
				lease, ok := s.Leases[id]
				q, exists := quota[quotaName(rule, lease)]
				live = ok && !lease.Closed && lease.DeadlineBootMillis > bootMillis() && exists && q.Used < q.Bytes
			}
			if live {
				allowed[rule.Token] = true
			}
		}
		identity, e := controlIdentity(rules, allowed)
		if e != nil {
			return e
		}
		if identity == a.control[family] {
			continue
		}
		text := renderControlFamily(family, rules, allowed)
		text = strings.ReplaceAll(text, "FP_I", p.prefix+"_I")
		text = strings.ReplaceAll(text, owner, advancedOwner)
		text, e = a.stale(p, text, "filter")
		if e != nil {
			return e
		}
		if _, e = a.parent.run(p.binary+"-restore", text, "--test", "--noflush", "--wait", "2"); e != nil {
			return e
		}
		if _, e = a.parent.run(p.binary+"-restore", text, "--noflush", "--wait", "2"); e != nil {
			return e
		}
		a.control[family] = identity
	}
	return nil
}

// Keep lookup costs independent of the number of forwards. NOSNAT uses the
// same target+business-mark identity as the allowance and accounting sets.
func trafficSets(p advancedPlane, rules map[string]Spec, addresses []string) (map[string]string, map[string]string) {
	output, noSNAT := map[string]string{}, map[string]string{}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Deleted {
			continue
		}
		if s.trafficPolicy().LocalOutput {
			for _, l := range s.Listeners {
				if l.Family != p.family {
					continue
				}
				ips := []string{l.Host}
				if l.Host == "0.0.0.0" || l.Host == "::" {
					ips = append([]string{}, addresses...)
					if loopbackOutputAllowed(s, p, addresses) {
						ips = append(ips, map[string]string{"ipv4": "127.0.0.1", "ipv6": "::1"}[p.family])
					}
				}
				for _, ip := range ips {
					output[fmt.Sprintf("%s,%s:%d", ip, l.Protocol, l.Port)] = fmt.Sprintf("skbmark 0x%x/%s comment flux:v5:%s:output", flowMark(s), markMask, id)
				}
			}
		}
		if s.preserveSource() {
			for _, t := range s.Paths() {
				if t.Family == p.family {
					noSNAT[fmt.Sprintf("%s,0x%x", t.Host, flowMark(s))] = "comment flux:v5:" + id + ":preserve"
				}
			}
		}
	}
	return output, noSNAT
}
func renderMarkChain(b *strings.Builder, p advancedPlane, chain, binding string) {
	fmt.Fprintf(b, "-A %s -m connmark --mark %s -j CONNMARK --restore-mark --nfmask %s --ctmask %s\n", p.set(chain), advancedMark, markMask, markMask)
	fmt.Fprintf(b, "-A %s -m connmark --mark %s -j %s\n-A %s -m connmark --mark %s -j RETURN\n", p.set(chain), advancedMark, p.set("AUX"), p.set(chain), advancedMark)
	fmt.Fprintf(b, "-A %s -m conntrack --ctdir ORIGINAL -m addrtype --dst-type LOCAL -m set --match-set %s dst,dst -j SET --map-set %s dst,dst --map-mark\n", p.set(chain), p.set(binding), p.set(binding))
	fmt.Fprintf(b, "-A %s -m mark --mark %s -j CONNMARK --save-mark --nfmask %s --ctmask %s\n-A %s -m connmark --mark %s -j %s\n", p.set(chain), advancedMark, markMask, markMask, p.set(chain), advancedMark, p.set("AUX"))
}

func localHookTargets(p advancedPlane, rules map[string]Spec, output bool, addresses []string) map[string]string {
	entries := map[string]string{}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Deleted || output && !s.trafficPolicy().LocalOutput || !output && !s.trafficPolicy().LocalTargets {
			continue
		}
		for _, t := range s.Paths() {
			if t.Family == p.family {
				entries[fmt.Sprintf("%s,0x%x", t.Host, flowMark(s))] = "comment flux:v5:" + id + ":local-policy"
			}
		}
		if output {
			for _, ip := range listenerAliases(s, p.family, addresses) {
				entries[fmt.Sprintf("%s,0x%x", ip, flowMark(s))] = "comment flux:v5:" + id + ":local-reply"
			}
		}
	}
	return entries
}

func listenerAliases(s Spec, family string, addresses []string) []string {
	result := []string{}
	for _, l := range s.Listeners {
		if l.Family != family {
			continue
		}
		if l.Host == "0.0.0.0" || l.Host == "::" {
			result = append(result, addresses...)
			if family == "ipv4" {
				result = append(result, "127.0.0.1")
			} else {
				result = append(result, "::1")
			}
		} else {
			result = append(result, l.Host)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}
func loopbackOutputAllowed(s Spec, p advancedPlane, addresses []string) bool {
	if p.family == "ipv4" && routeLocalnetEnabled() {
		return true
	}
	seen := false
	for _, target := range s.Paths() {
		if target.Family != p.family || target.RetiredAt != 0 || !target.AcceptNew || !target.Healthy {
			continue
		}
		seen = true
		ip := netip.MustParseAddr(target.Host)
		if !ip.IsLoopback() && !slices.Contains(addresses, target.Host) {
			return false
		}
	}
	return seen
}
