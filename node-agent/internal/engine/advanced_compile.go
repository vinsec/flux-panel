package engine

import (
	"fmt"
	"net"
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
		if s.Selection == "fifo" && len(targets[id]) > 1 {
			targets[id] = targets[id][:1]
		}
	}
	result := map[string]string{}
	for _, table := range []string{"filter", "nat", "mangle"} {
		chains := append([]string{}, p.chains(table)...)
		nodes := map[string]bool{}
		if table == "nat" {
			for _, s := range included {
				token := fmt.Sprintf("%04x", s.Token)
				for depth := 1; depth <= 3; depth++ {
					nodes[token[:depth]] = true
				}
				chains = append(chains, p.prefix+"_T"+token)
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
		var b strings.Builder
		fmt.Fprintf(&b, "*%s\n", table)
		for _, chain := range chains {
			fmt.Fprintf(&b, ":%s - [0:0]\n", chain)
		}
		switch table {
		case "mangle":
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
			fmt.Fprintf(&b, "-A %s -m connmark --mark %s -j DROP\n-A %s -m connmark --mark %s -j DROP\n", p.set("FWD"), advancedMark, p.set("INPUT"), advancedMark)
		case "nat":
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
			sources := map[uint8]string{}
			for _, id := range keys(included) {
				s := included[id]
				token := fmt.Sprintf("%04x", s.Token)
				leaf := p.prefix + "_T" + token
				for _, protocol := range s.Protocols {
					fmt.Fprintf(&b, "-A %s_N%s -p %s -m connmark --mark %s -j %s\n", p.prefix, token[:3], protocol, fullMark(s), leaf)
				}
				pool := targets[id]
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
			live := rule.Active()
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
