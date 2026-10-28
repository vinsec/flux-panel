package engine

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

var nativeChains = []string{"mark_pre", "mark_out", "dnat_pre", "dnat_out", "snat_post", "snat_input", "filter_forward", "filter_input", "filter_output"}

func nativeMaps() map[string]string {
	m := map[string]string{"preserve": "mark", "lorig": "mark", "ltarg": "mark", "live_control": "mark", "routes": "mark : mark", "routes_shaped": "mark : mark", "multi4": "mark : verdict", "multi6": "mark : verdict"}
	for _, f := range []string{"4", "6"} {
		addr := "ipv" + f + "_addr"
		for _, name := range []string{"bind", "obind"} {
			m[name+f] = addr + " . inet_proto . inet_service : mark"
		}
		m["dnat"+f] = "mark : " + addr + " . inet_service"
		m["source"+f] = "mark : " + addr
		for _, name := range []string{"up", "down"} {
			m[name+f] = addr + " . mark : counter"
		}
		m["allow"+f] = addr + " . mark"
	}
	return m
}

// fixed maps are created once. Only elements and rule references are replaced;
// neither named counters nor the ledger marker are recreated by configuration.
func (n *NativeNFT) ensureMaps() error {
	d, e := n.document()
	if e != nil {
		return e
	}
	present := map[string]bool{}
	for _, item := range d.NFT {
		for _, kind := range []string{"map", "set"} {
			if b := item[kind]; b != nil {
				var o struct{ Name string }
				_ = json.Unmarshal(b, &o)
				present[o.Name] = true
			}
		}
	}
	var b strings.Builder
	for _, name := range nativeNames(nativeMaps()) {
		if present[name] {
			continue
		}
		typ := nativeMaps()[name]
		kind := "set"
		if strings.Contains(typ, ":") {
			kind = "map"
		}
		opts := ""
		if strings.HasPrefix(name, "allow") || name == "live_control" {
			opts = " flags timeout;"
		}
		fmt.Fprintf(&b, "add %s inet %s %s { type %s;%s }\n", kind, nativeTable, name, typ, opts)
	}
	return n.batch(b.String())
}

func compileNative(rules map[string]Spec, addresses map[string][]string, objects map[string]counterRecord) (string, error) {
	var b strings.Builder
	for _, chain := range nativeChains {
		fmt.Fprintf(&b, "flush chain inet %s %s\n", nativeTable, chain)
	}
	for _, name := range nativeNames(nativeMaps()) {
		kind := "set"
		if strings.Contains(nativeMaps()[name], ":") {
			kind = "map"
		}
		fmt.Fprintf(&b, "flush %s inet %s %s\n", kind, nativeTable, name)
	}
	// Multi-target chains have stable token names and are retained empty when a
	// rule no longer selects a pool. This bounds total names by token capacity.
	elements := map[string]map[string]string{}
	for name := range nativeMaps() {
		elements[name] = map[string]string{}
	}
	newCounters := map[string]counterRecord{}
	weighted := map[string]string{}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Deleted {
			continue
		}
		value := fmt.Sprintf("0x%x", flowMark(s))
		if s.Advanced() {
			if s.trafficPolicy().LocalOutput {
				elements["lorig"][value] = ""
			}
			if s.trafficPolicy().LocalTargets {
				elements["ltarg"][value] = ""
			}
			if s.preserveSource() {
				elements["preserve"][value] = ""
			}
			if s.Egress.Interface != "" {
				elements["routes"][value] = fmt.Sprintf("0x%x", flowMark(s)|0x80|uint32(s.Runtime.EgressGroup))
				elements["routes_shaped"][value] = fmt.Sprintf("0x%x", flowMark(s)|0xc0|uint32(s.Runtime.EgressGroup))
			}
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			f := map[string]string{"ipv4": "4", "ipv6": "6"}[family]
			paths := []ResolvedTarget{}
			selected := []ResolvedTarget{}
			if s.Advanced() {
				for _, p := range s.Paths() {
					if p.Family != family {
						continue
					}
					paths = append(paths, p)
					if p.RetiredAt == 0 && p.AcceptNew && p.Healthy {
						selected = append(selected, p)
					}
				}
			} else if family == "ipv4" {
				p := ResolvedTarget{Host: s.TargetIP, Port: s.TargetPort, Weight: 1, Family: family}
				paths = append(paths, p)
				selected = append(selected, p)
			}
			if s.Advanced() && s.Selection == "fifo" && len(selected) > 1 {
				selected = selected[:1]
			}
			aliases := []string{}
			for _, l := range s.ListenerList() {
				if l.Family != family {
					continue
				}
				ips := []string{l.Host}
				if l.Host == "0.0.0.0" || l.Host == "::" {
					ips = addresses[family]
				} else if !slices.Contains(addresses[family], l.Host) && !(s.trafficPolicy().LocalOutput && netip.MustParseAddr(l.Host).IsLoopback()) {
					ips = nil
				}
				for _, ip := range ips {
					key := fmt.Sprintf("%s . %s . %d", ip, l.Protocol, l.Port)
					if old, exists := elements["bind"+f][key]; exists && old != value {
						return "", fmt.Errorf("duplicate native listener")
					}
					elements["bind"+f][key] = value
					if s.trafficPolicy().LocalOutput {
						elements["obind"+f][key] = value
						aliases = append(aliases, ip)
					}
				}
				if (l.Host == "0.0.0.0" || l.Host == "::") && s.trafficPolicy().LocalOutput {
					ip := map[string]string{"4": "127.0.0.1", "6": "::1"}[f]
					elements["obind"+f][fmt.Sprintf("%s . %s . %d", ip, l.Protocol, l.Port)] = value
					aliases = append(aliases, ip)
				}
			}
			if s.Active() {
				if len(selected) == 1 {
					elements["dnat"+f][value] = fmt.Sprintf("%s . %d", selected[0].Host, selected[0].Port)
				} else if len(selected) > 1 {
					chain := fmt.Sprintf("pool%s_%04x", f, s.Token)
					elements["multi"+f][value] = "jump " + chain
					total := 0
					slots := []string{}
					for _, p := range selected {
						for i := 0; i < p.Weight; i++ {
							slots = append(slots, fmt.Sprintf("%d : %s . %d", total, p.Host, p.Port))
							total++
						}
					}
					expr := fmt.Sprintf("numgen random mod %d", total)
					if s.Selection == "round" {
						expr = fmt.Sprintf("numgen inc mod %d", total)
					}
					if s.Selection == "hash" {
						expr = fmt.Sprintf("jhash %s saddr mod %d seed 0xf204", map[string]string{"4": "ip", "6": "ip6"}[f], total)
					}
					weighted[chain] = fmt.Sprintf("meta l4proto { tcp, udp } dnat ip%s to %s map { %s }", map[string]string{"4": "", "6": "6"}[f], expr, strings.Join(slots, ", "))
				}
			}
			allHosts := map[string]bool{}
			for _, p := range paths {
				allHosts[p.Host] = true
			}
			for _, ip := range aliases {
				allHosts[ip] = true
			}
			for _, host := range nativeNames(allHosts) {
				key := host + " . " + value
				if s.Active() {
					timeout := ""
					if s.ExpiresAt > 0 {
						ms := s.ExpiresAt - time.Now().UnixMilli()
						if ms < 1 {
							continue
						}
						timeout = fmt.Sprintf(" timeout %dms", ms)
					}
					elements["allow"+f][key] = timeout
				}
				for _, direction := range []string{"up", "down"} {
					r := nativeRecord(s, host, family, direction)
					name := nativeCounterName(r)
					newCounters[name] = r
					elements[direction+f][key] = fmt.Sprintf("%q", name)
				}
			}
			if s.Advanced() {
				source := s.Egress.SourceIPv4
				if family == "ipv6" {
					source = s.Egress.SourceIPv6
				}
				if source != "" {
					elements["source"+f][value] = source
				}
			}
		}
	}
	for _, name := range nativeNames(newCounters) {
		if _, exists := objects[name]; !exists {
			fmt.Fprintf(&b, "add counter inet %s %s { comment %q; }\n", nativeTable, name, encodeNativeCounter(newCounters[name]))
		}
	}
	for _, name := range nativeNames(elements) {
		entries := []string{}
		for _, key := range nativeNames(elements[name]) {
			v := elements[name][key]
			if strings.Contains(nativeMaps()[name], ":") {
				entries = append(entries, key+" : "+v)
			} else {
				entries = append(entries, key+v)
			}
		}
		if len(entries) > 0 {
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", nativeTable, name, strings.Join(entries, ", "))
		}
	}
	// Pool chain creation is reconciled against the kernel by apply(), before
	// this transaction. All pool rules are flushed before replacing references.
	for _, chain := range nativeNames(weighted) {
		fmt.Fprintf(&b, "add rule inet %s %s %s\n", nativeTable, chain, weighted[chain])
	}
	rule := func(chain, expr string) { fmt.Fprintf(&b, "add rule inet %s %s %s\n", nativeTable, chain, expr) }
	for _, which := range []string{"pre", "out"} {
		chain := "mark_" + which
		binding := "bind"
		if which == "out" {
			binding = "obind"
		}
		for _, f := range []string{"4", "6"} {
			ip := map[string]string{"4": "ip", "6": "ip6"}[f]
			rule(chain, fmt.Sprintf("ct direction original ct mark & 0xff000000 != 0xf1000000 ct mark & 0xff000000 != 0xf2000000 fib daddr type local meta l4proto { tcp, udp } ct mark set %s daddr . meta l4proto . th dport map @%s%s", ip, binding, f))
		}
		if localShapingEnabled(rules) {
			rule(chain, nativeOwned+" meta mark & 0x40 != 0 meta mark set (ct mark & 0xffffff00) | 0x40")
			rule(chain, nativeOwned+" meta mark & 0x40 == 0 meta mark set ct mark & 0xffffff00")
		} else {
			rule(chain, nativeOwned+" meta mark set ct mark & 0xffffff00")
		}
		rule(chain, nativeOwned+" ct direction original meta mark set meta mark | 0x80")
		if localShapingEnabled(rules) {
			rule(chain, nativeOwned+" ct direction original meta mark & 0x40 != 0 meta mark set ct mark & 0xffffff00 map @routes_shaped")
		}
		rule(chain, nativeOwned+" ct direction original meta mark & 0x40 == 0 meta mark set ct mark & 0xffffff00 map @routes")
	}
	for _, chain := range []string{"dnat_pre", "dnat_out"} {
		for _, f := range []string{"4", "6"} {
			nf := map[string]string{"4": "ipv4", "6": "ipv6"}[f]
			family := map[string]string{"4": "ip", "6": "ip6"}[f]
			rule(chain, fmt.Sprintf("meta nfproto %s meta l4proto { tcp, udp } dnat %s to ct mark & 0xffffff00 map @dnat%s", nf, family, f))
			rule(chain, fmt.Sprintf("meta nfproto %s ct mark & 0xffffff00 vmap @multi%s", nf, f))
		}
	}
	for _, chain := range []string{"snat_post", "snat_input"} {
		rule(chain, nativeOwned+" ct status & dnat == 0 return")
		rule(chain, "ct mark & 0xffffff00 @preserve return")
		if chain == "snat_input" {
			for _, f := range []string{"4", "6"} {
				family := map[string]string{"4": "ip", "6": "ip6"}[f]
				rule(chain, fmt.Sprintf("%s ct direction original ct mark & 0xffffff00 @ltarg snat %s to %s daddr", nativeOwned, family, family))
			}
			continue
		}
		for _, f := range []string{"4", "6"} {
			family := map[string]string{"4": "ip", "6": "ip6"}[f]
			rule(chain, fmt.Sprintf("%s ct direction original fib daddr type local ct mark & 0xffffff00 @ltarg snat %s to %s daddr", nativeOwned, family, family))
		}
		rule(chain, nativeOwned+" ct direction original fib daddr type local ct mark & 0xffffff00 @ltarg return")
		for _, f := range []string{"4", "6"} {
			family := map[string]string{"4": "ip", "6": "ip6"}[f]
			rule(chain, fmt.Sprintf("%s ct direction original snat %s to ct mark & 0xffffff00 map @source%s", nativeOwned, family, f))
		}
		rule(chain, nativeOwned+" ct direction original masquerade")
	}
	for _, hook := range []string{"forward", "input", "output"} {
		chain := "filter_" + hook
		rule(chain, "ct mark & 0xff000000 != 0xf1000000 ct mark & 0xff000000 != 0xf2000000 return")
		rule(chain, "ct status & dnat == 0 drop")
		if hook == "input" {
			rule(chain, "ct direction original ct mark & 0xffffff00 != @ltarg drop")
			rule(chain, "ct direction reply ct mark & 0xffffff00 != @lorig drop")
		}
		if hook == "output" {
			rule(chain, "ct direction original ct mark & 0xffffff00 != @lorig drop")
			rule(chain, "ct direction reply ct mark & 0xffffff00 != @ltarg drop")
			rule(chain, "ct direction original fib daddr type local ct mark & 0xffffff00 != @ltarg drop")
		}
		for _, f := range []string{"4", "6"} {
			family := map[string]string{"4": "ip", "6": "ip6"}[f]
			for _, dir := range []string{"original", "reply"} {
				field, counter := "daddr", "up"
				if dir == "reply" {
					field, counter = "saddr", "down"
				}
				key := fmt.Sprintf("%s %s . (ct mark & 0xffffff00)", family, field)
				admission := key + " @allow" + f
				if hook == "input" {
					rule(chain, "iifname \"lo\" ct direction "+dir+" "+admission+" accept")
				}
				rule(chain, "ct direction "+dir+" meta l4proto { tcp, udp } "+admission+" counter name "+key+" map @"+counter+f+" accept")
				// Related errors retain the conntrack token but their outer address
				// may be a transit router. Admit only live tokens through a separate
				// mark set, compiled below, rather than trusting that outer address.
			}
		}
		rule(chain, "ct state related meta l4proto { icmp, ipv6-icmp } ct mark & 0xffffff00 @live_control accept")
		// Untracked control packets (notably IPv6 ND) have no ct mark at
		// all, so a negative ct-mark match does not evaluate to true. Only
		// drop our positively identified connections; preserve host policy.
		rule(chain, nativeOwned+" drop")
	}
	return b.String(), nil
}
