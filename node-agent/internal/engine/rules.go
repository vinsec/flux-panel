package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const owner = "flux-owner:v2"
const mark = "0xf1000000/0xff000000"
const markMask = "0xffffff00"
const bindingSet = "FPV2_BIND"
const allowSet = "FPV2_ALLOW"
const upSet = "FPV2_UP"
const downSet = "FPV2_DOWN"

var chains = map[string][]string{"mangle": {"FP_MARK"}, "nat": {"FP_PRE", "FP_POST"}, "filter": {"FP_FWD", "FP_CUP", "FP_CDOWN"}}

type Hook struct{ Table, Parent, Child string }

// The policy gate is installed before marking can activate any new traffic.
var Hooks = []Hook{{"filter", "FORWARD", "FP_FWD"}, {"nat", "POSTROUTING", "FP_POST"}, {"nat", "PREROUTING", "FP_PRE"}, {"mangle", "PREROUTING", "FP_MARK"}}

func keys(rules map[string]Spec) []string {
	r := make([]string, 0, len(rules))
	for k := range rules {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
func flowMark(s Spec) uint32 { return 0xf1000000 | (s.Token << 8) }
func fullMark(s Spec) string { return fmt.Sprintf("0x%08x/%s", flowMark(s), markMask) }

// The only per-forward iptables rules are in the first-packet NAT trie.
// Classification, policy and accounting use hash sets, not linear rule lists.
func Render(rules map[string]Spec, _ map[string]uint64) map[string]string {
	plan := []Spec{}
	next := uint32(1)
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Token >= next {
			next = s.Token + 1
		}
	}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Token == 0 {
			s.Token = next
			next++
		}
		plan = append(plan, s)
	}
	out := map[string]string{}
	for table, static := range chains {
		cs := append([]string{}, static...)
		nodes := map[string]bool{}
		if table == "nat" {
			for _, s := range plan {
				if s.Deleted {
					continue
				}
				token := fmt.Sprintf("%04x", s.Token)
				for d := 1; d <= 3; d++ {
					nodes[token[:d]] = true
				}
			}
			names := []string{}
			for n := range nodes {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				cs = append(cs, "FP_N"+n)
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "*%s\n", table)
		for _, c := range cs {
			fmt.Fprintf(&b, ":%s - [0:0]\n", c)
		}
		switch table {
		case "mangle":
			fmt.Fprintf(&b, "-A FP_MARK -m connmark --mark %s -j CONNMARK --restore-mark --nfmask %s --ctmask %s\n", mark, markMask, markMask)
			fmt.Fprintf(&b, "-A FP_MARK -m connmark --mark %s -j RETURN\n", mark)
			fmt.Fprintf(&b, "-A FP_MARK -m conntrack --ctdir ORIGINAL -m addrtype --dst-type LOCAL -m set --match-set %s dst,dst -j SET --map-set %s dst,dst --map-mark\n", bindingSet, bindingSet)
			fmt.Fprintf(&b, "-A FP_MARK -m mark --mark %s -j CONNMARK --save-mark --nfmask %s --ctmask %s\n", mark, markMask, markMask)
		case "filter":
			fmt.Fprintf(&b, "-A FP_FWD -m connmark --mark %s -m conntrack --ctdir ORIGINAL -m set --match-set %s dst,dst -j FP_CUP\n", mark, allowSet)
			fmt.Fprintf(&b, "-A FP_FWD -m connmark --mark %s -m conntrack --ctdir REPLY -m set --match-set %s src,src -j FP_CDOWN\n", mark, allowSet)
			fmt.Fprintf(&b, "-A FP_FWD -m connmark --mark %s -j DROP\n", mark)
			fmt.Fprintf(&b, "-A FP_CUP -m set --match-set %s dst,dst -j ACCEPT\n", upSet)
			fmt.Fprintf(&b, "-A FP_CDOWN -m set --match-set %s src,src -j ACCEPT\n", downSet)
		case "nat":
			names := []string{}
			for n := range nodes {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				parent := "FP_PRE"
				if len(n) > 1 {
					parent = "FP_N" + n[:len(n)-1]
				}
				var prefix uint32
				fmt.Sscanf(n, "%x", &prefix)
				bits := 8 + len(n)*4
				mask := uint32(0xffffffff) << (32 - bits)
				value := uint32(0xf1000000) | (prefix << uint(24-len(n)*4))
				fmt.Fprintf(&b, "-A %s -m connmark --mark 0x%08x/0x%08x -j FP_N%s\n", parent, value, mask, n)
			}
			for _, s := range plan {
				if s.Deleted {
					continue
				}
				token := fmt.Sprintf("%04x", s.Token)
				for _, proto := range []string{"tcp", "udp"} {
					fmt.Fprintf(&b, "-A FP_N%s -p %s -m connmark --mark %s -j DNAT --to-destination %s:%d\n", token[:3], proto, fullMark(s), s.TargetIP, s.TargetPort)
				}
			}
			fmt.Fprintf(&b, "-A FP_POST -m connmark --mark %s -m conntrack --ctdir ORIGINAL -j MASQUERADE\n", mark)
		}
		for _, c := range cs {
			fmt.Fprintf(&b, "-A %s -m comment --comment %s -j RETURN\n", c, owner)
		}
		b.WriteString("COMMIT\n")
		out[table] = b.String()
	}
	encoded, _ := json.Marshal(plan)
	out["ipset_plan"] = string(encoded)
	return out
}
