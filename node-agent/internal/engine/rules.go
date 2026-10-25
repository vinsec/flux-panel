package engine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const owner = "flux-owner:v1"
const mark = "0xf1000000/0xff000000"

var chains = map[string][]string{"mangle": {"FP_MARK"}, "nat": {"FP_PRE", "FP_POST"}, "filter": {"FP_FWD"}}

type Hook struct{ Table, Parent, Child string }

var Hooks = []Hook{{"mangle", "PREROUTING", "FP_MARK"}, {"nat", "PREROUTING", "FP_PRE"}, {"nat", "POSTROUTING", "FP_POST"}, {"filter", "FORWARD", "FP_FWD"}}

func keys(rules map[string]Spec) []string {
	r := make([]string, 0, len(rules))
	for k := range rules {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}

func tuple(s Spec, proto string) string {
	r := fmt.Sprintf("-p %s -m connmark --mark %s -m conntrack --ctproto %s --ctorigdstport %d", proto, mark, proto, s.ListenPort)
	if s.ListenIP != "0.0.0.0" {
		r += " --ctorigdst " + s.ListenIP
	}
	return r
}

// Render declares only our chains. --noflush preserves every other chain.
// Counters are carried over by stable comment, including across target changes.
func Render(rules map[string]Spec, counters map[string]uint64) map[string]string {
	out := map[string]string{}
	for table, cs := range chains {
		var b strings.Builder
		fmt.Fprintf(&b, "*%s\n", table)
		for _, c := range cs {
			fmt.Fprintf(&b, ":%s - [0:0]\n", c)
		}
		for _, id := range keys(rules) {
			s := rules[id]
			if s.Deleted {
				continue
			}
			for _, proto := range []string{"tcp", "udp"} {
				listener := fmt.Sprintf("-p %s -m addrtype --dst-type LOCAL --dport %d", proto, s.ListenPort)
				if s.ListenIP != "0.0.0.0" {
					listener += " -d " + s.ListenIP
				}
				switch table {
				case "mangle":
					fmt.Fprintf(&b, "-A FP_MARK %s -m connmark --mark 0x0/0xff000000 -j CONNMARK --set-xmark %s\n", listener, mark)
				case "nat":
					fmt.Fprintf(&b, "-A FP_PRE %s -m connmark --mark %s -j DNAT --to-destination %s:%d\n", listener, mark, s.TargetIP, s.TargetPort)
				case "filter":
					for _, dir := range []string{"up", "down"} {
						ctdir := "ORIGINAL"
						if dir == "down" {
							ctdir = "REPLY"
						}
						comment := "flux:v1:" + id + ":" + proto + ":" + dir
						action := "DROP"
						if s.Active() {
							action = "ACCEPT"
						}
						// Paused/drop counters are deliberately not billed.
						if action == "DROP" {
							comment += ":blocked"
						}
						fmt.Fprintf(&b, "[0:%d] -A FP_FWD %s --ctdir %s -m comment --comment %s -j %s\n", counters[comment], tuple(s, proto), ctdir, comment, action)
					}
				}
			}
		}
		if table == "nat" {
			fmt.Fprintf(&b, "-A FP_POST -m connmark --mark %s -m conntrack --ctdir ORIGINAL -j MASQUERADE\n", mark)
		}
		if table == "filter" {
			fmt.Fprintf(&b, "-A FP_FWD -m connmark --mark %s -j DROP\n", mark)
		}
		for _, c := range cs {
			fmt.Fprintf(&b, "-A %s -m comment --comment %s -j RETURN\n", c, owner)
		}
		b.WriteString("COMMIT\n")
		out[table] = b.String()
	}
	return out
}

func ParseCounters(text string) map[string]uint64 {
	out := map[string]uint64{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasPrefix(f[0], "[") || f[1] != "-A" || f[2] != "FP_FWD" {
			continue
		}
		for i, v := range f {
			if v == "--comment" && i+1 < len(f) {
				name := strings.Trim(f[i+1], "\"")
				if !strings.HasPrefix(name, "flux:v1:") || strings.HasSuffix(name, ":blocked") {
					continue
				}
				n := strings.Split(strings.Trim(f[0], "[]"), ":")
				if len(n) == 2 {
					if v, e := strconv.ParseUint(n[1], 10, 64); e == nil {
						out[name] = v
					}
				}
			}
		}
	}
	return out
}
