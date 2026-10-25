package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

func controlIdentity(rules map[string]Spec, allowed map[uint32]bool) (string, error) {
	var bitmap [2 * 8192]byte
	for _, rule := range rules {
		if rule.Deleted {
			continue
		}
		if rule.Token > 65535 {
			return "", fmt.Errorf("invalid control token")
		}
		bitmap[rule.Token>>3] |= byte(1 << (rule.Token & 7))
		if allowed[rule.Token] {
			bitmap[8192+(rule.Token>>3)] |= byte(1 << (rule.Token & 7))
		}
	}
	hash := sha256.Sum256(bitmap[:])
	return hex.EncodeToString(hash[:]), nil
}

var icmpNode = regexp.MustCompile(`(?m)^:(FP_I[0-9a-f]{1,3}) `)

// Error packets come from intermediate routers, not necessarily the target IP.
// Only conntrack-associated errors enter this bounded token tree. Ordinary
// TCP/UDP still uses the constant hash path; control errors are not business bytes.
func renderControl(rules map[string]Spec, allowed map[uint32]bool) string {
	return renderControlFamily("ipv4", rules, allowed)
}
func renderControlFamily(family string, rules map[string]Spec, allowed map[uint32]bool) string {
	proto, flag, minLength, maxLength := "icmp", "--icmp-type", 28, 576
	types := []int{3, 11, 12}
	if family == "ipv6" {
		proto = "ipv6-icmp"
		flag = "--icmpv6-type"
		minLength = 48
		maxLength = 1280
		types = []int{1, 2, 3, 4}
	}
	nodes := map[string]bool{}
	ids := keys(rules)
	for _, id := range ids {
		s := rules[id]
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
	var b strings.Builder
	b.WriteString("*filter\n:FP_ICMP - [0:0]\n:FP_IROOT - [0:0]\n")
	for _, n := range names {
		fmt.Fprintf(&b, ":FP_I%s - [0:0]\n", n)
	}
	for _, typ := range types {
		fmt.Fprintf(&b, "-A FP_ICMP -p %s %s %d -m conntrack --ctstate RELATED -m length --length %d:%d -j FP_IROOT\n", proto, flag, typ, minLength, maxLength)
	}
	b.WriteString("-A FP_ICMP -j DROP\n")
	for _, n := range names {
		parent := "FP_IROOT"
		if len(n) > 1 {
			parent = "FP_I" + n[:len(n)-1]
		}
		var prefix uint32
		fmt.Sscanf(n, "%x", &prefix)
		mask := uint32(0xffffffff) << uint(24-len(n)*4)
		value := uint32(0xf1000000) | (prefix << uint(24-len(n)*4))
		fmt.Fprintf(&b, "-A %s -m connmark --mark 0x%08x/0x%08x -j FP_I%s\n", parent, value, mask, n)
	}
	for _, id := range ids {
		s := rules[id]
		if !s.Deleted && allowed[s.Token] {
			token := fmt.Sprintf("%04x", s.Token)
			fmt.Fprintf(&b, "-A FP_I%s -m connmark --mark %s -m limit --limit 10/second --limit-burst 10 -j ACCEPT\n", token[:3], fullMark(s))
		}
	}
	for _, c := range append([]string{"FP_ICMP", "FP_IROOT"}, func() []string {
		x := []string{}
		for _, n := range names {
			x = append(x, "FP_I"+n)
		}
		return x
	}()...) {
		fmt.Fprintf(&b, "-A %s -m comment --comment %s -j RETURN\n", c, owner)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}
func (k *IPTables) UpdateControl(s State) error {
	allowed := map[uint32]bool{}
	var credits map[string]setElement
	for _, r := range s.Rules {
		if r.LeaseRequired && !r.Deleted {
			saved, e := k.readSet(creditSet)
			if e != nil {
				return e
			}
			credits = parseSet(saved)
			break
		}
	}
	for _, r := range s.Rules {
		if !r.Active() {
			continue
		}
		if !r.LeaseRequired {
			allowed[r.Token] = true
			continue
		}
		l, ok := s.Leases[r.ID]
		v, present := credits[targetKey(r)]
		if ok && !l.Closed && l.DeadlineBootMillis > bootMillis() && present && v.Bytes < creditCeiling {
			allowed[r.Token] = true
		}
	}
	shape, e := controlIdentity(s.Rules, allowed)
	if e != nil {
		return e
	}
	if shape == k.controlShape {
		return nil
	}
	desired := renderControl(s.Rules, allowed)
	adjusted, e := k.cleanStaleChains(desired, "filter", icmpNode)
	if e != nil {
		return e
	}
	if _, e = k.run(k.Binary+"-restore", adjusted, "--test", "--noflush", "--wait", "2"); e != nil {
		return e
	}
	if _, e = k.run(k.Binary+"-restore", adjusted, "--noflush", "--wait", "2"); e != nil {
		return e
	}
	k.controlShape = shape
	return nil
}

// ControlPlan compiles the ICMP primitive in isolation. It does not enable the
// IPv6 data-plane capability; that still requires the later dual-stack work.
func ControlPlan(family string, rules map[string]Spec) (string, error) {
	if family != "ipv4" && family != "ipv6" {
		return "", fmt.Errorf("invalid control address family")
	}
	copy := map[string]Spec{}
	allowed := map[uint32]bool{}
	next := uint32(1)
	for _, id := range keys(rules) {
		s := rules[id]
		if !serviceID.MatchString(id) || s.Token > 65535 {
			return "", fmt.Errorf("invalid control token")
		}
		if s.Token == 0 {
			s.Token = next
			next++
		}
		copy[id] = s
		allowed[s.Token] = s.Active()
	}
	return renderControlFamily(family, copy, allowed), nil
}
