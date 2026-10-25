package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Kernel interface {
	Snapshot() (map[string]uint64, error)
	Apply(map[string]string) error
}
type IPTables struct {
	Binary       string
	shape        string
	controlShape string
}

func (k *IPTables) Configured() (bool, error) {
	s, e := k.run(k.Binary+"-save", "", "-t", "nat")
	for _, line := range strings.Split(s, "\n") {
		if (strings.HasPrefix(line, "-A FP_PRE ") || strings.HasPrefix(line, "-A FP_N")) && strings.Contains(line, "-j DNAT") {
			return true, e
		}
	}
	return false, e
}

func (k *IPTables) ValidateSpec(s Spec) error {
	if s.Deleted || !s.Enabled {
		return nil
	}
	addresses, e := net.InterfaceAddrs()
	if e != nil {
		return e
	}
	local := s.ListenIP == "0.0.0.0"
	for _, a := range addresses {
		ip, _, e := net.ParseCIDR(a.String())
		if e == nil && ip.Equal(net.ParseIP(s.ListenIP)) {
			local = true
		}
	}
	if !local {
		return fmt.Errorf("listen IPv4 is not assigned to this namespace")
	}
	for _, a := range addresses {
		ip, _, e := net.ParseCIDR(a.String())
		if e == nil && ip.Equal(net.ParseIP(s.TargetIP)) {
			return fmt.Errorf("local target is unsupported by the external-ingress engine")
		}
	}
	endpoint := net.JoinHostPort(s.ListenIP, fmt.Sprint(s.ListenPort))
	tcp, e := net.Listen("tcp4", endpoint)
	if e != nil {
		return fmt.Errorf("TCP listen port already occupied: %w", e)
	}
	tcp.Close()
	udp, e := net.ListenPacket("udp4", endpoint)
	if e != nil {
		return fmt.Errorf("UDP listen port already occupied: %w", e)
	}
	udp.Close()
	return nil
}

// Remove only this engine's original tuple. Deleting a NAT rule alone leaves
// conntrack mappings alive and could revive an old target when a port is reused.
func (k *IPTables) Forget(s Spec) error {
	for _, proto := range []string{"tcp", "udp"} {
		args := []string{"-D", "-f", "ipv4", "-p", proto, "--orig-port-dst", fmt.Sprint(s.ListenPort), "--mark", mark}
		if s.ListenIP != "0.0.0.0" {
			args = append(args, "--orig-dst", s.ListenIP)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		out, e := exec.CommandContext(ctx, "conntrack", args...).CombinedOutput()
		cancel()
		if e != nil && !strings.Contains(string(out), "0 flow entries") {
			return fmt.Errorf("targeted conntrack cleanup: %w: %s", e, out)
		}
	}
	return nil
}

// The transaction guard is already installed before this method runs. Revoked
// tokens cannot confirm new connections, so one conntrack dump safely excludes
// empty tokens without spawning two processes for every deleted forwarding.
func (k *IPTables) ForgetMany(specs []Spec) error {
	if len(specs) <= 16 {
		for _, s := range specs {
			if e := k.Forget(s); e != nil {
				return e
			}
		}
		return nil
	}
	refs, e := k.References()
	if e != nil {
		return e
	}
	for _, block := range forgetBlocks(specs) {
		live := false
		for token := block.first; token < block.end; token++ {
			if refs[fmt.Sprintf("mark:0x%x", uint32(0xf1000000)|(uint32(token)<<8))] {
				live = true
				break
			}
		}
		if !live {
			continue
		}
		// Sibling tokens are combined only when every token in the prefix is
		// revoked. A surviving forwarding can never match this deletion mask.
		value := uint32(0xf1000000) | uint32(block.first)<<8
		mask := uint32(0xffffffff) << uint(8+block.bits)
		_, e = k.run("conntrack", "", "-D", "-f", "ipv4", "--mark", fmt.Sprintf("0x%x/0x%x", value, mask))
		if e != nil && !strings.Contains(e.Error(), "0 flow entries") {
			return e
		}
	}
	return nil
}

type tokenBlock struct{ first, end, bits int }

func forgetBlocks(specs []Spec) []tokenBlock {
	selected := make([]int, 65537)
	for _, s := range specs {
		if s.Token > 0 && s.Token <= 65535 {
			selected[s.Token+1] = 1
		}
	}
	for i := 1; i < len(selected); i++ {
		selected[i] += selected[i-1]
	}
	blocks := []tokenBlock{}
	var visit func(int, int)
	visit = func(first, bits int) {
		end := first + 1<<bits
		count := selected[end] - selected[first]
		if count == 0 {
			return
		}
		if count == end-first {
			blocks = append(blocks, tokenBlock{first, end, bits})
			return
		}
		visit(first, bits-1)
		visit(first+1<<(bits-1), bits-1)
	}
	visit(0, 16)
	return blocks
}

func (m *Manager) forget(specs []Spec) error {
	if k, ok := m.Kernel.(interface{ ForgetMany([]Spec) error }); ok {
		return k.ForgetMany(specs)
	}
	if k, ok := m.Kernel.(interface{ Forget(Spec) error }); ok {
		for _, s := range specs {
			if e := k.Forget(s); e != nil {
				return e
			}
		}
	}
	return nil
}

func (k *IPTables) run(name, input string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	if input != "" {
		c.Stdin = bytes.NewBufferString(input)
	}
	out, e := c.CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("%s: %w: %s", name, e, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func (k *IPTables) Initialize() error {
	if _, e := exec.LookPath("ipset"); e != nil {
		return fmt.Errorf("ipset is required by the v2 hash path")
	}
	if _, e := exec.LookPath("conntrack"); e != nil {
		return fmt.Errorf("conntrack tool required for safe target changes and deletion")
	}
	data, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if e != nil || strings.TrimSpace(string(data)) != "1" {
		return fmt.Errorf("IPv4 forwarding must already be enabled in this network namespace")
	}
	// A live v1 ruleset must be explicitly drained before the format upgrade.
	for _, table := range []string{"mangle", "nat", "filter"} {
		r, e := k.run(k.Binary+"-save", "", "-t", table)
		if e != nil {
			return e
		}
		if strings.Contains(r, "flux-owner:v1") {
			return fmt.Errorf("live v1 rules detected; pause/drain and migrate explicitly before v2")
		}
		for _, c := range chains[table] {
			if strings.Contains(r, ":"+c+" ") && !strings.Contains(r, "-A "+c+" -m comment --comment "+owner+" -j RETURN") && !strings.Contains(r, "-A "+c+" -m comment --comment \""+owner+"\" -j RETURN") && !knownOwnedChain(r, c) {
				return fmt.Errorf("chain %s exists without ownership marker", c)
			}
		}
		for _, l := range strings.Split(r, "\n") {
			if reservedMark.MatchString(l) && !strings.Contains(l, "-A FP_") && !strings.Contains(l, gateComment) {
				return fmt.Errorf("reserved connmark namespace is already used")
			}
		}
	}
	if _, e := k.Preflight(); e != nil {
		return e
	}
	return k.initializeSets()
}

func (k *IPTables) Snapshot() (map[string]uint64, error) { return k.setCounters() }

func (k *IPTables) Apply(tables map[string]string) error {
	plan, e := decodePlan(tables)
	if e != nil {
		return e
	}
	bindings, active, e := k.plans(plan)
	if e != nil {
		return e
	}
	desired := shapeDigest(tables, bindings)
	full := desired != k.shape
	k.shape = ""
	if e = k.prepareCounters(plan); e != nil {
		return e
	}
	if full {
		k.controlShape = ""
		if e = k.stageSet(bindingSet, bindings); e != nil {
			return e
		}
		adjusted, e := k.cleanStaleNAT(tables["nat"])
		if e != nil {
			return e
		}
		input := map[string]string{"mangle": tables["mangle"], "filter": tables["filter"], "nat": adjusted}
		for _, t := range []string{"filter", "nat", "mangle"} {
			if _, e = k.run(k.Binary+"-restore", input[t], "--wait", "2", "--noflush", "--test"); e != nil {
				return e
			}
		}
		for _, t := range []string{"filter", "nat", "mangle"} {
			if _, e = k.run(k.Binary+"-restore", input[t], "--wait", "2", "--noflush"); e != nil {
				return e
			}
		}
		for _, h := range Hooks {
			args := []string{"--wait", "2", "-t", h.Table, "-C", h.Parent, "-m", "comment", "--comment", "flux-hook:v3", "-j", h.Child}
			if _, e = k.run(k.Binary, "", args...); e != nil {
				args[4] = "-I"
				position := "1"
				if h.Table == "filter" {
					gates, err := k.gateRules()
					if err != nil {
						return err
					}
					position = fmt.Sprint(1 + len(gates))
				}
				args = append(args[:6], append([]string{position}, args[6:]...)...)
				if _, e = k.run(k.Binary, "", args...); e != nil {
					return e
				}
			}
		}
		for _, h := range Hooks {
			for {
				args := []string{"--wait", "2", "-t", h.Table, "-D", h.Parent, "-m", "comment", "--comment", "flux-hook:v2", "-j", h.Child}
				if _, err := k.run(k.Binary, "", args...); err != nil {
					break
				}
			}
		}
		if _, e = k.run("ipset", "", "swap", bindingSet+"_NEW", bindingSet); e != nil {
			return e
		}
	}
	if e = k.policy(active); e != nil {
		return e
	}
	k.shape = desired
	return nil
}

var natNode = regexp.MustCompile(`(?m)^:(FP_N[0-9a-f]{1,3}) `)
var reservedMark = regexp.MustCompile(`(?i)0xf1[0-9a-f]{6}`)

func ownedChain(text, name string) bool {
	return strings.Contains(text, "-A "+name+" -m comment --comment "+owner+" -j RETURN") || strings.Contains(text, "-A "+name+" -m comment --comment \""+owner+"\" -j RETURN")
}
func (k *IPTables) cleanStaleNAT(desired string) (string, error) {
	return k.cleanStaleChains(desired, "nat", natNode)
}
func (k *IPTables) cleanStaleChains(desired, table string, node *regexp.Regexp) (string, error) {
	current, e := k.run(k.Binary+"-save", "", "-t", table)
	if e != nil {
		return "", e
	}
	newNames := map[string]bool{}
	for _, m := range node.FindAllStringSubmatch(desired, -1) {
		newNames[m[1]] = true
	}
	stale := []string{}
	for _, m := range node.FindAllStringSubmatch(current, -1) {
		if !knownOwnedChain(current, m[1]) {
			return "", fmt.Errorf("NAT trie chain %s has no ownership marker", m[1])
		}
		if !newNames[m[1]] {
			stale = append(stale, m[1])
		}
	}
	sort.Strings(stale)
	decl, remove := "", ""
	for _, name := range stale {
		decl += ":" + name + " - [0:0]\n"
		remove += "-X " + name + "\n"
	}
	desired = strings.Replace(desired, "*"+table+"\n", "*"+table+"\n"+decl, 1)
	return strings.Replace(desired, "COMMIT\n", remove+"COMMIT\n", 1), nil
}

func knownOwnedChain(text, name string) bool {
	return ownedChain(text, name) || strings.Contains(text, "-A "+name+" -m comment --comment "+previousOwner+" -j RETURN") || strings.Contains(text, "-A "+name+" -m comment --comment \""+previousOwner+"\" -j RETURN")
}
