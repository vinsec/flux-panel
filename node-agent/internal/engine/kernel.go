package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Kernel interface {
	Snapshot() (map[string]uint64, error)
	Apply(map[string]string) error
}
type NativeKernel struct {
	Gost   *GostRunner
	Mode   string
	DPI    *protocolEngine
	Native *NativeNFT
	P1     *AdvancedKernel
}

func (k *NativeKernel) Configured() (bool, error) { return k.Native.configured() }
func (k *NativeKernel) ValidateSpec(s Spec) error {
	if k.Gost != nil && k.Mode == "gost" {
		if e := k.Gost.validate(s); e != nil {
			return e
		}
		if e := k.checkGostShaping([]Spec{s}); e != nil {
			return e
		}
	}
	return k.P1.validate(s)
}
func ValidateCheckpointBackend(path string) error {
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var s struct {
		KernelBackend string `json:"kernelBackend"`
		FormatVersion int    `json:"formatVersion"`
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return e
	}
	if s.KernelBackend != "nftables" {
		return fmt.Errorf("iptables backend/state is retired; settle and export using the previous release before explicit migration")
	}
	return nil
}

func (k *NativeKernel) validateBaseSpec(s Spec) error {
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

func (k *NativeKernel) Forget(s Spec) error {
	if k.Gost != nil && k.Mode == "gost" {
		plan, _, e := k.Gost.project([]Spec{s})
		if e != nil {
			return e
		}
		s = plan[0]
	}
	seen := map[string]bool{}
	for _, l := range s.ListenerList() {
		if seen[l.Family] {
			continue
		}
		seen[l.Family] = true
		_, e := k.run("conntrack", "", "-D", "-f", l.Family, "--mark", fullMark(s))
		if e != nil && !strings.Contains(e.Error(), "0 flow entries") {
			return e
		}
	}
	return nil
}
func (k *NativeKernel) ForgetMany(specs []Spec) error {
	if len(specs) <= 16 {
		for _, s := range specs {
			if e := k.Forget(s); e != nil {
				return e
			}
		}
		return nil
	}
	if k.Gost != nil && k.Mode == "gost" {
		projected, _, e := k.Gost.project(specs)
		if e != nil {
			return e
		}
		specs = projected
	}
	groups := map[string][]Spec{}
	for _, s := range specs {
		seen := map[string]bool{}
		for _, l := range s.ListenerList() {
			key := fmt.Sprintf("%s/%x", l.Family, flowMark(s)&0xff000000)
			if !seen[key] {
				groups[key] = append(groups[key], s)
				seen[key] = true
			}
		}
	}
	refs, e := k.References()
	if e != nil {
		return e
	}
	for key, group := range groups {
		family := strings.Split(key, "/")[0]
		prefix := flowMark(group[0]) & 0xff000000
		for _, block := range forgetBlocks(group) {
			live := false
			for token := block.first; token < block.end; token++ {
				if refs[fmt.Sprintf("mark:0x%x", prefix|uint32(token)<<8)] {
					live = true
					break
				}
			}
			if !live {
				continue
			}
			value := prefix | uint32(block.first)<<8
			mask := uint32(0xffffffff) << uint(8+block.bits)
			_, e = k.run("conntrack", "", "-D", "-f", family, "--mark", fmt.Sprintf("0x%x/0x%x", value, mask))
			if e != nil && !strings.Contains(e.Error(), "0 flow entries") {
				return e
			}
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

func (k *NativeKernel) run(name, input string, args ...string) (string, error) {
	timeout := 4 * time.Second
	// Large restores are submitted as asynchronous jobs. Bound their process
	// lifetime without killing a valid 10k-rule transaction at the small-command
	// deadline on slower native hosts. Short control/inspection commands retain
	// the normal deadline.
	if len(input) > 512*1024 && (strings.HasSuffix(name, "restore") || name == "nft") {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	if input != "" {
		c.Stdin = bytes.NewBufferString(input)
	}
	out, e := c.CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("%s: %w: %s", name, e, strings.TrimSpace(string(out)))
	}
	result := strings.TrimSpace(string(out))
	if name == "nft" && input == "" {
		for _, a := range args {
			if a == "-j" || a == "--json" {
				return nftJSONTableComments(result, func(family, table string) (string, error) { return k.run("nft", "", "list", "table", family, table) })
			}
		}
	}
	return result, nil
}

func (k *NativeKernel) Initialize() error {
	if k.Native == nil || k.P1 == nil {
		return fmt.Errorf("native kernel is not configured")
	}
	if e := ValidateCheckpointBackend(k.P1.StatePath); e != nil {
		return e
	}
	if b, e := k.run("nft", "", "-j", "list", "tables"); e == nil && strings.Contains(b, `"FP_PROTOCOL"`) {
		k.protocolEngine()
	}
	if _, e := k.Native.preflight(); e != nil {
		return e
	}
	if e := k.Native.ensure(); e != nil {
		return e
	}
	return k.Native.ensureMaps()
}
func (k *NativeKernel) Snapshot() (map[string]uint64, error) {
	totals, _, e := k.Native.snapshot()
	return totals, e
}
func (k *NativeKernel) Apply(tables map[string]string) (failure error) {
	defer func() {
		if failure == nil && k.DPI != nil {
			failure = k.DPI.apply()
		}
	}()
	plan, e := decodePlan(tables)
	if e != nil {
		return e
	}
	if k.Gost != nil {
		if k.Mode == "gost" {
			projected, services, e := k.Gost.project(plan)
			if e != nil {
				return e
			}
			if e = k.Gost.guard(k, services); e != nil {
				return e
			}
			if e = k.Gost.sync(services); e != nil {
				return e
			}
			return k.Native.apply(projected)
		}
		if e := k.Gost.ready(); e == nil {
			if e = k.Gost.clear(); e != nil {
				return e
			}
			if e = k.Gost.guard(k, map[string]map[string]any{}); e != nil {
				return e
			}
		} else if len(k.Gost.applied) > 0 {
			return e
		}

	}
	return k.Native.apply(plan)
}
