package engine

import (
	"bytes"
	"context"
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
type IPTables struct{ Binary string }

func (k IPTables) Configured() (bool, error) {
	s, e := k.run(k.Binary+"-save", "", "-t", "nat")
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "-A FP_PRE ") && strings.Contains(line, "-j DNAT") {
			return true, e
		}
	}
	return false, e
}

func (k IPTables) ValidateSpec(s Spec) error {
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
func (k IPTables) Forget(s Spec) error {
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

func (k IPTables) run(name, input string, args ...string) (string, error) {
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
	return string(out), nil
}

func (k IPTables) Initialize() error {
	if _, e := exec.LookPath("conntrack"); e != nil {
		return fmt.Errorf("conntrack tool required for safe target changes and deletion")
	}
	data, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if e != nil || strings.TrimSpace(string(data)) != "1" {
		return fmt.Errorf("IPv4 forwarding must already be enabled in this network namespace")
	}
	for _, table := range []string{"mangle", "nat", "filter"} {
		r, e := k.run(k.Binary+"-save", "", "-t", table)
		if e != nil {
			return e
		}
		for _, c := range chains[table] {
			if strings.Contains(r, ":"+c+" ") && !strings.Contains(r, "-A "+c+" -m comment --comment "+owner+" -j RETURN") && !strings.Contains(r, "-A "+c+" -m comment --comment \""+owner+"\" -j RETURN") {
				return fmt.Errorf("chain %s exists without ownership marker", c)
			}
		}
		for _, l := range strings.Split(r, "\n") {
			if strings.Contains(l, "0xf1000000") && !strings.Contains(l, "-A FP_") {
				return fmt.Errorf("reserved connmark namespace is already used")
			}
		}
	}
	return nil
}

func (k IPTables) Snapshot() (map[string]uint64, error) {
	s, e := k.run(k.Binary+"-save", "", "-c", "-t", "filter")
	if e != nil {
		return nil, e
	}
	return ParseCounters(s), nil
}

func (k IPTables) Apply(tables map[string]string) error {
	for _, t := range []string{"mangle", "filter", "nat"} {
		if _, e := k.run(k.Binary+"-restore", tables[t], "--wait", "2", "--noflush", "--counters", "--test"); e != nil {
			return e
		}
	}
	// Each table is a separate commit; the manager restores owned tables on failure.
	for _, t := range []string{"mangle", "filter", "nat"} {
		if _, e := k.run(k.Binary+"-restore", tables[t], "--wait", "2", "--noflush", "--counters"); e != nil {
			return e
		}
	}
	for _, h := range Hooks {
		args := []string{"--wait", "2", "-t", h.Table, "-C", h.Parent, "-m", "comment", "--comment", "flux-hook:v1", "-j", h.Child}
		if _, e := k.run(k.Binary, "", args...); e != nil {
			args[4] = "-I"
			args = append(args[:6], append([]string{"1"}, args[6:]...)...)
			if _, e = k.run(k.Binary, "", args...); e != nil {
				return e
			}
		}
	}
	return nil
}
