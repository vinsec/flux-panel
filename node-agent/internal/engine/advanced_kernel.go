package engine

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
)

const advancedOwner = "flux-owner:v4"
const advancedMark = "0xf2000000/0xff000000"

type AdvancedKernel struct {
	parent            *NativeKernel
	StatePath         string
	last              map[string]Spec
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

func (k *NativeKernel) enableRuntime(path string) {
	k.P1 = &AdvancedKernel{parent: k, StatePath: path, last: map[string]Spec{}}
	k.P1.quota = &SharedQuota{parent: k}
}
func (a *AdvancedKernel) ensurePlane(family string) error {
	if family == "ipv6" {
		b, e := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
		if e != nil || strings.TrimSpace(string(b)) != "1" {
			return fmt.Errorf("IPv6 forwarding must already be enabled")
		}
	}
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

func (k *NativeKernel) RuntimeFailure(id string) string {
	if k.P1 != nil {
		return k.P1.runtimeErrors[id]
	}
	return ""
}

func counterBaseline(set, id, direction string) string {
	family := "all"
	if strings.HasPrefix(set, "FP6_") {
		family = "ipv6"
	}
	return "flux:v2:" + id + ":" + family + ":" + direction
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
