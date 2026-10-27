package engine

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// localRestoreObject is a read-only conntrack lookup and header restoration
// classifier, not a forwarding engine. Compile recipe and prerequisites live
// beside its source. No compiler, remote object, or BPF map is used at runtime.
//
//go:embed bpf/local_restore.o
var localRestoreObject []byte

type localShapeFilter struct {
	Interface string `json:"interface"`
	Hook      string `json:"hook"`
	Protocol  string `json:"protocol"`
	Chain     int    `json:"chain"`
	Pref      int    `json:"pref"`
	Handle    int    `json:"handle"`
	Kind      string `json:"kind"`
}

func localShapingEnabled(rules map[string]Spec) bool {
	for _, s := range rules {
		if !s.Deleted && s.Active() && s.localTraffic() && s.Bandwidth.Enabled() {
			return true
		}
	}
	return false
}
func localShapingProblem() string {
	for _, name := range []string{"tc", "ip", "xdp"} {
		if st, e := os.Stat("/sys/fs/bpf/" + name + "/globals"); e != nil || !st.IsDir() {
			return "local shaping requires administrator-prepared bpffs tc/ip/xdp globals directories"
		}
	}
	iface, e := net.InterfaceByName("lo")
	if e != nil || iface.MTU < 131072 {
		return "local shaping requires a preconfigured loopback MTU >= 131072 to queue complete UDP datagrams"
	}
	for _, p := range []struct{ key, value string }{{"accept_local", "1"}, {"rp_filter", "2"}} {
		b, e := os.ReadFile("/proc/sys/net/ipv4/conf/lo/" + p.key)
		if e != nil || strings.TrimSpace(string(b)) != p.value {
			return "local shaping requires preconfigured net.ipv4.conf.lo." + p.key + "=" + p.value
		}
	}
	if _, e := os.Stat("/sys/kernel/btf/vmlinux"); e != nil {
		return "local shaping requires kernel BTF and bpf_skb_ct_lookup support"
	}
	return ""
}
func (f localShapeFilter) selector() []string {
	handle := fmt.Sprintf("0x%x", f.Handle)
	if f.Kind == "fw" {
		handle += "/0xff000040"
	}
	return []string{"dev", f.Interface, f.Hook, "chain", strconv.Itoa(f.Chain), "protocol", f.Protocol, "pref", strconv.Itoa(f.Pref), "handle", handle, f.Kind}
}
func (x *Auxiliary) removeLocalShaping() error {
	for _, f := range x.manifest.LocalFilters {
		if _, e := net.InterfaceByName(f.Interface); e != nil {
			continue
		}
		if _, e := x.runTC(append([]string{"filter", "del"}, f.selector()...)...); e != nil && !strings.Contains(e.Error(), "No such") && !strings.Contains(e.Error(), "Cannot find") && !strings.Contains(e.Error(), "not found") {
			return e
		}
	}
	for _, f := range x.manifest.LocalFilters {
		if f.Chain == 0 {
			continue
		}
		if _, e := net.InterfaceByName(f.Interface); e != nil {
			continue
		}
		_, e := x.runTC("chain", "del", "dev", f.Interface, f.Hook, "chain", strconv.Itoa(f.Chain))
		if e != nil && !strings.Contains(e.Error(), "No such") && !strings.Contains(e.Error(), "Cannot find") && !strings.Contains(e.Error(), "not found") {
			return e
		}
	}
	x.manifest.LocalFilters = nil
	// A private, fixed-name regular file is replaced atomically on next use.
	return nil
}

type localShapeCommand struct {
	Filter localShapeFilter
	Args   []string
}

func (x *Auxiliary) addLocalFilter(f localShapeFilter, args ...string) error {
	x.pendingLocal = append(x.pendingLocal, localShapeCommand{f, args})
	return nil
}
func (x *Auxiliary) installLocalFilters() error {
	x.manifest.Version = 2
	for _, c := range x.pendingLocal {
		x.manifest.LocalFilters = append(x.manifest.LocalFilters, c.Filter)
	}
	if e := x.save(); e != nil {
		return e
	}
	for _, c := range x.pendingLocal {
		if _, e := x.runTC(append(append([]string{"filter", "add"}, c.Filter.selector()...), c.Args...)...); e != nil {
			return fmt.Errorf("local shaping %s %s chain %d: %w", c.Filter.Interface, c.Filter.Hook, c.Filter.Chain, e)
		}
	}
	return nil
}
func (x *Auxiliary) removeRestoreObject() error {
	dir := x.parent.StatePath + ".bpf"
	st, e := os.Lstat(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || !sameObjectOwner(st) {
		return fmt.Errorf("refusing to clean foreign BPF directory")
	}
	path := filepath.Join(dir, "local_restore.o")
	st, e = os.Lstat(path)
	if e == nil {
		if !st.Mode().IsRegular() || !sameObjectOwner(st) {
			return fmt.Errorf("refusing to clean nonregular BPF object")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if !bytes.Equal(b, localRestoreObject) {
			return fmt.Errorf("refusing to clean foreign BPF object")
		}
		if e = os.Remove(path); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	if len(entries) == 0 {
		return os.Remove(dir)
	}
	return nil
}
func (x *Auxiliary) restoreObject() (string, error) {
	dir := x.parent.StatePath + ".bpf"
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return "", e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return "", e
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || !sameObjectOwner(st) {
		return "", fmt.Errorf("BPF object directory must be private and regular")
	}
	path := filepath.Join(dir, "local_restore.o")
	if st, e := os.Lstat(path); e == nil && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !sameObjectOwner(st)) {
		return "", fmt.Errorf("unsafe BPF object file")
	}
	if b, e := os.ReadFile(path); e == nil && bytes.Equal(b, localRestoreObject) {
		return path, nil
	}
	tmp, e := os.CreateTemp(dir, "restore-*")
	if e != nil {
		return "", e
	}
	defer os.Remove(tmp.Name())
	if _, e = tmp.Write(localRestoreObject); e != nil {
		tmp.Close()
		return "", e
	}
	if e = tmp.Sync(); e != nil {
		tmp.Close()
		return "", e
	}
	if e = tmp.Close(); e != nil {
		return "", e
	}
	return path, os.Rename(tmp.Name(), path)
}
func (x *Auxiliary) auditLocalTracking() error {
	// Early tc tracking cannot coexist safely with a later raw NOTRACK or a
	// non-default CT zone. Refuse instead of silently changing foreign policy.
	for _, bin := range []string{x.parent.parent.Binary, strings.Replace(x.parent.parent.Binary, "iptables", "ip6tables", 1)} {
		b, e := x.parent.parent.run(bin+"-save", "", "-t", "raw")
		if e != nil {
			return e
		}
		if strings.Contains(b, "-j NOTRACK") || strings.Contains(b, "--notrack") || strings.Contains(b, "--zone") {
			return fmt.Errorf("local shaping requires default conntrack zone without raw NOTRACK")
		}
	}
	text, e := x.parent.parent.run("nft", "", "-j", "list", "ruleset")
	if e != nil {
		return e
	}
	if strings.Contains(text, `"notrack"`) || strings.Contains(text, `"key":"zone"`) || strings.Contains(text, `"key": "zone"`) {
		return fmt.Errorf("local shaping conflicts with native nft tracking policy")
	}
	return nil
}
func (x *Auxiliary) auditEmptyTC(iface, hook string) error {
	text, e := x.runTC("-j", "filter", "show", "dev", iface, hook)
	if e != nil {
		return e
	}
	var rows []map[string]any
	if e = json.Unmarshal([]byte(text), &rows); e != nil {
		return e
	}
	for _, row := range rows {
		// Normal physical shaping's owned fw filters have already been audited.
		if hook == "egress" && jsonUint(row["pref"]) == 49151 && row["kind"] == "fw" {
			continue
		}
		return fmt.Errorf("local shaping requires empty %s classifiers on %s", hook, iface)
	}
	// tc filter show does not enumerate disconnected chains. Audit those too.
	text, e = x.runTC("-j", "chain", "show", "dev", iface, hook)
	if e != nil {
		return e
	}
	rows = nil
	if e = json.Unmarshal([]byte(text), &rows); e != nil {
		return e
	}
	for _, row := range rows {
		if jsonUint(row["chain"]) != 0 {
			return fmt.Errorf("foreign tc chain on %s %s", iface, hook)
		}
	}
	return nil
}
func (x *Auxiliary) applyLocalShaping(rules map[string]Spec, classes map[string]shapeClass, filters []shapeFilter) error {
	x.pendingLocal = nil
	defer func() { x.pendingLocal = nil }()
	if !localShapingEnabled(rules) {
		return nil
	}
	if p := localShapingProblem(); p != "" {
		return fmt.Errorf("%s", p)
	}
	if e := x.auditLocalTracking(); e != nil {
		return e
	}
	interfaces := map[string]bool{}
	leaves := map[uint32]map[bool]uint16{}
	for _, f := range filters {
		if f.Interface != "lo" {
			interfaces[f.Interface] = true
		}
		base := f.Mark & 0xffffff00
		if leaves[base] == nil {
			leaves[base] = map[bool]uint16{}
		}
		leaves[base][f.Mark&0x80 != 0] = f.Class
	}
	for iface := range interfaces {
		if e := x.auditEmptyTC(iface, "ingress"); e != nil {
			return e
		}
	}
	if e := x.auditEmptyTC("lo", "egress"); e != nil {
		return e
	}
	object, e := x.restoreObject()
	if e != nil {
		return e
	}
	add := x.addLocalFilter
	// ICMP/ICMPv6 remains on the established error/PMTU path, not a data queue.
	for i, p := range []string{"ip", "ipv6"} {
		proto := "icmp"
		if i == 1 {
			proto = "icmpv6"
		}
		if e = add(localShapeFilter{"lo", "egress", p, 0, 49140 + i, 1, "flower"}, "skip_hw", "ip_proto", proto, "action", "pass"); e != nil {
			return e
		}
	}
	if e = add(localShapeFilter{"lo", "egress", "all", 201, 1, 1, "bpf"}, "da", "obj", object, "section", "tc"); e != nil {
		return fmt.Errorf("kernel does not support local conntrack restoration: %w", e)
	}
	if e = add(localShapeFilter{"lo", "egress", "all", 201, 2, 1, "matchall"}, "action", "mirred", "egress", "redirect", "dev", shapingDevice); e != nil {
		return e
	}
	addresses, e := localAddresses()
	if e != nil {
		return e
	}
	for iface := range interfaces {
		// Packets reinjected by IFB have already spent this queue's tokens.
		if e = add(localShapeFilter{iface, "ingress", "all", 0, 49139, 0xf2000040, "fw"}, "action", "pass"); e != nil {
			return e
		}
		// The fw mask belongs to its handle; addLocalFilter handles it specially.
		for fi, family := range []string{"ipv4", "ipv6"} {
			protocol := "ip"
			bits := 32
			if fi == 1 {
				protocol = "ipv6"
				bits = 128
			}
			if e = add(localShapeFilter{iface, "ingress", protocol, 0, 49140 + fi, 1, "flower"}, "skip_hw", "action", "ct", "zone", "0", "pipe", "action", "goto", "chain", "200"); e != nil {
				return e
			}
			handle := 1
			for _, id := range keys(rules) {
				s := rules[id]
				if s.Deleted || !s.Active() || !s.Bandwidth.Enabled() {
					continue
				}
				base := flowMark(s)
				for _, up := range []bool{true, false} {
					class := leaves[base][up]
					if class == 0 {
						continue
					}
					mark := base | 0x40
					state := "+trk+rpl"
					if up {
						mark |= 0x80
						state = "+trk-rpl"
					}
					for _, proto := range []string{"tcp", "udp"} {
						actions := []string{"action", "skbedit", "mark", fmt.Sprintf("0x%x", mark), "priority", fmt.Sprintf("f100:%x", class), "action", "mirred", "egress", "redirect", "dev", shapingDevice}
						if e = add(localShapeFilter{iface, "ingress", protocol, 200, 100 + fi, handle, "flower"}, append([]string{"skip_hw", "ip_proto", proto, "ct_state", state, "ct_mark", fmt.Sprintf("0x%x/0xffffff00", base)}, actions...)...); e != nil {
							return e
						}
						handle++
					}
				}
			}
			handle = 1
			for _, id := range keys(rules) {
				s := rules[id]
				class := leaves[flowMark(s)][true]
				if s.Deleted || !s.Active() || class == 0 {
					continue
				}
				for _, l := range s.Listeners {
					if l.Family != family {
						continue
					}
					ips := []string{l.Host}
					if l.Host == "0.0.0.0" || l.Host == "::" {
						ips = addresses[family]
					}
					for _, ip := range ips {
						a, err := netip.ParseAddr(ip)
						if err != nil || a.IsLoopback() || !slices.Contains(addresses[family], ip) {
							continue
						}
						actions := []string{"action", "skbedit", "mark", fmt.Sprintf("0x%x", flowMark(s)|0xc0), "priority", fmt.Sprintf("f100:%x", class), "action", "mirred", "egress", "redirect", "dev", shapingDevice}
						if e = add(localShapeFilter{iface, "ingress", protocol, 200, 200 + fi, handle, "flower"}, append([]string{"skip_hw", "ip_proto", l.Protocol, "ct_state", "+trk+new", "dst_ip", fmt.Sprintf("%s/%d", ip, bits), "dst_port", strconv.Itoa(l.Port)}, actions...)...); e != nil {
							return e
						}
						handle++
					}
				}
			}
		}
	}
	return x.installLocalFilters()
}

const localProbeDevice = "fp4probe"

func (x *Auxiliary) removeLocalProbe() error {
	text, e := x.parent.parent.run("ip", "", "-j", "link", "show", "dev", localProbeDevice)
	if e != nil {
		if strings.Contains(e.Error(), "does not exist") || strings.Contains(e.Error(), "Cannot find") {
			return nil
		}
		return e
	}
	var links []map[string]any
	if e = json.Unmarshal([]byte(text), &links); e != nil {
		return e
	}
	if len(links) != 1 || links[0]["ifalias"] != advancedOwner+":"+x.parent.epoch+":probe" {
		return fmt.Errorf("foreign local-shaping probe device")
	}
	_, e = x.parent.parent.run("ip", "", "link", "del", localProbeDevice)
	return e
}

// Load the exact embedded program on an unconnected, down IFB first. A kernel,
// BTF, libbpf or permission failure must become an operational failed rule,
// not roll back a newly introduced user cap to its old unlimited generation.
func (a *AdvancedKernel) probeLocalShaping() (problem string) {
	x, e := a.auxiliary()
	if e != nil {
		return e.Error()
	}
	if e = x.removeLocalProbe(); e != nil {
		return e.Error()
	}
	object, e := x.restoreObject()
	if e != nil {
		return e.Error()
	}
	if _, e = a.parent.run("ip", "", "link", "add", localProbeDevice, "type", "ifb"); e != nil {
		return "local shaping IFB probe: " + e.Error()
	}
	if _, e = a.parent.run("ip", "", "link", "set", "dev", localProbeDevice, "alias", advancedOwner+":"+a.epoch+":probe"); e != nil {
		_, _ = a.parent.run("ip", "", "link", "del", localProbeDevice)
		return e.Error()
	}
	defer func() {
		if e := x.removeLocalProbe(); e != nil {
			if problem != "" {
				problem += "; "
			}
			problem += "local shaping probe cleanup: " + e.Error()
		}
	}()
	for _, args := range [][]string{
		{"qdisc", "add", "dev", localProbeDevice, "clsact"},
		{"filter", "add", "dev", localProbeDevice, "ingress", "protocol", "all", "pref", "1", "matchall", "action", "ct", "zone", "0", "pipe"},
		{"filter", "add", "dev", localProbeDevice, "egress", "chain", "201", "protocol", "all", "pref", "1", "bpf", "da", "obj", object, "section", "tc"},
	} {
		if _, e = x.runTC(args...); e != nil {
			return "local shaping kernel preflight: " + e.Error()
		}
	}
	return ""
}

func sameObjectOwner(st os.FileInfo) bool {
	stat, ok := st.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
