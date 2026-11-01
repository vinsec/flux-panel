package panel

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/net/idna"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

var portPattern = regexp.MustCompile(`^[0-9]{1,5}$`)
var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func endpoint(text string) M {
	if text != strings.TrimSpace(text) {
		fail("invalid endpoint")
	}
	host, port, e := net.SplitHostPort(text)
	if e != nil || host == "" || !portPattern.MatchString(port) {
		fail("endpoint must be host:port; bracket IPv6")
	}
	n := num(port)
	if n < 1 || n > 65535 {
		fail("invalid port")
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			fail("invalid or scoped IPv6")
		}
		ip = ip.Unmap()
		family := "ipv6"
		if ip.Is4() {
			family = "ipv4"
		}
		return M{"kind": "ip", "host": ip.String(), "port": n, "family": family}
	}
	if strings.ContainsAny(host, ":%@/\\?#") {
		fail("invalid hostname")
	}
	if regexp.MustCompile(`^[0-9.]+$`).MatchString(host) {
		fail("ambiguous or invalid IPv4")
	}
	host, e = idna.New(idna.MapForLookup(), idna.Transitional(true), idna.StrictDomainName(true)).ToASCII(strings.TrimSuffix(host, "."))
	if e != nil {
		fail("invalid IDNA hostname")
	}
	host = strings.ToLower(host)
	if len(host) < 1 || len(host) > 253 {
		fail("invalid hostname length")
	}
	for _, s := range strings.Split(host, ".") {
		if !dnsLabel.MatchString(s) {
			fail("invalid DNS label")
		}
	}
	return M{"kind": "hostname", "host": host, "port": n, "family": "auto"}
}
func join(host string, port any) string { return net.JoinHostPort(strings.Trim(host, "[]"), str(port)) }
func allowed(m M, keys string) {
	set := M{}
	for _, k := range strings.Fields(keys) {
		set[k] = true
	}
	for k := range m {
		if set[k] == nil {
			fail("unsupported engine option: " + k)
		}
	}
}
func booleanFields(m M, keys string) {
	for _, k := range strings.Fields(keys) {
		if v, ok := m[k]; ok {
			if _, ok := v.(bool); !ok {
				fail("boolean required for " + k)
			}
		}
	}
}
func bound(m M, k string, def, min, max int64) {
	v := def
	if m[k] != nil {
		v = num(m[k])
	}
	if v < min || v > max {
		fail("invalid bound for " + k)
	}
}
func rates(m M) {
	for _, k := range []string{"upBitsPerSecond", "downBitsPerSecond"} {
		v := num(m[k])
		if v != 0 && (v < 1000 || v > 1000000000000) {
			fail("rate must be zero or 1000..1e12 bits/second")
		}
	}
}
func options(text string) M {
	if strings.TrimSpace(text) == "" {
		return M{}
	}
	if len(text) > 32768 {
		fail("engine options exceed 32KiB")
	}
	o := decode([]byte(text))
	allowed(o, "listeners targets selection dnsPolicy health egress bandwidth traffic protocolFilter")
	if v, ok := o["protocolFilter"]; ok {
		m := obj(v)
		allowed(m, "http tls socks unknown")
		booleanFields(m, "http tls socks")
		if str(m["unknown"]) != "allow" {
			fail("unknown protocols must be allowed")
		}
	}
	if v, ok := o["traffic"]; ok {
		m := obj(v)
		allowed(m, "localOutput localTargets sourceMode returnPathConfirmed")
		booleanFields(m, "localOutput localTargets returnPathConfirmed")
		mode := str(m["sourceMode"])
		if mode != "" && mode != "masquerade" && mode != "preserve" {
			fail("invalid source mode")
		}
		if (mode == "preserve") != truth(m["returnPathConfirmed"]) {
			fail("source preservation requires return routing confirmation")
		}
		if mode == "preserve" {
			eg := obj(o["egress"])
			if str(eg["sourceIPv4"]) != "" || str(eg["sourceIPv6"]) != "" {
				fail("source preservation conflicts with explicit SNAT")
			}
		}
	}
	if v, ok := o["listeners"]; ok {
		a := arr(v)
		if len(a) < 1 || len(a) > 16 {
			fail("1..16 listeners required")
		}
		for _, item := range a {
			m := obj(item)
			allowed(m, "host port protocol family")
			if str(m["protocol"]) != "tcp" && str(m["protocol"]) != "udp" {
				fail("TCP/UDP listener required")
			}
			e := endpoint(join(str(m["host"]), num(m["port"])))
			if str(e["kind"]) != "ip" {
				fail("listener must be numeric IP")
			}
		}
	}
	if v, ok := o["targets"]; ok {
		a := arr(v)
		if len(a) < 1 || len(a) > 16 {
			fail("1..16 targets required")
		}
		sum := int64(0)
		for _, item := range a {
			m := obj(item)
			allowed(m, "endpoint weight")
			ep := obj(m["endpoint"])
			allowed(ep, "kind host port family")
			endpoint(join(str(ep["host"]), num(ep["port"])))
			w := int64(1)
			if m["weight"] != nil {
				w = num(m["weight"])
			}
			if w < 1 || w > 32 {
				fail("target weight must be 1..32")
			}
			sum += w
		}
		if sum > 32 {
			fail("target weights exceed 32 buckets")
		}
	}
	if v, ok := o["selection"]; ok {
		switch str(v) {
		case "fifo", "hash", "round", "random":
		default:
			fail("invalid target selection")
		}
	}
	if v, ok := o["dnsPolicy"]; ok {
		m := obj(v)
		allowed(m, "failClosed staleMillis drainMillis")
		bound(m, "staleMillis", 30000, 0, 300000)
		bound(m, "drainMillis", 300000, 1000, 3600000)
	}
	if v, ok := o["health"]; ok {
		m := obj(v)
		allowed(m, "protocol port intervalMillis timeoutMillis rise fall payload expected")
		if str(m["protocol"]) != "tcp" && str(m["protocol"]) != "udp" {
			fail("health protocol required")
		}
		bound(m, "intervalMillis", 5000, 1000, 60000)
		bound(m, "timeoutMillis", 500, 50, 3000)
		bound(m, "rise", 2, 1, 10)
		bound(m, "fall", 2, 1, 10)
		bound(m, "port", 0, 0, 65535)
		if str(m["protocol"]) == "udp" {
			for _, k := range []string{"payload", "expected"} {
				b, e := base64.StdEncoding.DecodeString(str(m[k]))
				if e != nil || len(b) < 1 || len(b) > 64 {
					fail("UDP health requires bounded explicit exchange")
				}
			}
		}
	}
	if v, ok := o["egress"]; ok {
		m := obj(v)
		allowed(m, "interface sourceIPv4 sourceIPv6 gatewayIPv4 gatewayIPv6")
		if !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(str(m["interface"])) {
			fail("invalid egress interface")
		}
		for _, k := range []string{"sourceIPv4", "sourceIPv6", "gatewayIPv4", "gatewayIPv6"} {
			if str(m[k]) != "" {
				e := endpoint(join(str(m[k]), 1))
				family := "ipv6"
				if strings.HasSuffix(k, "4") {
					family = "ipv4"
				}
				if str(e["kind"]) != "ip" || str(e["family"]) != family {
					fail("invalid source/gateway family")
				}
			}
		}
	}
	if v, ok := o["bandwidth"]; ok {
		m := obj(v)
		allowed(m, "upBitsPerSecond downBitsPerSecond")
		rates(m)
	}
	return o
}
func listeners(f, t, o M) []M {
	result := []M{}
	if a, ok := o["listeners"]; ok {
		for _, item := range arr(a) {
			raw := obj(item)
			e := endpoint(join(str(raw["host"]), num(raw["port"])))
			delete(e, "kind")
			e["protocol"] = raw["protocol"]
			result = append(result, e)
		}
	} else {
		for _, protocol := range []string{"tcp", "udp"} {
			host := str(t[protocol+"ListenAddr"])
			if host == "[::]" && normalizeEngine(t["engine"]) == "kernel" {
				all := true
				for _, a := range strings.Split(str(f["remoteAddr"]), ",") {
					if str(endpoint(strings.TrimSpace(a))["family"]) != "ipv4" {
						all = false
					}
				}
				if all {
					host = "0.0.0.0"
				}
			}
			e := endpoint(join(host, num(f["inPort"])))
			delete(e, "kind")
			e["protocol"] = protocol
			result = append(result, e)
		}
	}
	seen := map[string]bool{}
	for _, e := range result {
		k := fmt.Sprint(e["family"], "/", e["protocol"], "/", e["host"], "/", e["port"])
		if seen[k] {
			fail("duplicate listener")
		}
		seen[k] = true
	}
	return result
}
func minimum(a, b int64) int64 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	return min(a, b)
}
func (p *Panel) wireSpec(s store, f, t M, reconcile bool, snapshots ...*specSnapshot) M {
	var snap *specSnapshot
	if len(snapshots) > 0 {
		snap = snapshots[0]
	}

	node := num(t["inNodeId"])
	o := options(str(f["engineOptions"]))
	targets := []M{}
	remote := []string{}
	for _, a := range strings.Split(str(f["remoteAddr"]), ",") {
		e := endpoint(strings.TrimSpace(a))
		remote = append(remote, join(str(e["host"]), e["port"]))
		targets = append(targets, M{"endpoint": e, "weight": 1})
	}
	if len(targets) < 1 || len(targets) > 16 {
		fail("1..16 target origins required")
	}
	if v, ok := o["targets"]; ok {
		a := arr(v)
		if len(a) != len(targets) {
			fail("remoteAddr and structured targets differ")
		}
		for i, v := range a {
			m := obj(v)
			ep := obj(m["endpoint"])
			e := endpoint(join(str(ep["host"]), num(ep["port"])))
			if join(str(e["host"]), e["port"]) != remote[i] {
				fail("remoteAddr and structured targets differ")
			}
			weight := int64(1)
			if m["weight"] != nil {
				weight = num(m["weight"])
			}
			targets[i] = M{"endpoint": e, "weight": weight}
		}
	}
	name, ut := serviceName(s, f, snapshots...)
	ids := strings.Split(name, "_")
	uid, permission := num(ids[1]), num(ids[2])
	user, perm := M{"upBitsPerSecond": int64(0), "downBitsPerSecond": int64(0)}, M{"upBitsPerSecond": int64(0), "downBitsPerSecond": int64(0)}
	var groups []M
	if snap != nil {
		groups = snap.groups
	} else {
		groups = s.rows("SELECT scope,owner_id,up_bits,down_bits FROM engine_bandwidth_group WHERE node_id=?", node)
	}
	for _, g := range groups {
		dst := M(nil)
		if str(g["scope"]) == "user" && num(g["ownerId"]) == uid {
			dst = user
		}
		if str(g["scope"]) == "userTunnel" && num(g["ownerId"]) == permission {
			dst = perm
		}
		if dst != nil {
			dst["upBitsPerSecond"] = g["upBits"]
			dst["downBitsPerSecond"] = g["downBits"]
		}
	}
	speed := int64(0)
	if ut != nil && ut["speedId"] != nil {
		var sl M
		if snap != nil {
			sl = snap.speeds[num(ut["speedId"])]
		} else {
			sl = s.get("speed_limit", ut["speedId"])
		}
		if sl != nil {
			speed = max(0, num(sl["speed"])) * 1000000
		}
	}
	for _, k := range []string{"upBitsPerSecond", "downBitsPerSecond"} {
		perm[k] = minimum(num(perm[k]), speed)
	}
	var n M
	if snap != nil {
		n = snap.node
	} else {
		n = found(s.get("node", node), "节点不存在")
	}
	pf := obj(o["protocolFilter"])
	for _, k := range []string{"http", "tls", "socks"} {
		if num(n[k]) == 1 {
			pf[k] = true
			pf["unknown"] = "allow"
		}
	}
	if len(pf) > 0 {
		o["protocolFilter"] = pf
	}
	ls := listeners(f, t, o)
	advanced := str(t["tcpListenAddr"]) == "[::]" || str(t["udpListenAddr"]) == "[::]" || len(o) > 0 || len(targets) > 1 || speed > 0 || str(f["interfaceName"]) != "" || str(t["tcpListenAddr"]) != str(t["udpListenAddr"])
	for _, g := range []M{user, perm} {
		if num(g["upBitsPerSecond"])+num(g["downBitsPerSecond"]) > 0 {
			advanced = true
		}
	}
	for _, v := range targets {
		e := obj(v["endpoint"])
		if str(e["kind"]) != "ip" || str(e["family"]) != "ipv4" {
			advanced = true
		}
	}
	for _, l := range ls {
		if str(l["family"]) != "ipv4" {
			advanced = true
		}
	}
	if !advanced {
		if num(t["type"]) != 1 {
			fail("kernel schema1 only supports direct port forwarding")
		}
		strategy := str(f["strategy"])
		if strategy != "" && strategy != "fifo" {
			fail("kernel schema1 only supports one target")
		}
		e := obj(targets[0]["endpoint"])
		d := M{"listenIP": t["tcpListenAddr"], "listenPort": f["inPort"], "targetIP": e["host"], "targetPort": e["port"]}
		if p.supports(node, "structuredEndpoint") {
			d["schemaVersion"] = 2
			d["listen"] = endpoint(join(str(t["tcpListenAddr"]), num(f["inPort"])))
			d["target"] = e
			d["protocols"] = []string{"tcp", "udp"}
		}
		return d
	}
	p.requireCapability(node, "structuredEndpoint")
	p.requireCapability(node, "independentProtocols")
	for _, l := range ls {
		if str(l["family"]) == "ipv6" {
			p.requireCapability(node, "ipv6")
		}
	}
	for _, v := range targets {
		e := obj(v["endpoint"])
		if str(e["kind"]) == "hostname" {
			p.requireCapability(node, "dns")
		}
		if str(e["family"]) == "ipv6" {
			p.requireCapability(node, "ipv6")
		}
	}
	if len(targets) > 1 || o["health"] != nil {
		p.requireCapability(node, "multiTarget")
	}
	d := M{"schemaVersion": 3, "listeners": ls, "targets": targets}
	selection := str(o["selection"])
	if selection == "" {
		selection = str(f["strategy"])
	}
	if selection == "" {
		selection = "fifo"
	}
	if selection == "rand" {
		selection = "random"
	}
	d["selection"] = selection
	if o["protocolFilter"] != nil {
		p.requireCapability(node, "protocolBlocking")
		d["protocolFilter"] = o["protocolFilter"]
		d["schemaVersion"] = 5
	}
	if o["traffic"] != nil {
		p.requireCapability(node, "trafficPolicy")
		traffic := obj(o["traffic"])
		for _, k := range []string{"localOutput", "localTargets"} {
			if truth(traffic[k]) {
				p.requireCapability(node, k)
			}
		}
		if str(traffic["sourceMode"]) == "preserve" {
			p.requireCapability(node, "preserveSource")
			if truth(traffic["localTargets"]) {
				for _, l := range ls {
					if str(l["protocol"]) == "udp" {
						p.requireCapability(node, "localUDPPreserveSource")
					}
				}
			}
		}
		d["traffic"] = traffic
		if o["protocolFilter"] == nil {
			d["schemaVersion"] = 4
		}
	}
	for _, k := range []string{"dnsPolicy", "health", "egress"} {
		if o[k] != nil {
			d[k] = o[k]
		}
	}
	if str(f["interfaceName"]) != "" {
		eg := obj(d["egress"])
		if eg["interface"] != nil && str(eg["interface"]) != str(f["interfaceName"]) {
			fail("conflicting egress interfaces")
		}
		eg["interface"] = f["interfaceName"]
		d["egress"] = eg
	}
	if d["egress"] != nil {
		p.requireCapability(node, "interfaceRouting")
	}
	bw := obj(o["bandwidth"])
	if num(user["upBitsPerSecond"])+num(user["downBitsPerSecond"])+num(perm["upBitsPerSecond"])+num(perm["downBitsPerSecond"]) > 0 || len(bw) > 0 {
		p.requireCapability(node, "shaping")
		user["id"] = fmt.Sprintf("u_%d", uid)
		perm["id"] = fmt.Sprintf("ut_%d_%d", uid, permission)
		bw["user"] = user
		bw["tunnel"] = perm
		d["bandwidth"] = bw
		limited := num(bw["upBitsPerSecond"])+num(bw["downBitsPerSecond"])+num(user["upBitsPerSecond"])+num(user["downBitsPerSecond"])+num(perm["upBitsPerSecond"])+num(perm["downBitsPerSecond"]) > 0
		if limited && !reconcile && (truth(obj(d["traffic"])["localOutput"]) || truth(obj(d["traffic"])["localTargets"])) {
			p.requireCapability(node, "localTrafficShaping")
		}
	}
	d["intentHash"] = digest(jsonText(d))
	return d
}

// One immutable DB view per bounded reconciliation, never a long-lived policy cache.
type specSnapshot struct {
	users, tunnels, speeds map[int64]M
	permissions            map[string]M
	groups                 []M
	node                   M
}

func (p *Panel) specSnapshot(s store, node int64) *specSnapshot {
	snap := &specSnapshot{users: map[int64]M{}, tunnels: map[int64]M{}, speeds: map[int64]M{}, permissions: map[string]M{}, node: found(s.get("node", node), "节点不存在")}
	for _, r := range s.rows("SELECT * FROM tunnel WHERE in_node_id=? AND engine='kernel'", node) {
		snap.tunnels[num(r["id"])] = r
	}
	for _, r := range s.rows("SELECT DISTINCT u.* FROM user u JOIN forward f ON f.user_id=u.id JOIN tunnel t ON t.id=f.tunnel_id WHERE t.in_node_id=? AND t.engine='kernel'", node) {
		snap.users[num(r["id"])] = r
	}
	for _, r := range s.rows("SELECT ut.* FROM user_tunnel ut JOIN tunnel t ON t.id=ut.tunnel_id WHERE t.in_node_id=? AND t.engine='kernel'", node) {
		snap.permissions[fmt.Sprint(num(r["userId"]), "/", num(r["tunnelId"]))] = r
	}
	for _, r := range s.rows("SELECT * FROM speed_limit WHERE status=0 OR status=1") {
		snap.speeds[num(r["id"])] = r
	}
	snap.groups = s.rows("SELECT scope,owner_id,up_bits,down_bits FROM engine_bandwidth_group WHERE node_id=?", node)
	return snap
}
