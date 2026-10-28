package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type ReturnPathQuery struct {
	ClientIP         string `json:"clientIP,omitempty"`
	IngressInterface string `json:"ingressInterface,omitempty"`
}

var diagnosticSlots = make(chan struct{}, 2)

func (q ReturnPathQuery) validate() error {
	if q.ClientIP != "" {
		a, e := netip.ParseAddr(q.ClientIP)
		if e != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return fmt.Errorf("clientIP must be a numeric unicast address")
		}
	}
	if q.IngressInterface != "" {
		if len(q.IngressInterface) > 15 || strings.ContainsAny(q.IngressInterface, "/\x00\r\n") {
			return fmt.Errorf("invalid ingress interface")
		}
		if _, e := net.InterfaceByName(q.IngressInterface); e != nil {
			return fmt.Errorf("ingress interface unavailable")
		}
	}
	return nil
}
func diagnosticRoute(ctx context.Context, family, host string, mark uint32, source string, ingress ...string) map[string]any {
	flag := "-4"
	if family == "ipv6" {
		flag = "-6"
	}
	args := []string{"-j", flag, "route", "get", host, "mark", fmt.Sprintf("0x%x", mark)}
	if source != "" {
		args = append(args, "from", source)
	}
	if len(ingress) > 0 && ingress[0] != "" {
		args = append(args, "iif", ingress[0])
	}
	result := map[string]any{"destination": host, "mark": fmt.Sprintf("0x%x", mark)}
	if source != "" {
		result["from"] = source
	}
	call, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	raw, e := exec.CommandContext(call, "ip", args...).Output()
	var rows []map[string]any
	if e != nil || len(raw) > 65536 || json.Unmarshal(raw, &rows) != nil || len(rows) == 0 {
		result["available"] = false
		result["error"] = "route unavailable"
		return result
	}
	result["available"] = true
	result["rows"] = rows
	for _, key := range []string{"dev", "gateway", "prefsrc", "src", "table", "type"} {
		if value, ok := rows[0][key]; ok {
			result[key] = value
		}
	}
	return result
}
func diagnosticSysctl(path string, max int) any {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil
	}
	v := strings.TrimSpace(string(b))
	for i := 0; i <= max; i++ {
		if v == fmt.Sprint(i) {
			return i
		}
	}
	return nil
}
func effectiveSysctl(a, b any) any {
	x, xok := a.(int)
	y, yok := b.(int)
	if !xok || !yok {
		return nil
	}
	return max(x, y)
}
func reversePathRisk(effective any, route map[string]any, ingress string) string {
	v, ok := effective.(int)
	if !ok {
		return "unknown"
	}
	if v == 0 {
		return "disabled"
	}
	available, _ := route["available"].(bool)
	if !available {
		return "unreachable-risk"
	}
	dev, _ := route["dev"].(string)
	if dev == "" {
		return "unknown"
	}
	if v == 1 && dev != ingress {
		return "strict-interface-mismatch-risk"
	}
	return "no-obvious-destination-route-conflict"
}
func (m *Manager) ReturnPathDiagnostics(ctx context.Context, id string, probe bool, q ReturnPathQuery) (map[string]any, error) {
	if e := q.validate(); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	select {
	case diagnosticSlots <- struct{}{}:
		defer func() { <-diagnosticSlots }()
	default:
		return nil, fmt.Errorf("diagnostic capacity busy")
	}
	m.mu.Lock()
	s, exists := m.state.Rules[id]
	s = cloneSpec(s)
	mark := flowMark(s)
	if k, ok := m.Kernel.(*IPTables); ok && k.P1 != nil {
		if applied, ok := k.P1.last[id]; ok && applied.Runtime.EgressGroup > 0 {
			mark |= 0x80 | uint32(applied.Runtime.EgressGroup)
		}
	}
	m.mu.Unlock()
	if !exists || s.Deleted {
		return nil, fmt.Errorf("forward not found")
	}
	result := map[string]any{"id": id, "sampledAt": time.Now().UnixMilli(), "state": m.RuntimeStatus(id), "probeRequested": probe, "probePerformed": false, "externalLoadTest": false, "diagnosticVersion": 2}
	routes := []any{}
	seen := map[string]bool{}
	attempts := 0
	truncated := false
	for _, target := range s.Paths() {
		key := target.Family + "/" + (Endpoint{Host: target.Host, Port: target.Port}).String()
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(routes) >= 8 || ctx.Err() != nil {
			truncated = true
			break
		}
		source := s.Egress.SourceIPv4
		if target.Family == "ipv6" {
			source = s.Egress.SourceIPv6
		}
		r := diagnosticRoute(ctx, target.Family, target.Host, mark, source)
		entry := map[string]any{"target": target.Host, "port": target.Port, "family": target.Family, "routeEvidence": r, "route": r["rows"], "healthy": target.Healthy, "acceptNew": target.AcceptNew}
		if q.ClientIP != "" && q.IngressInterface != "" {
			client := netip.MustParseAddr(q.ClientIP).Unmap()
			if client.Is4() == (target.Family == "ipv4") {
				entry["forwardRouteEvidence"] = diagnosticRoute(ctx, target.Family, target.Host, mark, client.String(), q.IngressInterface)
			}
		}

		if probe && attempts < 2 && (!s.Advanced() || containsProtocol(s.Protocols, "tcp")) {
			attempts++
			call, stop := context.WithTimeout(ctx, 500*time.Millisecond)
			dial := net.Dialer{Timeout: 500 * time.Millisecond}
			// A business connmark could make the diagnostic consume this forward's
			// quota. Bind interface/source only; do not claim this probes a mark-selected
			// gateway or the original client's return route.
			if s.Egress.Interface != "" {
				dial.Control = socketInterface(s.Egress.Interface)
			}
			if source != "" {
				dial.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
			}
			start := time.Now()
			conn, e := dial.DialContext(call, "tcp", (Endpoint{Host: target.Host, Port: target.Port}).String())
			if conn != nil {
				conn.Close()
			}
			stop()
			entry["tcpHandshakeMs"] = time.Since(start).Seconds() * 1000
			entry["reachable"] = e == nil
			entry["probePerformed"] = true
			entry["probeScope"] = "node-interface-source-socket"
			entry["businessMarkApplied"] = false
			if e != nil {
				entry["probeError"] = "bounded node TCP connection failed"
			}
		} else {
			entry["probePerformed"] = false
			entry["probe"] = "not requested or budget exhausted; UDP requires an explicit request/response contract"
		}
		routes = append(routes, entry)
	}
	result["routes"] = routes
	result["routesTruncated"] = truncated
	result["probePerformed"] = attempts > 0
	result["probeCount"] = attempts
	for _, family := range []string{"ipv4", "ipv6"} {
		path := "/proc/sys/net/ipv4/ip_forward"
		if family == "ipv6" {
			path = "/proc/sys/net/ipv6/conf/all/forwarding"
		}
		if v, ok := diagnosticSysctl(path, 1).(int); ok {
			result[family+"Forwarding"] = v == 1
		}
	}
	interfaces, e := net.Interfaces()
	if e != nil {
		return nil, e
	}
	names := []string{}
	for _, iface := range interfaces {
		use := iface.Name == q.IngressInterface
		if q.IngressInterface == "" {
			addresses, _ := iface.Addrs()
			for _, l := range s.ListenerList() {
				for _, address := range addresses {
					ip, _, e := net.ParseCIDR(address.String())
					if e == nil && (ip.String() == l.Host || l.Host == "0.0.0.0" && ip.To4() != nil || l.Host == "::" && ip.To4() == nil) {
						use = true
					}
				}
			}
		}
		if use && iface.Name != shapingDevice && iface.Name != localPrepareDevice && iface.Name != localProbeDevice {
			names = append(names, iface.Name)
		}
	}
	sort.Strings(names)
	if len(names) > 16 {
		names = names[:16]
	}
	allRPF := diagnosticSysctl("/proc/sys/net/ipv4/conf/all/rp_filter", 2)
	allMark := diagnosticSysctl("/proc/sys/net/ipv4/conf/all/src_valid_mark", 1)
	entries := []any{}
	for _, name := range names {
		rpf := diagnosticSysctl("/proc/sys/net/ipv4/conf/"+name+"/rp_filter", 2)
		svm := diagnosticSysctl("/proc/sys/net/ipv4/conf/"+name+"/src_valid_mark", 1)
		effective := effectiveSysctl(allRPF, rpf)
		validMark := effectiveSysctl(allMark, svm)
		entry := map[string]any{"interface": name, "ipv4RPFilterAll": allRPF, "ipv4RPFilterInterface": rpf, "ipv4RPFilterEffective": effective, "srcValidMarkEffective": validMark, "ipv6RPFilterApplicable": false, "risk": "client-sample-missing"}
		if q.ClientIP != "" {
			client := netip.MustParseAddr(q.ClientIP).Unmap()
			family := "ipv4"
			lookupMark := uint32(0)
			if client.Is6() {
				family = "ipv6"
			} else if validMark == 1 {
				lookupMark = mark
			}
			route := diagnosticRoute(ctx, family, client.String(), lookupMark, "")
			entry["clientRouteEvidence"] = route
			if client.Is6() {
				entry["risk"] = "ipv6-no-ipv4-rp-filter"
			} else {
				entry["risk"] = reversePathRisk(effective, route, name)
				if validMark == nil {
					entry["risk"] = "unknown"
				}
			}
		}
		entries = append(entries, entry)
	}
	mode := "masquerade"
	if s.preserveSource() {
		mode = "preserve"
	}
	result["returnPath"] = map[string]any{"status": "unverified", "sourceMode": mode, "administratorConfirmed": s.trafficPolicy().ReturnPathConfirmed, "remoteReturnVerified": false, "clientIP": q.ClientIP, "ingress": entries, "limitations": []string{"本机 route get 不是远端目标返回路由的证据", "TCP 探测仅代表节点自身的接口/源地址连接，不代表原客户端或指定策略网关", "rp_filter 风险基于目的路由线索，未完整模拟 from/iif、VRF、ECMP 或其他防火墙策略", "确认实际回程仍需要目标端路由/抓包或明确的协作探测协议"}}
	return result, nil
}
func containsProtocol(protocols []string, protocol string) bool {
	for _, v := range protocols {
		if v == protocol {
			return true
		}
	}
	return false
}
