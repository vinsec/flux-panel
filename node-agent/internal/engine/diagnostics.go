package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

func (m *Manager) Diagnostics(ctx context.Context, id string, probe bool) (map[string]any, error) {
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
	result := map[string]any{"id": id, "sampledAt": time.Now().UnixMilli(), "state": m.RuntimeStatus(id), "probePerformed": probe, "externalLoadTest": false}
	routes := []any{}
	seen := map[string]bool{}
	for _, target := range s.Paths() {
		if seen[target.Family] {
			continue
		}
		seen[target.Family] = true
		flag := "-4"
		if target.Family == "ipv6" {
			flag = "-6"
		}
		call, cancel := context.WithTimeout(ctx, time.Second)
		output, e := exec.CommandContext(call, "ip", "-j", flag, "route", "get", target.Host, "mark", fmt.Sprintf("0x%x", mark)).Output()
		cancel()
		entry := map[string]any{"target": target.Host, "port": target.Port, "family": target.Family}
		var route any
		if e == nil && json.Unmarshal(output, &route) == nil {
			entry["route"] = route
		} else {
			entry["error"] = "route unavailable"
		}
		if probe {
			if !slices.Contains(s.Protocols, "tcp") && s.Advanced() {
				entry["probe"] = "UDP requires a configured explicit request/response health exchange"
			} else {
				call, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
				dial := net.Dialer{Timeout: 500 * time.Millisecond}
				if s.Advanced() && s.Egress.Interface != "" {
					dial.Control = socketPolicy(s.Egress.Interface, mark)
					source := s.Egress.SourceIPv4
					if target.Family == "ipv6" {
						source = s.Egress.SourceIPv6
					}
					if source != "" {
						dial.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
					}
				}
				start := time.Now()
				conn, e := dial.DialContext(call, "tcp", (Endpoint{Host: target.Host, Port: target.Port}).String())
				elapsed := time.Since(start).Seconds() * 1000
				if conn != nil {
					conn.Close()
				}
				cancel()
				entry["tcpHandshakeMs"] = elapsed
				entry["reachable"] = e == nil
				if e != nil {
					entry["probeError"] = "bounded TCP connection failed"
				}
			}
		}
		routes = append(routes, entry)
		if len(routes) >= 2 {
			break
		}
	}
	result["routes"] = routes
	for _, family := range []string{"ipv4", "ipv6"} {
		file := "/proc/sys/net/ipv4/ip_forward"
		if family == "ipv6" {
			file = "/proc/sys/net/ipv6/conf/all/forwarding"
		}
		if b, e := os.ReadFile(file); e == nil {
			result[family+"Forwarding"] = strings.TrimSpace(string(b)) == "1"
		}
	}
	return result, nil
}
