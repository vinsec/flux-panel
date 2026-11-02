package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// GostRunner talks only to a private, unprivileged worker. It never executes a
// command supplied by the panel and never gives GOST kernel capabilities.
type GostRunner struct {
	Socket     string
	PortFile   string
	client     *http.Client
	ports      map[string]int
	applied    map[string]string
	generation string
}

func NewGostRunner(socket, path string) (*GostRunner, error) {
	if !filepath.IsAbs(socket) || len(socket) > 100 {
		return nil, fmt.Errorf("invalid managed GOST socket")
	}
	g := &GostRunner{Socket: socket, PortFile: path + ".gost-ports.json", ports: map[string]int{}, applied: map[string]string{}}
	if b, e := os.ReadFile(g.PortFile); e == nil {
		if e = json.Unmarshal(b, &g.ports); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	g.client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	return g, nil
}
func (g *GostRunner) call(method, path string, v any) (map[string]any, error) {
	var body io.Reader
	if v != nil {
		b, e := json.Marshal(v)
		if e != nil {
			return nil, e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequest(method, "http://managed"+path, body)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("flux-agent", "unix-socket")
	r, e := g.client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("managed GOST unavailable: %w", e)
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if e != nil {
		return nil, e
	}
	var result map[string]any
	if e = json.Unmarshal(b, &result); e != nil {
		return nil, fmt.Errorf("invalid managed GOST reply")
	}
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("managed GOST operation failed (%d)", r.StatusCode)
	}
	return result, nil
}
func (g *GostRunner) ready() error {
	reply, e := g.call("GET", "/agent/health", nil)
	if e != nil {
		return e
	}
	generation, _ := reply["generation"].(string)
	if len(generation) != 32 {
		return fmt.Errorf("invalid worker generation")
	}
	if generation != g.generation {
		g.applied = map[string]string{}
		values, ok := reply["services"].([]any)
		if !ok {
			return fmt.Errorf("invalid worker service inventory")
		}
		for _, v := range values {
			if name, ok := v.(string); ok {
				g.applied[name] = ""
			}
		}
		g.generation = generation
	}
	return nil
}
func (g *GostRunner) validate(s Spec) error {
	if s.Deleted {
		return nil
	}

	for _, l := range s.ListenerList() {
		for _, p := range g.ports {
			if l.Port == p {
				return fmt.Errorf("%s: listener conflicts with a managed backend port", s.ID)
			}
		}
	}
	if s.preserveSource() || (s.AdvancedOptions != nil && s.Egress != (EgressPolicy{})) {
		return fmt.Errorf("%s: GOST mode cannot preserve original source or apply kernel egress policy", s.ID)
	}
	if s.AdvancedOptions != nil && s.Health.Protocol != "" {
		return fmt.Errorf("%s: active target health checks require kernel mode", s.ID)
	}
	// Worker applies one target policy per address family. DNS is resolved by the
	// Agent; local/dual-stack listeners remain supported through the common meter.
	for _, l := range s.ListenerList() {
		if l.Protocol != "tcp" && l.Protocol != "udp" {
			return fmt.Errorf("unsupported managed protocol")
		}
	}
	return nil
}
func (g *GostRunner) port(id string, forbidden map[int]bool) (int, error) {
	if p := g.ports[id]; p != 0 {
		if forbidden[p] {
			return 0, fmt.Errorf("public listener conflicts with reserved GOST worker port")
		}
		return p, nil
	}
	used := map[int]bool{}
	for _, p := range g.ports {
		used[p] = true
	}
	for p := 40000; p <= 65535; p++ {
		if !used[p] && !forbidden[p] {
			g.ports[id] = p
			if e := atomicJSON(g.PortFile, g.ports); e != nil {
				return 0, e
			}
			return p, nil
		}
	}
	return 0, fmt.Errorf("managed GOST backend port capacity exhausted")
}

// project keeps business specs in the Manager. Only the native execution graph
// targets GOST's private services, so both modes use exactly one kernel ledger.
func (g *GostRunner) project(plan []Spec) ([]Spec, map[string]map[string]any, error) {
	addresses, e := localAddresses()
	if e != nil {
		return nil, nil, e
	}
	forbidden := map[int]bool{}
	for _, s := range plan {
		for _, l := range s.ListenerList() {
			forbidden[l.Port] = true
		}
	}
	projected := make([]Spec, 0, len(plan))
	services := map[string]map[string]any{}
	for _, s := range plan {
		if e = g.validate(s); e != nil {
			return nil, nil, e
		}
		if s.Deleted {
			projected = append(projected, s)
			continue
		}
		data, _ := json.Marshal(s)
		var target Spec
		if e = json.Unmarshal(data, &target); e != nil {
			return nil, nil, e
		}
		if target.AdvancedOptions == nil {
			target.AdvancedOptions = &AdvancedOptions{}
		}
		if target.SchemaVersion < 4 {
			target.SchemaVersion = 4
		}
		target.Listeners = s.ListenerList()
		target.Targets = nil
		target.Runtime = ResolutionState{Status: "ready"}
		target.Selection = "fifo"
		traffic := s.trafficPolicy()
		traffic.LocalTargets = true
		target.Traffic = &traffic
		families := map[string][]Listener{}
		for _, l := range s.ListenerList() {
			families[l.Family] = append(families[l.Family], l)
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			listeners := families[family]
			if len(listeners) == 0 {
				continue
			}
			if len(addresses[family]) == 0 {
				return nil, nil, fmt.Errorf("%s: no non-loopback %s address for managed GOST", s.ID, family)
			}
			host := addresses[family][0]
			port, e := g.port(s.ID+"/"+family, forbidden)
			if e != nil {
				return nil, nil, e
			}
			endpoint := Endpoint{Kind: "ip", Host: host, Family: family, Port: port}
			target.Targets = append(target.Targets, Target{Endpoint: endpoint, Weight: 1})
			target.Runtime.Targets = append(target.Runtime.Targets, ResolvedTarget{Host: host, Port: port, Family: family, Weight: 1, Healthy: true, AcceptNew: true, Origin: endpoint.String()})
			nodes := []map[string]any{}
			for _, p := range s.Paths() {
				if p.Family == family && p.Healthy && p.AcceptNew && p.RetiredAt == 0 {
					for i := 0; i < max(1, p.Weight); i++ {
						nodes = append(nodes, map[string]any{"name": fmt.Sprint("target-", len(nodes)), "addr": net.JoinHostPort(p.Host, strconv.Itoa(p.Port))})
					}
				}
			}
			if len(nodes) == 0 {
				target.Enabled = false
			}
			protocols := map[string]bool{}
			for _, l := range listeners {
				protocols[l.Protocol] = true
			}
			for _, protocol := range []string{"tcp", "udp"} {
				if !protocols[protocol] || !s.Enabled || len(nodes) == 0 {
					continue
				}
				name := "agent-" + strings.ReplaceAll(s.ID, "_", "-") + "-" + family + "-" + protocol
				listener := map[string]any{"type": protocol}
				if protocol == "udp" {
					listener["metadata"] = map[string]any{"keepAlive": true}
				}
				services[name] = map[string]any{"name": name, "addr": endpoint.String(), "handler": map[string]any{"type": protocol}, "listener": listener, "forwarder": map[string]any{"nodes": nodes, "selector": map[string]any{"strategy": targetSelection(s)}}}
			}
		}
		projected = append(projected, target)
	}
	return projected, services, nil
}
func (g *GostRunner) sync(want map[string]map[string]any) error {
	if e := g.ready(); e != nil {
		if len(want) == 0 {
			return nil
		}
		return e
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		v := want[name]
		h := digest(v)
		if g.applied[name] == h {
			continue
		}
		method, path := "POST", "/config/services"
		if _, seen := g.applied[name]; seen {
			method, path = "PUT", path+"/"+name
		}
		if _, e := g.call(method, path, v); e != nil {
			return e
		}
		g.applied[name] = h
	}
	for name := range g.applied {
		if _, ok := want[name]; !ok {
			if _, e := g.call("DELETE", "/config/services/"+name, nil); e != nil {
				return e
			}
			delete(g.applied, name)
		}
	}
	return nil
}
func (g *GostRunner) clear() error { return g.sync(map[string]map[string]any{}) }

func (g *GostRunner) guard(k *NativeKernel, services map[string]map[string]any) error {
	const table = "FP_GOST_WORKER"
	tables, e := k.run("nft", "", "-j", "list", "tables")
	if e != nil {
		return e
	}
	var d nativeDocument
	if e = json.Unmarshal([]byte(tables), &d); e != nil {
		return e
	}
	exists := false
	for _, v := range d.NFT {
		if b := v["table"]; b != nil {
			var t struct{ Family, Name string }
			_ = json.Unmarshal(b, &t)
			exists = exists || t.Family == "inet" && t.Name == table
		}
	}
	var input strings.Builder
	if exists {
		saved, e := k.run("nft", "", "-j", "list", "table", "inet", table)
		if e != nil {
			return e
		}
		var doc nativeDocument
		if e = json.Unmarshal([]byte(saved), &doc); e != nil {
			return e
		}
		owned := false
		for _, v := range doc.NFT {
			if b := v["table"]; b != nil {
				var t struct{ Comment string }
				_ = json.Unmarshal(b, &t)
				owned = t.Comment == "flux-managed-gost:v1"
			}
		}
		if !owned {
			return fmt.Errorf("foreign managed GOST guard table")
		}
		fmt.Fprintf(&input, "flush chain inet %s input\n", table)
	} else {
		fmt.Fprintf(&input, "add table inet %s { comment \"flux-managed-gost:v1\"; }\nadd chain inet %s input { type filter hook input priority -20; policy accept; }\n", table, table)
	}

	sets := map[string][]string{"back4": {}, "back6": {}}
	for _, v := range services {
		host, port, e := net.SplitHostPort(v["addr"].(string))
		if e != nil {
			return e
		}
		protocol := v["handler"].(map[string]any)["type"].(string)
		family := "back4"
		if strings.Contains(host, ":") {
			family = "back6"
		}
		sets[family] = append(sets[family], host+" . "+protocol+" . "+port)
	}
	// Constant-depth guarding, not one linear rule per managed listener.
	for _, family := range []string{"back4", "back6"} {
		typ, ip := "ipv4_addr", "ip"
		if family == "back6" {
			typ, ip = "ipv6_addr", "ip6"
		}
		if exists {
			saved, e := k.run("nft", "", "-j", "list", "table", "inet", table)
			if e != nil {
				return e
			}
			if strings.Contains(saved, `"name":"`+family+`"`) || strings.Contains(saved, `"name": "`+family+`"`) {
				fmt.Fprintf(&input, "flush set inet %s %s\n", table, family)
			} else {
				fmt.Fprintf(&input, "add set inet %s %s { type %s . inet_proto . inet_service; }\n", table, family, typ)
			}
		} else {
			fmt.Fprintf(&input, "add set inet %s %s { type %s . inet_proto . inet_service; }\n", table, family, typ)
		}
		if len(sets[family]) > 0 {
			sort.Strings(sets[family])
			unique := []string{}
			for _, v := range sets[family] {
				if len(unique) == 0 || v != unique[len(unique)-1] {
					unique = append(unique, v)
				}
			}
			fmt.Fprintf(&input, "add element inet %s %s { %s }\n", table, family, strings.Join(unique, ", "))
		}
		fmt.Fprintf(&input, "add rule inet %s input %s daddr . meta l4proto . th dport @%s ct mark & 0xff000000 != 0xf2000000 drop\n", table, ip, family)
	}
	_, e = k.run("nft", input.String(), "-f", "-")
	return e
}
func (g *GostRunner) preflight(plan []Spec) error {
	if e := g.ready(); e != nil {
		return e
	}
	_, services, e := g.project(plan)
	if e != nil {
		return e
	}
	for name, v := range services {
		if _, ok := g.applied[name]; ok {
			continue
		}
		address := v["addr"].(string)
		protocol := v["handler"].(map[string]any)["type"].(string)
		if protocol == "tcp" {
			ln, e := net.Listen("tcp", address)
			if e != nil {
				return fmt.Errorf("managed listener unavailable: %s", address)
			}
			ln.Close()
		} else {
			ln, e := net.ListenPacket("udp", address)
			if e != nil {
				return fmt.Errorf("managed UDP listener unavailable: %s", address)
			}
			ln.Close()
		}
	}
	return nil
}

// Delete only our explicitly owned guard during offline maintenance.
func removeGostGuard(k *NativeKernel) error {
	text, e := k.run("nft", "", "-j", "list", "tables")
	if e != nil {
		return e
	}
	var doc nativeDocument
	if e = json.Unmarshal([]byte(text), &doc); e != nil {
		return e
	}
	for _, v := range doc.NFT {
		if b := v["table"]; b != nil {
			var t struct{ Family, Name string }
			if e = json.Unmarshal(b, &t); e != nil {
				return e
			}
			if t.Family != "inet" || t.Name != "FP_GOST_WORKER" {
				continue
			}
			text, e = k.run("nft", "", "-j", "list", "table", "inet", t.Name)
			if e != nil {
				return e
			}
			var saved nativeDocument
			if e = json.Unmarshal([]byte(text), &saved); e != nil {
				return e
			}
			owned := false
			for _, v := range saved.NFT {
				if b := v["table"]; b != nil {
					var owner struct{ Comment string }
					if e = json.Unmarshal(b, &owner); e != nil {
						return e
					}
					owned = owner.Comment == "flux-managed-gost:v1"
				}
			}
			if !owned {
				return fmt.Errorf("refusing to remove foreign GOST guard")
			}
			_, e = k.run("nft", "", "delete", "table", "inet", t.Name)
			return e
		}
	}
	return nil
}

func targetSelection(s Spec) string {
	if s.AdvancedOptions == nil || s.Selection == "" {
		return "fifo"
	}
	return s.Selection
}

// WaitReady keeps a Type=simple helper alive while the unprivileged network
// service starts its worker. The helper never executes the GOST process.
func (g *GostRunner) WaitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := g.ready()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("waiting for unprivileged GOST worker: %w", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
