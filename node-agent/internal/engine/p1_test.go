package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func advancedExample() Spec {
	return Spec{SchemaVersion: 3, ID: "1_2_3", Revision: 1, Enabled: true, Listen: Endpoint{Host: "::", Family: "dual", Port: 18000}, AdvancedOptions: &AdvancedOptions{Targets: []Target{{Endpoint: Endpoint{Host: "origin.test", Port: 443}, Weight: 1}}}}
}
func TestAdvancedCanonicalListenersAndSafetyBounds(t *testing.T) {
	s, e := advancedExample().Normalize()
	if e != nil || len(s.Listeners) != 4 || s.Target.Kind != "hostname" {
		t.Fatal(s, e)
	}
	for _, modify := range []func(*Spec){func(s *Spec) { s.Targets[0].Weight = 33 }, func(s *Spec) { s.Egress.Interface = "eth0;reboot" }, func(s *Spec) { s.Targets[0].Endpoint.Host = "127.0.0.1" }, func(s *Spec) { s.Targets[0].Endpoint.Host = "fe80::1%eth0" }, func(s *Spec) { s.Bandwidth.UpBitsPerSecond = 999 }, func(s *Spec) { s.Health = HealthPolicy{Protocol: "udp", Payload: "", Expected: ""} }} {
		bad := advancedExample()
		modify(&bad)
		if _, e = bad.Normalize(); e == nil {
			t.Fatal("unsafe input accepted", bad)
		}
	}
}
func TestAdvancedSnapshotIsolationAndLegacyWireShape(t *testing.T) {
	s, e := advancedExample().Normalize()
	if e != nil {
		t.Fatal(e)
	}
	s.Runtime.Targets = []ResolvedTarget{{Host: "192.0.2.10"}}
	state := State{Rules: map[string]Spec{s.ID: s}}
	copy := cloneState(state)
	other := copy.Rules[s.ID]
	other.Listeners[0].Port = 99
	other.Targets[0].Endpoint.Host = "changed"
	other.Runtime.Targets[0].Host = "changed"
	if s.Listeners[0].Port != 18000 || s.Targets[0].Endpoint.Host != "origin.test" || s.Runtime.Targets[0].Host != "192.0.2.10" {
		t.Fatal("advanced transaction aliases the previous generation")
	}
	legacy := valid()
	b, _ := json.Marshal(legacy)
	for _, field := range []string{`"listeners"`, `"targets"`, `"runtime"`, `"health"`, `"egress"`, `"bandwidth"`, `"intentHash"`} {
		if strings.Contains(string(b), field) {
			t.Fatal("legacy fast-path wire shape grew", field)
		}
	}
}
func TestIndependentListenerCollisionSemantics(t *testing.T) {
	a := advancedExample()
	a.Listeners = []Listener{{Protocol: "tcp", Host: "0.0.0.0", Port: 18000}}
	a, _ = a.Normalize()
	b := cloneSpec(a)
	b.ID = "2_2_3"
	b.Listeners[0].Protocol = "udp"
	b, _ = b.Normalize()
	if e := validateListeners(map[string]Spec{a.ID: a, b.ID: b}); e != nil {
		t.Fatal("independent protocol was unnecessarily reserved", e)
	}
	b.Listeners[0].Protocol = "tcp"
	b.Listeners[0].Host = "192.0.2.10"
	if e := validateListeners(map[string]Spec{a.ID: a, b.ID: b}); e == nil {
		t.Fatal("wildcard TCP conflict accepted")
	}
}
func TestMaintenanceSettlementPagesDoNotLoseCumulativeUsage(t *testing.T) {
	report := Report{Epoch: "epoch", Sequence: 4}
	for i := 0; i < 25001; i++ {
		report.Usage = append(report.Usage, Usage{ID: fmt.Sprintf("%d_2_3", i), Up: uint64(i)})
	}
	seen := map[string]bool{}
	last := int64(1)
	ack, e := settleMaintenancePages(report, func(p Report) (Acknowledgement, error) {
		if p.Sequence != last+1 || len(p.Usage) > 10000 {
			t.Fatal("invalid page identity")
		}
		last = p.Sequence
		for _, u := range p.Usage {
			if seen[u.ID] {
				t.Fatal("repeated business usage")
			}
			seen[u.ID] = true
		}
		return Acknowledgement{Epoch: p.Epoch, Sequence: p.Sequence, MaintenanceAccepted: true}, nil
	})
	if e != nil || len(seen) != 25001 || ack.Sequence != 4 {
		t.Fatal(e, len(seen), ack)
	}
}
func TestPerFamilyCounterBaselinesAreIndependent(t *testing.T) {
	if counterBaseline("FP4_UP", "1_2_3", "up") == counterBaseline("FP6_UP", "1_2_3", "up") {
		t.Fatal("IPv6 counter regression could be hidden by IPv4 growth")
	}
}

func TestDNSAdmissionDeadlineIndependentOfRefresh(t *testing.T) {
	s, _ := advancedExample().Normalize()
	s.DNS.StaleMillis = 1000
	s.Runtime.Targets = []ResolvedTarget{{Host: "192.0.2.10", FreshUntil: 100, AcceptNew: true, Healthy: true}}
	state := State{Rules: map[string]Spec{s.ID: s}}
	if _, changed := expireRuntime(state, 1099); changed {
		t.Fatal("grace closed early")
	}
	after, changed := expireRuntime(state, 1100)
	if !changed || after.Rules[s.ID].Runtime.Targets[0].AcceptNew || !state.Rules[s.ID].Runtime.Targets[0].AcceptNew {
		t.Fatal("deadline or snapshot isolation failed")
	}
	s.DNS.FailClosed = true
	state.Rules[s.ID] = s
	if _, changed := expireRuntime(state, 100); !changed {
		t.Fatal("fail-closed grace accepted")
	}
}
