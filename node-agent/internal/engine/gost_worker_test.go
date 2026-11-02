package engine

import (
	"path/filepath"
	"testing"
)

func TestManagedProjectionPreservesBusinessSpecAndSupportsBasicRules(t *testing.T) {
	addresses, e := localAddresses()
	if e != nil {
		t.Fatal(e)
	}
	if len(addresses["ipv4"]) == 0 {
		t.Skip("requires a non-loopback IPv4 interface")
	}
	g, e := NewGostRunner("/tmp/flux-gost-unit.sock", filepath.Join(t.TempDir(), "state"))
	if e != nil {
		t.Fatal(e)
	}
	s := Spec{ID: "1_1_0", Revision: 1, Token: 27, Enabled: true, ListenIP: "0.0.0.0", ListenPort: 18000, TargetIP: "192.0.2.2", TargetPort: 19000, LeaseRequired: true}
	original := digest(s)
	p, services, e := g.project([]Spec{s})
	if e != nil {
		t.Fatal(e)
	}
	if digest(s) != original || len(p) != 1 || !p[0].Advanced() || p[0].Token != s.Token || !p[0].LeaseRequired || !p[0].trafficPolicy().LocalTargets || len(services) != 2 {
		t.Fatalf("projection lost identity/control: %+v %+v", p, services)
	}
	for _, v := range services {
		nodes := v["forwarder"].(map[string]any)["nodes"].([]map[string]any)
		if len(nodes) != 1 || nodes[0]["addr"] != "192.0.2.2:19000" {
			t.Fatal(v)
		}
	}
	again, _, e := g.project([]Spec{s})
	if e != nil || digest(again) != digest(p) {
		t.Fatal("backend allocation is not stable", e)
	}
}

func TestManagedPreflightRejectsUnsupportedPolicy(t *testing.T) {
	g := &GostRunner{ports: map[string]int{}}
	s := Spec{ID: "1_1_0", SchemaVersion: 4, AdvancedOptions: &AdvancedOptions{Traffic: &TrafficPolicy{SourceMode: "preserve", ReturnPathConfirmed: true}}}
	if g.validate(s) == nil {
		t.Fatal("source preservation silently lost")
	}
	s.Traffic = nil
	s.Health.Protocol = "tcp"
	if g.validate(s) == nil {
		t.Fatal("health policy silently lost")
	}
	s.Health.Protocol = ""
	s.Egress.Interface = "eth0"
	if g.validate(s) == nil {
		t.Fatal("egress policy silently lost")
	}
}
