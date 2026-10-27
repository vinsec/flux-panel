package engine

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestTrafficPolicyRequiresSchema4AndConfirmedRouting(t *testing.T) {
	s := advancedExample()
	s.Traffic = &TrafficPolicy{SourceMode: "preserve", ReturnPathConfirmed: true}
	if _, err := s.Normalize(); err == nil {
		t.Fatal("old wire schema silently accepted new NAT semantics")
	}
	s.SchemaVersion = 4
	s.Traffic.ReturnPathConfirmed = false
	if _, err := s.Normalize(); err == nil {
		t.Fatal("unconfirmed DNAT-only routing accepted")
	}
	s.Traffic.ReturnPathConfirmed = true
	if _, err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
	s.Egress = EgressPolicy{Interface: "eth1", SourceIPv4: "192.0.2.1"}
	if _, err := s.Normalize(); err == nil {
		t.Fatal("preserve source combined with SNAT")
	}
}

// A subsequent shared-cap update must reach apply, which closes unsupported
// unprepared local paths. Refusing the desired update would keep old unlimited rules live.
func TestLocalPathsRetainNewSharedCapsForFailClosedApply(t *testing.T) {
	for _, b := range []BandwidthPolicy{{UpBitsPerSecond: 1000000}, {User: BandwidthGroup{ID: "u1", DownBitsPerSecond: 1000000}}, {Tunnel: BandwidthGroup{ID: "t1", UpBitsPerSecond: 1000000}}} {
		s := advancedExample()
		s.SchemaVersion = 4
		s.Traffic = &TrafficPolicy{LocalOutput: true}
		s.Bandwidth = b
		n, err := s.Normalize()
		if err != nil || !n.localTraffic() || !n.Bandwidth.Enabled() {
			t.Fatal("new cap cannot reach fail-closed kernel application", err)
		}
	}
}
func TestStateVersionPreventsOldAgentDroppingTrafficPolicy(t *testing.T) {
	s := advancedExample()
	s.SchemaVersion = 4
	if requiredStateFormat(map[string]Spec{s.ID: s}) != 5 {
		t.Fatal("schema4 persisted in old-readable state")
	}
	s.SchemaVersion = 3
	if requiredStateFormat(map[string]Spec{s.ID: s}) != 4 {
		t.Fatal("P1 state changed version")
	}
	if requiredStateFormat(map[string]Spec{}) != 3 {
		t.Fatal("legacy state changed version")
	}
}

func TestP1TrafficPolicyDoesNotGrowStateOrWire(t *testing.T) {
	s, err := advancedExample().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(s)
	if err != nil || bytes.Contains(data, []byte(`"traffic"`)) {
		t.Fatal("P1 state grew for an unused P2 capability", err)
	}
	s.SchemaVersion = 4
	s.Traffic = &TrafficPolicy{LocalOutput: true}
	data, err = json.Marshal(s)
	if err != nil || !bytes.Contains(data, []byte(`"localOutput":true`)) {
		t.Fatal("explicit P2 policy missing from state", err)
	}
}

func TestIPv6ExternalLoopbackRemainsExplicitlyUnsupported(t *testing.T) {
	for _, pair := range [][2]string{{"10.0.0.1", "127.0.0.1"}, {"fd00::1", "::1"}} {
		s := advancedExample()
		s.SchemaVersion = 4
		s.Traffic = &TrafficPolicy{LocalOutput: true, LocalTargets: true, SourceMode: "preserve", ReturnPathConfirmed: true}
		s.Listeners = []Listener{{Protocol: "udp", Host: pair[0], Port: 18000}}
		s.Targets = []Target{{Endpoint: Endpoint{Host: pair[1], Port: 19000}, Weight: 1}}
		_, err := s.Normalize()
		if pair[1] == "::1" && err == nil {
			t.Fatal("unsupported external IPv6 loopback accepted")
		}
		if pair[1] == "127.0.0.1" && err != nil {
			t.Fatal("fixed-bind UDP source policy cannot reach node verification", err)
		}
		s.Listeners[0].Host = pair[1]
		s.Traffic.SourceMode = ""
		s.Traffic.ReturnPathConfirmed = false
		if _, err := s.Normalize(); err != nil {
			t.Fatal("host-only loopback was disabled", err)
		}
	}
}
func TestTrafficPolicySnapshotIsolation(t *testing.T) {
	s := advancedExample()
	s.SchemaVersion = 4
	s.Traffic = &TrafficPolicy{LocalOutput: true}
	other := cloneSpec(s)
	other.Traffic.LocalOutput = false
	if !s.Traffic.LocalOutput {
		t.Fatal("policy aliases previous generation")
	}
	copied := cloneState(State{Rules: map[string]Spec{s.ID: s}})
	copied.Rules[s.ID].Traffic.LocalTargets = true
	if s.Traffic.LocalTargets {
		t.Fatal("state aliases policy")
	}
}
