package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
)

func TestCounterIdentityCacheCannotHideMutationOrLoss(t *testing.T) {
	n := &NativeNFT{}
	r := nativeRecord(Spec{ID: "1_2_3", Token: 1}, "192.0.2.1", "ipv4", "up")
	c := nativeCounter{Name: nativeCounterName(r), Comment: encodeNativeCounter(r), Bytes: 100, Packets: 2}
	for _, value := range []uint64{100, 200, 0} {
		c.Bytes = value
		got, e := n.decodeCounterObjects([]nativeCounter{c})
		if e != nil || got[c.Name].Bytes != value {
			t.Fatal("stale sample", got, e)
		}
	}
	bad := c
	bad.Comment += "foreign"
	if _, e := n.decodeCounterObjects([]nativeCounter{bad}); e == nil {
		t.Fatal("changed metadata accepted from cache")
	}
	if _, e := n.decodeCounterObjects([]nativeCounter{c, c}); e == nil {
		t.Fatal("duplicate accepted")
	}
	if _, e := n.decodeCounterObjects(nil); e != nil || len(n.counterIdentities) != 0 || len(n.counterOrder) != 0 {
		t.Fatal("removed object survived", e)
	}
	if _, e := n.decodeCounterObjects([]nativeCounter{c}); e != nil {
		t.Fatal("cache did not recover", e)
	}
}
func TestCachedCheckpointStillPersistsCurrentRulesAndLedger(t *testing.T) {
	m, k := fixture(t)
	s := valid()
	check := func() {
		t.Helper()
		b, e := os.ReadFile(m.Path)
		if e != nil {
			t.Fatal(e)
		}
		var disk, actual any
		if json.Unmarshal(b, &disk) != nil {
			t.Fatal("invalid JSON")
		}
		encoded, _ := json.Marshal(m.state)
		_ = json.Unmarshal(encoded, &actual)
		if !reflect.DeepEqual(disk, actual) {
			t.Fatal("checkpoint differs from current state")
		}
	}
	if e := m.Apply(s); e != nil {
		t.Fatal(e)
	}
	check()
	for _, value := range []uint64{100, 200} {
		k.counters["flux:v1:1_2_3:tcp:up"] = value
		if _, e := m.Report(); e != nil {
			t.Fatal(e)
		}
		check()
	}
	if e := m.Change(s.ID, 2, false, false); e != nil {
		t.Fatal(e)
	}
	check()
	k.fail = true
	s.Revision = 3
	if e := m.Apply(s); e == nil {
		t.Fatal("failed apply succeeded")
	}
	check()
	reloaded, e := New(m.Path, k)
	if e != nil || reloaded.state.Rules[s.ID].Enabled {
		t.Fatal("rollback cache survived restart", e)
	}
}
func TestRuleSnapshotDoesNotAliasProtocolPolicy(t *testing.T) {
	s := advancedExample()
	s.SchemaVersion = 5
	s.ProtocolFilter = &ProtocolFilter{HTTP: true, Unknown: "allow"}
	copied := cloneState(State{Rules: map[string]Spec{s.ID: s}})
	copied.Rules[s.ID].ProtocolFilter.HTTP = false
	if !s.ProtocolFilter.HTTP {
		t.Fatal("transaction exposed mutable policy")
	}
}
func BenchmarkCachedCheckpoint(b *testing.B) {
	m := &Manager{state: State{Rules: map[string]Spec{}, CounterLast: map[string]uint64{}}}
	for i := 0; i < 10000; i++ {
		s := advancedExample()
		s.ID = fmt.Sprintf("%d_2_3", i)
		s.SchemaVersion = 5
		s.ProtocolFilter = &ProtocolFilter{HTTP: true, TLS: true, SOCKS: true, Unknown: "allow"}
		m.state.Rules[s.ID] = s
		m.state.CounterLast[s.ID] = 0
	}
	for _, cached := range []bool{false, true} {
		b.Run(fmt.Sprint(cached), func(b *testing.B) {
			_, _ = m.checkpointData()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if cached {
					_, _ = m.checkpointData()
				} else {
					_, _ = json.Marshal(m.state)
				}
			}
		})
	}
}

func TestPageDoesNotExposeMutableCachedPolicy(t *testing.T) {
	s := advancedExample()
	s.SchemaVersion = 5
	s.ProtocolFilter = &ProtocolFilter{HTTP: true, Unknown: "allow"}
	m := &Manager{state: State{Rules: map[string]Spec{s.ID: s}}}
	p, e := m.Page("", 10, nil)
	if e != nil {
		t.Fatal(e)
	}
	p.Items[0].ProtocolFilter.HTTP = false
	p.Items[0].Targets[0].Weight = 20
	if !m.state.Rules[s.ID].ProtocolFilter.HTTP || m.state.Rules[s.ID].Targets[0].Weight != 1 {
		t.Fatal("page changed cached live rules")
	}
}

func TestNormalizedPolicyDoesNotAliasCaller(t *testing.T) {
	s := advancedExample()
	s.SchemaVersion = 5
	s.ProtocolFilter = &ProtocolFilter{HTTP: true, Unknown: "allow"}
	normalized, e := s.Normalize()
	if e != nil {
		t.Fatal(e)
	}
	s.ProtocolFilter.HTTP = false
	if !normalized.ProtocolFilter.HTTP {
		t.Fatal("caller changed normalized cached policy")
	}
}
func TestCachedCheckpointEscapesText(t *testing.T) {
	s := advancedExample()
	s.IntentHash = "quoted\"<&\n☁"
	s.Runtime.Error = "\"\n<&"
	m := &Manager{state: State{Rules: map[string]Spec{s.ID: s}}}
	b, e := m.checkpointData()
	if e != nil {
		t.Fatal(e)
	}
	var disk State
	if e = json.Unmarshal(b, &disk); e != nil {
		t.Fatal(e)
	}
	if disk.Rules[s.ID].IntentHash != s.IntentHash || disk.Rules[s.ID].Runtime.Error != s.Runtime.Error {
		t.Fatal("cached JSON changed strings")
	}
}
