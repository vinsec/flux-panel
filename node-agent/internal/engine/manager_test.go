package engine

import (
	"errors"
	"path/filepath"
	"testing"
)

type memoryKernel struct {
	counters map[string]uint64
	fail     bool
	calls    int
}

func (k *memoryKernel) Snapshot() (map[string]uint64, error) {
	out := map[string]uint64{}
	for n, v := range k.counters {
		out[n] = v
	}
	return out, nil
}
func (k *memoryKernel) Apply(_ map[string]string) error {
	k.calls++
	if k.fail {
		k.fail = false
		return errors.New("injected restore failure")
	}
	return nil
}
func fixture(t *testing.T) (*Manager, *memoryKernel) {
	t.Helper()
	k := &memoryKernel{counters: map[string]uint64{}}
	m, e := New(filepath.Join(t.TempDir(), "state.json"), k)
	if e != nil {
		t.Fatal(e)
	}
	return m, k
}
func valid() Spec {
	return Spec{ID: "1_2_3", Revision: 1, ListenIP: "0.0.0.0", ListenPort: 18000, TargetIP: "10.99.2.2", TargetPort: 9000, Enabled: true}
}

func TestRevisionAndRollback(t *testing.T) {
	m, k := fixture(t)
	s := valid()
	if e := m.Apply(s); e != nil {
		t.Fatal(e)
	}
	if e := m.Change(s.ID, 2, false, false); e != nil {
		t.Fatal(e)
	}
	if e := m.Apply(s); e == nil {
		t.Fatal("stale revision re-enabled a paused forward")
	}
	old := m.Rules()[s.ID]
	k.fail = true
	s.Revision = 3
	if e := m.Apply(s); e == nil {
		t.Fatal("restore failure was acknowledged")
	}
	if m.Rules()[s.ID] != old {
		t.Fatal("failed revision replaced the last successful configuration")
	}
	reloaded, e := New(m.Path, k)
	if e != nil {
		t.Fatal(e)
	}
	if reloaded.Rules()[s.ID] != old {
		t.Fatal("disk state did not roll back")
	}
}
func TestCumulativeStatisticsAndRestart(t *testing.T) {
	m, k := fixture(t)
	s := valid()
	if e := m.Apply(s); e != nil {
		t.Fatal(e)
	}
	k.counters["flux:v1:1_2_3:tcp:up"] = 123
	k.counters["flux:v1:1_2_3:tcp:down"] = 456
	r, e := m.Report()
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Usage) != 1 || r.Usage[0].Up != 123 || r.Usage[0].Down != 456 {
		t.Fatal(r)
	}
	calls := k.calls
	r2, e := m.Report()
	if e != nil {
		t.Fatal(e)
	}
	if r2.Usage[0] != r.Usage[0] || r2.Sequence <= r.Sequence {
		t.Fatal("report retry changed bytes or failed to advance sequence")
	}
	if k.calls != calls {
		t.Fatal("polling rewrites the forwarding rules")
	}
	m, e = New(m.Path, k)
	if e != nil {
		t.Fatal(e)
	}
	r3, e := m.Report()
	if e != nil {
		t.Fatal(e)
	}
	if r3.Epoch != r.Epoch || r3.Usage[0] != r.Usage[0] {
		t.Fatal("process restart double-counted traffic")
	}
	k.counters = map[string]uint64{}
	m, e = New(m.Path, k)
	if e != nil {
		t.Fatal(e)
	}
	k.counters["flux:v1:1_2_3:tcp:up"] = 10
	r4, e := m.Report()
	if e != nil {
		t.Fatal(e)
	}
	if r4.Usage[0].Up != 133 {
		t.Fatal("kernel reset lost the persisted ledger", r4)
	}
}
func TestRejectUnsupportedAndConflicts(t *testing.T) {
	m, _ := fixture(t)
	s := valid()
	if e := m.Apply(s); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []Spec{{ID: "1;touch /tmp/owned", Revision: 1}, {ID: "1_2_4", Revision: 1, ListenIP: "::", ListenPort: 18001, TargetIP: "10.1.1.1", TargetPort: 1}, {ID: "1_2_4", Revision: 1, ListenIP: "0.0.0.0", ListenPort: 18000, TargetIP: "10.1.1.1", TargetPort: 1}} {
		if e := m.Apply(bad); e == nil {
			t.Fatal("invalid or conflicting request accepted", bad)
		}
	}
}

func TestLostStateCannotRebillHistoricalKernelCounters(t *testing.T) {
	k := &memoryKernel{counters: map[string]uint64{"flux:v1:1_2_3:tcp:up": 123}}
	if _, e := New(filepath.Join(t.TempDir(), "missing.json"), k); e == nil {
		t.Fatal("lost state silently adopted and rebilled existing counters")
	}
	if k.calls != 0 {
		t.Fatal("lost state mutated existing rules")
	}
}
