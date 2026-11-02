package engine

import (
	"path/filepath"
	"testing"
)

func TestIdleNewCreditClaimSurvivesDirtyUsagePagingAndRenews(t *testing.T) {
	k := &guardedKernel{memoryKernel: memoryKernel{counters: map[string]uint64{}}}
	m, e := New(filepath.Join(t.TempDir(), "state.json"), k)
	if e != nil {
		t.Fatal(e)
	}
	s := valid()
	s.LeaseRequired = true
	if e = m.Apply(s); e != nil {
		t.Fatal(e)
	}
	initial, e := m.Report()
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Acknowledge(Acknowledgement{Epoch: initial.Epoch, Sequence: initial.Sequence, Usage: initial.Usage}); e != nil {
		t.Fatal(e)
	}
	grant := LeaseGrant{ID: identity(), ServiceID: s.ID, Epoch: initial.Epoch, BootID: initial.BootID, Generation: 1, TotalGranted: 4096, WindowBytes: 4096, RequestSequence: initial.Sequence, ValidForMillis: 30000}
	if e = m.InstallGrants([]LeaseGrant{grant}); e != nil {
		t.Fatal(e)
	}
	for cycle := 0; cycle < 3; cycle++ {
		l := m.state.Leases[s.ID]
		l.DeadlineBootMillis = bootMillis() + 10000
		m.state.Leases[s.ID] = l
		r, e := m.Report()
		if e != nil {
			t.Fatal(e)
		}
		if len(r.Usage) != 0 || len(r.Leases) != 1 || r.Leases[0].Used != 0 || len(r.Requests) != 1 || r.Requests[0] != s.ID {
			t.Fatalf("idle renewal lost to paging, cycle %d: %+v", cycle, r)
		}
		if e = m.Acknowledge(Acknowledgement{Epoch: r.Epoch, Sequence: r.Sequence, Usage: r.Usage, LeaseWatermarks: r.Leases}); e != nil {
			t.Fatal(e)
		}
		grant.Generation++
		grant.RequestSequence = r.Sequence
		if e = m.InstallGrants([]LeaseGrant{grant}); e != nil {
			t.Fatal(e)
		}
		if !m.CreditReady(s.ID) {
			t.Fatal("renewed idle grant not usable")
		}
	}
}
