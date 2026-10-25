package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type guardedKernel struct {
	memoryKernel
	gated       bool
	config      map[string]Spec
	appliedOpen bool
}

func (k *guardedKernel) Quiesce() error  { k.gated = true; return nil }
func (k *guardedKernel) Activate() error { k.gated = false; return nil }
func (k *guardedKernel) Apply(t map[string]string) error {
	if !k.gated {
		k.appliedOpen = true
	}
	if e := k.memoryKernel.Apply(t); e != nil {
		return e
	}
	p, e := decodePlan(t)
	if e != nil {
		return e
	}
	k.config = map[string]Spec{}
	for _, s := range p {
		k.config[s.ID] = s
	}
	return nil
}
func (k *guardedKernel) SyncCredits(State) error { return nil }
func TestCrashRecoveryEveryCommitBoundary(t *testing.T) {
	stages := []string{"prepared", "quiesced", "kernel", "credits", "conntrack", "counters", "checkpoint", "committed", "activated"}
	for i, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			k := &guardedKernel{memoryKernel: memoryKernel{counters: map[string]uint64{}}}
			path := filepath.Join(t.TempDir(), "state.json")
			m, e := New(path, k)
			if e != nil {
				t.Fatal(e)
			}
			s := valid()
			if e = m.Apply(s); e != nil {
				t.Fatal(e)
			}
			epoch := m.state.Epoch
			k.counters["flux:v2:1_2_3:all:up"] = 1234
			m.Fault = func(at string) {
				if at == stage {
					panic("simulated power loss")
				}
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Error("fault was not reached")
					}
				}()
				s.Revision = 2
				s.TargetPort++
				_ = m.Apply(s)
			}()
			recovered, e := New(path, k)
			if e != nil {
				t.Fatal(e)
			}
			want := int64(1)
			if i >= 6 {
				want = 2
			}
			if recovered.Rules()[s.ID].Revision != want {
				t.Fatalf("revision=%d expected=%d", recovered.Rules()[s.ID].Revision, want)
			}
			r, e := recovered.Report()
			if e != nil || r.Epoch != epoch || r.Usage[0].Up != 1234 || k.gated || k.appliedOpen {
				t.Fatalf("recovery invalid: %#v %v gate=%v openApply=%v", r, e, k.gated, k.appliedOpen)
			}
			if _, e = os.Stat(path + ".journal"); !os.IsNotExist(e) {
				t.Fatal("journal not retired")
			}
		})
	}
}
func TestCorruptJournalKeepsGuardClosed(t *testing.T) {
	k := &guardedKernel{memoryKernel: memoryKernel{counters: map[string]uint64{}}}
	path := filepath.Join(t.TempDir(), "state.json")
	_, e := New(path, k)
	if e != nil {
		t.Fatal(e)
	}
	_ = os.WriteFile(path+".journal", []byte(`{"checksum":"wrong"}`), 0600)
	if _, e = New(path, k); e == nil || !k.gated {
		t.Fatal("corrupt WAL did not fail closed")
	}
}
func TestEndpointCanonicalAndCapabilityBoundary(t *testing.T) {
	for _, v := range []struct{ in, host, kind string }{{"EXAMPLE.com.:443", "example.com", "hostname"}, {"[2001:db8::1]:443", "2001:db8::1", "ip"}, {"[::ffff:192.0.2.1]:80", "192.0.2.1", "ip"}} {
		e, err := ParseEndpoint(v.in)
		if err != nil || e.Host != v.host || e.Kind != v.kind {
			t.Fatal(e, err)
		}
	}
	for _, v := range []string{"2001:db8::1:443", "127.0.0.1:0", "https://host:443", "a..b:80", "[fe80::1%eth0]:80", "012.0.0.1:80", "user@host:80"} {
		if _, e := ParseEndpoint(v); e == nil {
			t.Fatal("bad endpoint accepted", v)
		}
	}
	s := valid()
	s.SchemaVersion = 2
	s.Listen = Endpoint{Host: s.ListenIP, Port: s.ListenPort}
	s.Target = Endpoint{Host: "2001:db8::1", Port: 443}
	if _, e := s.Normalize(); e == nil {
		t.Fatal("parsing IPv6 incorrectly enabled forwarding")
	}
}
func TestBatchAtomicValidationAndRetry(t *testing.T) {
	m, k := fixture(t)
	specs := []Spec{}
	for i := 1; i <= 1000; i++ {
		s := valid()
		s.ID = fmt.Sprintf("%d_2_3", i)
		s.ListenPort = 10000 + i
		specs = append(specs, s)
	}
	b := Batch{ID: "repeatable", Specs: specs}
	calls := k.calls
	if e := m.ApplyBatch(b); e != nil {
		t.Fatal(e)
	}
	if k.calls != calls+1 {
		t.Fatal("batch installed rules more than once")
	}
	if e := m.ApplyBatch(b); e != nil || k.calls != calls+1 {
		t.Fatal("retry reapplied batch", e)
	}
	bad := Batch{ID: "invalid", Specs: []Spec{specs[0], specs[1]}}
	bad.Specs[0].Revision = 2
	bad.Specs[1].Revision = 2
	bad.Specs[1].ListenPort = bad.Specs[0].ListenPort
	before := m.Rules()
	if e := m.ApplyBatch(bad); e == nil || !reflect.DeepEqual(before, m.Rules()) {
		t.Fatal("invalid batch partially changed configuration")
	}
	page, e := m.Page("", 500, nil)
	if e != nil || len(page.Items) != 500 || page.Next == "" {
		t.Fatal(page, e)
	}
	page2, e := m.Page(page.Next, 500, &page.Generation)
	if e != nil || len(page2.Items) != 500 || page2.Next != "" {
		t.Fatal(page2, e)
	}
	b.Specs[0].TargetPort++
	if e := m.ApplyBatch(b); e == nil {
		t.Fatal("batch identity changed payload")
	}
}
func TestLeaseReplayExpiryAndLostClockAnchor(t *testing.T) {
	k := &guardedKernel{memoryKernel: memoryKernel{counters: map[string]uint64{}}}
	m, e := New(filepath.Join(t.TempDir(), "s.json"), k)
	if e != nil {
		t.Fatal(e)
	}
	s := valid()
	s.LeaseRequired = true
	if e = m.Apply(s); e != nil {
		t.Fatal(e)
	}
	r, e := m.Report()
	if e != nil {
		t.Fatal(e)
	}
	grant := LeaseGrant{ID: identity(), ServiceID: s.ID, Epoch: r.Epoch, BootID: m.state.BootID, Generation: 1, TotalGranted: 1024, RequestSequence: r.Sequence, ValidForMillis: 30000}
	if e = m.InstallGrants([]LeaseGrant{grant}); e != nil {
		t.Fatal(e)
	}
	old := m.state.Leases[s.ID]
	if e = m.InstallGrants([]LeaseGrant{grant}); e != nil || !reflect.DeepEqual(old, m.state.Leases[s.ID]) {
		t.Fatal("replay extended/reset credit", e)
	}
	grant.TotalGranted++
	if e = m.InstallGrants([]LeaseGrant{grant}); e == nil {
		t.Fatal("same generation changed credit")
	}
	grant.Generation++
	grant.RequestSequence = 999999
	if e = m.InstallGrants([]LeaseGrant{grant}); e == nil {
		t.Fatal("grant without durable request accepted")
	}
	l := m.state.Leases[s.ID]
	l.DeadlineBootMillis = bootMillis() - 1
	m.state.Leases[s.ID] = l
	if e = m.EnforceExpiration(); e != nil || !m.state.Leases[s.ID].Closed {
		t.Fatal("expired lease remained open", e)
	}
	b, _ := json.Marshal(CurrentCapabilities())
	if !json.Valid(b) {
		t.Fatal("invalid capability contract")
	}
}

type collectingKernel struct {
	guardedKernel
	records []counterRecord
	refs    map[string]bool
}

func (k *collectingKernel) SnapshotDetailed() (map[string]uint64, []counterRecord, error) {
	m := map[string]uint64{}
	for _, r := range k.records {
		p := strings.Split(r.Comment, ":")
		m["flux:v2:"+p[2]+":all:"+p[3]] += r.Bytes
	}
	return m, append([]counterRecord{}, k.records...), nil
}
func (k *collectingKernel) References() (map[string]bool, error) { return k.refs, nil }
func (k *collectingKernel) RemoveCounters(remove []counterRecord) error {
	gone := map[string]bool{}
	for _, r := range remove {
		gone[r.Set+"|"+r.Key] = true
	}
	kept := []counterRecord{}
	for _, r := range k.records {
		if !gone[r.Set+"|"+r.Key] {
			kept = append(kept, r)
		}
	}
	k.records = kept
	return nil
}
func (k *collectingKernel) RestoreCounters(old []counterRecord) error {
	for _, r := range old {
		exists := false
		for _, current := range k.records {
			if current.Set == r.Set && current.Key == r.Key {
				exists = true
			}
		}
		if !exists {
			k.records = append(k.records, r)
		}
	}
	return nil
}
func TestAcknowledgedCounterGCAndSafeTokenReuse(t *testing.T) {
	k := &collectingKernel{guardedKernel: guardedKernel{memoryKernel: memoryKernel{counters: map[string]uint64{}}}, refs: map[string]bool{}}
	m, e := New(filepath.Join(t.TempDir(), "state.json"), k)
	if e != nil {
		t.Fatal(e)
	}
	s := valid()
	if e = m.Apply(s); e != nil {
		t.Fatal(e)
	}
	s = m.Rules()[s.ID]
	key := targetKey(s)
	k.records = []counterRecord{{upSet, key, "flux:v2:" + s.ID + ":up", 123, 2}, {downSet, key, "flux:v2:" + s.ID + ":down", 456, 3}}
	if e = m.Change(s.ID, 2, false, true); e != nil {
		t.Fatal(e)
	}
	r, e := m.Report()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Collect(0); e != nil || len(k.records) != 2 {
		t.Fatal("unacknowledged counters were removed", e)
	}
	if e = m.Acknowledge(Acknowledgement{Epoch: r.Epoch, Sequence: r.Sequence, Usage: r.Usage, Counters: r.Counters}); e != nil {
		t.Fatal(e)
	}
	k.refs[key] = true
	k.refs[fmt.Sprintf("mark:0x%x", flowMark(s))] = true
	if _, e = m.Collect(0); e != nil || len(k.records) != 2 {
		t.Fatal("referenced counters were collected", e)
	}
	k.refs = map[string]bool{}
	if _, e = m.Collect(0); e != nil {
		t.Fatal(e)
	}
	if len(k.records) != 0 || len(m.Rules()) != 0 || len(m.state.FreeTokens) != 1 {
		t.Fatal("settled state not reclaimed")
	}
	if e = m.Apply(s); e == nil {
		t.Fatal("delayed retired revision recreated forwarding")
	}
	next := valid()
	next.ID = "99_2_3"
	next.ListenPort++
	if e = m.Apply(next); e != nil {
		t.Fatal(e)
	}
	if m.Rules()[next.ID].Token != s.Token {
		t.Fatal("verified free token not reused")
	}
}
func TestFailedTokenReservationIsQuarantinedThenReclaimed(t *testing.T) {
	k := &collectingKernel{guardedKernel: guardedKernel{memoryKernel: memoryKernel{counters: map[string]uint64{}}}, refs: map[string]bool{}}
	m, e := New(filepath.Join(t.TempDir(), "state.json"), k)
	if e != nil {
		t.Fatal(e)
	}
	k.fail = true
	if e = m.Apply(valid()); e == nil {
		t.Fatal("fault missing")
	}
	if len(m.state.Quarantine) != 1 {
		t.Fatal("failed reservation was not quarantined")
	}
	if _, e = m.Collect(0); e != nil || len(m.state.FreeTokens) != 1 || len(m.state.Quarantine) != 0 {
		t.Fatal("unreferenced failed reservation not reclaimed", e)
	}
}

type resetKernel struct {
	guardedKernel
	instance string
}

func (k *resetKernel) BootID() string                     { return "same-host-boot" }
func (k *resetKernel) ClaimLedger(string) (string, error) { return k.instance, nil }
func (k *resetKernel) RotateLedger(string) (string, error) {
	k.instance = identity()
	return k.instance, nil
}
func TestNetworkNamespaceResetInvalidatesCreditOnSameHostBoot(t *testing.T) {
	k := &resetKernel{guardedKernel: guardedKernel{memoryKernel: memoryKernel{counters: map[string]uint64{}}}, instance: "first-ledger"}
	path := filepath.Join(t.TempDir(), "state.json")
	m, e := New(path, k)
	if e != nil {
		t.Fatal(e)
	}
	s := valid()
	s.LeaseRequired = true
	if e = m.Apply(s); e != nil {
		t.Fatal(e)
	}
	k.counters["flux:v2:"+s.ID+":all:up"] = 100
	r, e := m.Report()
	if e != nil {
		t.Fatal(e)
	}
	g := LeaseGrant{ID: identity(), BootID: r.BootID, ServiceID: s.ID, Epoch: r.Epoch, Generation: 1, TotalGranted: 1024, RequestSequence: r.Sequence, ValidForMillis: 30000}
	if e = m.InstallGrants([]LeaseGrant{g}); e != nil {
		t.Fatal(e)
	}
	oldBoot := m.state.BootID
	k.counters = map[string]uint64{}
	k.instance = "recreated-netns"
	m, e = New(path, k)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.state.Leases) != 0 || m.state.BootID == oldBoot || !m.state.Recovery.PossibleLoss || m.state.Totals[s.ID].Up != 100 {
		t.Fatal("namespace reset reused uncheckpointed credit", m.state)
	}
}

func TestLiveCounterRegressionClosesGateAndDoesNotReissueCredit(t *testing.T) {
	k := &resetKernel{guardedKernel: guardedKernel{memoryKernel: memoryKernel{counters: map[string]uint64{}}}, instance: "ledger"}
	path := filepath.Join(t.TempDir(), "s.json")
	m, e := New(path, k)
	if e != nil {
		t.Fatal(e)
	}
	s := valid()
	s.LeaseRequired = true
	if e = m.Apply(s); e != nil {
		t.Fatal(e)
	}
	key := "flux:v2:" + s.ID + ":all:up"
	k.counters[key] = 100
	r, e := m.Report()
	if e != nil {
		t.Fatal(e)
	}
	g := LeaseGrant{ID: identity(), BootID: r.BootID, ServiceID: s.ID, Epoch: r.Epoch, Generation: 1, TotalGranted: 1024, RequestSequence: r.Sequence, ValidForMillis: 30000}
	if e = m.InstallGrants([]LeaseGrant{g}); e != nil {
		t.Fatal(e)
	}
	k.counters[key] = 25
	if _, e = m.Report(); e == nil || !k.gated || !m.state.AccountingBlocked || len(m.state.Leases) > 0 {
		t.Fatal("counter regression left credit active", e)
	}
	r, e = m.Report()
	if e != nil || !r.Recovery.PossibleLoss || len(r.Requests) > 0 || r.Usage[0].Up != 100 {
		t.Fatal("ambiguous bytes were rebilled or credit requested", r, e)
	}
	m, e = New(path, k)
	if e != nil || !m.blocked || !k.gated {
		t.Fatal("restart cleared an unresolved accounting block", e)
	}
}

func TestStrictCreditPolicyClosesPreexistingFiniteForwardsAndCannotDowngrade(t *testing.T) {
	k := &guardedKernel{memoryKernel: memoryKernel{counters: map[string]uint64{}}}
	m, e := New(filepath.Join(t.TempDir(), "s.json"), k)
	if e != nil {
		t.Fatal(e)
	}
	s := valid()
	if e = m.Apply(s); e != nil {
		t.Fatal(e)
	}
	if m.Rules()[s.ID].LeaseRequired {
		t.Fatal("legacy compatibility changed before negotiation")
	}
	if e = m.RequireCreditPolicy(); e != nil {
		t.Fatal(e)
	}
	if !m.Rules()[s.ID].LeaseRequired || !m.state.StrictCredit {
		t.Fatal("existing finite forwarding bypassed strict mode")
	}
	s.Revision++
	s.LeaseRequired = false
	if e = m.Apply(s); e != nil {
		t.Fatal(e)
	}
	if !m.Rules()[s.ID].LeaseRequired {
		t.Fatal("individual request downgraded the node policy")
	}
}
