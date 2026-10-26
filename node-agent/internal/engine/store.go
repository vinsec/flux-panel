package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

func identity() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func atomicJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return atomicBytes(path, b)
}
func atomicBytes(path string, b []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(path+".tmp", path); e != nil {
		return e
	}
	return syncDir(path)
}
func syncDir(path string) error {
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func removeDurable(path string) error {
	if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
		return e
	}
	return syncDir(path)
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func cloneState(s State) State {
	r := s
	r.Rules = maps.Clone(s.Rules)
	for id, spec := range r.Rules {
		spec.Protocols = slices.Clone(spec.Protocols)
		if spec.AdvancedOptions != nil {
			advanced := *spec.AdvancedOptions
			advanced.Listeners = slices.Clone(advanced.Listeners)
			advanced.Targets = slices.Clone(advanced.Targets)
			advanced.Runtime.Targets = slices.Clone(advanced.Runtime.Targets)
			spec.AdvancedOptions = &advanced
		}
		r.Rules[id] = spec
	}
	r.Totals = maps.Clone(s.Totals)
	r.Last = maps.Clone(s.Last)
	r.CounterLast = maps.Clone(s.CounterLast)
	r.Ack = maps.Clone(s.Ack)
	r.Quarantine = maps.Clone(s.Quarantine)
	r.LeaseAcks = maps.Clone(s.LeaseAcks)
	r.AckCounters = maps.Clone(s.AckCounters)
	r.CounterRetiredAt = maps.Clone(s.CounterRetiredAt)
	r.ClosedLeaseAcks = maps.Clone(s.ClosedLeaseAcks)
	r.Floors = maps.Clone(s.Floors)
	r.RetiredAt = maps.Clone(s.RetiredAt)
	r.Leases = maps.Clone(s.Leases)
	r.RequestTimes = maps.Clone(s.RequestTimes)
	r.FreeTokens = slices.Clone(s.FreeTokens)
	r.Receipts = slices.Clone(s.Receipts)
	if r.Quarantine == nil {
		r.Quarantine = map[uint32]int64{}
	}
	if r.LeaseAcks == nil {
		r.LeaseAcks = map[string]uint64{}
	}
	if r.Ack == nil {
		r.Ack = map[string]Usage{}
	}
	if r.Floors == nil {
		r.Floors = map[string]int64{}
	}
	if r.RetiredAt == nil {
		r.RetiredAt = map[string]int64{}
	}
	if r.Leases == nil {
		r.Leases = map[string]Lease{}
	}
	if r.RequestTimes == nil {
		r.RequestTimes = map[int64]int64{}
	}
	if r.AckCounters == nil {
		r.AckCounters = map[string]uint64{}
	}
	if r.CounterRetiredAt == nil {
		r.CounterRetiredAt = map[string]int64{}
	}
	if r.ClosedLeaseAcks == nil {
		r.ClosedLeaseAcks = map[string]bool{}
	}
	return r
}

type counterRecord struct {
	Set, Key, Comment string
	Bytes, Packets    uint64
}
type transaction struct {
	Version       int
	Before, After State
	Forget        []Spec
	GC            []counterRecord
	Reason        string
}
type journalEnvelope struct {
	Checksum    string      `json:"checksum"`
	Transaction transaction `json:"transaction"`
}

func (m *Manager) journal(t transaction) error {
	data, e := json.Marshal(t)
	if e != nil {
		return e
	}
	checksum := sha256.Sum256(data)
	// Persist the same serialized transaction used for the checksum. Avoid a
	// second traversal/serialization of both complete states on every renewal.
	prefix := []byte(`{"checksum":"` + hex.EncodeToString(checksum[:]) + `","transaction":`)
	body := make([]byte, 0, len(prefix)+len(data)+1)
	body = append(body, prefix...)
	body = append(body, data...)
	body = append(body, '}')
	return atomicBytes(m.Path+".journal", body)
}
func (m *Manager) recover() error {
	b, e := os.ReadFile(m.Path + ".journal")
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = m.quiesce(); e != nil {
		return e
	}
	var j journalEnvelope
	if e = json.Unmarshal(b, &j); e != nil || j.Transaction.Version != 1 || j.Checksum != digest(j.Transaction) {
		return fmt.Errorf("corrupt recovery journal; owned forwarding remains blocked")
	}
	t := j.Transaction
	committed := m.state.CommitID != "" && m.state.CommitID == t.After.CommitID
	if !committed {
		m.state = t.Before
		if r, ok := m.Kernel.(interface{ RestoreCounters([]counterRecord) error }); ok {
			if e = r.RestoreCounters(t.GC); e != nil {
				return e
			}
		}
	}
	// Re-establish the verified epoch before replaying auxiliary resources.
	// Normal startup claims it later, but recovery may need routes and IFB
	// ownership while replaying the interrupted generation itself.
	if ledger, ok := m.Kernel.(interface{ ClaimLedger(string) (string, error) }); ok {
		if _, e = ledger.ClaimLedger(m.state.Epoch); e != nil {
			return e
		}
	}
	if e = m.Kernel.Apply(Render(m.state.Rules, nil)); e != nil {
		return fmt.Errorf("journal replay: %w", e)
	}
	if e = m.capture(&m.state); e != nil {
		return e
	}
	if e = m.syncCredits(&m.state); e != nil {
		return e
	}
	if committed {
		if e = m.forget(t.Forget); e != nil {
			return e
		}
	}
	if e = m.capture(&m.state); e != nil {
		return e
	}
	if e = m.save(); e != nil {
		return e
	}
	if e = removeDurable(m.Path + ".journal"); e != nil {
		return e
	}
	return nil // New finishes reconstruction before it removes the guard.
}
