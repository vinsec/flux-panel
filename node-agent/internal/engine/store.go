package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	b, _ := json.Marshal(s)
	var r State
	if e := json.Unmarshal(b, &r); e != nil {
		panic(e)
	}
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
	return atomicJSON(m.Path+".journal", journalEnvelope{digest(t), t})
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
