package engine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Manager struct {
	mu     sync.Mutex
	Path   string
	Kernel Kernel
	state  State
	active map[string]bool
}

func New(path string, k Kernel) (*Manager, error) {
	m := &Manager{Path: path, Kernel: k, active: map[string]bool{}}
	data, e := os.ReadFile(path)
	fresh := os.IsNotExist(e)
	if e == nil {
		if e = json.Unmarshal(data, &m.state); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if fresh {
		counters, e := k.Snapshot()
		if e != nil {
			return nil, e
		}
		if len(counters) > 0 {
			return nil, fmt.Errorf("persistent state missing while owned kernel counters exist; restore the state file before starting")
		}
		if checker, ok := k.(interface{ Configured() (bool, error) }); ok {
			configured, e := checker.Configured()
			if e != nil {
				return nil, e
			}
			if configured {
				return nil, fmt.Errorf("persistent state missing while owned NAT rules exist; refusing to reset the accounting epoch")
			}
		}
	} else if len(m.state.Epoch) != 32 || m.state.Sequence < 0 {
		return nil, fmt.Errorf("invalid persistent accounting identity")
	}
	if m.state.Epoch == "" {
		var id [16]byte
		if _, e = rand.Read(id[:]); e != nil {
			return nil, e
		}
		m.state.Epoch = hex.EncodeToString(id[:])
	}
	if m.state.Rules == nil {
		m.state.Rules = map[string]Spec{}
	}
	if m.state.Totals == nil {
		m.state.Totals = map[string]Usage{}
	}
	if m.state.Last == nil {
		m.state.Last = map[string]uint64{}
	}
	for _, s := range m.state.Rules {
		if e = s.Validate(); e != nil {
			return nil, e
		}
	}
	if e = m.sample(); e != nil {
		return nil, e
	}
	// Old owned counters are preserved on process restart; after host reboot the
	// cumulative ledger survives and only the kernel baseline begins again.
	counters, e := k.Snapshot()
	if e != nil {
		return nil, e
	}
	if e = k.Apply(Render(m.state.Rules, counters)); e != nil {
		return nil, e
	}
	for id, s := range m.state.Rules {
		m.active[id] = s.Active()
	}
	if e = m.save(); e != nil {
		return nil, e
	}
	return m, nil
}

func (m *Manager) save() error {
	if e := os.MkdirAll(filepath.Dir(m.Path), 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(m.state, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(m.Path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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
	if e = os.Rename(m.Path+".tmp", m.Path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(m.Path))
	if e == nil {
		defer d.Close()
		e = d.Sync()
	}
	return e
}

func (m *Manager) sample() error {
	c, e := m.Kernel.Snapshot()
	if e != nil {
		return e
	}
	for name := range m.state.Last {
		if _, ok := c[name]; !ok {
			m.state.Last[name] = 0
		}
	}
	for name, value := range c {
		p := strings.Split(name, ":")
		if len(p) != 5 {
			continue
		}
		id, dir := p[2], p[4]
		u := m.state.Totals[id]
		u.ID = id
		last := m.state.Last[name]
		delta := value
		if value >= last {
			delta = value - last
		}
		if dir == "up" {
			u.Up += delta
		} else if dir == "down" {
			u.Down += delta
		}
		m.state.Totals[id] = u
		m.state.Last[name] = value
	}
	return m.save()
}

func (m *Manager) Apply(s Spec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := s.Validate(); e != nil {
		return e
	}
	if validator, ok := m.Kernel.(interface{ ValidateSpec(Spec) error }); ok {
		if e := validator.ValidateSpec(s); e != nil {
			return e
		}
	}
	old, exists := m.state.Rules[s.ID]
	if exists && s.Revision < old.Revision {
		return fmt.Errorf("stale revision")
	}
	if exists && s.Revision == old.Revision {
		if old == s {
			return nil
		}
		return fmt.Errorf("revision conflict")
	}
	for id, v := range m.state.Rules {
		if id != s.ID && !s.Deleted && !v.Deleted && s.ListenPort == v.ListenPort && (s.ListenIP == v.ListenIP || s.ListenIP == "0.0.0.0" || v.ListenIP == "0.0.0.0") {
			return fmt.Errorf("listener conflicts with %s", id)
		}
	}
	if e := m.sample(); e != nil {
		return e
	}
	c, e := m.Kernel.Snapshot()
	if e != nil {
		return e
	}
	m.state.Rules[s.ID] = s
	if e = m.Kernel.Apply(Render(m.state.Rules, c)); e != nil {
		if exists {
			m.state.Rules[s.ID] = old
		} else {
			delete(m.state.Rules, s.ID)
		}
		if re := m.Kernel.Apply(Render(m.state.Rules, c)); re != nil {
			return fmt.Errorf("apply: %v; rollback: %w", e, re)
		}
		return e
	}
	if exists && !old.Deleted && (s.Deleted || s.TargetIP != old.TargetIP || s.TargetPort != old.TargetPort || s.ListenIP != old.ListenIP || s.ListenPort != old.ListenPort) {
		if cleaner, ok := m.Kernel.(interface{ Forget(Spec) error }); ok {
			if e = cleaner.Forget(old); e != nil {
				m.state.Rules[s.ID] = old
				if re := m.Kernel.Apply(Render(m.state.Rules, c)); re != nil {
					return fmt.Errorf("cleanup: %v; rollback: %w", e, re)
				}
				return e
			}
		}
	}
	if e = m.save(); e != nil {
		if exists {
			m.state.Rules[s.ID] = old
		} else {
			delete(m.state.Rules, s.ID)
		}
		if re := m.Kernel.Apply(Render(m.state.Rules, c)); re != nil {
			return fmt.Errorf("persist: %v; rollback: %w", e, re)
		}
		return e
	}
	m.active[s.ID] = s.Active()
	return nil
}

func (m *Manager) Change(id string, revision int64, enabled, deleted bool) error {
	m.mu.Lock()
	s, ok := m.state.Rules[id]
	m.mu.Unlock()
	if !ok {
		if deleted {
			return m.Apply(Spec{ID: id, Revision: revision, Deleted: true})
		}
		return fmt.Errorf("forward not found")
	}
	if s.Deleted && !deleted {
		return fmt.Errorf("forward not found")
	}
	s.Revision = revision
	s.Enabled = enabled
	s.Deleted = deleted
	return m.Apply(s)
}

func (m *Manager) Report() (Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.sample(); e != nil {
		return Report{}, e
	}
	if e := m.enforceLocked(); e != nil {
		return Report{}, e
	}
	m.state.Sequence++
	if e := m.save(); e != nil {
		return Report{}, e
	}
	r := Report{Epoch: m.state.Epoch, Sequence: m.state.Sequence, Usage: []Usage{}}
	for _, id := range keys(m.state.Rules) {
		if u, ok := m.state.Totals[id]; ok {
			r.Usage = append(r.Usage, u)
		}
	}
	return r, nil
}

func (m *Manager) EnforceExpiration() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enforceLocked()
}
func (m *Manager) enforceLocked() error {
	// Enforce only on transitions. This runs independently of HTTP reporting,
	// so an unreachable panel cannot stall a local expiry deadline.
	changed := false
	for id, s := range m.state.Rules {
		if m.active[id] != s.Active() {
			changed = true
		}
	}
	if changed {
		if e := m.sample(); e != nil {
			return e
		}
		c, e := m.Kernel.Snapshot()
		if e != nil {
			return e
		}
		if e = m.Kernel.Apply(Render(m.state.Rules, c)); e != nil {
			return e
		}
		for id, s := range m.state.Rules {
			m.active[id] = s.Active()
		}
	}
	return nil
}

func (m *Manager) Rules() map[string]Spec {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := map[string]Spec{}
	for k, v := range m.state.Rules {
		r[k] = v
	}
	return r
}
