package engine

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Grants are cumulative. A replay cannot reset a byte budget or extend expiry.
// The node's durable request anchor avoids trusting a skewed wall clock.
type LeaseGrant struct {
	WindowBytes     uint64 `json:"windowBytes,omitempty"`
	BootID          string `json:"bootId"`
	ID              string `json:"id"`
	ServiceID       string `json:"serviceId"`
	Epoch           string `json:"epoch"`
	Generation      uint64 `json:"generation"`
	TotalGranted    uint64 `json:"totalGranted"`
	RequestSequence int64  `json:"requestSequence"`
	ValidForMillis  int64  `json:"validForMillis"`
}
type Lease struct {
	Grant              LeaseGrant `json:"grant"`
	StartUp            uint64     `json:"startUp"`
	StartDown          uint64     `json:"startDown"`
	DeadlineBootMillis int64      `json:"deadlineBootMillis"`
	Closed             bool       `json:"closed"`
}
type LeaseUsage struct {
	ID         string `json:"id"`
	ServiceID  string `json:"serviceId"`
	Generation uint64 `json:"generation"`
	Used       uint64 `json:"used"`
	Closed     bool   `json:"closed"`
}

const creditCeiling uint64 = 1 << 62

func bootMillis() int64 {
	if b, e := os.ReadFile("/proc/uptime"); e == nil {
		v, e := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
		if e == nil {
			return int64(v * 1000)
		}
	}
	return time.Now().UnixMilli()
}
func used(s *State, id string, l Lease) uint64 {
	u := s.Totals[id]
	if u.Up < l.StartUp || u.Down < l.StartDown {
		return l.Grant.TotalGranted
	}
	n := u.Up - l.StartUp + u.Down - l.StartDown
	if n > l.Grant.TotalGranted {
		return l.Grant.TotalGranted
	}
	return n
}
func applyGrants(s *State, grants []LeaseGrant) error {
	for _, g := range grants {
		spec, ok := s.Rules[g.ServiceID]
		if !ok || spec.Deleted || !spec.LeaseRequired {
			return fmt.Errorf("lease for an unmanaged service")
		}
		if !serviceID.MatchString(g.ServiceID) || len(g.ID) != 32 || g.Epoch != s.Epoch || g.BootID != s.BootID || g.Generation < 1 || g.TotalGranted == 0 || g.TotalGranted >= creditCeiling || g.ValidForMillis < 1 || g.ValidForMillis > 60000 {
			return fmt.Errorf("invalid credit grant")
		}
		if _, e := strconv.ParseUint(g.ID[:16], 16, 64); e != nil {
			return fmt.Errorf("invalid lease identity")
		}
		if _, e := strconv.ParseUint(g.ID[16:], 16, 64); e != nil {
			return fmt.Errorf("invalid lease identity")
		}
		started, ok := s.RequestTimes[g.RequestSequence]
		if !ok {
			return fmt.Errorf("lease has no durable request anchor")
		}
		deadline := started + g.ValidForMillis
		old, exists := s.Leases[g.ServiceID]
		if exists && old.Grant.ID == g.ID {
			if g.Generation < old.Grant.Generation {
				return fmt.Errorf("stale lease generation")
			}
			if g.Generation == old.Grant.Generation {
				if old.Grant.TotalGranted != g.TotalGranted {
					return fmt.Errorf("lease generation conflict")
				}
				continue
			}
			if old.Closed || g.TotalGranted < old.Grant.TotalGranted {
				return fmt.Errorf("closed or regressing lease")
			}
			old.Grant = g
			old.DeadlineBootMillis = deadline
			s.Leases[g.ServiceID] = old
		} else {
			if exists && !old.Closed {
				return fmt.Errorf("previous lease must settle before replacement")
			}
			u := s.Totals[g.ServiceID]
			s.Leases[g.ServiceID] = Lease{Grant: g, StartUp: u.Up, StartDown: u.Down, DeadlineBootMillis: deadline}
		}
	}
	return nil
}
func (m *Manager) syncCredits(s *State) error {
	if k, ok := m.Kernel.(interface{ SyncCredits(State) error }); ok {
		return k.SyncCredits(*s)
	}
	for _, r := range s.Rules {
		if r.LeaseRequired && !r.Deleted {
			return fmt.Errorf("kernel credit capability unavailable")
		}
	}
	return nil
}
func (m *Manager) leaseUsageLocked() []LeaseUsage {
	out := []LeaseUsage{}
	for _, id := range keys(m.state.Rules) {
		if l, ok := m.state.Leases[id]; ok {
			out = append(out, LeaseUsage{l.Grant.ID, id, l.Grant.Generation, used(&m.state, id, l), l.Closed})
		}
	}
	return out
}
func (m *Manager) InstallGrants(grants []LeaseGrant) error {
	if len(grants) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.capture(&m.state); e != nil {
		return e
	}
	after := cloneState(m.state)
	if e := applyGrants(&after, grants); e != nil {
		return e
	}
	if digest(after.Leases) == digest(m.state.Leases) {
		return nil
	}
	if renew, ok := m.Kernel.(interface {
		CanRenewCredits(State, State) (bool, error)
		RenewCredits(State, State) error
	}); ok {
		eligible, e := renew.CanRenewCredits(m.state, after)
		if e != nil {
			return e
		}
		if eligible {
			return m.commitRenewal(after, renew)
		}
	}
	return m.commit(after, nil, "credit grant", nil)
}
func (m *Manager) closeExpiredLocked() error {
	now := bootMillis()
	expired := []string{}
	for id, l := range m.state.Leases {
		if !l.Closed && now >= l.DeadlineBootMillis {
			expired = append(expired, id)
		}
	}
	if len(expired) == 0 {
		return nil
	}
	after := cloneState(m.state)
	for _, id := range expired {
		l := after.Leases[id]
		l.Closed = true
		after.Leases[id] = l
	}
	return m.commit(after, nil, "credit expiry", nil)
}

func (m *Manager) CreditReady(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.state.Rules[id]
	if !ok || !s.Active() {
		return false
	}
	if !s.LeaseRequired {
		return true
	}
	l, ok := m.state.Leases[id]
	return ok && !l.Closed && l.DeadlineBootMillis-bootMillis() >= 1000 && l.Grant.TotalGranted-used(&m.state, id, l) >= 128
}

func (m *Manager) commitRenewal(after State, k interface{ RenewCredits(State, State) error }) error {
	if m.blocked {
		return fmt.Errorf("recovery required")
	}
	before := cloneState(m.state)
	after.CommitID = identity()
	after.LastDurableAt = time.Now().UnixMilli()
	t := transaction{Version: 1, Before: before, After: after, Reason: "credit TTL renewal"}
	if e := m.journal(t); e != nil {
		return e
	}
	m.fault("renewal-prepared")
	m.state = after
	if e := m.save(); e != nil {
		m.state = before
		return e
	}
	m.fault("renewal-checkpoint")
	if e := k.RenewCredits(before, after); e != nil {
		_ = m.quiesce()
		m.blocked = true
		return e
	}
	m.fault("renewal-kernel")
	if e := removeDurable(m.Path + ".journal"); e != nil {
		return e
	}
	return nil
}
