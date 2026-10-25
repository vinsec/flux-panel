package engine

import (
	"fmt"
	"os"
	"time"
)

func (m *Manager) sealLoss(s *State, reason string) {
	_ = m.quiesce()
	m.blocked = true
	s.AccountingBlocked = true
	if !s.Recovery.PossibleLoss {
		s.Recovery = RecoveryInfo{true, s.LastDurableAt, reason}
	}
	s.Leases = map[string]Lease{}
	s.RequestTimes = map[int64]int64{}
	if k, ok := m.Kernel.(interface {
		RotateLedger(string) (string, error)
		BootID() string
	}); ok {
		if id, e := k.RotateLedger(s.Epoch); e == nil {
			s.KernelID = id
			s.BootID = k.BootID() + "-" + id
		}
	}
	if _, err := os.Stat(m.Path + ".counter-loss"); os.IsNotExist(err) {
		_ = atomicJSON(m.Path+".counter-loss", map[string]any{"epoch": s.Epoch, "lastDurableAt": s.LastDurableAt, "observedAt": time.Now().UnixMilli(), "reason": reason})
	}
}
func (m *Manager) counterContinuity(s *State, c map[string]uint64) error {
	if s.KernelID == "" {
		return nil
	}
	for name, last := range s.Last {
		if c[name] >= last {
			continue
		}
		reason := "owned kernel counters regressed; restore or settle the last durable ledger before resuming"
		m.sealLoss(s, reason)
		if !m.recovering {
			return fmt.Errorf("%s", reason)
		}
		// An ambiguous recovered counter is a baseline, never a fresh increment.
		s.Last[name] = c[name]
	}
	return nil
}
func (m *Manager) hasLoss() bool { _, e := os.Stat(m.Path + ".counter-loss"); return e == nil }
