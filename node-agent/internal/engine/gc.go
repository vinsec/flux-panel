package engine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type CounterWatermark struct {
	ID    string `json:"id"`
	Set   string `json:"set"`
	Key   string `json:"key"`
	Bytes uint64 `json:"bytes"`
}

func counterID(r counterRecord) string {
	p := strings.Split(r.Comment, ":")
	if len(p) == 4 && p[0] == "flux" && p[1] == "v2" {
		return p[2]
	}
	return ""
}
func watermarkKey(id, set, key string) string { return id + "|" + set + "|" + key }

type Acknowledgement struct {
	ServiceID           string             `json:"serviceId,omitempty"`
	MaintenanceAccepted bool               `json:"maintenanceAccepted"`
	LeaseWatermarks     []LeaseUsage       `json:"leaseWatermarks"`
	Epoch               string             `json:"epoch"`
	Sequence            int64              `json:"sequence"`
	Usage               []Usage            `json:"usage"`
	Counters            []CounterWatermark `json:"counters"`
	ClosedLeases        []string           `json:"closedLeases"`
	Grants              []LeaseGrant       `json:"grants"`
}

func (m *Manager) Acknowledge(ack Acknowledgement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ack.Epoch != m.state.Epoch || ack.Sequence < 1 || ack.Sequence > m.state.Sequence {
		return fmt.Errorf("invalid acknowledgement identity")
	}
	if ack.Sequence < m.state.AckSequence {
		return nil
	}
	for _, u := range ack.Usage {
		current, ok := m.state.Totals[u.ID]
		if !ok {
			continue
		}
		if u.Up > current.Up || u.Down > current.Down {
			return fmt.Errorf("acknowledgement exceeds local usage")
		}
		old := m.state.Ack[u.ID]
		if u.Up >= old.Up && u.Down >= old.Down {
			m.state.Ack[u.ID] = u
		}
	}
	for _, c := range ack.Counters {
		if !serviceID.MatchString(c.ID) || !accountingSet(c.Set) {
			return fmt.Errorf("invalid counter acknowledgement")
		}
		key := watermarkKey(c.ID, c.Set, c.Key)
		if old, seen := m.state.AckCounters[key]; !seen || c.Bytes > old {
			m.state.AckCounters[key] = c.Bytes
		}
	}
	for _, id := range ack.ClosedLeases {
		for _, l := range m.state.Leases {
			if l.Grant.ID == id && l.Closed {
				m.state.ClosedLeaseAcks[id] = true
			}
		}
	}
	for _, a := range ack.LeaseWatermarks {
		for id, l := range m.state.Leases {
			if l.Grant.ID == a.ID && a.Used <= used(&m.state, id, l) {
				if a.Used > m.state.LeaseAcks[a.ID] {
					m.state.LeaseAcks[a.ID] = a.Used
				}
				if _, seen := m.state.LeaseAcks[a.ID]; !seen {
					m.state.LeaseAcks[a.ID] = a.Used
				}
			}
		}
	}
	m.state.AckSequence = ack.Sequence
	m.state.LastAckAt = time.Now().UnixMilli()
	// The next checkpoint or GC journal persists this acknowledgement. A crash
	// before that only delays reclamation; the server's watermarks deduplicate it.
	return nil
}
func (m *Manager) Collect(retention time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blocked {
		return 0, fmt.Errorf("recovery required")
	}
	k, ok := m.Kernel.(interface {
		References() (map[string]bool, error)
	})
	if !ok {
		return 0, nil
	}
	if e := m.capture(&m.state); e != nil {
		return 0, e
	}
	refs, e := k.References()
	if e != nil {
		return 0, e
	}
	after := cloneState(m.state)
	now := time.Now().UnixMilli()
	current := map[string]bool{}
	for _, s := range after.Rules {
		if !s.Deleted {
			for _, key := range m.targetKeys(s) {
				current[key] = true
			}
		}
	}
	remove := []counterRecord{}
	kept := map[string]bool{}
	for _, r := range m.lastCounters {
		id := counterID(r)
		if id == "" {
			continue
		}
		retired := after.CounterRetiredAt[r.Key]
		orphan := false
		if _, exists := after.Rules[id]; !exists && r.Bytes == 0 {
			orphan = true
		}
		acked, confirmed := after.AckCounters[watermarkKey(id, r.Set, r.Key)]
		eligible := !current[r.Key] && !refs[r.Key] && (orphan || retired > 0 && now-retired >= retention.Milliseconds() && confirmed && acked >= r.Bytes)
		if eligible {
			remove = append(remove, r)
		} else {
			kept[id] = true
		}
	}
	for id, s := range after.Rules {
		if !s.Deleted || kept[id] || refs[fmt.Sprintf("mark:0x%x", flowMark(s))] || now-after.RetiredAt[id] < retention.Milliseconds() {
			continue
		}
		u := after.Totals[id]
		ack := after.Ack[id]
		if ack.Up < u.Up || ack.Down < u.Down {
			continue
		}
		if l, ok := after.Leases[id]; ok && (!l.Closed || !after.ClosedLeaseAcks[l.Grant.ID]) {
			continue
		}
		after.Floors[id] = s.Revision
		after.FreeTokens = append(after.FreeTokens, s.Token)
		delete(after.Rules, id)
		delete(after.Totals, id)
		delete(after.Ack, id)
		delete(after.RetiredAt, id)
		delete(after.Leases, id)
	}
	usedTokens := map[uint32]bool{}
	for _, s := range after.Rules {
		usedTokens[s.Token] = true
	}
	counterTokens := map[uint32]bool{}
	removedKeys := map[string]bool{}
	for _, r := range remove {
		removedKeys[r.Set+"|"+r.Key] = true
	}
	for _, r := range m.lastCounters {
		if removedKeys[r.Set+"|"+r.Key] {
			continue
		}
		p := strings.Split(r.Key, ",")
		if len(p) == 2 {
			v, _ := strconv.ParseUint(p[1], 0, 32)
			counterTokens[(uint32(v)>>8)&0xffff] = true
		}
	}
	freed := 0
	for token, retired := range after.Quarantine {
		if now-retired >= retention.Milliseconds() && !usedTokens[token] && !counterTokens[token] && !refs[fmt.Sprintf("mark:0x%x", uint32(0xf1000000)|(token<<8))] {
			after.FreeTokens = append(after.FreeTokens, token)
			delete(after.Quarantine, token)
			freed++
		}
	}
	if len(remove) == 0 && len(after.Rules) == len(m.state.Rules) && freed == 0 {
		return 0, nil
	}
	for _, r := range remove {
		delete(after.AckCounters, watermarkKey(counterID(r), r.Set, r.Key))
		delete(after.CounterRetiredAt, r.Key)
	}
	sort.Slice(after.FreeTokens, func(i, j int) bool { return after.FreeTokens[i] < after.FreeTokens[j] })
	after.Generation++
	if e = m.commit(after, nil, "counter and token GC", remove); e != nil {
		return 0, e
	}
	return len(remove), nil
}

func (m *Manager) CompleteMaintenance(ack Acknowledgement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.state.MaintenancePending {
		return nil
	}
	if !ack.MaintenanceAccepted || ack.Epoch != m.state.Epoch || ack.Sequence != m.state.Sequence {
		return fmt.Errorf("maintenance settlement not confirmed")
	}
	m.state.MaintenancePending = false
	m.state.MaintenanceBootID = ""
	m.state.Leases = map[string]Lease{}
	m.state.LeaseAcks = map[string]uint64{}
	if e := m.save(); e != nil {
		return e
	}
	if e := m.activate(); e != nil {
		return e
	}
	m.blocked = false
	return nil
}
