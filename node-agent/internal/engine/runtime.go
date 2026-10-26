package engine

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

func effectiveRuntime(s Spec) string {
	paths := []string{}
	for _, p := range s.Paths() {
		paths = append(paths, fmt.Sprintf("%s/%s/%d/%t/%t", p.Family, p.Key(), p.Weight, p.RetiredAt > 0, p.AcceptNew && p.Healthy))
	}
	slices.Sort(paths)
	return strings.Join(paths, ";")
}
func cloneSpec(s Spec) Spec {
	if s.AdvancedOptions != nil {
		o := *s.AdvancedOptions
		if s.Traffic != nil {
			policy := *s.Traffic
			o.Traffic = &policy
		}
		o.Listeners = slices.Clone(o.Listeners)
		o.Targets = slices.Clone(o.Targets)
		o.Runtime.Targets = slices.Clone(o.Runtime.Targets)
		s.AdvancedOptions = &o
	}
	return s
}

func (m *Manager) ConfigureResolver(servers []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Resolver = &Resolver{Servers: slices.Clone(servers)}
}
func (m *Manager) RefreshRuntime(ctx context.Context) error {
	m.mu.Lock()
	if m.blocked {
		m.mu.Unlock()
		return nil
	}
	resolver := m.Resolver
	if resolver == nil {
		resolver = &Resolver{}
		m.Resolver = resolver
	}
	now := time.Now().UnixMilli()
	ids := keys(m.state.Rules)
	selected := []Spec{}
	start := slices.IndexFunc(ids, func(id string) bool { return id > m.runtimeCursor })
	if start < 0 {
		start = 0
	}
	for offset := 0; offset < len(ids) && len(selected) < 8; offset++ {
		id := ids[(start+offset)%len(ids)]
		s := m.state.Rules[id]
		if !s.Advanced() || s.Deleted {
			continue
		}
		due := s.Runtime.NextResolveAt > 0 && now >= s.Runtime.NextResolveAt || len(s.Runtime.Targets) == 0
		for _, p := range s.Paths() {
			if p.RetiredAt > 0 || s.Health.Protocol != "" && now >= p.NextProbeAt {
				due = true
			}
		}
		if due {
			if k, ok := m.Kernel.(*IPTables); ok && k.P1 != nil {
				s = cloneSpec(s)
				if applied, exists := k.P1.last[id]; exists {
					s.Runtime.EgressGroup = applied.Runtime.EgressGroup
				}
			}
			selected = append(selected, cloneSpec(s))
			m.runtimeCursor = id
		}
	}
	m.mu.Unlock()
	updates := make([]Spec, len(selected))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for i, s := range selected {
		wg.Add(1)
		go func(i int, s Spec) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				updates[i] = s
				return
			}
			work, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			if s.Runtime.NextResolveAt > 0 && now >= s.Runtime.NextResolveAt || len(s.Paths()) == 0 {
				resolved, e := resolver.Resolve(work, s)
				if e == nil {
					s = resolved
				} else {
					s.Runtime.Error = e.Error()
					s.Runtime.NextResolveAt = now + 1000
				}
			}
			s = resolver.Probe(work, s)
			updates[i] = s
		}(i, s)
	}
	wg.Wait()
	refs := map[string]bool{}
	if k, ok := m.Kernel.(interface {
		References() (map[string]bool, error)
	}); ok && len(updates) > 0 {
		var e error
		refs, e = k.References()
		if e != nil {
			return e
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blocked {
		return nil
	}
	pending := map[string]Spec{}
	for i, s := range updates {
		current, exists := m.state.Rules[s.ID]
		if !exists || current.Revision != selected[i].Revision || resolutionIntentDigest(current) != resolutionIntentDigest(selected[i]) {
			continue
		}
		paths := []ResolvedTarget{}
		for _, p := range s.Runtime.Targets {
			key := fmt.Sprintf("%s,0x%x", p.Host, flowMark(s))
			if p.RetiredAt > 0 && now-p.RetiredAt >= 1000 && !refs[key] {
				continue
			}
			paths = append(paths, p)
		}
		s.Runtime.Targets = paths
		if v, ok := m.Kernel.(interface{ ValidateSpec(Spec) error }); ok {
			if e := v.ValidateSpec(s); e != nil {
				s.Runtime.Error = e.Error()
				s.Runtime.Status = "failed"
				for j := range s.Runtime.Targets {
					s.Runtime.Targets[j].AcceptNew = false
				}
			}
		}
		if effectiveRuntime(current) != effectiveRuntime(s) {
			s.Runtime.Generation = current.Runtime.Generation + 1
			pending[s.ID] = s
		} else {
			s.Runtime.Generation = current.Runtime.Generation
			m.state.Rules[s.ID] = s
		}
	}
	if len(pending) == 0 {
		return m.refreshAddressesLocked()
	}
	if e := m.capture(&m.state); e != nil {
		return e
	}
	after := cloneState(m.state)
	for id, s := range pending {
		old := after.Rules[id]
		keys := map[string]bool{}
		for _, p := range s.Paths() {
			if p.RetiredAt == 0 {
				keys[fmt.Sprintf("%s,0x%x", p.Host, flowMark(s))] = true
			}
		}
		for _, key := range old.TargetKeys() {
			if !keys[key] {
				after.CounterRetiredAt[key] = now
			}
		}
		after.Rules[id] = s
	}
	after.Generation++
	paths := 0
	for _, s := range after.Rules {
		if s.Advanced() && !s.Deleted {
			paths += len(s.Paths())
		}
	}
	if paths > 32768 {
		return fmt.Errorf("node resolved path capacity reached")
	}
	if e := m.commit(after, nil, "runtime refresh", nil); e != nil {
		return e
	}
	return m.refreshAddressesLocked()
}

func (m *Manager) RuntimeStatus(id string) map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.state.Rules[id]
	if !ok {
		return map[string]any{"status": "absent"}
	}
	status := "applied"
	healthFailure := false
	if s.Deleted {
		status = "deleted"
	} else if !s.Active() {
		status = "paused"
	} else if s.Advanced() {
		usable := false
		eligible, failed := 0, 0
		for _, p := range s.Paths() {
			if p.RetiredAt == 0 && p.AcceptNew {
				eligible++
				if s.Health.Protocol != "" && p.Failures >= s.Health.Fall {
					failed++
				}
			}
			if p.RetiredAt == 0 && p.AcceptNew && p.Healthy {
				usable = true
			}
		}
		if !usable {
			status = "pending"
		}
		if !usable && eligible > 0 && failed == eligible {
			status = "failed"
			healthFailure = true
		}
		if s.Runtime.Status == "failed" {
			status = "failed"
		}
	}
	result := map[string]any{"id": id, "desiredRevision": s.Revision, "appliedRevision": s.Revision, "generation": m.state.Generation, "status": status, "counterLayer": "network", "intentHash": s.IntentHash}
	if healthFailure {
		result["error"] = "all current targets failed the configured health checks"
	}
	if k, ok := m.Kernel.(interface{ RuntimeFailure(string) string }); ok {
		if failure := k.RuntimeFailure(id); failure != "" {
			result["status"] = "failed"
			result["error"] = failure
		}
	}
	if s.Advanced() {
		result["resolution"] = s.Runtime
	}
	return result
}

func (m *Manager) RuntimeStatuses(ids []string) map[string]map[string]any {
	result := map[string]map[string]any{}
	if len(ids) > 100 {
		return result
	}
	for _, id := range ids {
		if serviceID.MatchString(id) {
			result[id] = m.RuntimeStatus(id)
		}
	}
	return result
}

// expireRuntime is independent of DNS transport and scheduler fairness.
func expireRuntime(state State, now int64) (State, bool) {
	var after State
	changed := false
	for id, current := range state.Rules {
		if !current.Advanced() || current.Deleted {
			continue
		}
		s := current
		closed := false
		for i, p := range current.Runtime.Targets {
			grace := current.DNS.StaleMillis
			if current.DNS.FailClosed {
				grace = 0
			}
			if p.AcceptNew && p.FreshUntil > 0 && now >= p.FreshUntil+grace {
				if !closed {
					s = cloneSpec(current)
				}
				s.Runtime.Targets[i].AcceptNew = false
				closed = true
			}
		}
		if closed {
			if !changed {
				after = cloneState(state)
				changed = true
			}
			s.Runtime.Generation++
			s.Runtime.Status = "failed"
			for _, p := range s.Runtime.Targets {
				if p.RetiredAt == 0 && p.AcceptNew {
					s.Runtime.Status = "partial"
					break
				}
			}
			s.Runtime.Error = "DNS freshness deadline exceeded; new connections closed"
			after.Rules[id] = s
		}
	}
	return after, changed
}
