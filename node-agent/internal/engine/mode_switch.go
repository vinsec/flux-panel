package engine

import (
	"fmt"
	"time"
)

type ModeRequest struct {
	ID   string `json:"id"`
	Mode string `json:"mode"`
}
type ModeSwitch struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	UpdatedAt int64  `json:"updatedAt"`
}

func validMode(mode string) bool { return mode == "kernel" || mode == "gost" }
func (m *Manager) SubmitModeSwitch(r ModeRequest) (ModeSwitch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.Kernel.(*NativeKernel)
	if !ok || k.Gost == nil {
		return ModeSwitch{}, fmt.Errorf("node does not support managed GOST switching")
	}
	if len(r.ID) < 1 || len(r.ID) > 100 || !validMode(r.Mode) {
		return ModeSwitch{}, fmt.Errorf("invalid mode switch request")
	}
	old := m.state.EngineSwitch
	if old.ID == r.ID {
		if old.To != r.Mode {
			return old, fmt.Errorf("mode switch ID conflict")
		}
		return old, nil
	}
	if old.Status == "queued" || old.Status == "running" || m.blocked || m.state.MaintenancePending || m.state.AccountingBlocked {
		return old, fmt.Errorf("node is busy or requires recovery")
	}
	for _, s := range m.state.Rules {
		if s.Deleted {
			continue
		}
		if r.Mode == "gost" {
			if e := k.Gost.validate(s); e != nil {
				return old, e
			}
		}
	}
	if r.Mode == "gost" {
		if e := k.Gost.preflight(mapSpecs(m.state.Rules)); e != nil {
			return old, e
		}
		if e := k.checkGostShaping(mapSpecs(m.state.Rules)); e != nil {
			return old, e
		}
	}
	job := ModeSwitch{ID: r.ID, From: k.Mode, To: r.Mode, Status: "queued", UpdatedAt: time.Now().UnixMilli()}
	wasManaged, oldFormat := m.state.ManagedEngines, m.state.FormatVersion
	m.state.ManagedEngines = true
	m.state.FormatVersion = max(m.state.FormatVersion, 8)
	m.state.EngineSwitch = job
	if e := m.save(); e != nil {
		m.state.EngineSwitch = old
		m.state.ManagedEngines, m.state.FormatVersion = wasManaged, oldFormat
		return job, e
	}
	go m.runModeSwitch(r.ID)
	return job, nil
}
func (m *Manager) ModeSwitchStatus(id string) (ModeSwitch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.EngineSwitch.ID != id {
		return ModeSwitch{ID: id, Status: "unknown"}, nil
	}
	return m.state.EngineSwitch, nil
}
func (m *Manager) runModeSwitch(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.Kernel.(*NativeKernel)
	job := m.state.EngineSwitch
	if job.ID != id {
		return
	}
	job.Status = "running"
	job.UpdatedAt = time.Now().UnixMilli()
	m.state.EngineSwitch = job
	fail := func(cause error) {
		k.Mode = job.From
		rollback := k.Apply(Render(m.state.Rules, nil))
		if rollback == nil {
			rollback = m.capture(&m.state)
		}
		if rollback == nil {
			rollback = m.syncCredits(&m.state)
		}
		job.Status = "failed"
		job.Error = cause.Error()
		m.state.ForwardingMode = job.From
		if rollback != nil {
			job.Status = "blocked"
			job.Error += "; rollback failed; forwarding remains closed"
			m.blocked = true
		}
		job.UpdatedAt = time.Now().UnixMilli()
		m.state.EngineSwitch = job
		if e := m.save(); e != nil {
			m.blocked = true
			return
		}
		if rollback == nil {
			if e := m.activate(); e != nil {
				m.blocked = true
			}
		}
	}
	if e := m.quiesce(); e != nil {
		fail(e)
		return
	}
	if e := m.capture(&m.state); e != nil {
		m.blocked = true
		job.Status = "blocked"
		job.Error = e.Error()
		m.state.EngineSwitch = job
		_ = m.save()
		return
	}
	if e := m.save(); e != nil {
		m.blocked = true
		return
	}
	m.fault("mode-prepared")
	for _, s := range m.state.Rules {
		for _, key := range m.targetKeys(s) {
			m.state.CounterRetiredAt[key] = time.Now().UnixMilli()
		}
	}
	if e := k.ForgetMany(mapSpecs(m.state.Rules)); e != nil {
		fail(e)
		return
	}
	k.Mode = job.To
	if e := k.Apply(Render(m.state.Rules, nil)); e != nil {
		fail(e)
		return
	}
	for id, problem := range k.P1.runtimeErrors {
		if m.state.Rules[id].Active() && problem != "" {
			fail(fmt.Errorf("target mode cannot activate %s: %s", id, problem))
			return
		}
	}
	m.fault("mode-applied")
	if m.ModeFailure != nil {
		if e := m.ModeFailure(); e != nil {
			fail(e)
			return
		}
	}
	if e := m.capture(&m.state); e != nil {
		fail(e)
		return
	}
	if e := m.syncCredits(&m.state); e != nil {
		fail(e)
		return
	}
	m.state.ForwardingMode = job.To
	job.Status = "succeeded"
	job.UpdatedAt = time.Now().UnixMilli()
	m.state.EngineSwitch = job
	m.state.Generation++
	if e := m.save(); e != nil {
		fail(e)
		return
	}
	m.fault("mode-committed")
	if e := m.activate(); e != nil {
		m.blocked = true
		job.Status = "blocked"
		job.Error = e.Error()
		m.state.EngineSwitch = job
		_ = m.save()
	}
}
func (m *Manager) targetKeys(s Spec) []string {
	if k, ok := m.Kernel.(*NativeKernel); ok && k.Gost != nil && k.Mode == "gost" {
		if p, _, e := k.Gost.project([]Spec{s}); e == nil && len(p) == 1 {
			return p[0].TargetKeys()
		}
	}
	return s.TargetKeys()
}

func (k *NativeKernel) checkGostShaping(plan []Spec) error {
	for _, s := range plan {
		if s.Active() && s.AdvancedOptions != nil && s.Bandwidth.Enabled() {
			if problem := localShapingProblem(); problem != "" {
				return fmt.Errorf("GOST local shaping prerequisites: %s", problem)
			}
			if problem := k.P1.probeLocalShaping(); problem != "" {
				return fmt.Errorf("GOST local shaping unavailable: %s", problem)
			}
			break
		}
	}
	return nil
}
