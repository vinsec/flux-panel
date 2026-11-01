package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	rulesJSON      json.RawMessage
	rulesJSONCount int
	recovering     bool
	jobsMu         sync.Mutex
	jobsOnce       sync.Once
	jobs           map[string]Job
	queue          chan Batch
	mu             sync.Mutex
	Path           string
	Kernel         Kernel
	state          State
	active         map[string]bool
	blocked        bool
	lastCounters   []counterRecord
	Resolver       *Resolver
	lastAddresses  string
	runtimeCursor  string
	// Fault is injected by tests only. It is never supplied in remote commands.
	Fault func(string)
}

func New(path string, k Kernel) (manager *Manager, err error) {
	if _, ok := k.(*NativeKernel); ok {
		if e := ValidateCheckpointBackend(path); e != nil {
			return nil, e
		}
	}
	defer func() {
		if err != nil {
			if q, ok := k.(interface{ Quiesce() error }); ok {
				_ = q.Quiesce()
			}
		}
	}()
	m := &Manager{Path: path, Kernel: k, active: map[string]bool{}, recovering: true}
	data, e := os.ReadFile(path)
	fresh := os.IsNotExist(e)
	if e == nil {
		if e = json.Unmarshal(data, &m.state); e != nil {
			return nil, e
		}
	} else if !fresh {
		return nil, e
	}
	if m.state.FormatVersion > 7 {
		return nil, fmt.Errorf("unsupported state format")
	}
	if _, ok := k.(*NativeKernel); ok {
		if !fresh && m.state.KernelBackend != "nftables" {
			return nil, fmt.Errorf("iptables state is retired; settle it using the previous release before explicit migration")
		}
		m.state.KernelBackend = "nftables"
	}
	if !fresh && (len(m.state.Epoch) != 32 || m.state.Sequence < 0) {
		return nil, fmt.Errorf("invalid persistent accounting identity")
	}
	if e = m.recover(); e != nil {
		return nil, e
	}
	if m.state.Epoch != "" {
		fresh = false
	}
	if fresh {
		c, e := k.Snapshot()
		if e != nil {
			return nil, e
		}
		if len(c) > 0 {
			_ = m.quiesce()
			return nil, fmt.Errorf("persistent state missing while owned kernel counters exist; restore the state file before starting")
		}
		if r, ok := k.(interface{ Configured() (bool, error) }); ok {
			present, e := r.Configured()
			if e != nil {
				return nil, e
			}
			if present {
				_ = m.quiesce()
				return nil, fmt.Errorf("persistent state missing while owned NAT rules exist; refusing to reset the accounting epoch")
			}
		}
	}
	m.defaults()
	m.state.LastAckAt = 0
	m.state.LastConnectedAt = 0
	if e = m.validateState(); e != nil {
		return nil, e
	}
	if e = m.quiesce(); e != nil {
		return nil, e
	}
	boot := "unknown"
	if reader, ok := k.(interface{ BootID() string }); ok {
		boot = reader.BootID()
	}
	modern := false
	lost := false
	if ledger, ok := k.(interface{ ClaimLedger(string) (string, error) }); ok {
		modern = true
		id, e := ledger.ClaimLedger(m.state.Epoch)
		if e != nil {
			return nil, e
		}
		lost = m.state.KernelID != "" && m.state.KernelID != id
		m.state.KernelID = id
		counters, e := k.Snapshot()
		if e != nil {
			return nil, e
		}
		regressed := false
		for name, last := range m.state.Last {
			if counters[name] < last {
				regressed = true
				m.state.Last[name] = counters[name]
			}
		}
		if regressed && !lost {
			if rotate, ok := k.(interface{ RotateLedger(string) (string, error) }); ok {
				id, e = rotate.RotateLedger(m.state.Epoch)
				if e != nil {
					return nil, e
				}
				m.state.KernelID = id
			}
			lost = true
		}
		boot += "-" + m.state.KernelID
	}
	if m.state.BootID != "" && m.state.BootID != boot {
		lost = true
	}
	if lost {
		m.state.CounterLast = map[string]uint64{}
		m.state.Recovery = RecoveryInfo{true, m.state.LastDurableAt, "host or kernel ledger changed; uncheckpointed traffic is unavailable and old credit remains reserved"}
		m.state.Leases = map[string]Lease{}
		m.state.RequestTimes = map[int64]int64{}
	}
	m.state.BootID = boot
	if m.hasLoss() {
		m.state.AccountingBlocked = true
		m.state.Leases = map[string]Lease{}
		m.state.RequestTimes = map[int64]int64{}
		m.state.Recovery.PossibleLoss = true
	}
	if e = m.capture(&m.state); e != nil {
		return nil, e
	}
	_ = modern
	if e = k.Apply(Render(m.state.Rules, nil)); e != nil {
		return nil, e
	}
	if e = m.syncCredits(&m.state); e != nil {
		return nil, e
	}
	m.refreshActive()
	if e = m.save(); e != nil {
		return nil, e
	}
	m.recovering = false
	if m.state.MaintenancePending || m.state.AccountingBlocked {
		m.blocked = true
	} else if e = m.activate(); e != nil {
		return nil, e
	}
	return m, nil
}
func (m *Manager) defaults() {
	m.invalidateRuleEncoding()
	s := &m.state
	if s.CounterLast == nil {
		s.CounterLast = map[string]uint64{}
	}
	if s.Quarantine == nil {
		s.Quarantine = map[uint32]int64{}
	}
	if s.LeaseAcks == nil {
		s.LeaseAcks = map[string]uint64{}
	}
	if s.AckCounters == nil {
		s.AckCounters = map[string]uint64{}
	}
	if s.CounterRetiredAt == nil {
		s.CounterRetiredAt = map[string]int64{}
	}
	if s.ClosedLeaseAcks == nil {
		s.ClosedLeaseAcks = map[string]bool{}
	}
	if s.Epoch == "" {
		s.Epoch = identity()
	}
	if s.Rules == nil {
		s.Rules = map[string]Spec{}
	}
	if s.Totals == nil {
		s.Totals = map[string]Usage{}
	}
	if s.Last == nil {
		s.Last = map[string]uint64{}
	}
	if s.Ack == nil {
		s.Ack = map[string]Usage{}
	}
	if s.Floors == nil {
		s.Floors = map[string]int64{}
	}
	if s.RetiredAt == nil {
		s.RetiredAt = map[string]int64{}
	}
	if s.Leases == nil {
		s.Leases = map[string]Lease{}
	}
	if s.RequestTimes == nil {
		s.RequestTimes = map[int64]int64{}
	}
	if s.NextToken == 0 {
		s.NextToken = 1
	}
	s.FormatVersion = requiredStateFormat(s.Rules)
	if s.KernelBackend == "nftables" {
		s.FormatVersion = max(s.FormatVersion, 6)
	}
}
func (m *Manager) validateState() error {
	m.invalidateRuleEncoding()
	if m.state.NextToken > 65536 {
		return fmt.Errorf("invalid token cursor")
	}
	used := map[uint32]bool{}
	for _, id := range keys(m.state.Rules) {
		s, e := m.state.Rules[id].Normalize()
		if e != nil {
			return e
		}
		if s.Token > 65535 || s.Token != 0 && used[s.Token] {
			return fmt.Errorf("invalid or duplicate persistent token")
		}
		if s.Token != 0 {
			used[s.Token] = true
			if s.Token >= m.state.NextToken {
				m.state.NextToken = s.Token + 1
			}
		}
		m.state.Rules[id] = s
	}
	for _, id := range keys(m.state.Rules) {
		s := m.state.Rules[id]
		if s.Token == 0 {
			if m.state.NextToken > 65535 {
				return fmt.Errorf("connection token capacity exhausted")
			}
			s.Token = m.state.NextToken
			m.state.NextToken++
			m.state.Rules[id] = s
			used[s.Token] = true
		}
	}
	free := map[uint32]bool{}
	for _, t := range m.state.FreeTokens {
		if t == 0 || t > 65535 || used[t] || free[t] {
			return fmt.Errorf("invalid free token ledger")
		}
		free[t] = true
	}
	for token := uint32(1); token < m.state.NextToken; token++ {
		if !used[token] && !free[token] {
			if _, ok := m.state.Quarantine[token]; !ok {
				m.state.Quarantine[token] = time.Now().UnixMilli()
			}
		}
	}
	return nil
}
func (m *Manager) save() error {
	m.state.LastDurableAt = time.Now().UnixMilli()
	data, e := m.checkpointData()
	if e != nil {
		return e
	}
	return atomicBytes(m.Path, data)
}
func (m *Manager) capture(s *State) error {
	var c map[string]uint64
	var e error
	if k, ok := m.Kernel.(interface {
		SnapshotDetailed() (map[string]uint64, []counterRecord, error)
	}); ok {
		c, m.lastCounters, e = k.SnapshotDetailed()
	} else {
		c, e = m.Kernel.Snapshot()
	}
	if e != nil {
		if s.KernelID != "" && !m.recovering {
			m.sealLoss(s, "kernel counter collection failed; accounting cannot safely continue")
		}
		return e
	}
	if _, ok := m.Kernel.(interface {
		SnapshotDetailed() (map[string]uint64, []counterRecord, error)
	}); ok {
		observed := map[string]uint64{}
		for _, r := range m.lastCounters {
			if strings.HasPrefix(r.Set, "FP4_") || strings.HasPrefix(r.Set, "FP6_") {
				observed[r.Set+"|"+r.Key] = r.Bytes
			}
		}
		for key, last := range s.CounterLast {
			value, exists := observed[key]
			if !exists || value < last {
				m.sealLoss(s, "an owned per-target counter disappeared or regressed")
				return fmt.Errorf("per-target accounting continuity lost")
			}
		}
		s.CounterLast = observed
	}
	if e = m.counterContinuity(s, c); e != nil {
		return e
	}
	for name := range s.Last {
		if _, ok := c[name]; !ok {
			s.Last[name] = 0
		}
	}
	for name, value := range c {
		p := strings.Split(name, ":")
		if len(p) != 5 || p[0] != "flux" || p[4] != "up" && p[4] != "down" {
			continue
		}
		id := p[2]
		u := s.Totals[id]
		u.ID = id
		last := s.Last[name]
		delta := value
		if value >= last {
			delta = value - last
		}
		if p[4] == "up" {
			u.Up += delta
		} else {
			u.Down += delta
		}
		s.Totals[id] = u
		s.Last[name] = value
	}
	return nil
}
func (m *Manager) sample() error {
	if e := m.capture(&m.state); e != nil {
		return e
	}
	return m.save()
}
func (m *Manager) quiesce() error {
	if k, ok := m.Kernel.(interface{ Quiesce() error }); ok {
		return k.Quiesce()
	}
	return nil
}
func (m *Manager) activate() error {
	if k, ok := m.Kernel.(interface{ Activate() error }); ok {
		return k.Activate()
	}
	return nil
}
func (m *Manager) fault(stage string) {
	if m.Fault != nil {
		m.Fault(stage)
	}
}
func (m *Manager) refreshActive() {
	for id, s := range m.state.Rules {
		m.active[id] = s.Active()
	}
}

func (m *Manager) commit(after State, forget []Spec, reason string, gc []counterRecord) error {
	if m.blocked {
		return fmt.Errorf("recovery required; forwarding remains blocked")
	}
	before := cloneState(m.state)
	// Reserve IDs durably even if a partially installed transaction rolls back.
	if after.NextToken > before.NextToken {
		before.NextToken = after.NextToken
	}
	remaining := map[uint32]bool{}
	for _, t := range after.FreeTokens {
		remaining[t] = true
	}
	free := []uint32{}
	for _, t := range before.FreeTokens {
		if remaining[t] {
			free = append(free, t)
		}
	}
	before.FreeTokens = free
	for id, s := range after.Rules {
		if _, exists := before.Rules[id]; !exists {
			before.Quarantine[s.Token] = time.Now().UnixMilli()
		}
	}
	after.CommitID = identity()
	after.LastDurableAt = time.Now().UnixMilli()
	t := transaction{Version: 1, Before: before, After: after, Forget: forget, Reason: reason, GC: gc}
	if e := m.journal(t); e != nil {
		return e
	}
	m.fault("prepared")
	rollback := func(cause error) error {
		m.invalidateRuleEncoding()
		m.state = before
		e := m.Kernel.Apply(Render(before.Rules, nil))
		if e == nil {
			if k, ok := m.Kernel.(interface{ RestoreCounters([]counterRecord) error }); ok {
				e = k.RestoreCounters(gc)
			}
		}
		if e == nil {
			e = m.capture(&m.state)
		}
		if e == nil {
			e = m.syncCredits(&m.state)
		}
		if e == nil {
			e = m.save()
		}
		if e == nil {
			e = removeDurable(m.Path + ".journal")
		}
		if e == nil {
			e = m.activate()
		}
		if e != nil {
			_ = m.quiesce()
			m.blocked = true
			return fmt.Errorf("%v; rollback failed: %w; guard retained", cause, e)
		}
		m.refreshActive()
		return cause
	}
	tokens := map[uint32]bool{}
	for id, s := range after.Rules {
		old, exists := before.Rules[id]
		if !exists || !reflect.DeepEqual(old, s) || m.active[id] != s.Active() {
			tokens[s.Token] = true
		}
	}
	for id, l := range after.Leases {
		if !reflect.DeepEqual(l, before.Leases[id]) {
			tokens[after.Rules[id].Token] = true
		}
	}
	for _, r := range gc {
		p := strings.Split(r.Key, ",")
		if len(p) == 2 {
			v, _ := strconv.ParseUint(p[1], 0, 32)
			tokens[(uint32(v)>>8)&0xffff] = true
		}
	}
	selected := []uint32{}
	for token := range tokens {
		if token != 0 {
			selected = append(selected, token)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i] < selected[j] })
	var barrier error
	if reason == "counter and token GC" {
		// ACKed unreferenced retired entries have no packet path. The live
		// baselines are adjusted by deletion deltas, so no data fence is needed.
	} else if reason == "runtime refresh" {
		if k, ok := m.Kernel.(interface{ QuiesceNewTokens([]uint32) error }); ok {
			barrier = k.QuiesceNewTokens(selected)
		} else {
			barrier = m.quiesce()
		}
	} else if k, ok := m.Kernel.(interface{ QuiesceTokens([]uint32) error }); ok {
		barrier = k.QuiesceTokens(selected)
	} else {
		barrier = m.quiesce()
	}
	if barrier != nil {
		m.blocked = true
		return barrier
	}

	m.fault("quiesced")
	if reason != "counter and token GC" {
		if e := m.Kernel.Apply(Render(after.Rules, nil)); e != nil {
			return rollback(e)
		}
	}
	m.fault("kernel")
	if e := m.capture(&after); e != nil {
		return rollback(e)
	}
	if reason != "counter and token GC" {
		if e := m.syncCredits(&after); e != nil {
			return rollback(e)
		}
	}
	m.fault("credits")
	if e := m.forget(forget); e != nil {
		return rollback(e)
	}
	m.fault("conntrack")
	if e := m.capture(&after); e != nil {
		return rollback(e)
	}
	if len(gc) > 0 {
		k, ok := m.Kernel.(interface{ RemoveCounters([]counterRecord) error })
		if !ok {
			return rollback(fmt.Errorf("counter GC unavailable"))
		}
		if e := k.RemoveCounters(gc); e != nil {
			return rollback(e)
		}
		// Only the retired tokens are fenced. Other forwards may keep
		// incrementing while GC runs; do not replace their live baseline.
		for _, r := range gc {
			delete(after.CounterLast, r.Set+"|"+r.Key)
			parts := strings.Split(r.Comment, ":")
			if len(parts) != 4 {
				return rollback(fmt.Errorf("invalid GC counter identity"))
			}
			name := counterBaseline(r.Set, parts[2], parts[3])
			if after.Last[name] < r.Bytes {
				return rollback(fmt.Errorf("GC exceeds the sampled baseline"))
			}
			after.Last[name] -= r.Bytes
		}
		for id := range after.Floors {
			if _, ok := after.Rules[id]; !ok {
				delete(after.Totals, id)
			}
		}
	}
	m.fault("counters")
	m.invalidateRuleEncoding()
	m.state = after
	if e := m.save(); e != nil {
		return rollback(e)
	}
	m.fault("checkpoint")
	if e := removeDurable(m.Path + ".journal"); e != nil {
		m.blocked = true
		return e
	}
	m.fault("committed")
	m.refreshActive()
	if e := m.activate(); e != nil {
		m.blocked = true
		return e
	}
	m.fault("activated")
	return nil
}

type Batch struct {
	ID             string       `json:"id"`
	BaseGeneration *uint64      `json:"baseGeneration,omitempty"`
	Specs          []Spec       `json:"specs"`
	Credits        []LeaseGrant `json:"credits,omitempty"`
}
type Receipt struct {
	ID, Hash   string
	Generation uint64
}

func (m *Manager) Apply(s Spec) error { return m.ApplyBatch(Batch{ID: identity(), Specs: []Spec{s}}) }
func (m *Manager) ApplyBatch(b Batch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(b.ID) < 1 || len(b.ID) > 100 || len(b.Specs) > 10000 || len(b.Credits) > 10000 {
		return fmt.Errorf("invalid batch ID or size")
	}
	hash := digest(b)
	for _, r := range m.state.Receipts {
		if r.ID == b.ID {
			if r.Hash != hash {
				return fmt.Errorf("batch ID payload conflict")
			}
			return nil
		}
	}
	if b.BaseGeneration != nil && *b.BaseGeneration != m.state.Generation {
		return fmt.Errorf("stale base generation")
	}
	after := cloneState(m.state)
	changed := false
	seen := map[string]bool{}
	forget := []Spec{}
	for _, incoming := range b.Specs {
		// Runtime IPs and health are node-owned. Internal Change preserves them;
		// a new desired request receives a fresh node-side resolution schedule.
		s, e := incoming.Normalize()
		if after.StrictCredit && !strings.HasSuffix(s.ID, "_0") {
			s.LeaseRequired = true
		}
		if e != nil {
			return e
		}
		if seen[s.ID] {
			return fmt.Errorf("duplicate service in batch")
		}
		seen[s.ID] = true
		old, exists := after.Rules[s.ID]
		if s.Advanced() {
			if exists && resolutionIntentDigest(old) == resolutionIntentDigest(s) {
				s.Runtime = old.Runtime
			} else {
				s.Runtime = ResolutionState{Status: "pending", NextResolveAt: time.Now().UnixMilli()}
				if allNumericTargets(s) {
					resolver := m.Resolver
					if resolver == nil {
						resolver = &Resolver{}
					}
					s, e = resolver.Resolve(context.Background(), s)
					if e != nil {
						return e
					}
				}
			}
		}
		s.Token = old.Token
		if !exists && s.Revision <= after.Floors[s.ID] {
			return fmt.Errorf("retired revision")
		}
		if exists && s.Revision < old.Revision {
			return fmt.Errorf("stale revision")
		}
		if exists && s.Revision == old.Revision {
			if reflect.DeepEqual(old, s) {
				continue
			}
			return fmt.Errorf("revision conflict")
		}
		if v, ok := m.Kernel.(interface{ ValidateSpec(Spec) error }); ok {
			if e = v.ValidateSpec(s); e != nil {
				return e
			}
		}
		if !exists {
			if len(after.FreeTokens) > 0 {
				s.Token = after.FreeTokens[0]
				after.FreeTokens = after.FreeTokens[1:]
			} else {
				if after.NextToken > 65535 {
					return fmt.Errorf("connection token capacity exhausted")
				}
				s.Token = after.NextToken
				after.NextToken++
			}
		}
		if exists && !old.Deleted && (s.Deleted || desiredNetworkDigest(s) != desiredNetworkDigest(old)) {
			forget = append(forget, old)
			if l, ok := after.Leases[s.ID]; ok {
				l.Closed = true
				after.Leases[s.ID] = l
			}
			for _, key := range old.TargetKeys() {
				after.CounterRetiredAt[key] = time.Now().UnixMilli()
			}
		}
		if !s.Enabled {
			if l, ok := after.Leases[s.ID]; ok {
				l.Closed = true
				after.Leases[s.ID] = l
			}
		}
		after.Rules[s.ID] = s
		after.FormatVersion = max(after.FormatVersion, requiredStateFormat(map[string]Spec{s.ID: s}))
		changed = true
		if s.Deleted {
			after.RetiredAt[s.ID] = time.Now().UnixMilli()
		}
	}
	configured := 0
	resolvedPaths := 0
	for _, s := range after.Rules {
		if !s.Deleted {
			configured++
			if s.Advanced() {
				resolvedPaths += len(s.Paths())
			}
		}
	}
	if configured > 10000 {
		return fmt.Errorf("validated capacity is 10000 configured forwards")
	}
	if resolvedPaths > 32768 {
		return fmt.Errorf("resolved path capacity exceeds 32768")
	}
	if e := validateListeners(after.Rules); e != nil {
		return e
	}
	if !changed && len(b.Credits) == 0 {
		return nil
	}
	if e := m.capture(&m.state); e != nil {
		return e
	}
	after.Totals = m.state.Totals
	after.Last = m.state.Last
	if e := applyGrants(&after, b.Credits); e != nil {
		return e
	}
	after.Generation++
	after.Receipts = append(after.Receipts, Receipt{b.ID, hash, after.Generation})
	if len(after.Receipts) > 128 {
		after.Receipts = after.Receipts[len(after.Receipts)-128:]
	}
	return m.commit(after, forget, "configuration", nil)
}
func validateListeners(rules map[string]Spec) error {
	type endpoints struct {
		wild string
		ips  map[string]string
	}
	ports := map[string]*endpoints{}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Deleted {
			continue
		}
		for _, l := range s.ListenerList() {
			key := fmt.Sprintf("%s/%s/%d", l.Family, l.Protocol, l.Port)
			p := ports[key]
			if p == nil {
				p = &endpoints{ips: map[string]string{}}
				ports[key] = p
			}
			wildcard := l.Host == "0.0.0.0" || l.Host == "::"
			if p.wild != "" || wildcard && len(p.ips) > 0 || p.ips[l.Host] != "" {
				return fmt.Errorf("listener conflicts with existing %s", key)
			}
			if wildcard {
				p.wild = id
			} else {
				p.ips[l.Host] = id
			}
		}
	}
	return nil
}

func (m *Manager) Change(id string, rev int64, enabled, deleted bool) error {
	m.mu.Lock()
	s, ok := m.state.Rules[id]
	m.mu.Unlock()
	if !ok {
		if deleted {
			return m.Apply(Spec{ID: id, Revision: rev, Deleted: true})
		}
		return fmt.Errorf("forward not found")
	}
	if s.Deleted && !deleted {
		return fmt.Errorf("forward not found")
	}
	s.Revision = rev
	s.Enabled = enabled
	s.Deleted = deleted
	return m.Apply(s)
}
func (m *Manager) Report() (Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blocked && !m.state.MaintenancePending && !m.state.AccountingBlocked {
		return Report{}, fmt.Errorf("recovery required")
	}
	if !m.state.AccountingBlocked {
		if e := m.capture(&m.state); e != nil {
			return Report{}, e
		}
	}
	if !m.state.MaintenancePending && !m.state.AccountingBlocked {
		if e := m.enforceLocked(); e != nil {
			return Report{}, e
		}
	}
	m.state.Sequence++
	m.state.RequestTimes[m.state.Sequence] = bootMillis()
	for seq := range m.state.RequestTimes {
		if seq < m.state.Sequence-16 {
			delete(m.state.RequestTimes, seq)
		}
	}
	r := Report{BootID: m.state.BootID, Epoch: m.state.Epoch, Sequence: m.state.Sequence, Usage: []Usage{}, Generation: m.state.Generation, CheckpointAt: m.state.LastDurableAt, Recovery: m.state.Recovery}
	forced := map[string]bool{}
	for _, c := range m.lastCounters {
		if m.state.CounterRetiredAt[c.Key] > 0 && !m.state.AccountingBlocked {
			key := watermarkKey(counterID(c), c.Set, c.Key)
			ack, seen := m.state.AckCounters[key]
			if !seen || ack < c.Bytes {
				r.Counters = append(r.Counters, CounterWatermark{counterID(c), c.Set, c.Key, c.Bytes})
				forced[counterID(c)] = true
			}
		}
	}
	for _, id := range keys(m.state.Rules) {
		if u, ok := m.state.Totals[id]; ok {
			ack, seen := m.state.Ack[id]
			if !seen || u.Up != ack.Up || u.Down != ack.Down || forced[id] {
				r.Usage = append(r.Usage, u)
			}
		}
	}
	if m.state.MaintenancePending && m.state.MaintenanceBootID != "" {
		r.BootID = m.state.MaintenanceBootID
	}
	usageIDs := map[string]bool{}
	for _, u := range r.Usage {
		usageIDs[u.ID] = true
	}
	for _, l := range m.leaseUsageLocked() {
		ack, seen := m.state.LeaseAcks[l.ID]
		if !seen || ack != l.Used || usageIDs[l.ServiceID] || l.Closed && !m.state.ClosedLeaseAcks[l.ID] {
			r.Leases = append(r.Leases, l)
		}
	}
	for _, id := range keys(m.state.Rules) {
		s := m.state.Rules[id]
		if s.Active() && s.LeaseRequired && !m.state.AccountingBlocked && !m.state.MaintenancePending {
			r.CreditMode = true
			if s.Advanced() && len(s.Paths()) == 0 {
				continue
			}
			l, ok := m.state.Leases[id]
			window := l.Grant.WindowBytes
			if window == 0 || window > l.Grant.TotalGranted {
				window = l.Grant.TotalGranted
			}
			if !ok || l.Closed || l.Grant.TotalGranted-used(&m.state, id, l) < window*3/4 || l.DeadlineBootMillis-bootMillis() < 15000 {
				r.Requests = append(r.Requests, id)
				if ok {
					found := false
					for _, c := range r.Leases {
						if c.ID == l.Grant.ID {
							found = true
						}
					}
					if !found {
						r.Leases = append(r.Leases, LeaseUsage{l.Grant.ID, id, l.Grant.Generation, used(&m.state, id, l), l.Closed})
					}
				}
			}
		}
	}
	selected := map[string]bool{}
	if len(r.Usage) > 10000 {
		all := r.Usage
		start := sort.Search(len(all), func(i int) bool { return all[i].ID > m.state.ReportCursor })
		if start == len(all) {
			start = 0
		}
		page := make([]Usage, 0, 10000)
		for i := 0; i < 10000; i++ {
			page = append(page, all[(start+i)%len(all)])
		}
		r.Usage = page
	}
	for _, u := range r.Usage {
		selected[u.ID] = true
	}
	if len(r.Usage) > 0 {
		m.state.ReportCursor = r.Usage[len(r.Usage)-1].ID
	}
	counters := []CounterWatermark{}
	for _, c := range r.Counters {
		if selected[c.ID] && len(counters) < 20000 {
			counters = append(counters, c)
		}
	}
	r.Counters = counters
	claims := []LeaseUsage{}
	claimIDs := map[string]bool{}
	for _, l := range r.Leases {
		ack, seen := m.state.LeaseAcks[l.ID]
		if selected[l.ServiceID] || seen && ack == l.Used {
			claims = append(claims, l)
			claimIDs[l.ServiceID] = true
		}
	}
	r.Leases = claims
	requests := []string{}
	for _, id := range r.Requests {
		u := m.state.Totals[id]
		_, leased := m.state.Leases[id]
		if selected[id] || claimIDs[id] || !leased && u.Up == 0 && u.Down == 0 {
			requests = append(requests, id)
		}
	}
	r.Requests = requests
	if e := m.save(); e != nil {
		return Report{}, e
	}
	r.CheckpointAt = m.state.LastDurableAt
	return r, nil
}
func (m *Manager) EnforceExpiration() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enforceLocked()
}
func (m *Manager) enforceLocked() error {
	if m.blocked {
		return fmt.Errorf("recovery required")
	}
	needControl := false
	for _, l := range m.state.Leases {
		if !l.Closed {
			needControl = true
			break
		}
	}
	if k, ok := m.Kernel.(interface{ UpdateControl(State) error }); ok && needControl {
		if e := k.UpdateControl(m.state); e != nil {
			return e
		}
	}
	if e := m.closeExpiredLocked(); e != nil {
		return e
	}
	// DNS admission expires independently of worker capacity or DNS refresh
	// success. Existing confirmed connections retain their draining path.
	if _, changed := expireRuntime(m.state, time.Now().UnixMilli()); changed {
		if e := m.capture(&m.state); e != nil {
			return e
		}
		after, _ := expireRuntime(m.state, time.Now().UnixMilli())
		after.Generation++
		return m.commit(after, nil, "runtime refresh", nil)
	}
	changed := false
	for id, s := range m.state.Rules {
		if m.active[id] != s.Active() {
			changed = true
		}
	}
	if changed {
		if e := m.capture(&m.state); e != nil {
			return e
		}
		after := cloneState(m.state)
		after.Generation++
		return m.commit(after, nil, "expiration", nil)
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

type Page struct {
	Generation uint64 `json:"generation"`
	Epoch      string `json:"epoch"`
	Items      []Spec `json:"items"`
	Next       string `json:"next,omitempty"`
}

func (m *Manager) Page(after string, limit int, generation *uint64) (Page, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := Page{Generation: m.state.Generation, Epoch: m.state.Epoch, Items: []Spec{}}
	if limit < 1 || limit > 500 {
		return p, fmt.Errorf("page limit must be 1..500")
	}
	if generation != nil && *generation != p.Generation {
		return p, fmt.Errorf("snapshot generation changed")
	}
	ids := keys(m.state.Rules)
	i := sort.SearchStrings(ids, after)
	for ; i < len(ids); i++ {
		id := ids[i]
		if id <= after {
			continue
		}
		if len(p.Items) == limit {
			p.Next = p.Items[len(p.Items)-1].ID
			break
		}
		p.Items = append(p.Items, cloneSpec(m.state.Rules[id]))
	}
	return p, nil
}
func (m *Manager) Info() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	paths, configured := 0, 0
	for _, s := range m.state.Rules {
		if s.Deleted {
			continue
		}
		configured++
		if s.Advanced() {
			paths += len(s.Paths())
		}
	}
	sets := map[string]int{}
	for _, r := range m.lastCounters {
		sets[r.Set]++
	}
	capacity := map[string]any{"configuredForwards": configured, "retainedForwards": len(m.state.Rules), "forwardLimit": 10000, "resolvedPaths": paths, "resolvedPathLimit": 32768, "counterEntriesBySet": sets, "freeTokens": len(m.state.FreeTokens), "quarantinedTokens": len(m.state.Quarantine), "retiredCounters": len(m.state.CounterRetiredAt)}
	caps := CurrentCapabilities()
	caps.Features["nativeNFTMap"] = m.state.KernelBackend == "nftables"
	return map[string]any{"kernelBackend": m.state.KernelBackend, "capacity": capacity, "lastAckAt": m.state.LastAckAt, "lastConnectedAt": m.state.LastConnectedAt, "strictCreditPolicy": m.state.StrictCredit, "bootId": m.state.BootID, "capabilities": caps, "epoch": m.state.Epoch, "generation": m.state.Generation, "blocked": m.blocked, "maintenancePending": m.state.MaintenancePending, "accountingBlocked": m.state.AccountingBlocked, "lastDurableAt": m.state.LastDurableAt, "recovery": m.state.Recovery}
}

func (m *Manager) Connected(value bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if value {
		m.state.LastConnectedAt = time.Now().UnixMilli()
	} else {
		m.state.LastConnectedAt = 0
	}
}
func (m *Manager) TransportAcknowledged() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.LastAckAt = time.Now().UnixMilli()
}

func (m *Manager) RequireCreditPolicy() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.StrictCredit {
		return nil
	}
	if e := m.capture(&m.state); e != nil {
		return e
	}
	after := cloneState(m.state)
	after.StrictCredit = true
	for id, s := range after.Rules {
		if !s.Deleted && !strings.HasSuffix(id, "_0") {
			s.LeaseRequired = true
			after.Rules[id] = s
		}
	}
	after.Generation++
	return m.commit(after, nil, "strict credit policy", nil)
}
