package engine

import (
	"reflect"
	"strings"
)

func legacyState(s State) State {
	advanced := false
	for _, rule := range s.Rules {
		if rule.Advanced() {
			advanced = true
			break
		}
	}
	if !advanced {
		return s
	}
	r := s
	r.Rules = map[string]Spec{}
	r.Leases = map[string]Lease{}
	for id, rule := range s.Rules {
		if !rule.Advanced() {
			r.Rules[id] = rule
			if lease, ok := s.Leases[id]; ok {
				r.Leases[id] = lease
			}
		}
	}
	return r
}
func (k *IPTables) QuiesceTokens(tokens []uint32) error {
	if k.Native != nil {
		return k.Native.gate(tokens, false, false)
	}
	if e := k.quiesceBaseTokens(tokens); e != nil {
		return e
	}
	if k.P1 != nil {
		return k.P1.gate(tokens, false, false)
	}
	return nil
}
func (k *IPTables) QuiesceNewTokens(tokens []uint32) error {
	if k.Native != nil {
		return k.Native.gate(tokens, true, false)
	}
	if k.P1 == nil {
		return k.QuiesceTokens(tokens)
	}
	return k.P1.gate(tokens, true, false)
}
func (k *IPTables) Activate() error {
	if k.Native != nil {
		return k.Native.gate(nil, false, true)
	}
	if e := k.activateBase(); e != nil {
		return e
	}
	if k.P1 != nil {
		return k.P1.gate(nil, false, true)
	}
	return nil
}
func (k *IPTables) SyncCredits(s State) error {
	if k.Native != nil {
		if e := k.P1.quota.sync(s); e != nil {
			return e
		}
		return k.Native.updateControl(s)
	}
	if e := k.syncBaseCredits(legacyState(s)); e != nil {
		return e
	}
	if k.P1 != nil {
		if e := k.P1.quota.sync(s); e != nil {
			return e
		}
		return k.P1.updateControl(s)
	}
	return nil
}
func (k *IPTables) UpdateControl(s State) error {
	if k.Native != nil {
		return k.Native.updateControl(s)
	}
	if e := k.updateBaseControl(legacyState(s)); e != nil {
		return e
	}
	if k.P1 != nil {
		return k.P1.updateControl(s)
	}
	return nil
}
func (k *IPTables) CanRenewCredits(before, after State) (bool, error) {
	if k.Native != nil {
		return k.P1.quota.canRenew(before, after)
	}
	legacyChanged, advancedChanged := false, false
	for id, l := range after.Leases {
		if reflect.DeepEqual(l, before.Leases[id]) {
			continue
		}
		if after.Rules[id].Advanced() {
			advancedChanged = true
		} else {
			legacyChanged = true
		}
	}
	if legacyChanged {
		ok, e := k.canRenewBaseCredits(legacyState(before), legacyState(after))
		if e != nil || !ok {
			return false, e
		}
	}
	if advancedChanged {
		if k.P1 == nil {
			return false, nil
		}
		ok, e := k.P1.quota.canRenew(before, after)
		if e != nil || !ok {
			return false, e
		}
	}
	return legacyChanged || advancedChanged, nil
}
func (k *IPTables) RenewCredits(before, after State) error {
	if k.Native != nil {
		return k.P1.quota.renew(after)
	}
	if e := k.renewBaseCredits(legacyState(before), legacyState(after)); e != nil {
		return e
	}
	if k.P1 != nil {
		return k.P1.quota.renew(after)
	}
	return nil
}

func advancedOwnedChain(text, name string) bool {
	return strings.Contains(text, "-A "+name+" -m comment --comment "+advancedOwner+" -j RETURN") || strings.Contains(text, "-A "+name+" -m comment --comment \""+advancedOwner+"\" -j RETURN")
}
