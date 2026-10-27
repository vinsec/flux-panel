package engine

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

func (m *Manager) StartRuntime(ctx context.Context) error {
	if k, ok := m.Kernel.(interface{ StartAddressWatcher(context.Context) error }); ok {
		return k.StartAddressWatcher(ctx)
	}
	return nil
}
func (m *Manager) refreshAddressesLocked() error {
	if k, ok := m.Kernel.(interface {
		RefreshBindings(map[string]Spec) (bool, error)
	}); ok {
		changed, e := k.RefreshBindings(m.state.Rules)
		if e != nil {
			return e
		}
		if changed {
			if e = m.capture(&m.state); e != nil {
				return e
			}
			if e = m.syncCredits(&m.state); e != nil {
				return e
			}
			m.state.Generation++
			if e = m.save(); e != nil {
				return e
			}
			return m.activate()
		}
	}
	return nil
}
func (k *IPTables) RefreshBindings(rules map[string]Spec) (changed bool, failure error) {
	defer func() {
		if failure != nil && k.P1 != nil {
			k.P1.addressDirty.Store(true)
			for id, s := range rules {
				if s.Advanced() && (s.Egress.Interface != "" || s.Bandwidth.Enabled() || s.needsTrafficSets()) {
					if k.P1.runtimeErrors == nil {
						k.P1.runtimeErrors = map[string]string{}
					}
					k.P1.runtimeErrors[id] = failure.Error()
				}
			}
		}
	}()
	if k.P1 == nil {
		return false, nil
	}
	addressDirty := k.P1.addressDirty.Swap(false)
	contractsChanged := k.P1.runtimeContractsChanged(rules)
	if !addressDirty && !contractsChanged {
		return false, nil
	}
	plan := []Spec{}
	for _, id := range keys(rules) {
		if !rules[id].Advanced() {
			plan = append(plan, rules[id])
		}
	}
	bindings, _, e := k.plans(plan)
	if e != nil {
		return false, e
	}
	signature := digest(bindings)
	changed = false
	if signature != k.bindingShape {
		if e = k.stageSet(bindingSet, bindings); e != nil {
			return false, e
		}
		if _, e = k.run("ipset", "", "swap", bindingSet+"_NEW", bindingSet); e != nil {
			return false, e
		}
		k.bindingShape = signature
		tables := Render(legacyRules(plan), nil)
		k.shape = shapeDigest(tables, bindings)
		changed = true
	}
	addresses, e := localAddresses()
	if e != nil {
		return false, e
	}
	auxTokens := []uint32{}
	advancedPlan := []Spec{}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Advanced() {
			advancedPlan = append(advancedPlan, s)
			if !s.Deleted && (s.Egress.Interface != "" || s.Bandwidth.Enabled() || s.needsTrafficSets()) {
				auxTokens = append(auxTokens, s.Token)
			}
		}
	}
	if len(auxTokens) > 0 {
		if e = k.P1.gate(auxTokens, false, false); e != nil {
			return false, e
		}
		if e = k.P1.apply(advancedPlan); e != nil {
			return false, e
		}
		changed = true
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !k.P1.ready[family] {
			continue
		}
		p := k.P1.plane(family)
		_, entries, _, e := compileAdvancedPlane(p, k.P1.last, addresses[family])
		if e != nil {
			return false, e
		}
		var output map[string]string
		signature := digest(entries)
		if k.P1.trafficReady[family] {
			output, _ = trafficSets(p, k.P1.last, addresses[family])
			signature = digest([]any{entries, output})
		}
		if signature == k.P1.bindings[family] {
			continue
		}
		if e = k.P1.stage(p, "BNEW", entries, true); e != nil {
			return false, e
		}
		if _, e = k.run("ipset", "", "swap", p.set("BNEW"), p.set("BIND")); e != nil {
			return false, e
		}
		if k.P1.trafficReady[family] {
			if e = k.P1.stage(p, "ONEW", output, true); e != nil {
				return false, e
			}
			if _, e = k.run("ipset", "", "swap", p.set("ONEW"), p.set("OBIND")); e != nil {
				return false, e
			}
		}
		k.P1.bindings[family] = signature
		changed = true
	}
	return changed, nil
}
func usableAddress(ip string, addresses []string) bool {
	return ip == "0.0.0.0" || ip == "::" || slices.Contains(addresses, ip)
}
func addressStatus(s Spec, addresses map[string][]string) string {
	missing := []string{}
	for _, l := range s.ListenerList() {
		ip, _ := netip.ParseAddr(l.Host)
		if !usableAddress(l.Host, addresses[l.Family]) && !(s.AdvancedOptions != nil && s.trafficPolicy().LocalOutput && ip.IsLoopback()) {
			missing = append(missing, l.Host)
		}
	}
	if len(missing) > 0 {
		return fmt.Sprintf("listener addresses unavailable: %s", strings.Join(missing, ","))
	}
	return ""
}
