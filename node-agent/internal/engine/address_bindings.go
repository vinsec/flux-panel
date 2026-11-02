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

func (k *NativeKernel) RefreshBindings(rules map[string]Spec) (bool, error) {
	if k.Gost != nil && k.Mode == "gost" {
		previous := k.Gost.generation
		if e := k.Gost.ready(); e != nil {
			_ = k.Quiesce()
			k.P1.addressDirty.Store(true)
			return false, e
		}
		if previous != k.Gost.generation {
			k.P1.addressDirty.Store(true)
			k.Native.bindings = ""
		}
	}
	dirty := k.P1.addressDirty.Swap(false)
	contractsChanged := k.P1.runtimeContractsChanged(rules)
	if !dirty && !contractsChanged {
		return false, nil
	}
	addresses, e := localAddresses()
	if e != nil {
		_ = k.Native.gate(nil, false, false)
		return false, e
	}
	identity, e := nativeBindingIdentity(rules, addresses)
	if e != nil {
		_ = k.Native.gate(nil, false, false)
		return false, e
	}
	if identity == k.Native.bindings && !contractsChanged {
		return false, nil
	}
	if e := k.Native.gate(nil, false, false); e != nil {
		return false, e
	}
	if e := k.Apply(Render(rules, nil)); e != nil {
		k.P1.addressDirty.Store(true)
		return false, e
	}
	return true, nil

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
