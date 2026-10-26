package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
)

const shapingDevice = "fp4shape"
const auxRouteProtocol = 186

type routeEntry struct {
	Family      string `json:"family"`
	Group       uint8  `json:"group"`
	Interface   string `json:"interface"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Source      string `json:"source,omitempty"`
}
type shapeFilter struct {
	Interface string `json:"interface"`
	Mark      uint32 `json:"mark"`
	Class     uint16 `json:"class"`
}
type auxManifest struct {
	Version       int              `json:"version"`
	Epoch         string           `json:"epoch"`
	Groups        map[string]uint8 `json:"groups"`
	Routes        []routeEntry     `json:"routes"`
	Filters       []shapeFilter    `json:"filters"`
	CreatedClsact []string         `json:"createdClsact"`
}
type Auxiliary struct {
	parent     *AdvancedKernel
	manifest   auxManifest
	classes    map[string]uint16
	classPlans map[string]shapeClass
	shapeReady bool
	loaded     bool
}

func (a *AdvancedKernel) auxiliary() (*Auxiliary, error) {
	if a.aux != nil {
		return a.aux, nil
	}
	x := &Auxiliary{parent: a, classes: map[string]uint16{}, classPlans: map[string]shapeClass{}, manifest: auxManifest{Version: 1, Epoch: a.epoch, Groups: map[string]uint8{}}}
	if data, e := os.ReadFile(a.StatePath + ".aux.json"); e == nil {
		if e = json.Unmarshal(data, &x.manifest); e != nil {
			return nil, e
		}
		if x.manifest.Version != 1 || x.manifest.Epoch != a.epoch {
			return nil, fmt.Errorf("auxiliary ownership checkpoint mismatch")
		}
		x.loaded = true
	}
	a.aux = x
	return x, nil
}
func (a *AdvancedKernel) validateAux(s Spec) error {
	if s.Egress.Interface == "" && !s.Bandwidth.Enabled() {
		return nil
	}
	mask := uint64(0xc0)
	if s.Egress.Interface != "" {
		mask = 0xff
		iface, e := net.InterfaceByName(s.Egress.Interface)
		if e != nil || iface.Flags&net.FlagUp == 0 {
			return fmt.Errorf("egress interface must be present and up")
		}
		addresses, e := iface.Addrs()
		if e != nil {
			return e
		}
		assigned := map[string]bool{}
		for _, address := range addresses {
			ip, _, e := net.ParseCIDR(address.String())
			if e == nil {
				assigned[ip.String()] = true
			}
		}
		for _, source := range []string{s.Egress.SourceIPv4, s.Egress.SourceIPv6} {
			if source != "" && !assigned[source] {
				return fmt.Errorf("source IP must be assigned to the selected egress interface")
			}
		}
	}
	for _, binary := range []string{a.parent.Binary, strings.Replace(a.parent.Binary, "iptables", "ip6tables", 1)} {
		saved, e := a.parent.run(binary+"-save", "", "-t", "mangle")
		if e == nil {
			if e = validateMarkBits(saved, mask); e != nil {
				return fmt.Errorf("auxiliary mark bits conflict: %w", e)
			}
		}
	}
	x, e := a.auxiliary()
	if e != nil {
		return e
	}
	return x.auditRules(mask)
}
func (a *AdvancedKernel) prepareAux(rules map[string]Spec) (map[string]Spec, error) {
	need := false
	for _, s := range rules {
		if s.Egress.Interface != "" || s.Bandwidth.Enabled() {
			need = true
		}
	}
	if !need && a.aux == nil {
		return rules, nil
	}
	x, e := a.auxiliary()
	if e != nil {
		return nil, e
	}
	used := map[uint8]bool{}
	for _, id := range x.manifest.Groups {
		used[id] = true
	}
	result := map[string]Spec{}
	for _, id := range keys(rules) {
		s := cloneSpec(rules[id])
		if !s.Deleted && s.Egress.Interface != "" {
			key := digest(s.Egress)
			group := x.manifest.Groups[key]
			if group == 0 {
				for n := uint8(1); n < 64; n++ {
					if !used[n] {
						group = n
						break
					}
				}
				if group == 0 {
					return nil, fmt.Errorf("at most 63 distinct egress policies per node")
				}
				used[group] = true
				x.manifest.Groups[key] = group
			}
			s.Runtime.EgressGroup = group
		}
		result[id] = s
	}
	return result, nil
}
func (a *AdvancedKernel) applyAux(rules map[string]Spec) error {
	need := false
	for _, s := range rules {
		if s.Egress.Interface != "" || s.Bandwidth.Enabled() {
			need = true
		}
	}
	if !need && a.aux == nil {
		return nil
	}
	x, e := a.auxiliary()
	if e != nil {
		return e
	}
	return x.apply(rules)
}
func (x *Auxiliary) save() error {
	x.manifest.Epoch = x.parent.epoch
	return atomicJSON(x.parent.StatePath+".aux.json", x.manifest)
}
func routeTable(group uint8) string { return fmt.Sprint(uint32(0xf2000000) | uint32(group)) }
func routeMark(group uint8) string {
	return fmt.Sprintf("0x%x/0xff0000bf", uint32(0xf2000080)|uint32(group))
}
func (x *Auxiliary) auditRules(mask uint64) error {
	for _, family := range []string{"ipv4", "ipv6"} {
		flag := "-4"
		if family == "ipv6" {
			flag = "-6"
		}
		text, e := x.parent.parent.run("ip", "", "-j", flag, "rule", "show")
		if e != nil {
			return e
		}
		var rows []map[string]any
		if e = json.Unmarshal([]byte(text), &rows); e != nil {
			return e
		}
		for _, r := range rows {
			value, ok := r["fwmark"]
			if !ok {
				continue
			}
			mark := jsonUint(value)
			bits := uint64(0xffffffff)
			if v, ok := r["fwmask"]; ok {
				bits = jsonUint(v)
			}
			if (mark^0xf2000000)&bits&0xff000000 != 0 || bits&mask == 0 {
				continue
			}
			owned := false
			for _, entry := range x.manifest.Routes {
				if entry.Family == family && fmt.Sprint(jsonUint(r["table"])) == routeTable(entry.Group) && mark == uint64(0xf2000080)|uint64(entry.Group) && bits == 0xff0000bf {
					owned = true
					break
				}
			}
			if !owned {
				return fmt.Errorf("foreign policy routing reads reserved auxiliary mark bits")
			}
		}
	}
	return nil
}
func (x *Auxiliary) routePlan(rules map[string]Spec) ([]routeEntry, error) {
	entries := map[string]routeEntry{}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Deleted || !s.Active() || s.Egress.Interface == "" {
			continue
		}
		group := s.Runtime.EgressGroup
		for _, listener := range s.Listeners {
			family := listener.Family
			source, gateway := s.Egress.SourceIPv4, s.Egress.GatewayIPv4
			if family == "ipv6" {
				source, gateway = s.Egress.SourceIPv6, s.Egress.GatewayIPv6
			}
			entry := routeEntry{Family: family, Group: group, Interface: s.Egress.Interface, Destination: "default", Gateway: gateway, Source: source}
			entries[family+"/"+routeTable(group)+"/default"] = entry
		}
		for _, target := range s.Paths() {
			family := target.Family
			source, gateway := s.Egress.SourceIPv4, s.Egress.GatewayIPv4
			flag := "-4"
			bits := 32
			if family == "ipv6" {
				source, gateway = s.Egress.SourceIPv6, s.Egress.GatewayIPv6
				flag = "-6"
				bits = 128
			}
			entryKey := family + "/" + routeTable(group) + "/" + target.Host + "/" + strconv.Itoa(bits)
			if _, exists := entries[entryKey]; exists {
				continue
			}
			if gateway == "" {
				text, e := x.parent.parent.run("ip", "", "-j", flag, "route", "get", target.Host, "oif", s.Egress.Interface)
				if e != nil {
					return nil, fmt.Errorf("selected interface has no route to target")
				}
				var route []map[string]any
				if e = json.Unmarshal([]byte(text), &route); e != nil || len(route) == 0 {
					return nil, fmt.Errorf("egress route unavailable")
				}
				if g, ok := route[0]["gateway"].(string); ok {
					gateway = g
				}
			}
			entry := routeEntry{Family: family, Group: group, Interface: s.Egress.Interface, Destination: target.Host + "/" + strconv.Itoa(bits), Gateway: gateway, Source: source}
			entries[family+"/"+routeTable(group)+"/"+entry.Destination] = entry
		}
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := []routeEntry{}
	for _, key := range keys {
		out = append(out, entries[key])
	}
	return out, nil
}
func (x *Auxiliary) apply(rules map[string]Spec) error {
	mask := uint64(0xc0)
	for _, s := range rules {
		if s.Egress.Interface != "" {
			mask = 0xff
		}
	}
	if e := x.auditRules(mask); e != nil {
		return e
	}
	newRoutes, e := x.routePlan(rules)
	if e != nil {
		return e
	}
	old := x.manifest
	next := old
	next.Routes = newRoutes
	// Persist an ownership superset before netlink operations. A failed commit
	// can safely remove newly prepared resources without guessing ownership.
	union := append(slices.Clone(old.Routes), newRoutes...)
	x.manifest.Routes = union
	if e = x.save(); e != nil {
		return e
	}
	wantedGroups := map[string]routeEntry{}
	for _, entry := range newRoutes {
		wantedGroups[entry.Family+"/"+routeTable(entry.Group)] = entry
	}
	for _, entry := range newRoutes {
		flag := "-4"
		if entry.Family == "ipv6" {
			flag = "-6"
		}
		args := []string{flag, "route", "replace", entry.Destination}
		if entry.Gateway != "" {
			args = append(args, "via", entry.Gateway)
		}
		args = append(args, "dev", entry.Interface)
		if entry.Source != "" {
			args = append(args, "src", entry.Source)
		}
		args = append(args, "table", routeTable(entry.Group), "proto", strconv.Itoa(auxRouteProtocol))
		if _, e = x.parent.parent.run("ip", "", args...); e != nil {
			return e
		}
	}
	for _, entry := range wantedGroups {
		flag := "-4"
		if entry.Family == "ipv6" {
			flag = "-6"
		}
		text, err := x.parent.parent.run("ip", "", "-j", flag, "rule", "show")
		if err != nil {
			return err
		}
		var current []map[string]any
		if err = json.Unmarshal([]byte(text), &current); err != nil {
			return err
		}
		present := false
		for _, r := range current {
			if jsonUint(r["table"]) == uint64(0xf2000000)|uint64(entry.Group) && jsonUint(r["fwmark"]) == uint64(0xf2000080)|uint64(entry.Group) && jsonUint(r["fwmask"]) == 0xff0000bf {
				present = true
				break
			}
		}
		if present {
			continue
		}
		args := []string{flag, "rule", "add", "pref", strconv.Itoa(19000 + int(entry.Group)), "fwmark", routeMark(entry.Group), "lookup", routeTable(entry.Group), "protocol", strconv.Itoa(auxRouteProtocol)}
		if _, e = x.parent.parent.run("ip", "", args...); e != nil && !strings.Contains(e.Error(), "File exists") {
			return e
		}
	}
	newKeys := map[string]bool{}
	for _, entry := range newRoutes {
		newKeys[entry.Family+"/"+routeTable(entry.Group)+"/"+entry.Destination] = true
	}
	removedGroups := map[string]bool{}
	for _, entry := range old.Routes {
		if newKeys[entry.Family+"/"+routeTable(entry.Group)+"/"+entry.Destination] {
			continue
		}
		flag := "-4"
		if entry.Family == "ipv6" {
			flag = "-6"
		}
		if _, exists := wantedGroups[entry.Family+"/"+routeTable(entry.Group)]; !exists {
			key := entry.Family + "/" + routeTable(entry.Group)
			if !removedGroups[key] {
				_, err := x.parent.parent.run("ip", "", flag, "rule", "del", "pref", strconv.Itoa(19000+int(entry.Group)), "fwmark", routeMark(entry.Group), "lookup", routeTable(entry.Group), "protocol", strconv.Itoa(auxRouteProtocol))
				if err != nil && !strings.Contains(err.Error(), "No such") {
					return err
				}
				removedGroups[key] = true
			}
		}
		_, err := x.parent.parent.run("ip", "", flag, "route", "del", entry.Destination, "table", routeTable(entry.Group), "proto", strconv.Itoa(auxRouteProtocol))
		if err != nil && !strings.Contains(err.Error(), "No such") && !strings.Contains(err.Error(), "No such process") {
			return err
		}
	}
	x.manifest = next
	usedGroups := map[string]bool{}
	for _, s := range rules {
		if !s.Deleted && s.Egress.Interface != "" {
			usedGroups[digest(s.Egress)] = true
		}
	}
	for key := range x.manifest.Groups {
		if !usedGroups[key] {
			delete(x.manifest.Groups, key)
		}
	}
	if e = x.applyShaping(rules); e != nil {
		return e
	}
	return x.save()
}
func numericAddress(value string) bool {
	a, e := netip.ParseAddr(value)
	return e == nil && a.Zone() == "" && !a.IsMulticast()
}
