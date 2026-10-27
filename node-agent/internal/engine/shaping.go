package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type shapeClass struct {
	Key, Parent  string
	ID, ParentID uint16
	Rate         uint64
	Guarantee    uint64
	Depth        int
}

func effectiveRate(values ...uint64) uint64 {
	result := uint64(0)
	for _, v := range values {
		if v > 0 && (result == 0 || v < result) {
			result = v
		}
	}
	return result
}
func (x *Auxiliary) classID(key string) (uint16, error) {
	if id := x.classes[key]; id != 0 {
		return id, nil
	}
	used := map[uint16]bool{}
	for _, id := range x.classes {
		used[id] = true
	}
	for id := uint16(16); id < 65534; id++ {
		if !used[id] {
			x.classes[key] = id
			return id, nil
		}
	}
	return 0, fmt.Errorf("shaping class capacity exhausted")
}
func (x *Auxiliary) shapePlan(rules map[string]Spec) (map[string]shapeClass, []shapeFilter, error) {
	definitions := map[string]shapeClass{}
	leafKeys := map[string]map[bool]string{}
	groupRates := map[string]uint64{}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Deleted || !s.Active() || !s.Bandwidth.Enabled() {
			continue
		}
		p := strings.Split(id, "_")
		for _, up := range []bool{true, false} {
			direction := "down"
			ur, tr := s.Bandwidth.User.DownBitsPerSecond, s.Bandwidth.Tunnel.DownBitsPerSecond
			if up {
				direction = "up"
				ur, tr = s.Bandwidth.User.UpBitsPerSecond, s.Bandwidth.Tunnel.UpBitsPerSecond
			}
			user := s.Bandwidth.User.ID
			if user == "" {
				user = "u_" + p[1]
			}
			tunnel := s.Bandwidth.Tunnel.ID
			if tunnel == "" {
				tunnel = "ut_" + p[1] + "_" + p[2]
			}
			uk := "user:" + user + ":" + direction
			tk := "tunnel:" + user + ":" + tunnel + ":" + direction
			groupRates[uk] = effectiveRate(groupRates[uk], ur)
			groupRates[tk] = effectiveRate(groupRates[tk], tr)
		}
	}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Deleted || !s.Active() || !s.Bandwidth.Enabled() {
			continue
		}
		p := strings.Split(id, "_")
		for _, up := range []bool{true, false} {
			direction := "down"
			rate := s.Bandwidth.DownBitsPerSecond
			if up {
				direction = "up"
				rate = s.Bandwidth.UpBitsPerSecond
			}
			user := s.Bandwidth.User.ID
			if user == "" {
				user = "u_" + p[1]
			}
			tunnel := s.Bandwidth.Tunnel.ID
			if tunnel == "" {
				tunnel = "ut_" + p[1] + "_" + p[2]
			}
			uk := "user:" + user + ":" + direction
			tk := "tunnel:" + user + ":" + tunnel + ":" + direction
			ur := groupRates[uk]
			tr := effectiveRate(ur, groupRates[tk])
			lr := effectiveRate(rate, tr)
			if lr == 0 {
				continue
			}
			if ur == 0 {
				ur = 1000000000000
			}
			if tr == 0 {
				tr = ur
			}
			lk := "forward:" + id + ":" + direction
			definitions[uk] = shapeClass{Key: uk, Rate: ur, Depth: 1}
			definitions[tk] = shapeClass{Key: tk, Parent: uk, Rate: tr, Depth: 2}
			definitions[lk] = shapeClass{Key: lk, Parent: tk, Rate: lr, Depth: 3}
			if leafKeys[id] == nil {
				leafKeys[id] = map[bool]string{}
			}
			leafKeys[id][up] = lk
		}
	}
	if e := assignGuarantees(definitions); e != nil {
		return nil, nil, e
	}
	classKeys := make([]string, 0, len(definitions))
	for key := range definitions {
		classKeys = append(classKeys, key)
	}
	slices.Sort(classKeys)
	for _, key := range classKeys {
		d := definitions[key]
		id, e := x.classID(key)
		if e != nil {
			return nil, nil, e
		}
		d.ID = id
		d.ParentID = 1
		if d.Parent != "" {
			parent, e := x.classID(d.Parent)
			if e != nil {
				return nil, nil, e
			}
			d.ParentID = parent
		}
		definitions[key] = d
	}
	interfaces, e := net.Interfaces()
	if e != nil {
		return nil, nil, e
	}
	filters := []shapeFilter{}
	for _, iface := range interfaces {
		if iface.Name == shapingDevice || iface.Flags&net.FlagUp == 0 {
			continue
		}
		for _, id := range keys(rules) {
			for _, up := range []bool{true, false} {
				if iface.Flags&net.FlagLoopback != 0 && !rules[id].localTraffic() {
					continue
				}
				key := leafKeys[id][up]
				if key == "" {
					continue
				}
				mark := flowMark(rules[id])
				if up {
					mark |= 0x80
				}
				filters = append(filters, shapeFilter{iface.Name, mark, definitions[key].ID})
			}
		}
	}
	return definitions, filters, nil
}
func (x *Auxiliary) runTC(args ...string) (string, error) {
	return x.parent.parent.run("tc", "", args...)
}
func (x *Auxiliary) removeFilter(f shapeFilter) error {
	if _, e := net.InterfaceByName(f.Interface); e != nil {
		return nil
	}
	_, e := x.runTC("filter", "del", "dev", f.Interface, "egress", "protocol", "all", "pref", "49151", "handle", fmt.Sprintf("0x%x", f.Mark), "fw")
	if e != nil && !strings.Contains(e.Error(), "No such") && !strings.Contains(e.Error(), "Cannot find") {
		return e
	}
	return nil
}
func (x *Auxiliary) ensureShape() error {
	if x.shapeReady {
		return nil
	}
	text, e := x.parent.parent.run("ip", "", "-j", "link", "show", "dev", shapingDevice)
	hadShape := e == nil
	if e == nil {
		var links []map[string]any
		if e = json.Unmarshal([]byte(text), &links); e != nil || len(links) != 1 {
			return fmt.Errorf("invalid shaping device")
		}
		if links[0]["ifalias"] != advancedOwner+":"+x.parent.epoch {
			return fmt.Errorf("foreign IFB device occupies the shaping name")
		}
		for _, filter := range x.manifest.Filters {
			if e = x.removeFilter(filter); e != nil {
				return e
			}
		}
		if _, e = x.parent.parent.run("ip", "", "link", "del", shapingDevice); e != nil {
			return e
		}
	}
	if !hadShape {
		for _, filter := range x.manifest.Filters {
			if e = x.removeFilter(filter); e != nil {
				return e
			}
		}
	}
	if _, e = x.parent.parent.run("ip", "", "link", "add", shapingDevice, "type", "ifb"); e != nil {
		return fmt.Errorf("IFB module unavailable: %w", e)
	}
	if _, e = x.parent.parent.run("ip", "", "link", "set", "dev", shapingDevice, "alias", advancedOwner+":"+x.parent.epoch); e != nil {
		return e
	}
	if _, e = x.parent.parent.run("ip", "", "link", "set", shapingDevice, "up"); e != nil {
		return e
	}
	if _, e = x.runTC("qdisc", "add", "dev", shapingDevice, "root", "handle", "f100:", "htb"); e != nil {
		return e
	}
	if _, e = x.runTC("class", "add", "dev", shapingDevice, "parent", "f100:", "classid", "f100:1", "htb", "rate", "1000000000000bit", "ceil", "1000000000000bit", "burst", "1250000000", "cburst", "1250000000"); e != nil {
		return e
	}
	// An in-flight packet for a removed class must drop, never bypass a limit.
	if _, e = x.runTC("filter", "add", "dev", shapingDevice, "parent", "f100:", "protocol", "all", "pref", "9999", "matchall", "action", "drop"); e != nil {
		return e
	}
	iface, e := net.InterfaceByName(shapingDevice)
	if e != nil {
		return e
	}
	x.shapeIndex = iface.Index
	x.shapeReady = true
	x.classPlans = map[string]shapeClass{}
	return nil
}
func filterKey(f shapeFilter) string { return fmt.Sprintf("%s/%x", f.Interface, f.Mark) }
func (x *Auxiliary) applyShaping(rules map[string]Spec) error {
	classes, filters, e := x.shapePlan(rules)
	if e != nil {
		return e
	}
	if len(filters) == 0 {
		return x.removeShaping()
	}
	if e = x.removeLocalShaping(); e != nil {
		return e
	}
	oldFilters := slices.Clone(x.manifest.Filters)
	initializing := !x.shapeReady
	if e = x.ensureShape(); e != nil {
		return e
	}
	if initializing {
		oldFilters = nil
	}
	ordered := make([]shapeClass, 0, len(classes))
	for _, c := range classes {
		ordered = append(ordered, c)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Depth != ordered[j].Depth {
			return ordered[i].Depth < ordered[j].Depth
		}
		return ordered[i].Key < ordered[j].Key
	})
	for _, c := range ordered {
		if old, ok := x.classPlans[c.Key]; ok && old == c {
			continue
		}
		burst := max(uint64(65536), c.Rate/800)
		if burst > 4000000000 {
			burst = 4000000000
		}
		if _, e = x.runTC("class", "replace", "dev", shapingDevice, "parent", fmt.Sprintf("f100:%x", c.ParentID), "classid", fmt.Sprintf("f100:%x", c.ID), "htb", "rate", fmt.Sprint(c.Guarantee)+"bit", "ceil", fmt.Sprint(c.Rate)+"bit", "burst", fmt.Sprint(burst), "cburst", fmt.Sprint(burst), "quantum", "1514"); e != nil {
			return e
		}
		if c.Depth == 3 {
			if _, exists := x.classPlans[c.Key]; !exists {
				if _, e = x.runTC("qdisc", "add", "dev", shapingDevice, "parent", fmt.Sprintf("f100:%x", c.ID), "fq_codel", "limit", "1024"); e != nil {
					return e
				}
			}
		}
	}
	wanted := map[string]shapeFilter{}
	for _, f := range filters {
		wanted[filterKey(f)] = f
	}
	for _, old := range oldFilters {
		if next, ok := wanted[filterKey(old)]; !ok || next.Class != old.Class {
			if e = x.removeFilter(old); e != nil {
				return e
			}
		}
	}
	removed := []shapeClass{}
	for key, c := range x.classPlans {
		if _, ok := classes[key]; !ok {
			removed = append(removed, c)
		}
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i].Depth > removed[j].Depth })
	for _, c := range removed {
		if c.Depth == 3 {
			_, _ = x.runTC("qdisc", "del", "dev", shapingDevice, "parent", fmt.Sprintf("f100:%x", c.ID))
		}
		if _, e = x.runTC("class", "del", "dev", shapingDevice, "classid", fmt.Sprintf("f100:%x", c.ID)); e != nil {
			return e
		}
		delete(x.classes, c.Key)
	}
	oldMap := map[string]shapeFilter{}
	for _, f := range oldFilters {
		oldMap[filterKey(f)] = f
	}
	created := slices.Clone(x.manifest.CreatedClsact)
	presentFilters := map[string]bool{}
	interfaces := map[string]bool{}
	for _, f := range filters {
		interfaces[f.Interface] = true
	}
	for iface := range interfaces {
		text, e := x.runTC("qdisc", "show", "dev", iface)
		if e != nil {
			return e
		}
		if !strings.Contains(text, "qdisc clsact ") {
			created = append(created, iface)
			x.manifest.CreatedClsact = created
			if e = x.save(); e != nil {
				return e
			}
			if _, e = x.runTC("qdisc", "add", "dev", iface, "clsact"); e != nil {
				return e
			}
		}
		text, e = x.runTC("filter", "show", "dev", iface, "egress")
		if e != nil {
			return e
		}
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] != "filter" {
				continue
			}
			pref := ""
			fw := false
			var mark uint64
			hasHandle := false
			for i, value := range fields {
				if value == "pref" && i+1 < len(fields) {
					pref = fields[i+1]
				}
				if value == "fw" {
					fw = true
				}
				if value == "handle" && i+1 < len(fields) {
					text := strings.Split(fields[i+1], "/")[0]
					mark, _ = strconv.ParseUint(text, 0, 32)
					hasHandle = true
				}
			}
			if pref != "49151" || !fw {
				return fmt.Errorf("existing egress classifiers require explicit coexistence review")
			}
			if hasHandle {
				key := filterKey(shapeFilter{Interface: iface, Mark: uint32(mark)})
				presentFilters[key] = true
				if _, ok := oldMap[key]; !ok {
					return fmt.Errorf("foreign egress classifier occupies reserved priority")
				}
			}
		}
	}
	x.manifest.Filters = append(slices.Clone(oldFilters), filters...)
	x.manifest.CreatedClsact = created
	if e = x.save(); e != nil {
		return e
	}
	if e = x.applyLocalShaping(rules, classes, filters); e != nil {
		return e
	}
	for _, f := range filters {
		if old, ok := oldMap[filterKey(f)]; ok && old.Class == f.Class && presentFilters[filterKey(f)] {
			continue
		}
		args := []string{"filter", "add", "dev", f.Interface, "egress", "protocol", "all", "pref", "49151", "handle", fmt.Sprintf("0x%x/0xffffffc0", f.Mark), "fw", "action", "skbedit", "mark", "0x40/0x40", "priority", fmt.Sprintf("f100:%x", f.Class)}
		if f.Interface == "lo" {
			args = append(args, "action", "goto", "chain", "201")
		} else {
			args = append(args, "action", "mirred", "egress", "redirect", "dev", shapingDevice)
		}
		if _, e = x.runTC(args...); e != nil {
			return e
		}
	}
	x.manifest.Filters = filters
	x.classPlans = classes
	return nil
}
func jsonUint(v any) uint64 {
	switch n := v.(type) {
	case float64:
		return uint64(n)
	case json.Number:
		r, _ := strconv.ParseUint(string(n), 0, 64)
		return r
	case string:
		r, _ := strconv.ParseUint(n, 0, 64)
		return r
	}
	return 0
}
func (x *Auxiliary) removeShaping() error {
	if e := x.removeLocalShaping(); e != nil {
		return e
	}
	if e := x.removeLocalProbe(); e != nil {
		return e
	}
	if e := x.removeRestoreObject(); e != nil {
		return e
	}
	for _, f := range x.manifest.Filters {
		if e := x.removeFilter(f); e != nil {
			return e
		}
	}
	x.manifest.Filters = nil
	if text, e := x.parent.parent.run("ip", "", "-j", "link", "show", "dev", shapingDevice); e == nil {
		var links []map[string]any
		if e = json.Unmarshal([]byte(text), &links); e != nil || len(links) != 1 || links[0]["ifalias"] != advancedOwner+":"+x.parent.epoch {
			return fmt.Errorf("refusing to remove foreign shaping device")
		}
		if _, e = x.parent.parent.run("ip", "", "link", "del", shapingDevice); e != nil {
			return e
		}
	}
	kept := []string{}
	for _, iface := range x.manifest.CreatedClsact {
		if _, e := net.InterfaceByName(iface); e != nil {
			continue
		}
		egress, e1 := x.runTC("-j", "filter", "show", "dev", iface, "egress")
		ingress, e2 := x.runTC("-j", "filter", "show", "dev", iface, "ingress")
		if e1 == nil && e2 == nil && strings.TrimSpace(egress) == "[]" && strings.TrimSpace(ingress) == "[]" {
			_, _ = x.runTC("qdisc", "del", "dev", iface, "clsact")
		} else {
			kept = append(kept, iface)
		}
	}
	x.manifest.CreatedClsact = kept
	x.shapeReady = false
	x.classPlans = map[string]shapeClass{}
	return nil
}

// HTB only borrows through ancestors after a child's guaranteed tokens are
// spent. Setting each child's rate equal to its independent ceiling lets an
// overcommitted sibling group bypass the intended shared ceiling. Allocate
// non-overcommitted guarantees top-down; keep requested maxima as ceilings.
func assignGuarantees(classes map[string]shapeClass) error {
	children := map[string][]string{}
	for key, c := range classes {
		children[c.Parent] = append(children[c.Parent], key)
	}
	var visit func(string, uint64) error
	visit = func(parent string, budget uint64) error {
		names := children[parent]
		if len(names) == 0 {
			return nil
		}
		share := budget / uint64(len(names))
		if share < 8 {
			return fmt.Errorf("bandwidth group has too many children for its rate; minimum HTB guarantee is 8 bit/s per child")
		}
		for _, key := range names {
			c := classes[key]
			c.Guarantee = min(c.Rate, share)
			classes[key] = c
			if e := visit(key, c.Guarantee); e != nil {
				return e
			}
		}
		return nil
	}
	return visit("", 1000000000000)
}
