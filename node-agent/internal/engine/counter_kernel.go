package engine

import (
	"fmt"
	"strconv"
	"strings"
)

func (k *IPTables) SnapshotDetailed() (map[string]uint64, []counterRecord, error) {
	if k.Native != nil {
		return k.Native.snapshot()
	}
	totals := map[string]uint64{}
	records := []counterRecord{}
	for _, name := range []string{upSet, downSet} {
		text, e := k.readSet(name)
		if e != nil {
			return nil, nil, e
		}
		for _, v := range parseSet(text) {
			r := counterRecord{name, v.Key, v.Comment, v.Bytes, v.Packets}
			id := counterID(r)
			if id == "" {
				continue
			}
			p := strings.Split(v.Comment, ":")
			totals["flux:v2:"+id+":all:"+p[3]] += v.Bytes
			records = append(records, r)
		}
	}
	if k.P1 != nil {
		extra, more, e := k.P1.snapshot()
		if e != nil {
			return nil, nil, e
		}
		for key, n := range extra {
			totals[key] += n
		}
		records = append(records, more...)
	}
	return totals, records, nil
}
func (k *IPTables) References() (map[string]bool, error) {
	if k.Native != nil {
		return k.Native.references()
	}
	text, e := k.run("conntrack", "", "-L", "-f", "ipv4", "--mark", mark)
	if e != nil && !strings.Contains(e.Error(), "0 flow entries") {
		return nil, e
	}
	out := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		target := ""
		srcCount := 0
		var value uint64
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "src=") {
				srcCount++
				if srcCount == 2 {
					target = strings.TrimPrefix(f, "src=")
				}
			}
			if strings.HasPrefix(f, "mark=") {
				value, _ = strconv.ParseUint(strings.TrimPrefix(f, "mark="), 0, 32)
			}
		}
		if target != "" && uint32(value)&0xff000000 == 0xf1000000 {
			out[fmt.Sprintf("%s,0x%x", target, uint32(value)&0xffffff00)] = true
			out[fmt.Sprintf("mark:0x%x", uint32(value)&0xffffff00)] = true
		}
	}
	if k.P1 != nil {
		more, e := k.P1.references()
		if e != nil {
			return nil, e
		}
		for key, value := range more {
			out[key] = value
		}
	}
	return out, nil
}
func (k *IPTables) counterSets() (map[string]map[string]setElement, error) {
	out := map[string]map[string]setElement{}
	names := []string{upSet, downSet}
	if k.P1 != nil {
		for _, family := range []string{"ipv4", "ipv6"} {
			if k.P1.ready[family] {
				p := k.P1.plane(family)
				names = append(names, p.set("UP"), p.set("DOWN"))
			}
		}
	}
	for _, name := range names {
		text, e := k.readSet(name)
		if e != nil {
			return nil, e
		}
		out[name] = parseSet(text)
	}
	return out, nil
}
func (k *IPTables) RemoveCounters(records []counterRecord) error {
	if k.Native != nil {
		return k.Native.restore(records, true)
	}
	sets, e := k.counterSets()
	if e != nil {
		return e
	}
	var b strings.Builder
	for _, r := range records {
		if !accountingSet(r.Set) {
			return fmt.Errorf("foreign counter set in GC")
		}
		v, exists := sets[r.Set][r.Key]
		if !exists {
			continue
		}
		if v.Comment != r.Comment || v.Bytes != r.Bytes || v.Packets != r.Packets {
			return fmt.Errorf("counter changed after GC preparation")
		}
		fmt.Fprintf(&b, "del %s %s\n", r.Set, r.Key)
	}
	if b.Len() == 0 {
		return nil
	}
	_, e = k.run("ipset", b.String(), "restore")
	return e
}
func (k *IPTables) RestoreCounters(records []counterRecord) error {
	if k.Native != nil {
		return k.Native.restore(records, false)
	}
	if len(records) == 0 {
		return nil
	}
	sets, e := k.counterSets()
	if e != nil {
		return e
	}
	var b strings.Builder
	for _, r := range records {
		if !accountingSet(r.Set) {
			return fmt.Errorf("foreign counter set in journal")
		}
		if old, ok := sets[r.Set][r.Key]; ok {
			if old.Comment != r.Comment {
				return fmt.Errorf("counter ownership changed during recovery")
			}
			continue
		}
		fmt.Fprintf(&b, "add %s %s packets %d bytes %d comment %s\n", r.Set, r.Key, r.Packets, r.Bytes, r.Comment)
	}
	if b.Len() == 0 {
		return nil
	}
	_, e = k.run("ipset", b.String(), "restore")
	return e
}
