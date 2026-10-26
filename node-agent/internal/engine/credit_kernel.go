package engine

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

const creditSet = "FPV3_CREDIT"
const limitedSet = "FPV3_LIMITED"
const liveSet = "FPV3_LIVE"
const gateComment = "flux-transaction:v3"

func (k *IPTables) Quiesce() error { return k.QuiesceTokens(nil) }
func (k *IPTables) quiesceBaseTokens(tokens []uint32) error {
	marks := []string{mark}
	if len(tokens) > 0 && len(tokens) <= 16 {
		marks = nil
		for _, token := range tokens {
			if token == 0 || token > 65535 {
				return fmt.Errorf("invalid transaction token")
			}
			marks = append(marks, fmt.Sprintf("0x%08x/%s", uint32(0xf1000000)|(token<<8), markMask))
		}
	}
	for _, value := range marks {
		args := []string{"--wait", "2", "-t", "filter", "-C", "FORWARD", "-m", "connmark", "--mark", value, "-m", "comment", "--comment", gateComment, "-j", "DROP"}
		if _, e := k.run(k.Binary, "", args...); e == nil {
			continue
		}
		args[4] = "-I"
		args = append(args[:6], append([]string{"1"}, args[6:]...)...)
		if _, e := k.run(k.Binary, "", args...); e != nil {
			return e
		}
	}
	return nil
}
func (k *IPTables) gateRules() ([][]string, error) {
	saved, e := k.run(k.Binary+"-save", "", "-t", "filter")
	if e != nil {
		return nil, e
	}
	out := [][]string{}
	for _, line := range strings.Split(saved, "\n") {
		if !strings.HasPrefix(line, "-A FORWARD ") || !strings.Contains(line, gateComment) {
			continue
		}
		fields := strings.Fields(line)
		valid := false
		for i, field := range fields {
			fields[i] = strings.Trim(field, "\"")
			if field == "--mark" && i+1 < len(fields) && strings.HasPrefix(fields[i+1], "0xf1") {
				valid = true
			}
		}
		if !valid || fields[len(fields)-1] != "DROP" {
			return nil, fmt.Errorf("foreign rule uses the transaction marker")
		}
		out = append(out, fields)
	}
	return out, nil
}
func (k *IPTables) activateBase() error {
	rules, e := k.gateRules()
	if e != nil {
		return e
	}
	for _, rule := range rules {
		rule[0] = "-D"
		args := append([]string{"--wait", "2", "-t", "filter"}, rule...)
		if _, e = k.run(k.Binary, "", args...); e != nil {
			return e
		}
	}
	return nil
}
func (k *IPTables) BootID() string {
	b, e := k.run("cat", "", "/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "unknown"
	}
	return b
}
func (k *IPTables) syncBaseCredits(s State) error {
	text, e := k.readSet(creditSet)
	if e != nil {
		return e
	}
	existing := parseSet(text)
	delete(existing, "192.0.2.255,0x0")
	want := map[string]string{}
	liveWant := map[string]string{}
	limited := map[string]string{}
	now := bootMillis()
	for _, id := range keys(s.Rules) {
		r := s.Rules[id]
		if !r.Active() || !r.LeaseRequired {
			continue
		}
		key := targetKey(r)
		limited[key] = "comment flux:v3:" + id + ":limited"
		l, ok := s.Leases[id]
		if !ok || l.Closed || l.DeadlineBootMillis <= now {
			continue
		}
		owner := fmt.Sprintf("credit:%s:%d", l.Grant.ID, l.Grant.TotalGranted)
		want[key] = owner
		liveWant[key] = fmt.Sprint(secondsUntil(l.DeadlineBootMillis, now))
		if old, ok := existing[key]; ok && old.Comment == owner {
			continue
		}
		remaining := l.Grant.TotalGranted - used(&s, id, l)
		if remaining == 0 {
			delete(want, key)
			continue
		}
		seconds := (l.DeadlineBootMillis - now) / 1000
		if seconds < 1 {
			delete(want, key)
			continue
		} // floor expiry; never use ipset timeout=0 (permanent).
		if _, e = k.run("ipset", "", "-exist", "add", creditSet, key, "bytes", fmt.Sprint(creditCeiling-remaining), "packets", "0", "comment", owner); e != nil {
			return e
		}
	}
	for key, seconds := range liveWant {
		if seconds == "0" {
			continue
		}
		if _, e = k.run("ipset", "", "-exist", "add", liveSet, key, "timeout", seconds, "comment", "lease-live"); e != nil {
			return e
		}
	}
	liveSaved, e := k.readSet(liveSet)
	if e != nil {
		return e
	}
	for key, v := range parseSet(liveSaved) {
		if v.Comment == owner {
			continue
		}
		if _, ok := liveWant[key]; !ok {
			if _, e = k.run("ipset", "", "-exist", "del", liveSet, key); e != nil {
				return e
			}
		}
	}
	for key := range existing {
		if _, ok := want[key]; !ok {
			if _, e = k.run("ipset", "", "-exist", "del", creditSet, key); e != nil {
				return e
			}
		}
	}
	// Limited-set membership is configuration; updating it cannot extend credit.
	if e := k.updatePlainSet(limitedSet, limited); e != nil {
		return e
	}
	return k.updateBaseControl(s)
}
func (k *IPTables) updatePlainSet(name string, want map[string]string) error {
	saved, e := k.readSet(name)
	if e != nil {
		return e
	}
	old := parseSet(saved)
	delete(old, "192.0.2.255,0x0")
	list := []string{}
	for key := range old {
		if _, ok := want[key]; !ok {
			list = append(list, "del "+name+" "+key)
		}
	}
	for key, value := range want {
		if _, ok := old[key]; !ok {
			list = append(list, "add "+name+" "+key+" "+value)
		}
	}
	if len(list) == 0 {
		return nil
	}
	sort.Strings(list)
	_, e = k.run("ipset", strings.Join(list, "\n")+"\n", "-exist", "restore")
	return e
}

// TTL-only renewal updates only the non-counter live set. The permanent byte
// budget never gets recreated by expiry, and receives no counter writes.
func (k *IPTables) canRenewBaseCredits(before, after State) (bool, error) {
	saved, e := k.readSet(creditSet)
	if e != nil {
		return false, e
	}
	entries := parseSet(saved)
	now := bootMillis()
	changed := false
	for id, l := range after.Leases {
		old, ok := before.Leases[id]
		if reflect.DeepEqual(l, old) {
			continue
		}
		changed = true
		s, exists := after.Rules[id]
		if !ok || !exists || !s.Active() || l.Closed || old.Closed || l.Grant.ID != old.Grant.ID || l.Grant.TotalGranted != old.Grant.TotalGranted || old.DeadlineBootMillis-now < 1000 {
			return false, nil
		}
		v, present := entries[targetKey(s)]
		if !present || !strings.HasPrefix(v.Comment, "credit:"+old.Grant.ID+":") {
			return false, nil
		}
	}
	return changed, nil
}
func secondsUntil(deadline, now int64) int64 {
	n := (deadline - now) / 1000
	if n < 1 {
		return 0
	}
	return n
}
func (k *IPTables) renewBaseCredits(before, after State) error {
	now := bootMillis()
	for id, l := range after.Leases {
		old := before.Leases[id]
		if reflect.DeepEqual(l, old) {
			continue
		}
		seconds := secondsUntil(l.DeadlineBootMillis, now)
		if seconds < 1 {
			return fmt.Errorf("renewal deadline already elapsed")
		}
		key := targetKey(after.Rules[id])
		if _, e := k.run("ipset", "", "-exist", "add", liveSet, key, "timeout", fmt.Sprint(seconds), "comment", "lease-live"); e != nil {
			return e
		}
	}
	return nil
}
