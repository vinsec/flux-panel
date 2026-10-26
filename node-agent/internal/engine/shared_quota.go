package engine

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

const quotaTable = "FP4_QUOTA"

type nativeQuota struct {
	Name    string `json:"name"`
	Bytes   uint64 `json:"bytes"`
	Used    uint64 `json:"used"`
	Comment string `json:"comment"`
}
type SharedQuota struct {
	parent     *IPTables
	ready      bool
	hook       bool
	localHooks bool
	localSets  bool
	shape      string
}

func quotaName(s Spec, l Lease) string {
	return fmt.Sprintf("q_%04x_%s_%x", s.Token, l.Grant.ID, l.Grant.TotalGranted)
}
func (q *SharedQuota) ensure() error {
	if q.ready {
		return nil
	}
	saved, e := q.parent.run("nft", "", "-j", "list", "table", "inet", quotaTable)
	if e == nil {
		if !strings.Contains(saved, advancedOwner) {
			return fmt.Errorf("shared quota table has foreign ownership")
		}
		q.ready = true
		var parsed struct {
			NFT []struct {
				Chain *struct {
					Name string `json:"name"`
					Hook string `json:"hook"`
				} `json:"chain"`
				Set *struct {
					Name string `json:"name"`
				} `json:"set"`
			} `json:"nftables"`
		}
		_ = json.Unmarshal([]byte(saved), &parsed)
		localSets := map[string]bool{}
		for _, item := range parsed.NFT {
			if item.Set != nil {
				localSets[item.Set.Name] = true
			}
			if item.Chain != nil && item.Chain.Name == "gate" && item.Chain.Hook == "forward" {
				q.hook = true
			}
			if item.Chain != nil && item.Chain.Name == "gate_input" && item.Chain.Hook == "input" {
				q.localHooks = true
			}
		}
		q.localSets = localSets["lorig"] && localSets["ltarg"]
		return nil
	}
	text := fmt.Sprintf("add table inet %s\nadd chain inet %s owner\nadd rule inet %s owner return comment \"%s\"\nadd set inet %s required { type mark; }\nadd set inet %s live { type mark; flags timeout; }\nadd map inet %s budgets { type mark : quota; }\n", quotaTable, quotaTable, quotaTable, advancedOwner, quotaTable, quotaTable, quotaTable)
	if _, e = q.parent.run("nft", text, "-f", "-"); e != nil {
		return e
	}
	q.ready = true
	return nil
}

func (q *SharedQuota) transactionGate(tokens []uint32, newOnly, remove bool) error {
	if e := q.ensure(); e != nil {
		return e
	}
	saved, e := q.parent.run("nft", "", "-j", "list", "table", "inet", quotaTable)
	if e != nil {
		return e
	}
	var document struct {
		NFT []struct {
			Chain *struct {
				Name string `json:"name"`
			} `json:"chain"`
		} `json:"nftables"`
	}
	if e = json.Unmarshal([]byte(saved), &document); e != nil {
		return e
	}
	existingChains := map[string]bool{}
	for _, item := range document.NFT {
		if item.Chain != nil {
			existingChains[item.Chain.Name] = true
		}
	}
	for _, token := range tokens {
		if token == 0 || token > 65535 {
			return fmt.Errorf("invalid transaction token")
		}
	}
	var b strings.Builder
	condition := ""
	if newOnly {
		condition = " ct status & confirmed == 0"
	}
	// Every packet terminates at INPUT, OUTPUT or FORWARD. These atomic drop
	// gates never meter, so a local-to-local packet cannot burn credit twice.
	for _, hook := range []string{"forward", "input", "output"} {
		chain := "transaction"
		if hook != "forward" {
			chain += "_" + hook
		}
		if remove {
			if existingChains[chain] {
				fmt.Fprintf(&b, "flush chain inet %s %s\ndelete chain inet %s %s\n", quotaTable, chain, quotaTable, chain)
			}
			continue
		}
		if existingChains[chain] {
			fmt.Fprintf(&b, "flush chain inet %s %s\n", quotaTable, chain)
		} else {
			fmt.Fprintf(&b, "add chain inet %s %s { type filter hook %s priority -10; policy accept; }\n", quotaTable, chain, hook)
		}
		if len(tokens) == 0 || len(tokens) > 16 {
			fmt.Fprintf(&b, "add rule inet %s %s ct mark & 0xff000000 == 0xf2000000%s drop\n", quotaTable, chain, condition)
		} else {
			for _, token := range tokens {
				fmt.Fprintf(&b, "add rule inet %s %s ct mark & 0xffffff00 == 0x%x%s drop\n", quotaTable, chain, uint32(0xf2000000)|(token<<8), condition)
			}
		}
	}
	if b.Len() == 0 {
		return nil
	}
	_, e = q.parent.run("nft", b.String(), "-f", "-")
	return e
}

func (q *SharedQuota) snapshot() (map[string]nativeQuota, error) {
	result := map[string]nativeQuota{}
	if !q.ready {
		return result, nil
	}
	saved, e := q.parent.run("nft", "", "-j", "list", "table", "inet", quotaTable)
	if e != nil {
		return nil, e
	}
	var document struct {
		NFT []struct {
			Quota *nativeQuota `json:"quota"`
		} `json:"nftables"`
	}
	if e = json.Unmarshal([]byte(saved), &document); e != nil {
		return nil, e
	}
	for _, item := range document.NFT {
		if item.Quota != nil {
			result[item.Quota.Name] = *item.Quota
		}
	}
	return result, nil
}
func (q *SharedQuota) sync(s State) error {
	required := []Spec{}
	for _, id := range keys(s.Rules) {
		rule := s.Rules[id]
		if rule.Advanced() && !rule.Deleted && rule.LeaseRequired && rule.Active() {
			required = append(required, rule)
		}
	}
	if len(required) == 0 && !q.ready {
		return nil
	}
	if e := q.ensure(); e != nil {
		return e
	}
	existing, e := q.snapshot()
	if e != nil {
		return e
	}
	var b strings.Builder
	if len(required) > 0 && !q.hook {
		fmt.Fprintf(&b, "add chain inet %s gate { type filter hook forward priority -5; policy accept; }\n", quotaTable)
		fmt.Fprintf(&b, "add rule inet %s gate meta l4proto { tcp, udp } ct mark & 0xffffff00 @required ct mark & 0xffffff00 != @live drop\n", quotaTable)
		fmt.Fprintf(&b, "add rule inet %s gate meta l4proto { tcp, udp } quota name ct mark & 0xffffff00 map @budgets drop\n", quotaTable)
	}
	needLocal := false
	for _, rule := range required {
		if rule.localTraffic() {
			needLocal = true
		}
	}
	if needLocal {
		if !q.localSets {
			fmt.Fprintf(&b, "add set inet %s lorig { type mark; }\nadd set inet %s ltarg { type mark; }\n", quotaTable, quotaTable)
		}
		fmt.Fprintf(&b, "flush set inet %s lorig\nflush set inet %s ltarg\n", quotaTable, quotaTable)
		for _, rule := range required {
			if q.parent.P1 != nil && q.parent.P1.runtimeErrors[rule.ID] != "" {
				continue
			}
			if rule.trafficPolicy().LocalOutput {
				fmt.Fprintf(&b, "add element inet %s lorig { 0x%x }\n", quotaTable, flowMark(rule))
			}
			if rule.trafficPolicy().LocalTargets {
				fmt.Fprintf(&b, "add element inet %s ltarg { 0x%x }\n", quotaTable, flowMark(rule))
			}
		}
		for _, hook := range []string{"input", "output"} {
			chain := "gate_" + hook
			if q.localHooks {
				fmt.Fprintf(&b, "flush chain inet %s %s\n", quotaTable, chain)
			} else {
				fmt.Fprintf(&b, "add chain inet %s %s { type filter hook %s priority -5; policy accept; }\n", quotaTable, chain, hook)
			}
			if hook == "input" {
				fmt.Fprintf(&b, "add rule inet %s %s iifname \"lo\" return\n", quotaTable, chain)
			}
			fmt.Fprintf(&b, "add rule inet %s %s ct status & dnat == 0 return\n", quotaTable, chain)
			origPolicy, replyPolicy := "ltarg", "lorig"
			if hook == "output" {
				origPolicy, replyPolicy = "lorig", "ltarg"
			}
			fmt.Fprintf(&b, "add rule inet %s %s ct direction original ct mark & 0xffffff00 != @%s return\nadd rule inet %s %s ct direction reply ct mark & 0xffffff00 != @%s return\n", quotaTable, chain, origPolicy, quotaTable, chain, replyPolicy)
			fmt.Fprintf(&b, "add rule inet %s %s meta l4proto { tcp, udp } ct mark & 0xffffff00 @required ct mark & 0xffffff00 != @live drop\n", quotaTable, chain)
			fmt.Fprintf(&b, "add rule inet %s %s meta l4proto { tcp, udp } quota name ct mark & 0xffffff00 map @budgets drop\n", quotaTable, chain)
		}
	}
	if !needLocal && q.localHooks {
		for _, hook := range []string{"input", "output"} {
			fmt.Fprintf(&b, "flush chain inet %s gate_%s\ndelete chain inet %s gate_%s\n", quotaTable, hook, quotaTable, hook)
		}
	}
	if len(required) == 0 && q.hook {
		fmt.Fprintf(&b, "flush chain inet %s gate\ndelete chain inet %s gate\n", quotaTable, quotaTable)
	}
	fmt.Fprintf(&b, "flush set inet %s required\nflush set inet %s live\nflush map inet %s budgets\n", quotaTable, quotaTable, quotaTable)
	want := map[string]bool{}
	for _, rule := range required {
		fmt.Fprintf(&b, "add element inet %s required { 0x%x }\n", quotaTable, flowMark(rule))
		lease, ok := s.Leases[rule.ID]
		if q.parent.P1 != nil && q.parent.P1.runtimeErrors[rule.ID] != "" {
			continue
		}
		if !ok || lease.Closed || lease.DeadlineBootMillis-bootMillis() < 1000 {
			continue
		}
		remaining := lease.Grant.TotalGranted - used(&s, rule.ID, lease)
		if remaining == 0 {
			continue
		}
		name := quotaName(rule, lease)
		want[name] = true
		if _, exists := existing[name]; !exists {
			fmt.Fprintf(&b, "add quota inet %s %s { over %d bytes; comment \"%s:%s\"; }\n", quotaTable, name, remaining, advancedOwner, lease.Grant.ID)
		}
		fmt.Fprintf(&b, "add element inet %s budgets { 0x%x : \"%s\" }\nadd element inet %s live { 0x%x timeout %ds }\n", quotaTable, flowMark(rule), name, quotaTable, flowMark(rule), secondsUntil(lease.DeadlineBootMillis, bootMillis()))
	}
	for name, entry := range existing {
		if !want[name] {
			if !strings.HasPrefix(entry.Comment, advancedOwner+":") {
				return fmt.Errorf("foreign object in shared quota table")
			}
			fmt.Fprintf(&b, "delete quota inet %s %s\n", quotaTable, name)
		}
	}
	if _, e = q.parent.run("nft", b.String(), "-c", "-f", "-"); e != nil {
		return e
	}
	if _, e = q.parent.run("nft", b.String(), "-f", "-"); e != nil {
		return e
	}
	q.hook = len(required) > 0
	q.localHooks = needLocal
	if needLocal {
		q.localSets = true
	}
	return nil
}
func (q *SharedQuota) canRenew(before, after State) (bool, error) {
	objects, e := q.snapshot()
	if e != nil {
		return false, e
	}
	for id, lease := range after.Leases {
		rule := after.Rules[id]
		if !rule.Advanced() {
			continue
		}
		old := before.Leases[id]
		if reflect.DeepEqual(old, lease) {
			continue
		}
		if lease.Closed || old.Closed || !rule.Active() || lease.Grant.ID != old.Grant.ID || lease.Grant.TotalGranted != old.Grant.TotalGranted || old.DeadlineBootMillis-bootMillis() < 1000 {
			return false, nil
		}
		if _, ok := objects[quotaName(rule, old)]; !ok {
			return false, nil
		}
	}
	return true, nil
}
func (q *SharedQuota) renew(after State) error {
	if !q.ready {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s live\n", quotaTable)
	for _, id := range keys(after.Rules) {
		rule := after.Rules[id]
		if !rule.Advanced() || !rule.Active() || !rule.LeaseRequired {
			continue
		}
		if q.parent.P1 != nil && q.parent.P1.runtimeErrors[id] != "" {
			continue
		}
		l, ok := after.Leases[id]
		if !ok || l.Closed {
			continue
		}
		seconds := secondsUntil(l.DeadlineBootMillis, bootMillis())
		if seconds > 0 && used(&after, id, l) < l.Grant.TotalGranted {
			fmt.Fprintf(&b, "add element inet %s live { 0x%x timeout %ds }\n", quotaTable, flowMark(rule), seconds)
		}
	}
	_, e := q.parent.run("nft", b.String(), "-f", "-")
	return e
}
