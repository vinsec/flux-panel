package engine

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Counter labels are stable checkpoint identities, not ipset resources.
const upSet = "FPV2_UP"
const downSet = "FPV2_DOWN"

func accountingSet(name string) bool {
	return name == upSet || name == downSet || name == "FP4_UP" || name == "FP4_DOWN" || name == "FP6_UP" || name == "FP6_DOWN"
}

const mark = "0xf1000000/0xff000000"
const markMask = "0xffffff00"

func keys(rules map[string]Spec) []string {
	r := make([]string, 0, len(rules))
	for k := range rules {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}

func flowMark(s Spec) uint32 {
	if s.Advanced() {
		return 0xf2000000 | (s.Token << 8)
	}
	return 0xf1000000 | (s.Token << 8)
}

func fullMark(s Spec) string { return fmt.Sprintf("0x%08x/%s", flowMark(s), markMask) }

// Render carries normalized business specs only. All kernel rules are native nftables.
func Render(rules map[string]Spec, _ map[string]uint64) map[string]string {
	plan := []Spec{}
	next := uint32(1)
	for _, s := range rules {
		if s.Token >= next {
			next = s.Token + 1
		}
	}
	for _, id := range keys(rules) {
		s := rules[id]
		if s.Token == 0 {
			s.Token = next
			next++
		}
		plan = append(plan, s)
	}
	b, _ := json.Marshal(plan)
	return map[string]string{"kernel_plan": string(b)}
}
func decodePlan(tables map[string]string) ([]Spec, error) {
	var p []Spec
	e := json.Unmarshal([]byte(tables["kernel_plan"]), &p)
	return p, e
}
