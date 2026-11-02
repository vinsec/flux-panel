package engine

import "testing"

func TestShapingGroupChangeAllocatesNewLeafInsteadOfReparenting(t *testing.T) {
	x := &Auxiliary{classes: map[string]uint16{}}
	s := Spec{ID: "1_1_0", Enabled: true, Token: 1, AdvancedOptions: &AdvancedOptions{Bandwidth: BandwidthPolicy{UpBitsPerSecond: 8000000, DownBitsPerSecond: 8000000}}}
	old, _, e := x.shapePlan(map[string]Spec{s.ID: s})
	if e != nil {
		t.Fatal(e)
	}
	s.Bandwidth.User = BandwidthGroup{ID: "different-user", UpBitsPerSecond: 8000000, DownBitsPerSecond: 8000000}
	next, _, e := x.shapePlan(map[string]Spec{s.ID: s})
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range old {
		if a.Depth != 3 {
			continue
		}
		for _, b := range next {
			if b.Depth == 3 && a.ID == b.ID {
				t.Fatal("HTB leaf was reused across a parent change")
			}
		}
	}
	s.Bandwidth.UpBitsPerSecond = 4000000
	rates, _, e := x.shapePlan(map[string]Spec{s.ID: s})
	if e != nil {
		t.Fatal(e)
	}
	for key, a := range next {
		if b, ok := rates[key]; !ok || a.ID != b.ID {
			t.Fatal("rate-only changes must preserve class identity")
		}
	}
}
