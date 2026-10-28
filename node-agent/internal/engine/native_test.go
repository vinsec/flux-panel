package engine

import (
	"fmt"
	"strings"
	"testing"
)

func TestNativeCounterIdentity(t *testing.T) {
	s := Spec{ID: "1_2_3", Token: 14}
	r := nativeRecord(s, "192.0.2.1", "ipv4", "up")
	r.Bytes = 123
	r.Packets = 3
	c := nativeCounter{Name: nativeCounterName(r), Comment: encodeNativeCounter(r), Bytes: r.Bytes, Packets: r.Packets}
	got, e := decodeNativeCounter(c)
	if e != nil || got != r {
		t.Fatal(got, e)
	}
	c.Name = "c_foreign"
	if _, e = decodeNativeCounter(c); e == nil {
		t.Fatal("counter substitution accepted")
	}
	if _, e = nativeTuple("192.0.2.1,0xf1000100;flush ruleset"); e == nil {
		t.Fatal("invalid journal tuple accepted")
	}
}

func TestNativeMapScaleAndPersistentCounters(t *testing.T) {
	rules := map[string]Spec{}
	for i := 1; i <= 10000; i++ {
		s := Spec{ID: fmt.Sprintf("%d_1_0", i), Token: uint32(i), Revision: 1, Enabled: true, ListenIP: "192.0.2.1", ListenPort: 20000 + i, TargetIP: "198.51.100.1", TargetPort: 19000}
		rules[s.ID] = s
	}
	text, e := compileNative(rules, map[string][]string{"ipv4": {"192.0.2.1"}}, map[string]counterRecord{})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(text, "iptables") || strings.Contains(text, "flush ruleset") || strings.Contains(text, "delete table") {
		t.Fatal("not an isolated native transaction")
	}
	if strings.Count(text, "add counter inet") != 20000 {
		t.Fatal("incorrect persistent counter cardinality")
	}
	if strings.Count(text, "add rule inet") > 100 {
		t.Fatal("packet path grew with forwarding count")
	}
	for _, fragment := range []string{"map @bind4", "map @dnat4", "map @up4", "map @down4", "vmap @multi4"} {
		if !strings.Contains(text, fragment) {
			t.Fatal(fragment)
		}
	}
	existing := map[string]counterRecord{}
	for _, s := range rules {
		for _, direction := range []string{"up", "down"} {
			r := nativeRecord(s, s.TargetIP, "ipv4", direction)
			r.Bytes = 99
			existing[nativeCounterName(r)] = r
		}
	}
	text, e = compileNative(rules, map[string][]string{"ipv4": {"192.0.2.1"}}, existing)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(text, "add counter") || strings.Contains(text, "reset counter") || strings.Contains(text, "delete counter") {
		t.Fatal("configuration rewrites cumulative counters")
	}
}

func TestNativePauseRetainsBindingWithoutNATOrAllowance(t *testing.T) {
	s := Spec{ID: "1_1_0", Token: 7, Revision: 2, Enabled: false, ListenIP: "192.0.2.1", ListenPort: 18000, TargetIP: "198.51.100.1", TargetPort: 19000}
	text, e := compileNative(map[string]Spec{s.ID: s}, map[string][]string{"ipv4": {"192.0.2.1"}}, map[string]counterRecord{})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(text, "add element inet FP_NATIVE bind4") {
		t.Fatal("paused listener lost classification")
	}
	if strings.Contains(text, "add element inet FP_NATIVE dnat4") || strings.Contains(text, "add element inet FP_NATIVE allow4") {
		t.Fatal("paused rule retained admission")
	}
}
