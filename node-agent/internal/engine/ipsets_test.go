package engine

import (
	"fmt"
	"strings"
	"testing"
)

func TestPacketPathDoesNotGrowWithForwardCount(t *testing.T) {
	for _, n := range []int{2, 100, 1000} {
		rules := map[string]Spec{}
		for i := 1; i <= n; i++ {
			s := valid()
			s.ID = fmt.Sprintf("%d_1_0", i)
			s.Token = uint32(i)
			s.ListenPort = 10000 + i
			rules[s.ID] = s
		}
		tables := Render(rules, nil)
		if got := strings.Count(tables["mangle"], "-A FP_MARK "); got != 5 {
			t.Fatalf("%d forwards generate %d packet classification rules", n, got)
		}
		if got := strings.Count(tables["filter"], "-A "); got != 8 {
			t.Fatalf("%d forwards generate %d filter rules", n, got)
		}
		if strings.Contains(tables["filter"], "--ctorigdstport") || strings.Contains(tables["mangle"], "--dport") {
			t.Fatal("linear per-forward packet rules remain")
		}
		if strings.Contains(tables["nat"], "-A FP_PRE -p tcp") {
			t.Fatal("first-packet NAT dispatch is still flat")
		}
	}
}
func TestSetParserHandlesMaskedMarksAndStableComments(t *testing.T) {
	data := `create FPV2_UP hash:ip,mark family inet markmask 0xffffff00 counters comment
add FPV2_UP 192.0.2.255,0x0 packets 0 bytes 0 comment "flux-owner:v2"
add FPV2_UP 10.0.0.2,0xf1000100 packets 2 bytes 123 comment "flux:v2:1_2_3:up"
add FPV2_UP 10.0.0.3,4043309312 packets 3 bytes 456 comment "flux:v2:1_2_3:up"
`
	v := parseSet(data)
	if len(v) != 3 || v["10.0.0.2,0xf1000100"].Bytes != 123 {
		t.Fatal(v)
	}
	if canonicalSetKey("10.0.0.2,0xf10001ff") != "10.0.0.2,0xf1000100" {
		t.Fatal("unowned low mark bits were not masked")
	}
}
func TestTokensStayStableAndFailedReservationsAreNotReused(t *testing.T) {
	m, k := fixture(t)
	a := valid()
	a.Token = 500
	if e := m.Apply(a); e != nil {
		t.Fatal(e)
	}
	first := m.Rules()[a.ID].Token
	if first == 0 || first == 500 {
		t.Fatal("external token was trusted")
	}
	if e := m.Change(a.ID, 2, false, false); e != nil {
		t.Fatal(e)
	}
	if m.Rules()[a.ID].Token != first {
		t.Fatal("pause changed the connection identity")
	}
	b := valid()
	b.ID = "2_2_3"
	b.ListenPort++
	k.fail = true
	if e := m.Apply(b); e == nil {
		t.Fatal("injected restore failure not returned")
	}
	reserved := m.state.NextToken
	c := valid()
	c.ID = "3_2_3"
	c.ListenPort += 2
	if e := m.Apply(c); e != nil {
		t.Fatal(e)
	}
	if m.Rules()[c.ID].Token < reserved {
		t.Fatal("a possibly exposed token was reused")
	}
}
