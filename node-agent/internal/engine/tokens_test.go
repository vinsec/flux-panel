package engine

import (
	"testing"
)

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
