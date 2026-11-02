package engine

import "testing"

func TestUDPSourceBindingInventory(t *testing.T) {
	b := udpBindings{exact: map[string]bool{}, wildcard: map[string]bool{}}
	if err := parseUDPBindings("ipv4", " sl local_address rem_address st\n 0: 0102CD0A:4A3C 00000000:0000 07\n 1: 00000000:4A38 00000000:0000 07\n", &b); err != nil {
		t.Fatal(err)
	}
	if !b.exact["ipv4/10.205.2.1/19004"] || !b.wildcard["ipv4/19000"] {
		t.Fatal(b)
	}
	if err := parseUDPBindings("ipv6", " 0: 020025FD000000000000000001000000:4A3C 00000000000000000000000000000000:0000 07\n", &b); err != nil {
		t.Fatal(err)
	}
	if !b.exact["ipv6/fd25:2::1/19004"] {
		t.Fatal(b)
	}
}
