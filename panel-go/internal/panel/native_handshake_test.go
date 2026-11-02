package panel

import "testing"

func TestNativeHandshakePreservesPanelProtocolBlockingPolicy(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	f.store().update("node", node, M{"http": 1, "tls": 1, "socks": 1})
	f.fakeNode(t, node)
	got := f.store().get("node", node)
	for _, key := range []string{"http", "tls", "socks"} {
		if num(got[key]) != 1 {
			t.Fatalf("native handshake erased %s: %v", key, got[key])
		}
	}
}
