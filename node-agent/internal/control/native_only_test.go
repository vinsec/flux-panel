package control

import "testing"

func TestRetiredBackendCannotSelectAnyControlPath(t *testing.T) {
	for _, c := range []Config{
		{Addr: "wss://panel.invalid", KernelBackend: "iptables"},
		{Addr: "wss://panel.invalid", Iptables: "iptables-nft"},
		{Addr: "wss://panel.invalid", KernelBackend: "unknown"},
	} {
		if _, _, e := c.URLs(); e == nil {
			t.Fatal("retired backend accepted")
		}
	}
	for _, backend := range []string{"", "nftables"} {
		c := Config{Addr: "wss://panel.invalid", KernelBackend: backend}
		if _, _, e := c.URLs(); e != nil {
			t.Fatal(e)
		}
	}
}
