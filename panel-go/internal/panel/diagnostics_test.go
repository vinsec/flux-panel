package panel

import (
	"sync/atomic"
	"testing"
)

func TestForwardDiagnosticsDefaultToICMPAndTCP(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	tunnel := f.seedTunnel(node, "kernel")
	rule := f.seedForward(tunnel, 1)
	var called atomic.Bool
	f.fakeNode(t, node, func(event M) M {
		if str(event["type"]) != "ProbeForward" {
			return nil
		}
		called.Store(true)
		return M{"message": "OK", "data": M{"probePerformed": true, "results": []M{{"target": "10.203.2.2", "port": 18002, "icmp": M{"sent": 4, "received": 0, "packetLoss": 100, "averageTime": nil}, "tcp": M{"sent": 2, "received": 2, "packetLoss": 0, "averageTime": 1.2}}}}}
	})
	r := f.post(t, "/api/v1/forward/diagnose", M{"forwardId": rule})
	if num(r["code"]) != 0 {
		t.Fatal(r)
	}
	d := obj(r["data"])
	result := obj(arr(d["results"])[0])
	if !called.Load() || !truth(d["probePerformed"]) || d["returnPath"] != nil || str(result["probeKind"]) != "icmpTcp" || !truth(result["success"]) || obj(result["icmp"])["averageTime"] != nil || num(obj(result["tcp"])["received"]) != 2 {
		t.Fatal(d)
	}
}

func TestNativeTunnelDiagnosticsNeverUseLegacyPing(t *testing.T) {
	for _, status := range []string{"applied", "absent", "failed"} {
		t.Run(status, func(t *testing.T) {
			f := setupDB(t)
			node := f.seedNode("kernel")
			tunnel := f.seedTunnel(node, "kernel")
			rule := f.seedForward(tunnel, 1)
			name, _ := serviceName(f.store(), f.store().get("forward", rule))
			events := f.fakeNode(t, node, func(event M) M {
				if str(event["type"]) == "GetForwardStatuses" {
					return M{"message": "OK", "data": M{name: M{"status": status}}}
				}
				return nil
			})
			response := f.post(t, "/api/v1/tunnel/diagnose", M{"tunnelId": tunnel})
			if num(response["code"]) != 0 {
				t.Fatal(response)
			}
			report := obj(response["data"])
			results := arr(report["results"])
			if len(results) != 1 {
				t.Fatal(report)
			}
			result := obj(results[0])
			if str(result["probeKind"]) != "runtimeState" || truth(result["success"]) != (status == "applied") || num(result["checkedForwards"]) != 1 || truth(report["probePerformed"]) {
				t.Fatal(report)
			}
			for {
				select {
				case event := <-events:
					if str(event["type"]) == "TcpPing" {
						t.Fatal("native diagnostic attempted public legacy probe")
					}
				default:
					return
				}
			}
		})
	}
}
