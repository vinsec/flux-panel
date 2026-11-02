package panel

import "testing"

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
