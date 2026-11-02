package panel

import (
	"sync"
	"testing"
)

func TestManagedModeSwitchContractAndLedgerContinuity(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	tid := f.seedTunnel(node, "kernel")
	fid := f.seedForward(tid, 1)
	f.store().update("forward", fid, M{"inFlow": 12345, "outFlow": 6789})
	var mu sync.Mutex
	job := M{"status": "unknown"}
	failSwitch := false
	f.fakeNode(t, node, func(event M) M {
		mu.Lock()
		defer mu.Unlock()
		data := obj(event["data"])
		switch str(event["type"]) {
		case "GetCapabilities":
			return M{"message": "OK", "data": M{"kernelBackend": "nftables", "forwardingMode": "kernel", "capabilities": M{"features": M{"engineSwitch": true}}}}
		case "GetModeSwitchStatus":
			return M{"message": "OK", "data": job}
		case "SubmitModeSwitch":
			if failSwitch {
				return M{"message": "unsupported source policy", "success": false}
			}
			job = M{"id": data["id"], "from": "kernel", "to": data["mode"], "status": "running"}
			return M{"message": "OK", "data": job}
		}
		return nil
	})
	req := M{"nodeId": node, "id": "mode-contract-one", "mode": "gost"}
	r := f.post(t, "/api/v1/engine/switch-mode", req)
	if str(obj(r["data"])["status"]) != "running" {
		t.Fatal(r)
	}
	if str(f.store().get("node", node)["forwardingMode"]) != "kernel" {
		t.Fatal("desired mode committed before receipt")
	}
	// Pending mode transition must serialize against data-plane mutations.
	_, r, _ = f.request(t, "/api/v1/forward/pause", M{"id": fid}, f.token)
	if num(r["code"]) == 0 {
		t.Fatal("rule mutation escaped switch barrier")
	}
	mu.Lock()
	job["status"] = "succeeded"
	mu.Unlock()
	r = f.post(t, "/api/v1/engine/mode-switch-status", M{"nodeId": node})
	if str(obj(r["data"])["status"]) != "succeeded" || str(f.store().get("node", node)["forwardingMode"]) != "gost" {
		t.Fatal(r)
	}
	row := f.store().get("forward", fid)
	if num(row["inFlow"]) != 12345 || num(row["outFlow"]) != 6789 {
		t.Fatal("historical usage changed")
	}
	f.post(t, "/api/v1/engine/switch-mode", req) // Same ID is a receipt lookup.
	mu.Lock()
	failSwitch = true
	job = M{"status": "unknown"}
	mu.Unlock()
	r = f.post(t, "/api/v1/engine/switch-mode", M{"nodeId": node, "id": "mode-contract-two", "mode": "kernel"})
	if str(obj(r["data"])["status"]) != "failed" || str(f.store().get("node", node)["forwardingMode"]) != "gost" {
		t.Fatal(r)
	}
}
