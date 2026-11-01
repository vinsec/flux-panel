package panel

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCreditPriceFreezeRollbackAndMaintenance(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	f.fakeNode(t, node)
	tunnel := f.seedTunnel(node, "kernel")
	uid := f.seedUser()
	permission := f.seedPermission(tunnel, uid)
	fid := f.seedForward(tunnel, uid)
	name := fmt.Sprintf("%d_%d_%d", fid, uid, permission)
	f.p.cfg.LeaseMaxBytes = 1024
	f.p.enableCredit(f.store(), node)
	n := f.store().get("node", node)
	epoch := strings.Repeat("d", 32)
	report := M{"epoch": epoch, "bootId": "boot-test", "sequence": 1, "usage": []M{{"id": name, "up": 0, "down": 0}}, "requests": []string{name}, "leases": []any{}}
	ack := f.p.exchange(f.store(), n, report, false)
	grants := arr(ack["grants"])
	if len(grants) != 1 {
		t.Fatal(ack)
	}
	grant := obj(grants[0])
	if num(grant["totalGranted"]) != 1024 {
		t.Fatal(grant)
	}
	f.store().update("tunnel", tunnel, M{"trafficRatio": "2.0"})
	closed := M{"id": grant["id"], "serviceId": name, "generation": grant["generation"], "used": 120, "closed": true}
	final := M{"epoch": epoch, "bootId": "boot-test", "sequence": 2, "usage": []M{{"id": name, "up": 100, "down": 20}}, "requests": []any{}, "leases": []M{closed}}
	ack = f.p.exchange(f.store(), n, final, false)
	u := f.store().get("user", uid)
	if num(u["inFlow"]) != 100 || num(u["outFlow"]) != 20 {
		t.Fatalf("old lease price was changed: %s", jsonText(u))
	}
	lease := f.store().one("SELECT * FROM engine_credit_lease WHERE lease_id=?", grant["id"])
	if num(lease["reservedBill"]) != 0 || num(lease["closed"]) != 1 {
		t.Fatal("unused reservation not returned")
	}
	restarted := New(f.db, f.p.cfg)
	replayed := restarted.exchange(f.store(), n, final, false)
	restarted.Close()
	if jsonText(ack) != jsonText(replayed) || num(f.store().get("user", uid)["inFlow"]) != 100 {
		t.Fatal("process restart replay changed accounting")
	}
	invalid := decode([]byte(jsonText(final)))
	invalid["sequence"] = 3
	invalid["usage"] = []M{{"id": name, "up": 150, "down": 20}}
	badClaim := decode([]byte(jsonText(closed)))
	badClaim["used"] = 0
	invalid["leases"] = []M{badClaim}
	if panicMessage(func() { f.p.exchange(f.store(), n, invalid, false) }) == "" {
		t.Fatal("invalid final claim accepted")
	}
	if num(f.store().get("user", uid)["inFlow"]) != 100 {
		t.Fatal("transaction failure partially billed")
	}
	if num(f.store().one("SELECT up_bytes FROM engine_usage WHERE node_id=? AND epoch=? AND service_id=?", node, epoch, name)["upBytes"]) != 100 {
		t.Fatal("failed transaction advanced watermark")
	}
	final["sequence"] = 3
	final["leases"] = []any{}
	ack = f.p.exchange(f.store(), n, final, true)
	if !truth(ack["maintenanceAccepted"]) || num(f.store().get("forward", fid)["status"]) != 0 {
		t.Fatal("maintenance did not pause durable business state")
	}
	if !truth(f.p.exchange(f.store(), n, final, true)["maintenanceAccepted"]) {
		t.Fatal("maintenance replay failed")
	}
}
func TestExclusiveOwnerAndLostConnectionFailClosed(t *testing.T) {
	f := setupDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.p.Start(ctx)
	other := New(f.db, f.p.cfg)
	if panicMessage(func() { other.Start(ctx) }) == "" {
		t.Fatal("second Go writer acquired execution right")
	}
	other.Close()
	row := store{f.p.leader, context.Background()}.one("SELECT CONNECTION_ID() id")
	f.store().exec("KILL CONNECTION " + str(row["id"]))
	deadline := time.Now().Add(7 * time.Second)
	for {
		f.p.mu.Lock()
		lost := f.p.writeFailed
		f.p.mu.Unlock()
		if lost {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lost owner kept mutation rights")
		}
		time.Sleep(25 * time.Millisecond)
	}
	status, _, _ := f.request(t, "/api/v1/node/create", M{}, f.token)
	if status != 503 {
		t.Fatal("lost owner accepted writes")
	}
	f.p.Close()
	next := New(f.db, f.p.cfg)
	next.Start(ctx)
	next.Close()
}

func TestEngineProtocolHTTPErrorShapes(t *testing.T) {
	f := setupDB(t)
	status, m, _ := f.request(t, "/flow/engine/v1/traffic", M{}, "")
	if status != 401 || str(m["error"]) != "engine protocol rejected" {
		t.Fatal(status, m)
	}
	node := f.seedNode("kernel")
	secret := str(f.store().get("node", node)["secret"])
	status, m, _ = f.request(t, "/flow/engine/v2/traffic", M{"epoch": "bad", "sequence": 1, "usage": []any{}}, "Bearer "+secret)
	if status != 400 || m["error"] == nil {
		t.Fatal(status, m)
	}
	status, m, _ = f.request(t, "/flow/engine/v2/traffic", M{"epoch": strings.Repeat("e", 32), "bootId": "array-contract", "sequence": 1, "usage": []any{}}, "Bearer "+secret)
	if status != 200 || m["leaseWatermarks"] == nil {
		t.Fatal("omitted leases must acknowledge an empty array", status, m)
	}
	status, m, _ = f.request(t, "/flow/engine/v3/session", M{}, "Bearer invalid")
	if status != 200 || num(m["code"]) != -2 {
		t.Fatal(status, m)
	}
}

func TestRapidSocketRotationCannotLeaveLiveNodeOffline(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	f.fakeNode(t, node)
	for i := 0; i < 20; i++ {
		f.p.mu.Lock()
		old := f.p.nodes[node]
		f.p.mu.Unlock()
		old.close()
		f.fakeNode(t, node)
		deadline := time.Now().Add(2 * time.Second)
		for {
			f.p.mu.Lock()
			current := f.p.nodes[node]
			f.p.mu.Unlock()
			online := num(f.store().get("node", node)["status"]) == 1
			if current != nil && current != old && online {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("live replacement left offline status")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestCanceledMutationReleasesPhysicalPortLock(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	tid := f.seedTunnel(node, "kernel")
	tunnel := f.store().get("tunnel", tid)
	other, e := f.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	ctx, cancel := context.WithCancel(context.Background())
	f.p.withPort(store{f.db, ctx}, tunnel, func(store) any { cancel(); return nil })
	key := "flux-port-" + digest("10.203.2.1")[:40]
	row := store{other, context.Background()}.one("SELECT IS_FREE_LOCK(?) available", key)
	if num(row["available"]) != 1 {
		t.Fatal("canceled request leaked a named lock into the connection pool")
	}
}

func TestAdministrativeCascadeWithOfflineNodes(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	f.store().update("node", node, M{"status": 0})
	tid := f.seedTunnel(node, "kernel")
	uid := f.seedUser()
	permission := f.seedPermission(tid, uid)
	fid := f.seedForward(tid, uid)
	f.post(t, "/api/v1/user/delete", M{"id": uid})
	if f.store().get("user", uid) != nil || f.store().get("forward", fid) != nil || f.store().get("user_tunnel", permission) != nil {
		t.Fatal("offline account cascade incomplete")
	}
	uid = f.seedUser()
	permission = f.seedPermission(tid, uid)
	fid = f.seedForward(tid, uid)
	f.post(t, "/api/v1/tunnel/user/remove", M{"id": permission})
	if f.store().get("forward", fid) != nil || f.store().get("user_tunnel", permission) != nil {
		t.Fatal("offline permission cascade incomplete")
	}
}
func TestNativeAuditActionCompatibility(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	f.fakeNode(t, node)
	tid := f.seedTunnel(node, "kernel")
	f.post(t, "/api/v1/forward/create", M{"name": "audit-test", "tunnelId": tid, "remoteAddr": "10.203.2.2:18002", "inPort": 18001})
	row := f.store().one("SELECT * FROM forward WHERE name='audit-test'")
	f.post(t, "/api/v1/forward/update", M{"id": row["id"], "userId": 1, "name": "audit-test", "tunnelId": tid, "remoteAddr": "10.203.2.2:18003", "inPort": 18001})
	records := f.store().rows("SELECT action FROM engine_audit WHERE node_id=? ORDER BY id", node)
	if len(records) != 2 || str(records[0]["action"]) != "CREATE_FORWARD" || str(records[1]["action"]) != "UPDATE_FORWARD" {
		t.Fatal("Java audit actions changed", records)
	}
}

func TestReconnectWaitsForActualCapabilityAdvertisement(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	ready := make(chan struct{})
	go func() { defer close(ready); time.Sleep(100 * time.Millisecond); f.fakeNode(t, node) }()
	started := time.Now()
	f.p.requireCapability(node, "dns")
	f.p.verifyAgent(f.store(), node)
	<-ready
	if time.Since(started) < 80*time.Millisecond {
		t.Fatal("accepted capabilities before live node advertisement")
	}
}

func TestActualCommandSessionMustAdvertiseNftables(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	events := f.fakeNode(t, node)
	for len(events) > 0 {
		<-events
	}
	f.p.mu.Lock()
	peer := f.p.nodes[node]
	f.p.mu.Unlock()
	peer.mu.Lock()
	mismatch := decode([]byte(jsonText(peer.info)))
	mismatch["kernelBackend"] = "iptables"
	peer.info = mismatch
	peer.mu.Unlock()
	r := f.p.rpc(node, M{"id": "1_1_0"}, "ApplyForward")
	if str(r["message"]) == "OK" {
		t.Fatal("mismatched actual session accepted kernel command")
	}
	select {
	case e := <-events:
		if str(e["type"]) == "ApplyForward" {
			t.Fatal("command sent before actual backend check")
		}
	default:
	}
}

func TestConcurrentCatalogAndPermissionsStayUnique(t *testing.T) {
	f := setupDB(t)
	var wg sync.WaitGroup
	codes := make(chan int64, 12)
	body := M{"user": "same-concurrent-name", "pwd": "test-password", "flow": 1, "num": 1, "expTime": now() + 86400000, "flowResetTime": 0}
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, r, _ := f.request(t, "/api/v1/user/create", body, f.token)
			codes <- num(r["code"])
		}()
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 0 {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("username successes %d", success)
	}
	node := f.seedNode("kernel")
	tid := f.seedTunnel(node, "kernel")
	uid := num(f.store().one("SELECT id FROM user WHERE user='same-concurrent-name'")["id"])
	permission := M{"userId": uid, "tunnelId": tid, "flow": 1, "num": 1, "flowResetTime": 0, "expTime": now() + 86400000}
	codes = make(chan int64, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, r, _ := f.request(t, "/api/v1/tunnel/user/assign", permission, f.token)
			codes <- num(r["code"])
		}()
	}
	wg.Wait()
	close(codes)
	success = 0
	for code := range codes {
		if code == 0 {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("permission successes %d", success)
	}
}
func TestAuthorizationRemovalSerializesWithCreation(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	f.fakeNode(t, node)
	tid := f.seedTunnel(node, "kernel")
	uid := f.seedUser()
	pid := f.seedPermission(tid, uid)
	token := f.p.token(f.store().get("user", uid))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f.request(t, "/api/v1/forward/create", M{"name": fmt.Sprintf("racing-%d", i), "tunnelId": tid, "inPort": 18010 + i, "remoteAddr": "10.203.2.2:18002"}, token)
		}(i)
	}
	wg.Add(1)
	go func() { defer wg.Done(); f.post(t, "/api/v1/tunnel/user/remove", M{"id": pid}) }()
	wg.Wait()
	if num(f.store().one("SELECT COUNT(*) n FROM forward WHERE user_id=?", uid)["n"]) != 0 {
		t.Fatal("forward appeared after its permission was removed")
	}
	f.p.mu.Lock()
	remaining := len(f.p.owners)
	f.p.mu.Unlock()
	if remaining != 0 {
		t.Fatal("owner gate references leaked")
	}
}

func TestConcurrentTunnelNamesStayUnique(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	var wg sync.WaitGroup
	codes := make(chan int64, 8)
	body := M{"name": "same-tunnel", "engine": "kernel", "inNodeId": node, "type": 1, "flow": 1}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, r, _ := f.request(t, "/api/v1/tunnel/create", body, f.token)
			codes <- num(r["code"])
		}()
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 0 {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("tunnel successes %d", success)
	}
}

func TestMissingServiceDoesNotSkipOtherCascadeCleanup(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("gost")
	var deletes atomic.Int32
	f.fakeNode(t, node, func(event M) M {
		if str(event["type"]) == "DeleteService" && deletes.Add(1) == 1 {
			return M{"message": "service not found"}
		}
		return nil
	})
	tid := f.seedTunnel(node, "gost")
	uid := f.seedUser()
	f.seedPermission(tid, uid)
	f.seedForward(tid, uid)
	f.seedForward(tid, uid)
	f.post(t, "/api/v1/user/delete", M{"id": uid})
	if deletes.Load() != 2 {
		t.Fatal("a missing service suppressed cleanup of a different live service")
	}
}

func TestFailedGostRelayCreationCompensatesBothNodes(t *testing.T) {
	f := setupDB(t)
	entry, exit := f.seedNode("gost"), f.seedNode("gost")
	f.store().update("node", exit, M{"serverIp": "10.203.2.2"})
	inEvents := f.fakeNode(t, entry, func(e M) M {
		if str(e["type"]) == "AddService" {
			return M{"message": "listener busy"}
		}
		return nil
	})
	outEvents := f.fakeNode(t, exit)
	tid := f.seedTunnel(entry, "gost")
	f.store().update("tunnel", tid, M{"type": 2, "outNodeId": exit, "outIp": "10.203.2.2", "protocol": "tls"})
	_, result, _ := f.request(t, "/api/v1/forward/create", M{"name": "failed-relay", "tunnelId": tid, "inPort": 18001, "remoteAddr": "10.203.2.2:18002"}, f.token)
	if num(result["code"]) == 0 {
		t.Fatal("failed relay reported success")
	}
	foundMain, foundChain, foundRemote := false, false, false
	for len(inEvents) > 0 {
		e := <-inEvents
		if str(e["type"]) == "DeleteService" {
			foundMain = true
		}
		if str(e["type"]) == "DeleteChains" {
			foundChain = true
		}
	}
	for len(outEvents) > 0 {
		if str((<-outEvents)["type"]) == "DeleteService" {
			foundRemote = true
		}
	}
	if !foundMain || !foundChain || !foundRemote {
		t.Fatal("partial relay components were left behind")
	}
	if num(f.store().one("SELECT COUNT(*) n FROM forward")["n"]) != 0 {
		t.Fatal("failed creation retained a successful DB row")
	}
}
func TestFailedGostUpdateStaysVisibleAndQuotaEnforced(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("gost")
	f.fakeNode(t, node, func(e M) M {
		if str(e["type"]) == "UpdateService" {
			return M{"message": "listener busy"}
		}
		return nil
	})
	tid := f.seedTunnel(node, "gost")
	uid := f.seedUser()
	f.seedPermission(tid, uid)
	fid := f.seedForward(tid, uid)
	_, r, _ := f.request(t, "/api/v1/forward/update", M{"id": fid, "userId": uid, "name": "update-failure", "tunnelId": tid, "inPort": 18001, "remoteAddr": "10.203.2.2:18003"}, f.token)
	if num(r["code"]) == 0 || num(f.store().get("forward", fid)["status"]) != -1 {
		t.Fatal("failed GOST update was shown as active success")
	}
	f.store().update("user", uid, M{"inFlow": (1 << 30) + 1})
	if len(invalidQuotaRows(f.store(), uid)) != 1 {
		t.Fatal("error-state live service escaped quota enforcement")
	}
}

func TestRebootWithoutFinalClaimKeepsOutstandingReservation(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	f.fakeNode(t, node)
	tid := f.seedTunnel(node, "kernel")
	uid := f.seedUser()
	pid := f.seedPermission(tid, uid)
	fid := f.seedForward(tid, uid)
	name := fmt.Sprintf("%d_%d_%d", fid, uid, pid)
	f.p.cfg.LeaseMaxBytes = 1024
	f.p.enableCredit(f.store(), node)
	epoch := strings.Repeat("f", 32)
	n := f.store().get("node", node)
	ack := f.p.exchange(f.store(), n, M{"epoch": epoch, "bootId": "boot-test", "sequence": 1, "usage": []any{}, "requests": []string{name}}, false)
	grant := obj(arr(ack["grants"])[0])
	f.p.mu.Lock()
	peer := f.p.nodes[node]
	f.p.mu.Unlock()
	peer.mu.Lock()
	info := decode([]byte(jsonText(peer.info)))
	info["bootId"] = "boot-new"
	peer.info = info
	peer.mu.Unlock()
	f.p.exchange(f.store(), n, M{"epoch": epoch, "bootId": "boot-new", "sequence": 2, "usage": []any{}}, false)
	row := f.store().one("SELECT reserved_bill,closed,lost FROM engine_credit_lease WHERE lease_id=?", grant["id"])
	if num(row["reservedBill"]) != 1024 || num(row["closed"]) != 0 || num(row["lost"]) != 1 {
		t.Fatal("reboot guessed unused credit and released it", row)
	}
}
