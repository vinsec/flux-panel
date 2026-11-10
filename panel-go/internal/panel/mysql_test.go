package panel

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMySQLIntegration(t *testing.T) {
	t.Run("AuthenticationAndAllRoutePermissions", func(t *testing.T) {
		f := setupDB(t)
		_, login, _ := f.request(t, "/api/v1/user/login", M{"username": "admin_user", "password": "admin_user"}, "")
		if num(login["code"]) != 0 || str(obj(login["data"])["token"]) == "" {
			t.Fatal(login)
		}
		user := f.seedUser()
		token := f.p.token(f.store().get("user", user))
		for path, route := range routeByPath {
			if route.Public {
				continue
			}
			status, rejected, _ := f.request(t, path, M{}, "")
			if status != 200 || num(rejected["code"]) != 401 {
				t.Errorf("%s missing auth: %d", path, status)
			}
			if route.Admin {
				status, rejected, _ := f.request(t, path, M{}, token)
				if status != 200 || num(rejected["code"]) != 403 {
					t.Errorf("%s nonadmin: %d", path, status)
				}
			}
		}
		status, _, _ := f.request(t, "/api/v1/node/create", M{}, f.token)
		if status != 200 {
			t.Fatal(status)
		}
		_, r, _ := f.request(t, "/api/v1/user/login", M{"username": "admin_user", "password": "wrong"}, "")
		if num(r["code"]) == 0 {
			t.Fatal("wrong password accepted")
		}
	})
	t.Run("UserConfigOpenAPIAndPasswords", func(t *testing.T) {
		f := setupDB(t)
		b := M{"user": "alice", "pwd": "password-a", "flow": 10, "num": 5, "expTime": now() + 86400000, "flowResetTime": 1}
		f.post(t, "/api/v1/user/create", b)
		u := f.store().one("SELECT * FROM user WHERE user='alice'")
		if u == nil {
			t.Fatal("user missing")
		}
		_, r, _ := f.request(t, "/api/v1/user/login", M{"username": "alice", "password": "password-a"}, "")
		token := str(obj(r["data"])["token"])
		if token == "" {
			t.Fatal(r)
		}
		f.post(t, "/api/v1/config/update", M{"app_name": "go-test", "captcha_enabled": "false"})
		got := f.post(t, "/api/v1/config/get", M{"name": "app_name"})
		if str(obj(got["data"])["value"]) != "go-test" {
			t.Fatal(got)
		}
		_, r, _ = f.request(t, "/api/v1/user/updatePassword", M{"newUsername": "alice2", "currentPassword": "password-a", "newPassword": "password-b", "confirmPassword": "password-b"}, token)
		if num(r["code"]) != 0 {
			t.Fatal(r)
		}
		resp, e := http.Get(f.http.URL + "/api/v1/open_api/sub_store?user=alice2&pwd=password-b")
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		if !strings.Contains(resp.Header.Get("subscription-userinfo"), "total=10737418240") {
			t.Fatal(resp.Header)
		}
		_, pack, _ := f.request(t, "/api/v1/user/package", M{}, token)
		if len(arr(obj(pack["data"])["statisticsFlows"])) != 24 {
			t.Fatal("24-hour padding")
		}
		b["id"] = u["id"]
		b["pwd"] = ""
		b["user"] = "alice3"
		f.post(t, "/api/v1/user/update", b)
		if str(f.store().get("user", u["id"])["pwd"]) != passwordHash("password-b") {
			t.Fatal("blank password overwrote record")
		}
		f.post(t, "/api/v1/user/reset", M{"id": u["id"], "type": 1})
		f.post(t, "/api/v1/user/delete", M{"id": u["id"]})
		if f.store().get("user", u["id"]) != nil {
			t.Fatal("delete failed")
		}
	})
	t.Run("NativeOnlyNodeContracts", func(t *testing.T) {
		f := setupDB(t)
		b := M{"name": "native", "engine": "kernel", "ip": "10.203.1.1", "serverIp": "10.203.2.1", "portSta": 18000, "portEnd": 19000}
		f.post(t, "/api/v1/node/create", b)
		n := f.store().one("SELECT * FROM node WHERE name='native'")
		if str(n["kernelBackend"]) != "nftables" {
			t.Fatal(n)
		}
		list := f.post(t, "/api/v1/node/list", M{})
		for _, v := range arr(list["data"]) {
			if obj(v)["secret"] != nil {
				t.Fatal("secret leaked")
			}
		}
		b["id"] = n["id"]
		b["engine"] = "iptables"
		b["name"] = "renamed"
		f.post(t, "/api/v1/node/update", b)
		if str(f.store().get("node", n["id"])["engine"]) != "kernel" {
			t.Fatal("legacy alias persisted")
		}
		b["kernelBackend"] = "iptables"
		_, r, _ := f.request(t, "/api/v1/node/create", b, f.token)
		if num(r["code"]) == 0 {
			t.Fatal("legacy backend accepted")
		}
		f.store().update("node", n["id"], M{"kernelBackend": "iptables"})
		delete(b, "kernelBackend")
		_, r, _ = f.request(t, "/api/v1/node/update", b, f.token)
		if num(r["code"]) == 0 {
			t.Fatal("legacy deployed backend taken over")
		}
		f.post(t, "/api/v1/node/delete", M{"id": n["id"]})
	})
	t.Run("CRUDWithControlFixture", func(t *testing.T) {
		f := setupDB(t)
		node := f.seedNode("kernel")
		f.fakeNode(t, node)
		f.post(t, "/api/v1/tunnel/create", M{"name": "native-api", "engine": "kernel", "inNodeId": node, "type": 1, "flow": 1})
		tunnel := num(f.store().one("SELECT id FROM tunnel WHERE name='native-api'")["id"])
		f.post(t, "/api/v1/forward/create", M{"name": "native-rule", "tunnelId": tunnel, "remoteAddr": "10.203.2.2:18002", "inPort": 18001})
		rule := f.store().one("SELECT * FROM forward WHERE tunnel_id=?", tunnel)
		if rule == nil {
			t.Fatal("rule missing")
		}
		f.post(t, "/api/v1/forward/pause", M{"id": rule["id"]})
		f.post(t, "/api/v1/forward/resume", M{"id": rule["id"]})
		f.post(t, "/api/v1/forward/update", M{"id": rule["id"], "userId": 1, "name": "updated", "tunnelId": tunnel, "inPort": 18003, "remoteAddr": "10.203.2.2:18002"})
		f.post(t, "/api/v1/forward/update-order", M{"forwards": []M{{"id": rule["id"], "inx": 7}}})
		f.post(t, "/api/v1/engine/capabilities", M{"nodeId": node})
		f.post(t, "/api/v1/engine/tunnel-capabilities", M{"tunnelId": tunnel})
		f.post(t, "/api/v1/engine/set-bandwidth-group", M{"nodeId": node, "scope": "user", "ownerId": 1, "upBitsPerSecond": 1000000})
		f.post(t, "/api/v1/engine/bandwidth-groups", M{"nodeId": node})
		f.post(t, "/api/v1/engine/audit", M{"nodeId": node, "limit": 20})
		f.post(t, "/api/v1/forward/delete", M{"id": rule["id"]})
		f.post(t, "/api/v1/tunnel/delete", M{"id": tunnel})
	})
	t.Run("PermissionsAndLimiter", func(t *testing.T) {
		f := setupDB(t)
		node := f.seedNode("gost")
		f.fakeNode(t, node)
		tunnel := f.seedTunnel(node, "gost")
		f.post(t, "/api/v1/speed-limit/create", M{"name": "limit", "speed": 8, "tunnelId": tunnel, "tunnelName": f.store().get("tunnel", tunnel)["name"]})
		limit := f.store().one("SELECT * FROM speed_limit")
		uid := f.seedUser()
		f.post(t, "/api/v1/tunnel/user/assign", M{"userId": uid, "tunnelId": tunnel, "speedId": limit["id"], "flow": 1, "num": 5, "flowResetTime": 1, "expTime": now() + 86400000})
		ut := f.store().one("SELECT * FROM user_tunnel WHERE user_id=?", uid)
		f.post(t, "/api/v1/tunnel/user/list", M{"userId": uid})
		_, r, _ := f.request(t, "/api/v1/speed-limit/delete", M{"id": limit["id"]}, f.token)
		if num(r["code"]) == 0 {
			t.Fatal("assigned limiter deleted")
		}
		b := pick(ut, "id flow num flowResetTime expTime status")
		f.post(t, "/api/v1/tunnel/user/update", b)
		f.post(t, "/api/v1/tunnel/user/remove", M{"id": ut["id"]})
		f.post(t, "/api/v1/speed-limit/delete", M{"id": limit["id"]})
	})
	t.Run("CumulativeTransactionsAndReplay", func(t *testing.T) {
		f := setupDB(t)
		node := f.seedNode("kernel")
		tunnel := f.seedTunnel(node, "kernel")
		user := f.seedUser()
		permission := f.seedPermission(tunnel, user)
		forward := f.seedForward(tunnel, user)
		name := fmt.Sprintf("%d_%d_%d", forward, user, permission)
		report := M{"epoch": strings.Repeat("a", 32), "sequence": 1, "usage": []M{{"id": name, "up": 100, "down": 40}}}
		n := f.store().get("node", node)
		var wg sync.WaitGroup
		errs := make(chan string, 16)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if e := panicMessage(func() { f.p.ingest(f.store(), n, report, nil) }); e != "" {
					errs <- e
				}
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Error(e)
		}
		if got := num(f.store().get("user", user)["inFlow"]); got != 100 {
			t.Fatalf("duplicate billing %d", got)
		}
		if num(f.store().get("user_tunnel", permission)["outFlow"]) != 40 {
			t.Fatal("permission accounting")
		}
		report["sequence"] = 2
		report["usage"] = []M{{"id": name, "up": 90, "down": 40}}
		if panicMessage(func() { f.p.ingest(f.store(), n, report, nil) }) == "" {
			t.Fatal("regression accepted")
		}
		if num(f.store().get("user", user)["inFlow"]) != 100 {
			t.Fatal("failed transaction changed ledger")
		}
	})
	t.Run("SharedCreditNeverOverallocates", func(t *testing.T) {
		f := setupDB(t)
		uid := f.seedUser()
		f.store().update("user", uid, M{"inFlow": (1 << 30) - 65536})
		nodes := []int64{f.seedNode("kernel"), f.seedNode("kernel")}
		reports := []M{}
		for _, node := range nodes {
			f.fakeNode(t, node)
			tunnel := f.seedTunnel(node, "kernel")
			permission := f.seedPermission(tunnel, uid)
			forward := f.seedForward(tunnel, uid)
			name := fmt.Sprintf("%d_%d_%d", forward, uid, permission)
			f.p.enableCredit(f.store(), node)
			reports = append(reports, M{"epoch": strings.Repeat("b", 32), "bootId": "boot-test", "sequence": 1, "usage": []M{{"id": name, "up": 0, "down": 0}}, "requests": []string{name}, "leases": []any{}})
		}
		var wg sync.WaitGroup
		errors := make(chan string, 2)
		for i, node := range nodes {
			wg.Add(1)
			go func(i int, node int64) {
				defer wg.Done()
				if e := panicMessage(func() { f.p.exchange(f.store(), f.store().get("node", node), reports[i], false) }); e != "" {
					errors <- e
				}
			}(i, node)
		}
		wg.Wait()
		close(errors)
		for e := range errors {
			t.Error(e)
		}
		sum := num(f.store().one("SELECT COALESCE(SUM(reserved_bill),0) total FROM engine_credit_lease WHERE closed=0")["total"])
		if sum > 65536 || sum < 128 {
			t.Fatalf("reserved %d", sum)
		}
		before := num(f.store().one("SELECT COUNT(*) n FROM engine_credit_lease")["n"])
		f.p.exchange(f.store(), f.store().get("node", nodes[0]), reports[0], false)
		after := num(f.store().one("SELECT COUNT(*) n FROM engine_credit_lease")["n"])
		if before != after {
			t.Fatal("replay issued duplicate lease")
		}
		bad := decode([]byte(jsonText(reports[0])))
		bad["requests"] = []any{}
		if panicMessage(func() { f.p.exchange(f.store(), f.store().get("node", nodes[0]), bad, false) }) == "" {
			t.Fatal("conflicting replay accepted")
		}
	})
	t.Run("HourlyDailyIdempotence", func(t *testing.T) {
		f := setupDB(t)
		uid := f.seedUser()
		f.store().update("user", uid, M{"flowResetTime": 31, "inFlow": 100, "outFlow": 50})
		at := time.Date(2026, 2, 28, 0, 0, 5, 0, time.FixedZone("test", 8*3600))
		f.p.hourly(f.store(), at)
		f.p.hourly(f.store(), at)
		if num(f.store().one("SELECT COUNT(*) n FROM statistics_flow WHERE user_id=?", uid)["n"]) != 1 {
			t.Fatal("duplicate hour")
		}
		f.p.daily(f.store(), at)
		if num(f.store().get("user", uid)["inFlow"]) != 0 {
			t.Fatal("month end reset failed")
		}
		f.store().update("user", uid, M{"inFlow": 7})
		f.p.daily(f.store(), at)
		if num(f.store().get("user", uid)["inFlow"]) != 7 {
			t.Fatal("duplicate daily reset")
		}
	})
	t.Run("ReadOnlyRejectsSideEffects", func(t *testing.T) {
		f := setupDB(t)
		f.p.cfg.ReadOnly = true
		status, _, _ := f.request(t, "/api/v1/node/create", M{}, f.token)
		if status != 403 {
			t.Fatal(status)
		}
		f.post(t, "/api/v1/node/list", M{})
		status, _, _ = f.request(t, "/flow/engine/v2/traffic", M{}, "")
		if status != 403 {
			t.Fatal(status)
		}
	})
}

func TestLegacyGostDeltaContract(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("gost")
	tunnel := f.seedTunnel(node, "gost")
	uid := f.seedUser()
	permission := f.seedPermission(tunnel, uid)
	forward := f.seedForward(tunnel, uid)
	secret := str(f.store().get("node", node)["secret"])
	name := fmt.Sprintf("%d_%d_%d_tcp", forward, uid, permission)
	body := M{"n": name, "u": 100, "d": 40}
	response, e := http.Post(f.http.URL+"/flow/upload?secret="+secret, "application/json", strings.NewReader(jsonText(body)))
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	b, e := io.ReadAll(response.Body)
	if e != nil || string(b) != "ok" {
		t.Fatalf("legacy report %s %v", b, e)
	}
	if num(f.store().get("forward", forward)["inFlow"]) != 40 || num(f.store().get("user", uid)["outFlow"]) != 100 {
		t.Fatal("GOST direction or suffix contract changed")
	}
}

func TestLegacyWildcardAndProtocolPolicy(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	f.fakeNode(t, node)
	tunnel := f.seedTunnel(node, "kernel")
	f.store().update("tunnel", tunnel, M{"tcpListenAddr": "[::]", "udpListenAddr": "[::]"})
	fid := f.seedForward(tunnel, 1)
	forward := f.store().get("forward", fid)
	tun := f.store().get("tunnel", tunnel)
	f.store().update("node", node, M{"http": 1, "tls": 1, "socks": 1})
	interactive := f.p.wireSpec(f.store(), forward, tun, false)
	batch := f.p.wireSpec(f.store(), forward, tun, true, f.p.specSnapshot(f.store(), node))
	if jsonText(interactive) != jsonText(batch) {
		t.Fatal("interactive/batch policy differs")
	}
	if num(interactive["schemaVersion"]) != 5 || str(obj(interactive["protocolFilter"])["unknown"]) != "allow" {
		t.Fatal(interactive)
	}
	for _, v := range arr(interactive["listeners"]) {
		if str(obj(v)["host"]) != "0.0.0.0" {
			t.Fatal("legacy bracketed wildcard incorrectly retained")
		}
	}
	f.store().update("node", node, M{"http": 0, "tls": 0, "socks": 0})
	off := f.p.wireSpec(f.store(), forward, tun, true)
	if off["protocolFilter"] != nil || str(off["intentHash"]) == str(interactive["intentHash"]) {
		t.Fatal("node policy removal did not alter desired intent")
	}
	if !specChanged(off, interactive) {
		t.Fatal("node policy removal was not scheduled for reconciliation")
	}
}

func TestSimpleForwardProtocolDisableReconciliation(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	f.fakeNode(t, node)
	tunnel := f.seedTunnel(node, "kernel")
	fid := f.seedForward(tunnel, 1)
	forward, tun := f.store().get("forward", fid), f.store().get("tunnel", tunnel)
	f.store().update("node", node, M{"http": 1, "tls": 1, "socks": 1})
	on := f.p.wireSpec(f.store(), forward, tun, true)
	if num(on["schemaVersion"]) != 5 {
		t.Fatal(on)
	}
	f.store().update("node", node, M{"http": 0, "tls": 0, "socks": 0})
	off := f.p.wireSpec(f.store(), forward, tun, true)
	if num(off["schemaVersion"]) > 2 || off["protocolFilter"] != nil || !specChanged(off, on) {
		t.Fatal("unchanged IPv4 endpoints masked the removed filter", off)
	}
	canonical := M{}
	for k, v := range off {
		canonical[k] = v
	}
	canonical["schemaVersion"] = int64(0)
	for _, k := range []string{"listen", "target", "protocols"} {
		delete(canonical, k)
	}
	if specChanged(off, canonical) {
		t.Fatal("Agent's normalized simple state caused an endless reconcile loop")
	}
}

func TestPausedAutomaticReconciliationAllowsOneSelectedNode(t *testing.T) {
	f := setupDB(t)
	f.p.cfg.PauseAutomaticReconcile = true
	first, second := f.seedNode("kernel"), f.seedNode("kernel")
	firstEvents, secondEvents := f.fakeNode(t, first), f.fakeNode(t, second)
	f.seedForward(f.seedTunnel(first, "kernel"), 1)
	f.seedForward(f.seedTunnel(second, "kernel"), 1)
	f.p.queueReconcile(first)
	f.p.queueReconcile(second)
	f.p.mu.Lock()
	queued := len(f.p.reconcileQueue)
	f.p.mu.Unlock()
	if queued != 0 {
		t.Fatal("maintenance pause queued automatic changes")
	}
	f.post(t, "/api/v1/engine/reconcile", M{"nodeId": first})
	seen := false
	for len(firstEvents) > 0 {
		if str((<-firstEvents)["type"]) == "SubmitBatch" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("selected node was not reconciled")
	}
	for len(secondEvents) > 0 {
		if str((<-secondEvents)["type"]) == "SubmitBatch" {
			t.Fatal("unselected node changed")
		}
	}
}
