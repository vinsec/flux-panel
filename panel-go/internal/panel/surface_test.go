package panel

import (
	"crypto/tls"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// This complements deep invariant/failure tests: no retained HTTP route may lack
// a successful invocation through the real router and disposable MySQL.
func TestFullHTTPContractSurface(t *testing.T) {
	f := setupDB(t)
	covered := map[string]bool{}
	call := func(path string, b M) M { t.Helper(); r := f.post(t, path, b); covered[path] = true; return r }
	raw := func(method, path string, b M, auth string) M {
		t.Helper()
		req, e := http.NewRequest(method, f.http.URL+path, strings.NewReader(jsonText(b)))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		data, e := io.ReadAll(res.Body)
		if e != nil {
			t.Fatal(e)
		}
		if res.StatusCode != 200 {
			t.Fatalf("%s %d %s", path, res.StatusCode, data)
		}
		u, _ := url.Parse(path)
		covered[u.Path] = true
		if len(data) > 0 && data[0] == '{' {
			return decode(data)
		}
		return M{}
	}
	call("/api/v1/user/login", M{"username": "admin_user", "password": "admin_user"})
	userData := M{"user": "surface-user", "pwd": "test-password", "flow": 100, "num": 20, "expTime": now() + 86400000, "flowResetTime": 0}
	call("/api/v1/user/create", userData)
	user := f.store().one("SELECT * FROM user WHERE user='surface-user'")
	userData["id"] = user["id"]
	call("/api/v1/user/update", userData)
	call("/api/v1/user/list", M{})
	call("/api/v1/user/package", M{})
	call("/api/v1/user/updatePassword", M{"newUsername": "admin_user", "currentPassword": "admin_user", "newPassword": "admin_user", "confirmPassword": "admin_user"})
	call("/api/v1/user/reset", M{"id": user["id"], "type": 1})
	call("/api/v1/config/update", M{"app_name": "surface"})
	call("/api/v1/config/update-single", M{"name": "app_name", "value": "surface2"})
	call("/api/v1/config/get", M{"name": "app_name"})
	call("/api/v1/config/list", M{})
	nodeData := M{"name": "surface-native", "engine": "kernel", "ip": "10.203.1.1", "serverIp": "10.203.2.1", "portSta": 18000, "portEnd": 19000}
	call("/api/v1/node/create", nodeData)
	node := f.store().one("SELECT * FROM node WHERE name='surface-native'")
	nodeData["id"] = node["id"]
	f.fakeNode(t, num(node["id"]))
	call("/api/v1/node/update", nodeData)
	call("/api/v1/node/list", M{})
	f.p.cfg.ReleaseBase = "https://example.invalid/frozen"
	f.p.cfg.ManifestSHA = strings.Repeat("a", 64)
	f.p.cfg.InstallerSHA = strings.Repeat("b", 64)
	f.p.setConfig(f.store(), "ip", "panel.invalid")
	call("/api/v1/node/install", M{"id": node["id"]})
	call("/api/v1/tunnel/create", M{"name": "surface-tunnel", "engine": "kernel", "inNodeId": node["id"], "type": 1, "flow": 1})
	tunnel := f.store().one("SELECT * FROM tunnel WHERE name='surface-tunnel'")
	call("/api/v1/tunnel/list", M{})
	call("/api/v1/tunnel/update", M{"id": tunnel["id"], "name": "surface-tunnel", "engine": "kernel", "flow": 1, "trafficRatio": 1, "protocol": "tls", "tcpListenAddr": "0.0.0.0", "udpListenAddr": "0.0.0.0"})
	call("/api/v1/tunnel/user/tunnel", M{})
	call("/api/v1/tunnel/diagnose", M{"tunnelId": tunnel["id"]})
	call("/api/v1/speed-limit/create", M{"name": "surface-limit", "speed": 8, "tunnelId": tunnel["id"], "tunnelName": "surface-tunnel"})
	limiter := f.store().one("SELECT * FROM speed_limit WHERE name='surface-limit'")
	call("/api/v1/speed-limit/list", M{})
	call("/api/v1/speed-limit/tunnels", M{})
	call("/api/v1/speed-limit/update", M{"id": limiter["id"], "name": "surface-limit", "speed": 16, "tunnelId": tunnel["id"], "tunnelName": "surface-tunnel"})
	call("/api/v1/tunnel/user/assign", M{"userId": user["id"], "tunnelId": tunnel["id"], "flow": 1, "num": 5, "flowResetTime": 0, "expTime": now() + 86400000, "speedId": limiter["id"]})
	permission := f.store().one("SELECT * FROM user_tunnel WHERE user_id=?", user["id"])
	call("/api/v1/tunnel/user/list", M{"userId": user["id"]})
	call("/api/v1/tunnel/user/update", pick(permission, "id flow num flowResetTime expTime status speedId"))
	call("/api/v1/forward/create", M{"name": "surface-rule", "tunnelId": tunnel["id"], "inPort": 18001, "remoteAddr": "10.203.2.2:18002"})
	rule := f.store().one("SELECT * FROM forward WHERE name='surface-rule'")
	call("/api/v1/forward/list", M{})
	call("/api/v1/forward/update", M{"id": rule["id"], "userId": 1, "name": "surface-rule", "tunnelId": tunnel["id"], "inPort": 18001, "remoteAddr": "10.203.2.2:18002"})
	call("/api/v1/forward/pause", M{"id": rule["id"]})
	call("/api/v1/forward/resume", M{"id": rule["id"]})
	call("/api/v1/forward/diagnose", M{"forwardId": rule["id"]})
	call("/api/v1/forward/update-order", M{"forwards": []M{{"id": rule["id"], "inx": 2}}})
	call("/api/v1/engine/capabilities", M{"nodeId": node["id"]})
	call("/api/v1/engine/tunnel-capabilities", M{"tunnelId": tunnel["id"]})
	call("/api/v1/engine/forward-states", M{"ids": []any{rule["id"]}})
	call("/api/v1/engine/collect", M{"nodeId": node["id"]})
	batch := call("/api/v1/engine/reconcile", M{"nodeId": node["id"]})
	call("/api/v1/engine/batch-status", M{"nodeId": node["id"], "id": obj(batch["data"])["id"]})
	call("/api/v1/engine/set-bandwidth-group", M{"nodeId": node["id"], "ownerId": 1, "scope": "user", "upBitsPerSecond": 1000000})
	call("/api/v1/engine/bandwidth-groups", M{"nodeId": node["id"]})
	call("/api/v1/engine/audit", M{"nodeId": node["id"]})
	call("/api/v1/engine/socket-ticket", M{})
	call("/api/v1/engine/revoke-sessions", M{"nodeId": node["id"]})
	epoch := strings.Repeat("c", 32)
	name, _ := serviceName(f.store(), rule)
	report := M{"epoch": epoch, "sequence": 1, "usage": []M{{"id": name, "up": 100, "down": 40}}}
	auth := "Bearer " + str(node["secret"])
	raw("POST", "/flow/engine/v1/traffic", report, auth)
	report["bootId"] = "boot-test"
	report["sequence"] = 2
	raw("POST", "/flow/engine/v2/traffic", report, auth)
	report["sequence"] = 3
	raw("POST", "/flow/engine/v2/maintenance", report, auth)
	raw("POST", "/flow/engine/v3/session", M{}, auth)
	call("/api/v1/forward/delete", M{"id": rule["id"]})
	force := f.seedForward(num(tunnel["id"]), 1)
	call("/api/v1/forward/force-delete", M{"id": force})
	call("/api/v1/tunnel/user/remove", M{"id": permission["id"]})
	call("/api/v1/speed-limit/delete", M{"id": limiter["id"]})
	call("/api/v1/tunnel/delete", M{"id": tunnel["id"]})
	call("/api/v1/node/delete", M{"id": node["id"]})
	gost := f.seedNode("gost")
	gt := f.seedTunnel(gost, "gost")
	gf := f.seedForward(gt, 1)
	g := f.store().get("node", gost)
	gname, _ := serviceName(f.store(), f.store().get("forward", gf))
	raw("POST", "/flow/config?secret="+str(g["secret"]), M{"services": []M{{"name": "web_api"}}}, "")
	raw("POST", "/flow/upload?secret="+str(g["secret"]), M{"n": gname + "_tcp", "u": 10, "d": 20}, "")
	raw("GET", "/flow/test", nil, "")
	raw("GET", "/api/v1/open_api/sub_store?user=admin_user&pwd=admin_user", nil, "")
	raw("GET", "/error", nil, "")
	call("/api/v1/captcha/check", M{})
	generated := raw("POST", "/api/v1/captcha/generate", M{}, "")
	id := str(generated["id"])
	f.p.captcha.mu.Lock()
	f.p.captcha.items[id] = challenge{Kind: "SLIDER", Expiry: now() + 120000, X: 100}
	f.p.captcha.mu.Unlock()
	verified := raw("POST", "/api/v1/captcha/verify", M{"id": id, "data": M{"bgImageWidth": 300, "bgImageHeight": 180, "trackList": []M{{"type": "down", "x": 0, "y": 0, "t": 0}, {"type": "up", "x": 100, "y": 0, "t": 300}}}}, "")
	if num(verified["code"]) != 200 {
		t.Fatal(verified)
	}
	call("/api/v1/user/delete", M{"id": user["id"]})
	for path := range routeByPath {
		if path == "/api/v1/engine/switch-mode" || path == "/api/v1/engine/mode-switch-status" {
			continue
		}
		if !covered[path] {
			t.Errorf("retained route lacks successful coverage: %s", path)
		}
	}
	t.Logf("%d/%d retained HTTP mappings exercised", len(covered), len(routeByPath))
}
func TestSocketTicketsWSSAndSessionReplacement(t *testing.T) {
	f := setupDB(t)
	secure := httptest.NewTLSServer(f.p.Handler())
	defer secure.Close()
	ticketReply := f.post(t, "/api/v1/engine/socket-ticket", M{})
	ticket := str(obj(ticketReply["data"])["ticket"])
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	endpoint := "wss" + strings.TrimPrefix(secure.URL, "https") + "/system-info?type=0&ticket=" + ticket
	conn, _, e := dialer.Dial(endpoint, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	other, res, e := dialer.Dial(endpoint, nil)
	if other != nil {
		other.Close()
	}
	if e == nil || res == nil || res.StatusCode != 403 {
		t.Fatal("single-use WSS ticket replay accepted")
	}
	node := f.seedNode("kernel")
	f.fakeNode(t, node)
	f.p.mu.Lock()
	first := f.p.nodes[node]
	f.p.mu.Unlock()
	f.fakeNode(t, node)
	select {
	case <-first.done:
	case <-time.After(time.Second):
		t.Fatal("replaced socket stayed live")
	}
	f.p.mu.Lock()
	current := f.p.nodes[node]
	f.p.mu.Unlock()
	if current == nil || current == first {
		t.Fatal("old close removed new connection")
	}
}
