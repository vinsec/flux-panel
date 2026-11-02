package panel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func panicMessage(fn func()) (message string) {
	defer func() {
		if v := recover(); v != nil {
			if e, ok := v.(apiError); ok {
				message = e.Message
			} else {
				message = "internal"
			}
		}
	}()
	fn()
	return
}
func TestEndpointContract(t *testing.T) {
	good := map[string]string{"127.0.0.1:80": "127.0.0.1", "[2001:db8::1]:443": "2001:db8::1", "[::ffff:192.0.2.1]:25": "192.0.2.1", "EXAMPLE.com.:443": "example.com", "例子.测试:443": "xn--fsqu00a.xn--0zwm56d"}
	for input, want := range good {
		t.Run(input, func(t *testing.T) {
			if got := str(endpoint(input)["host"]); got != want {
				t.Fatalf("got %q want %q", got, want)
			}
		})
	}
	for _, v := range []string{" 127.0.0.1:80", "127.00.0.1:80", "1.2.3.4:0", "[fe80::1%eth0]:80", "example.com:65536", "bad_host:80", "a@b:80", "::1:80", "1.2.3.4:1e2"} {
		if panicMessage(func() { endpoint(v) }) == "" {
			t.Errorf("accepted %q", v)
		}
	}
}
func TestAccountingArithmetic(t *testing.T) {
	for _, tc := range []struct {
		raw                       int64
		ratio                     string
		flow, wantFloor, wantCeil int64
	}{{3, "0.5", 2, 2, 4}, {5, "1.25", 1, 6, 7}, {100, "0", 2, 0, 0}, {9007199254740993, "1", 1, 9007199254740993, 9007199254740993}} {
		p := price{tc.ratio, tc.flow}
		if got := bill(tc.raw, p, false); got != tc.wantFloor {
			t.Fatalf("floor: %d", got)
		}
		if got := bill(tc.raw, p, true); got != tc.wantCeil {
			t.Fatalf("ceil: %d", got)
		}
	}
	if rawCredit(9, price{"1.25", 2}, 100) != 3 {
		t.Fatal("reservation rounding")
	}
	if panicMessage(func() { bill(1<<62, price{"3", 2}, false) }) == "" {
		t.Fatal("overflow accepted")
	}
}
func TestJWTAndCryptoCompatibility(t *testing.T) {
	p := New(nil, Config{JWTSecret: "test-only"})
	u := M{"id": int64(3), "user": "alice", "roleId": 1}
	v := p.token(u)
	if num(p.claims(v)["sub"]) != 3 {
		t.Fatal("JWT roundtrip")
	}
	if p.claims(v+"x") != nil {
		t.Fatal("bad signature accepted")
	}
	if passwordHash("admin_user") != "3c85cdebade1c51cf64ca9f3c09d182d" {
		t.Fatal("legacy password changed")
	}
	plain := []byte(`{"type":"ApplyForward","requestId":"sample"}`)
	encrypted := encrypt("test-secret", plain)
	if !bytes.Equal(decrypt("test-secret", encrypted), plain) {
		t.Fatal("AES GCM roundtrip")
	}
	if panicMessage(func() { decrypt("wrong", encrypted) }) == "" {
		t.Fatal("bad authentication tag accepted")
	}
}
func TestAdvancedOptionGuards(t *testing.T) {
	for _, v := range []string{`{"protocolFilter":{"unknown":"drop"}}`, `{"traffic":{"sourceMode":"preserve"}}`, `{"listeners":[]}`, `{"bandwidth":{"upBitsPerSecond":0.5}}`, `{"egress":{"interface":";sh"}}`, `{"health":{"protocol":"udp","payload":"","expected":""}}`, `{"targets":[{"endpoint":{"host":"127.0.0.1","port":80},"weight":33}]}`, `{"unexpected":1}`} {
		if panicMessage(func() { options(v) }) == "" {
			t.Errorf("accepted %s", v)
		}
	}
	options(`{"traffic":{"sourceMode":"preserve","returnPathConfirmed":true},"protocolFilter":{"unknown":"allow","http":true}}`)
}
func TestAllCaptchaModesAndReplay(t *testing.T) {
	for _, kind := range []string{"SLIDER", "ROTATE", "CONCAT", "WORD_IMAGE_CLICK"} {
		t.Run(kind, func(t *testing.T) {
			c := newCaptchas()
			response := c.generate(kind)
			id := str(response["id"])
			ch := c.items[id]
			vo := obj(response["captcha"])
			if !strings.HasPrefix(str(vo["backgroundImage"]), "data:image/png;base64,") {
				t.Fatal("missing image")
			}
			tracks := []any{M{"type": "down", "x": 0, "y": 0, "t": 0}}
			width := int64(300)
			if kind == "ROTATE" {
				width = 242
			}
			if kind == "WORD_IMAGE_CLICK" {
				tracks = nil
				for i, pt := range ch.Points {
					tracks = append(tracks, M{"type": "click", "x": pt.X, "y": pt.Y, "t": (i + 1) * 300})
				}
			} else {
				x := int64(ch.X)
				if kind == "ROTATE" {
					x = int64(ch.X * 242 / 360)
				}
				tracks = append(tracks, M{"type": "move", "x": x / 2, "y": 0, "t": 150}, M{"type": "up", "x": x, "y": 0, "t": 400})
			}
			data := M{"bgImageWidth": width, "bgImageHeight": 180, "trackList": tracks}
			if !c.verify(id, data) {
				t.Fatal("correct interaction rejected")
			}
			if !c.consume(id) {
				t.Fatal("verified login rejected")
			}
			if c.consume(id) {
				t.Fatal("replay accepted")
			}
			if c.verify(id, data) {
				t.Fatal("challenge replay accepted")
			}
		})
	}
	c := newCaptchas()
	r := c.generate("SLIDER")
	id := str(r["id"])
	if c.consume(id) {
		t.Fatal("unverified captcha accepted")
	}
}

type testPanel struct {
	p     *Panel
	db    *sql.DB
	http  *httptest.Server
	token string
}

func setupDB(t *testing.T) *testPanel {
	t.Helper()
	dsn := os.Getenv("FLUX_TEST_DSN")
	if dsn == "" {
		t.Skip("FLUX_TEST_DSN required for isolated MySQL integration")
	}
	cfg, e := mysql.ParseDSN(dsn)
	if e != nil || !strings.HasPrefix(cfg.DBName, "flux_go_test") {
		t.Fatal("only a disposable flux_go_test database is allowed")
	}
	cfg.MultiStatements = true
	db, e := sql.Open("mysql", cfg.FormatDSN())
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		e = db.Ping()
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	rows, e := db.Query("SHOW TABLES")
	if e != nil {
		t.Fatal(e)
	}
	tables := []string{}
	for rows.Next() {
		var name string
		rows.Scan(&name)
		tables = append(tables, name)
	}
	rows.Close()
	for _, name := range tables {
		if _, e = db.Exec("DROP TABLE `" + name + "`"); e != nil {
			t.Fatal(e)
		}
	}
	root := os.Getenv("FLUX_TEST_SCHEMA_ROOT")
	if root == "" {
		root = "../../.."
	}
	files := []string{"gost.sql", "database/migrations/001-forward-engines.sql", "database/migrations/002-engine-foundation.sql", "database/migrations/003-engine-p1.sql", "database/migrations/004-node-kernel-backend.sql", "database/migrations/005-native-only.sql", "database/migrations/006-go-panel-runtime.sql"}
	for _, f := range files {
		b, e := os.ReadFile(filepath.Join(root, f))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(string(b)); e != nil {
			t.Fatalf("schema %s: %v", f, e)
		}
	}
	p := New(db, Config{JWTSecret: "isolated-go-test-only", AllowLegacyQuery: true, TimeZone: "Asia/Shanghai"})
	handler := p.Handler()
	oraclePath := os.Getenv("FLUX_TEST_BROWSER_ORACLE")
	if oraclePath != "" {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.Handler().ServeHTTP(w, r)
			if r.URL.Path == "/api/v1/captcha/generate" {
				p.captcha.mu.Lock()
				snapshot := M{}
				for id, c := range p.captcha.items {
					snapshot[id] = M{"kind": c.Kind, "x": c.X, "points": c.Points}
				}
				p.captcha.mu.Unlock()
				must(os.WriteFile(oraclePath, []byte(jsonText(snapshot)), 0600))
			}
		})
	}
	srv := httptest.NewUnstartedServer(handler)
	if addr := os.Getenv("FLUX_TEST_BROWSER_LISTEN"); addr != "" {
		listener, e := net.Listen("tcp", addr)
		if e != nil {
			t.Fatal(e)
		}
		srv.Listener = listener
	}
	srv.Start()
	fixture := &testPanel{p, db, srv, p.token(M{"id": 1, "user": "admin_user", "roleId": 0})}
	t.Cleanup(func() { p.Close(); srv.Close(); db.Close() })
	return fixture
}
func (f *testPanel) request(t *testing.T, path string, b any, token string) (int, M, http.Header) {
	t.Helper()
	req, e := http.NewRequest("POST", f.http.URL+path, strings.NewReader(jsonText(b)))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	r, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	body, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	var m M
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if e = d.Decode(&m); e != nil {
		t.Fatalf("%s: status=%d body=%s", path, r.StatusCode, body)
	}
	return r.StatusCode, m, r.Header
}
func (f *testPanel) post(t *testing.T, path string, b any) M {
	t.Helper()
	status, m, _ := f.request(t, path, b, f.token)
	if status != 200 || num(m["code"]) != 0 {
		t.Fatalf("%s: %d %s", path, status, jsonText(m))
	}
	return m
}
func (f *testPanel) store() store { return store{f.db, context.Background()} }
func (f *testPanel) seedNode(engine string) int64 {
	return f.store().insert("node", M{"name": "isolated-" + engine, "engine": engine, "kernelBackend": "nftables", "secret": randomHex(16), "ip": "10.203.1.1", "serverIp": "10.203.2.1", "portSta": 18000, "portEnd": 30000, "createdTime": now(), "updatedTime": now(), "status": 1})
}
func (f *testPanel) seedTunnel(node int64, engine string) int64 {
	return f.store().insert("tunnel", M{"name": "test-tunnel-" + randomHex(3), "engine": engine, "trafficRatio": 1, "inNodeId": node, "inIp": "10.203.1.1", "outNodeId": node, "outIp": "10.203.2.1", "type": 1, "protocol": "tls", "flow": 1, "tcpListenAddr": "0.0.0.0", "udpListenAddr": "0.0.0.0", "createdTime": now(), "updatedTime": now(), "status": 1})
}
func (f *testPanel) seedUser() int64 {
	return f.store().insert("user", M{"user": "user-" + randomHex(3), "pwd": passwordHash("test-password"), "roleId": 1, "expTime": now() + 86400000, "flow": 1, "inFlow": 0, "outFlow": 0, "flowResetTime": 0, "num": 10, "createdTime": now(), "status": 1})
}
func (f *testPanel) seedForward(tunnel, user int64) int64 {
	return f.store().insert("forward", M{"name": "test-forward", "userId": user, "userName": "fixture", "tunnelId": tunnel, "inPort": 18001, "remoteAddr": "10.203.2.2:18002", "strategy": "fifo", "inFlow": 0, "outFlow": 0, "createdTime": now(), "updatedTime": now(), "status": 1, "inx": 0})
}
func (f *testPanel) seedPermission(tunnel, user int64) int64 {
	return f.store().insert("user_tunnel", M{"userId": user, "tunnelId": tunnel, "flow": 1, "num": 10, "flowResetTime": 0, "expTime": now() + 86400000, "status": 1})
}
func (f *testPanel) fakeNode(t *testing.T, node int64, responders ...func(M) M) chan M {
	t.Helper()
	n := f.store().get("node", node)
	url := "ws" + strings.TrimPrefix(f.http.URL, "http") + "/system-info?type=1&engine=" + str(n["engine"]) + "&version=kernel-v6.0"
	head := http.Header{"Authorization": []string{"Bearer " + str(n["secret"])}}
	conn, _, e := websocket.DefaultDialer.Dial(url, head)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close() })
	events := make(chan M, 256)
	features := M{}
	for _, k := range []string{"batch", "structuredEndpoint", "independentProtocols", "ipv6", "dns", "multiTarget", "creditLease", "creditPolicy", "creditPush", "shaping", "protocolBlocking", "returnPathDiagnostics", "interfaceRouting", "trafficPolicy", "localOutput", "localTargets", "preserveSource", "localUDPPreserveSource", "localTrafficShaping"} {
		features[k] = true
	}
	info := M{"kernelBackend": "nftables", "bootId": "boot-test", "strictCreditPolicy": true, "capabilities": M{"features": features}}
	var writer sync.Mutex
	send := func(v M) {
		writer.Lock()
		defer writer.Unlock()
		conn.WriteMessage(websocket.TextMessage, encrypt(str(n["secret"]), []byte(jsonText(v))))
	}
	send(M{"type": "EngineHello", "info": info})
	go func() {
		defer close(events)
		for {
			_, b, e := conn.ReadMessage()
			if e != nil {
				return
			}
			var event M
			func() { defer func() { recover() }(); event = decode(decrypt(str(n["secret"]), b)) }()
			if event == nil {
				continue
			}
			select {
			case events <- event:
			default:
			}
			kind := str(event["type"])
			if len(responders) > 0 {
				if reply := responders[0](event); reply != nil {
					reply["requestId"] = event["requestId"]
					send(reply)
					continue
				}
			}
			d := M{}
			switch kind {
			case "GetCapabilities", "RequireCreditPolicy":
				d = info
			case "GetEngineStatePage":
				d = M{"generation": 1, "items": []any{}, "next": ""}
			case "SubmitBatch":
				d = M{"id": obj(event["data"])["id"], "status": "queued"}
			case "GetBatchStatus":
				d = M{"status": "complete"}
			case "TcpPing":
				d = M{"success": true, "averageTime": 0.1, "packetLoss": 0}
			case "RequestCredit":
				send(M{"requestId": event["requestId"], "message": "unavailable"})
				continue
			}
			if event["requestId"] != nil {
				send(M{"requestId": event["requestId"], "message": "OK", "data": d})
			}
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for f.p.capability(node) == nil {
		if time.Now().After(deadline) {
			t.Fatal("hello timeout")
		}
		time.Sleep(time.Millisecond)
	}
	return events
}

func TestServiceIdentityCannotAliasAnotherWatermark(t *testing.T) {
	for _, id := range []string{"01_2_3", "1_02_3", "1_2_03", "1_2_3x"} {
		if panicMessage(func() { serviceID(id) }) == "" {
			t.Fatal("noncanonical identity accepted", id)
		}
	}
	serviceID("1_2_0")
}

func TestGostLimiterKeepsJavaHalfUpRounding(t *testing.T) {
	for speed, want := range map[int64]string{1: "0.1", 2: "0.3", 3: "0.4", 4: "0.5", 6: "0.8", 10: "1.3", 16: "2.0"} {
		if got := gostRate(speed); got != want {
			t.Fatalf("%d Mbps: got %s want %s", speed, got, want)
		}
	}
}
