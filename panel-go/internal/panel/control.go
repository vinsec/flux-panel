package panel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

func jsonText(v any) string {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	must(encoder.Encode(v))
	return strings.TrimSuffix(b.String(), "\n")
}

func decode(b []byte) M {
	m := M{}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	must(d.Decode(&m))
	return m
}
func obj(v any) M {
	if v == nil {
		return M{}
	}
	switch m := v.(type) {
	case M:
		return m
	case map[string]any:
		return M(m)
	default:
		return decode([]byte(jsonText(v)))
	}
}
func arr(v any) []any {
	if v == nil {
		return nil
	}
	switch a := v.(type) {
	case []any:
		return a
	case []string:
		r := []any{}
		for _, v := range a {
			r = append(r, v)
		}
		return r
	case []M:
		r := []any{}
		for _, v := range a {
			r = append(r, v)
		}
		return r
	}
	fail("array required")
	return nil
}
func truth(v any) bool { return v == true || str(v) == "true" }
func cryptoGCM(secret string) cipher.AEAD {
	k := sha256.Sum256([]byte(secret))
	b, e := aes.NewCipher(k[:])
	must(e)
	g, e := cipher.NewGCM(b)
	must(e)
	return g
}
func encrypt(secret string, b []byte) []byte {
	g := cryptoGCM(secret)
	n := make([]byte, g.NonceSize())
	_, e := io.ReadFull(rand.Reader, n)
	must(e)
	out := g.Seal(n, n, b, nil)
	return []byte(jsonText(M{"encrypted": true, "timestamp": now(), "data": base64.StdEncoding.EncodeToString(out)}))
}
func decrypt(secret string, b []byte) []byte {
	m := decode(b)
	if !truth(m["encrypted"]) {
		return b
	}
	g := cryptoGCM(secret)
	v, e := base64.StdEncoding.DecodeString(str(m["data"]))
	must(e)
	if len(v) < g.NonceSize()+g.Overhead() {
		fail("invalid encrypted message")
	}
	plain, e := g.Open(nil, v[:g.NonceSize()], v[g.NonceSize():], nil)
	must(e)
	return plain
}

type peer struct {
	engine  string
	outbox  chan string
	conn    *websocket.Conn
	id      int64
	secret  string
	expiry  int64
	version string
	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]chan M
	info    M
	done    chan struct{}
	once    sync.Once
}

func (x *peer) close() { x.once.Do(func() { close(x.done); x.conn.Close() }) }
func (x *peer) send(v any) error {
	x.writeMu.Lock()
	defer x.writeMu.Unlock()
	x.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	b := []byte(jsonText(v))
	if x.secret != "" {
		b = encrypt(x.secret, b)
	}
	return x.conn.WriteMessage(websocket.TextMessage, b)
}
func (p *Panel) socket(w http.ResponseWriter, r *http.Request, s store) {
	q := r.URL.Query()
	nodeMode := q.Get("type") == "1"
	id := int64(0)
	secret := ""
	expiry := int64(0)
	var n M
	if nodeMode {
		auth := r.Header.Get("Authorization")
		if auth == "" && p.cfg.AllowLegacyQuery {
			auth = "Bearer " + q.Get("secret")
		}
		n, expiry = p.identity(s, auth)
		if n == nil {
			statusError(403, "invalid node credential")
		}
		id = num(n["id"])
		secret = str(n["secret"])
		if normalizeEngine(q.Get("engine")) != normalizeEngine(n["engine"]) {
			statusError(403, "node engine mismatch")
		}
		if normalizeEngine(n["engine"]) == "kernel" {
			nativeNode(n)
		}
	} else {
		p.mu.Lock()
		t, ok := p.tickets[digest(q.Get("ticket"))]
		delete(p.tickets, digest(q.Get("ticket")))
		p.mu.Unlock()
		if ok && t.Expiry > now() {
			id = t.User
		} else if p.cfg.AllowLegacyQuery {
			c := p.claims(q.Get("secret"))
			if c != nil && num(c["role_id"]) == 0 {
				id = num(c["sub"])
			}
		}
		if id == 0 {
			statusError(403, "invalid admin ticket")
		}
	}
	up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }, HandshakeTimeout: 10 * time.Second}
	conn, e := up.Upgrade(w, r, nil)
	if e != nil {
		return
	}
	x := &peer{conn: conn, id: id, secret: secret, expiry: expiry, version: q.Get("version"), pending: map[string]chan M{}, done: make(chan struct{})}
	p.mu.Lock()
	if p.writeFailed {
		p.mu.Unlock()
		x.close()
		return
	}
	p.wg.Add(1)
	p.mu.Unlock()
	defer p.wg.Done()
	if nodeMode {
		x.engine = normalizeEngine(n["engine"])
	}
	conn.SetReadLimit(16 << 20)
	defer func() {
		if recover() != nil {
			x.close()
		}
	}()
	defer func() {
		x.close()
		statusLock := p.nodeStatusLock(id)
		statusLock.Lock()
		defer statusLock.Unlock()
		p.mu.Lock()
		current := p.nodes[id] == x
		if nodeMode && current {
			delete(p.nodes, id)
		}
		delete(p.admins, x)
		p.mu.Unlock()
		if nodeMode && current {
			p.background(func(s store) {
				s.update("node", id, M{"status": 0})
				p.broadcast(M{"id": fmt.Sprint(id), "type": "status", "data": 0})
			})
		}
	}()
	if nodeMode {
		statusLock := p.nodeStatusLock(id)
		statusLock.Lock()
		func() {
			defer statusLock.Unlock()
			p.mu.Lock()
			if p.writeFailed {
				p.mu.Unlock()
				x.close()
				return
			}
			old := p.nodes[id]
			p.nodes[id] = x
			p.mu.Unlock()
			if old != nil {
				old.close()
			}
			m := M{"status": 1}
			if x.version != "" {
				m["version"] = x.version
			}
			for _, k := range []string{"http", "tls", "socks"} {
				if q.Get(k) != "" {
					m[k] = num(q.Get(k))
				}
			}
			s.update("node", id, m)
		}()
		p.broadcast(M{"id": fmt.Sprint(id), "type": "status", "data": 1})
	} else {
		p.mu.Lock()
		if p.writeFailed || len(p.admins) >= 128 {
			p.mu.Unlock()
			x.close()
			return
		}
		x.outbox = make(chan string, 32)
		p.admins[x] = true
		p.wg.Add(1)
		p.mu.Unlock()
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-x.done:
					return
				case <-p.stop:
					return
				case message := <-x.outbox:
					if e := x.sendRaw(message); e != nil {
						x.close()
						return
					}
				}
			}
		}()
	}

	for {
		_, b, e := conn.ReadMessage()
		if e != nil {
			return
		}
		if nodeMode {
			p.mu.Lock()
			current := p.nodes[id] == x
			p.mu.Unlock()
			if !current {
				return
			}
		}
		func() {
			defer func() { recover() }()
			raw := b
			if secret != "" {
				raw = decrypt(secret, b)
			}
			event := decode(raw)
			if str(event["type"]) == "EngineHello" && nodeMode {
				x.mu.Lock()
				x.info = obj(event["info"])
				x.mu.Unlock()
				p.queueReconcile(id)
				return
			}
			if request := str(event["requestId"]); request != "" {
				x.mu.Lock()
				ch := x.pending[request]
				delete(x.pending, request)
				x.mu.Unlock()
				if ch != nil {
					select {
					case ch <- event:
					default:
					}
				}
			}
			if strings.Contains(string(raw), "memory_usage") {
				x.send(M{"type": "call"})
			}
			if nodeMode {
				p.broadcast(M{"id": fmt.Sprint(id), "type": "info", "data": string(raw)})
			}
		}()
	}
}
func (p *Panel) rpc(node int64, data any, kind string) M {
	p.mu.Lock()
	x := p.nodes[node]
	p.mu.Unlock()
	if x == nil {
		return M{"message": "节点不在线"}
	}
	if x.engine == "kernel" && kind != "GetCapabilities" {
		x.mu.Lock()
		info := x.info
		x.mu.Unlock()
		if info == nil {
			return M{"message": "node capabilities unavailable during reconnect"}
		}
		if str(info["kernelBackend"]) != "nftables" {
			return M{"message": "node kernel backend mismatch"}
		}
	}

	if x.expiry > 0 && x.expiry <= now() {
		x.close()
		return M{"message": "节点凭据已过期"}
	}
	request := randomHex(16)
	ch := make(chan M, 1)
	x.mu.Lock()
	if len(x.pending) >= 256 {
		x.mu.Unlock()
		return M{"message": "node command queue is full"}
	}
	x.pending[request] = ch
	x.mu.Unlock()
	defer func() { x.mu.Lock(); delete(x.pending, request); x.mu.Unlock() }()
	if e := x.send(M{"type": kind, "data": data, "requestId": request}); e != nil {
		x.close()
		return M{"message": "节点连接已断开"}
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case reply := <-ch:
		p.mu.Lock()
		current := p.nodes[node] == x
		p.mu.Unlock()
		if !current {
			return M{"message": "节点会话已替换"}
		}
		return reply
	case <-x.done:
		return M{"message": "节点连接已断开"}
	case <-p.stop:
		return M{"message": "面板关闭中"}
	case <-timer.C:
		return M{"message": "等待响应超时"}
	}
}
func (p *Panel) commandOK(node int64, data any, kind string) M {
	r := p.rpc(node, data, kind)
	if str(r["message"]) != "OK" {
		fail(str(r["message"]))
	}
	return obj(r["data"])
}
func (x *peer) sendRaw(message string) error {
	x.writeMu.Lock()
	defer x.writeMu.Unlock()
	x.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return x.conn.WriteMessage(websocket.TextMessage, []byte(message))
}
func (p *Panel) broadcast(v any) {
	message := jsonText(v)
	if len(message) > 1<<20 {
		return
	}
	p.mu.Lock()
	xs := []*peer{}
	for x := range p.admins {
		xs = append(xs, x)
	}
	p.mu.Unlock()
	for _, x := range xs {
		select {
		case x.outbox <- message:
		default:
			x.close()
		}
	}
}
func (p *Panel) capability(node int64) M {
	p.mu.Lock()
	x := p.nodes[node]
	p.mu.Unlock()
	if x == nil {
		return nil
	}
	select {
	case <-x.done:
		return nil
	default:
	}
	if x.expiry > 0 && x.expiry <= now() {
		x.close()
		return nil
	}

	x.mu.Lock()
	info := x.info
	x.mu.Unlock()
	if info != nil {
		return obj(decode([]byte(jsonText(info))))
	}
	r := p.rpc(node, M{}, "GetCapabilities")
	if str(r["message"]) == "OK" {
		p.mu.Lock()
		current := p.nodes[node] == x
		p.mu.Unlock()
		if current {
			info = obj(r["data"])
			x.mu.Lock()
			x.info = info
			x.mu.Unlock()
			return info
		}
	}
	return nil
}
func (p *Panel) supports(node int64, feature string) bool {
	p.mu.Lock()
	x := p.nodes[node]
	p.mu.Unlock()
	if x == nil {
		return false
	}
	select {
	case <-x.done:
		return false
	default:
	}
	if x.expiry > 0 && x.expiry <= now() {
		return false
	}

	x.mu.Lock()
	info := x.info
	x.mu.Unlock()
	return truth(obj(obj(obj(info)["capabilities"])["features"])[feature])
}
func (p *Panel) requireCapability(node int64, feature string) {
	i := p.awaitCapabilities(node)
	if !truth(obj(obj(obj(i)["capabilities"])["features"])[feature]) {
		fail("node does not advertise capability: " + feature)
	}
}
func (p *Panel) verifyAgent(s store, node int64) {
	nativeNode(found(s.get("node", node), "节点不存在"))
	i := p.awaitCapabilities(node)
	if str(i["kernelBackend"]) != "nftables" {
		fail("node kernel backend mismatch")
	}
}
func (p *Panel) background(fn func(store)) {
	ctx, c := context.WithTimeout(context.Background(), 45*time.Second)
	defer c()
	defer func() { recover() }()
	fn(store{p.db, ctx})
}

func (p *Panel) nodeStatusLock(node int64) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	lock := p.nodeStatusLocks[node]
	if lock == nil {
		lock = &sync.Mutex{}
		p.nodeStatusLocks[node] = lock
	}
	return lock
}

func (p *Panel) awaitCapabilities(node int64) M {
	deadline := time.Now().Add(3 * time.Second)
	for {
		if info := p.capability(node); info != nil {
			return info
		}
		if time.Now().After(deadline) {
			fail("node capabilities unavailable during reconnect")
		}
		select {
		case <-p.stop:
			fail("panel is closing")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func nodeUnavailable(e apiError) bool {
	message := strings.ToLower(e.Message)
	for _, part := range []string{"节点不在线", "节点连接已断开", "节点凭据已过期", "节点会话已替换", "等待响应超时", "面板关闭中", "node command queue is full", "node capabilities unavailable", "node kernel backend mismatch", "panel is closing", "maintenance"} {
		if strings.Contains(message, part) {
			return true
		}
	}
	return false
}
