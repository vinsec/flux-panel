package panel

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

func randomHex(n int) string {
	b := make([]byte, n)
	_, e := rand.Read(b)
	must(e)
	return hex.EncodeToString(b)
}
func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// Legacy record compatibility. A password-format migration must be a separate change.
func passwordHash(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
func (p *Panel) token(u M) string {
	enc := base64.RawURLEncoding.EncodeToString
	h := enc([]byte(`{"alg":"HmacSHA256","typ":"JWT"}`))
	b, e := json.Marshal(M{"sub": str(u["id"]), "iat": time.Now().Unix(), "exp": time.Now().Add(90 * 24 * time.Hour).Unix(), "user": u["user"], "name": u["user"], "role_id": u["roleId"]})
	must(e)
	v := h + "." + enc(b)
	mac := hmac.New(sha256.New, []byte(p.cfg.JWTSecret))
	mac.Write([]byte(v))
	return v + "." + enc(mac.Sum(nil))
}
func (p *Panel) claims(token string) M {
	a := strings.Split(token, ".")
	if len(a) != 3 {
		return nil
	}
	sig, e := base64.RawURLEncoding.DecodeString(a[2])
	if e != nil {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(p.cfg.JWTSecret))
	mac.Write([]byte(a[0] + "." + a[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil
	}
	b, e := base64.RawURLEncoding.DecodeString(a[1])
	if e != nil {
		return nil
	}
	m := M{}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	if d.Decode(&m) != nil {
		return nil
	}
	exp, e := json.Number(str(m["exp"])).Int64()
	if e != nil || exp <= time.Now().Unix() || m["role_id"] == nil || m["sub"] == nil {
		return nil
	}
	return m
}
func (p *Panel) identity(s store, authorization string) (M, int64) {
	if !strings.HasPrefix(authorization, "Bearer ") {
		return nil, 0
	}
	v := strings.TrimPrefix(authorization, "Bearer ")
	if len(v) > 256 {
		return nil, 0
	}
	if len(v) == 64 {
		r := s.one("SELECT node_id,expires_at FROM engine_session WHERE token_hash=? AND expires_at>?", digest(v), now())
		if r != nil {
			n := s.get("node", r["nodeId"])
			if n != nil {
				return n, num(r["expiresAt"])
			}
		}
	}
	return s.one("SELECT * FROM node WHERE secret=?", v), 0
}
func normalizeEngine(v any) string {
	switch strings.TrimSpace(str(v)) {
	case "", "gost":
		return "gost"
	case "kernel", "iptables":
		return "kernel"
	default:
		fail("不支持的转发引擎")
	}
	return ""
}
func nativeNode(n M) {
	if normalizeEngine(n["engine"]) != "kernel" {
		fail("not a kernel node")
	}
	if str(n["kernelBackend"]) != "nftables" {
		fail("旧 iptables 节点需要迁移，不允许接管")
	}
}
