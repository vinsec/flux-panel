package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Config struct {
	LeaseMaxBytes, LeaseDurationMillis                int64
	JWTSecret, ReleaseBase, ManifestSHA, InstallerSHA string
	AllowLegacyQuery                                  bool
	SessionMillis                                     int64
	ReadOnly                                          bool
	TimeZone                                          string
}
type Panel struct {
	userNames       sync.Mutex
	tunnelNames     sync.Mutex
	owners          map[int64]*ownerGate
	nodeStatusLocks map[int64]*sync.Mutex
	quotaJobs       chan M
	quotaPending    map[int64]bool
	gostCleanup     map[int64]M
	db              *sql.DB
	cfg             Config
	mu              sync.Mutex
	nodes           map[int64]*peer
	admins          map[*peer]bool
	tickets         map[string]ticket
	captcha         *captchas
	jobsCancel      context.CancelFunc
	wg              sync.WaitGroup
	stop            chan struct{}
	closeOnce       sync.Once
	leader          *sql.Conn
	reconcileQueue  map[int64]bool
	writeFailed     bool
}
type ticket struct{ User, Expiry int64 }

func New(db *sql.DB, cfg Config) *Panel {
	if cfg.JWTSecret == "" {
		panic("JWT_SECRET is required")
	}
	if cfg.LeaseMaxBytes == 0 {
		cfg.LeaseMaxBytes = 1 << 32
	}
	if cfg.LeaseDurationMillis == 0 {
		cfg.LeaseDurationMillis = 30000
	}
	if cfg.LeaseMaxBytes < 128 || cfg.LeaseMaxBytes > 1<<32 || cfg.LeaseDurationMillis < 1000 || cfg.LeaseDurationMillis > 60000 {
		panic("invalid credit lease configuration")
	}
	if cfg.SessionMillis == 0 {
		cfg.SessionMillis = 900000
	}
	return &Panel{db: db, cfg: cfg, owners: map[int64]*ownerGate{}, nodes: map[int64]*peer{}, nodeStatusLocks: map[int64]*sync.Mutex{}, quotaJobs: make(chan M, 64), quotaPending: map[int64]bool{}, gostCleanup: map[int64]M{}, admins: map[*peer]bool{}, tickets: map[string]ticket{}, captcha: newCaptchas(), stop: make(chan struct{})}
}
func (p *Panel) Handler() http.Handler { return http.HandlerFunc(p.serve) }
func (p *Panel) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
	w.Header().Set("Access-Control-Expose-Headers", "Authorization")
	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}
	defer func() {
		if v := recover(); v != nil {
			if r.Context().Err() != nil {
				return
			}
			if e, ok := v.(apiError); ok {
				if strings.HasPrefix(r.URL.Path, "/flow/engine/v1/") || strings.HasPrefix(r.URL.Path, "/flow/engine/v2/") {
					writeJSON(w, e.Status, M{"error": e.Message})
					return
				}
				writeJSON(w, e.Status, M{"code": e.Code, "msg": e.Message, "ts": now(), "data": nil})
				return
			}
			slog.Error("request failed", "path", r.URL.Path, "kind", errorKind(v))
			writeJSON(w, 500, M{"code": -1, "msg": "服务器内部错误", "ts": now(), "data": nil})
		}
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	s := store{p.db, ctx}
	if r.URL.Path == "/healthz" {
		if e := p.db.PingContext(ctx); e != nil {
			statusError(503, "database unavailable")
		}
		writeJSON(w, 200, M{"status": "ok", "readOnly": p.cfg.ReadOnly})
		return
	}
	p.mu.Lock()
	writeFailed := p.writeFailed
	p.mu.Unlock()
	if writeFailed {
		statusError(503, "control plane ownership lost")
	}
	if r.URL.Path == "/system-info" {
		if p.cfg.ReadOnly {
			statusError(403, "read-only mode")
		}
		p.socket(w, r, s)
		return
	}
	route, ok := routeByPath[r.URL.Path]
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(404)
		io.WriteString(w, "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='UTF-8'><title>错误 404</title></head><body><div class='error-code'>404</div><div class='error-title'>你推开了后端的大门，却发现里面只有寂寞。</div></body></html>")
		return
	}
	if route.Method != "ANY" && r.Method != route.Method {
		statusError(405, "Method Not Allowed")
	}
	var c M
	if strings.HasPrefix(r.URL.Path, "/api/") && !route.Public {
		c = p.claims(r.Header.Get("Authorization"))
		if c == nil {
			message := "未登录或token已过期"
			if r.Header.Get("Authorization") != "" {
				message = "无效的token或token已过期"
			}
			panic(apiError{message, 401, 200})
		}
		if route.Admin && num(c["role_id"]) != 0 {
			panic(apiError{"权限不足，仅管理员可操作", 403, 200})
		}
	}

	if p.cfg.ReadOnly && !route.ReadOnly {
		statusError(403, "read-only mode")
	}
	b := M{}
	if r.Body != nil {
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 50<<20))
		d.UseNumber()
		if e := d.Decode(&b); e != nil && !errors.Is(e, io.EOF) {
			statusError(400, "invalid JSON body")
		}
		var trailing any
		if d.Decode(&trailing) != io.EOF {
			statusError(400, "invalid trailing JSON")
		}
	}
	if route.DTO != "" {
		validateDTO(route.DTO, b)
	}
	if owner := p.managementOwner(s, c, b, r.URL.Path); owner > 0 {
		unlock := p.lockOwner(s.ctx, owner)
		defer unlock()
	}
	result := p.dispatch(r, w, s, c, b)
	if _, ok := result.(writtenType); ok {
		return
	}
	if raw, ok := result.(rawJSON); ok {
		writeJSON(w, 200, raw.Value)
		return
	}
	if text, ok := result.(plain); ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, string(text))
		return
	}
	writeJSON(w, 200, M{"code": 0, "msg": "操作成功", "ts": now(), "data": result})
}
func errorKind(v any) string {
	if _, ok := v.(error); ok {
		return redact(v.(error).Error())
	}
	return "internal panic"
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type plain string
type rawJSON struct{ Value any }
type writtenType int

const written writtenType = 1
