package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/vinsec/flux-panel/node-agent/internal/engine"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Addr            string `json:"addr"`
	Secret          string `json:"secret"`
	StatePath       string `json:"statePath"`
	Iptables        string `json:"iptables"`
	Apply           bool   `json:"apply"`
	AllowInsecure   bool   `json:"allowInsecure"`
	IntervalSeconds int    `json:"intervalSeconds"`
}

func (c Config) URLs() (string, string, error) {
	u, e := url.Parse(c.Addr)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("panel address must be a ws(s)/http(s) URL without credentials or query")
	}
	secure := u.Scheme == "https" || u.Scheme == "wss"
	if !secure && (!c.AllowInsecure || (u.Scheme != "http" && u.Scheme != "ws")) {
		return "", "", fmt.Errorf("WSS/HTTPS required (allowInsecure is for isolated tests)")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	ws := *u
	h := *u
	if secure {
		ws.Scheme = "wss"
		h.Scheme = "https"
	} else {
		ws.Scheme = "ws"
		h.Scheme = "http"
	}
	ws.Path += "/system-info"
	q := ws.Query()
	q.Set("type", "1")
	q.Set("engine", "iptables")
	q.Set("version", "iptables-v2")
	q.Set("secret", c.Secret)
	q.Set("http", "0")
	q.Set("tls", "0")
	q.Set("socks", "0")
	ws.RawQuery = q.Encode()
	h.Path += "/flow/engine/v1/traffic"
	return ws.String(), h.String(), nil
}

type command struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	RequestID string          `json:"requestId"`
}
type response struct {
	Type      string      `json:"type"`
	RequestID string      `json:"requestId"`
	Success   bool        `json:"success"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data,omitempty"`
}

func Handle(m *engine.Manager, data []byte) ([]byte, error) {
	var cmd command
	if e := json.Unmarshal(data, &cmd); e != nil {
		return nil, e
	}
	r := response{Type: cmd.Type + "Response", RequestID: cmd.RequestID, Message: "OK", Success: true}
	var e error
	switch cmd.Type {
	case "ApplyForward":
		var s engine.Spec
		if e = json.Unmarshal(cmd.Data, &s); e == nil {
			e = m.Apply(s)
		}
	case "SetForwardState", "DeleteForward":
		var d struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			Enabled  bool   `json:"enabled"`
		}
		if e = json.Unmarshal(cmd.Data, &d); e == nil {
			e = m.Change(d.ID, d.Revision, d.Enabled, cmd.Type == "DeleteForward")
		}
		if e == nil && cmd.Type == "DeleteForward" {
			r.Data, e = m.Report()
		}
	case "GetEngineState":
		r.Data = m.Rules()
	case "call":
		return nil, nil
	default:
		e = fmt.Errorf("unsupported command %s", cmd.Type)
	}
	if e != nil {
		r.Success = false
		r.Message = e.Error()
	}
	return json.Marshal(r)
}

func Run(ctx context.Context, c Config, m *engine.Manager) error {
	wsURL, httpURL, e := c.URLs()
	if e != nil {
		return e
	}
	if c.IntervalSeconds < 1 {
		c.IntervalSeconds = 5
	}
	var workers sync.WaitGroup
	workers.Add(2)
	defer workers.Wait()
	go func() {
		defer workers.Done()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if e := m.EnforceExpiration(); e != nil {
					log.Printf("local expiration enforcement failed: %v", e)
				}
			}
		}
	}()
	go func() {
		defer workers.Done()
		tick := time.NewTicker(time.Duration(c.IntervalSeconds) * time.Second)
		defer tick.Stop()
		client := &http.Client{Timeout: 5 * time.Second}
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				r, e := m.Report()
				if e != nil {
					log.Printf("statistics collection failed: %v", e)
					continue
				}
				b, _ := json.Marshal(r)
				req, e := http.NewRequestWithContext(ctx, "POST", httpURL, bytes.NewReader(b))
				if e != nil {
					continue
				}
				req.Header.Set("Authorization", "Bearer "+c.Secret)
				req.Header.Set("Content-Type", "application/json")
				resp, e := client.Do(req)
				if e != nil {
					log.Print("traffic report unavailable; cumulative totals retained")
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				resp.Body.Close()
				if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "ok" {
					log.Printf("traffic report rejected: HTTP %d", resp.StatusCode)
				}
			}
		}
	}()
	for ctx.Err() == nil {
		conn, _, e := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
		if e != nil {
			log.Print("panel connection unavailable; owned rules retained")
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
				continue
			}
		}
		log.Print("iptables agent connected")
		conn.SetReadLimit(1 << 20)
		var write sync.Mutex
		writeFrame := func(b []byte) error {
			v, e := Encrypt(b, c.Secret)
			if e != nil {
				return e
			}
			write.Lock()
			defer write.Unlock()
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			return conn.WriteMessage(websocket.TextMessage, v)
		}
		done := make(chan struct{})
		go func() {
			t := time.NewTicker(15 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-ctx.Done():
					conn.Close()
					return
				case <-t.C:
					if writeFrame([]byte(`{"memory_usage":0,"cpu_usage":0,"engine":"iptables"}`)) != nil {
						conn.Close()
						return
					}
				}
			}
		}()
		for {
			_, raw, e := conn.ReadMessage()
			if e != nil {
				break
			}
			plain, e := Decrypt(raw, c.Secret)
			if e != nil {
				log.Print("rejected invalid control frame")
				continue
			}
			reply, e := Handle(m, plain)
			if e != nil {
				log.Printf("invalid command: %v", e)
				continue
			}
			if reply != nil && writeFrame(reply) != nil {
				break
			}
		}
		close(done)
		conn.Close()
	}
	return nil
}
