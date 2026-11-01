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
	KernelBackend   string   `json:"kernelBackend,omitempty"`
	DNSServers      []string `json:"dnsServers,omitempty"`
	LegacyQueryAuth bool     `json:"legacyQueryAuth,omitempty"`
	UseSessions     bool     `json:"useSessions,omitempty"`
	HelperSocket    string   `json:"helperSocket,omitempty"`
	Addr            string   `json:"addr"`
	Secret          string   `json:"secret"`
	StatePath       string   `json:"statePath"`
	Iptables        string   `json:"iptables"`
	Apply           bool     `json:"apply"`
	AllowInsecure   bool     `json:"allowInsecure"`
	IntervalSeconds int      `json:"intervalSeconds"`
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
	q.Set("version", "iptables-v5.4")
	if c.LegacyQueryAuth {
		q.Set("secret", c.Secret)
	}
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

func Handle(m ManagerAPI, data []byte) ([]byte, error) {
	var cmd command
	if e := strictJSON(data, &cmd); e != nil {
		return nil, e
	}
	r := response{Type: cmd.Type + "Response", RequestID: cmd.RequestID, Message: "OK", Success: true}
	var e error
	switch cmd.Type {
	case "RequireCreditPolicy":
		e = m.RequireCreditPolicy()
		r.Data = m.Info()
	case "RequestCredit":
		r.Data, e = m.Report()
	case "InstallCredit":
		var ack engine.Acknowledgement
		if e = strictJSON(cmd.Data, &ack); e == nil {
			e = m.Acknowledge(ack)
		}
		if e == nil {
			e = m.InstallGrants(ack.Grants)
		}
		r.Data = map[string]bool{"ready": m.CreditReady(ack.ServiceID)}

	case "CollectCounters":
		var count int
		count, e = m.Collect(time.Minute)
		r.Data = map[string]int{"removed": count}
	case "GetCapabilities":
		r.Data = m.Info()
	case "GetForwardStatus":
		var query struct {
			ID string `json:"id"`
		}
		if e = strictJSON(cmd.Data, &query); e == nil {
			r.Data = m.RuntimeStatus(query.ID)
		}
	case "GetForwardStatuses":
		var query struct {
			IDs []string `json:"ids"`
		}
		if e = strictJSON(cmd.Data, &query); e == nil {
			if len(query.IDs) > 100 {
				e = fmt.Errorf("status page exceeds 100 forwards")
			} else {
				r.Data = m.RuntimeStatuses(query.IDs)
			}
		}
	case "DiagnoseForward":
		var query struct {
			ID               string `json:"id"`
			Probe            bool   `json:"probe"`
			ClientIP         string `json:"clientIP"`
			IngressInterface string `json:"ingressInterface"`
		}
		if e = strictJSON(cmd.Data, &query); e == nil {
			r.Data, e = m.ReturnPathDiagnostics(context.Background(), query.ID, query.Probe, engine.ReturnPathQuery{ClientIP: query.ClientIP, IngressInterface: query.IngressInterface})
		}
	case "SubmitBatch":
		var b engine.Batch
		if e = strictJSON(cmd.Data, &b); e == nil {
			r.Data, e = m.Submit(b)
		}
	case "GetBatchStatus":
		var d struct {
			ID string `json:"id"`
		}
		if e = strictJSON(cmd.Data, &d); e == nil {
			r.Data, e = m.Job(d.ID)
		}
	case "GetEngineStatePage":
		var d struct {
			After      string  `json:"after"`
			Limit      int     `json:"limit"`
			Generation *uint64 `json:"generation"`
		}
		if e = strictJSON(cmd.Data, &d); e == nil {
			r.Data, e = m.Page(d.After, d.Limit, d.Generation)
		}
	case "ApplyForward":
		var s engine.Spec
		if e = strictJSON(cmd.Data, &s); e == nil {
			if s.Advanced() && s.AdvancedOptions != nil {
				if s.Runtime.Generation != 0 || len(s.Runtime.Targets) > 0 || s.Runtime.Error != "" || s.Runtime.Status != "" {
					e = fmt.Errorf("runtime resolution is node-owned")
					break
				}
				s.Runtime = engine.ResolutionState{}
			}
			e = m.Apply(s)
		}
		if e == nil {
			r.Data = m.RuntimeStatus(s.ID)
		}
	case "SetForwardState", "DeleteForward":
		var d struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			Enabled  bool   `json:"enabled"`
		}
		if e = strictJSON(cmd.Data, &d); e == nil {
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

func Run(ctx context.Context, c Config, m ManagerAPI) error {
	wsURL, httpURL, e := c.URLs()
	if e != nil {
		return e
	}
	if c.IntervalSeconds < 1 {
		c.IntervalSeconds = 5
	}
	m.StartJobs(ctx)
	m.ConfigureResolver(c.DNSServers)
	if e := m.StartRuntime(ctx); e != nil {
		return e
	}
	wake := make(chan struct{}, 1)
	var connectionMu sync.Mutex
	var live *websocket.Conn
	connectionBoot := ""
	connectionCredential := ""
	access := &accessCredentials{config: c, url: httpURL}
	metrics := &metricSampler{}
	metrics.sample()
	var workers sync.WaitGroup
	workers.Add(1)
	defer workers.Wait()
	if _, remote := m.(*RemoteManager); !remote {
		workers.Add(2)
		go func() {
			defer workers.Done()
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if e := m.RefreshRuntime(ctx); e != nil {
						log.Printf("runtime reconciliation deferred: %v", e)
					}
				}
			}
		}()
		go func() {
			defer workers.Done()
			tick := time.NewTicker(time.Second)
			nextGC := time.Now().Add(time.Minute)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if e := m.EnforceExpiration(); e != nil {
						log.Printf("local expiration enforcement failed: %v", e)
					}
					if time.Now().After(nextGC) {
						if _, e := m.Collect(5 * time.Minute); e != nil {
							log.Printf("counter collection deferred: %v", e)
						}
						nextGC = time.Now().Add(time.Minute)
					}
				}
			}
		}()
	}
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
			case <-wake:
			}
			{
				r, e := m.Report()
				if e != nil {
					log.Printf("statistics collection failed: %v", e)
					continue
				}
				if r.CreditMode {
					tick.Reset(time.Second)
				} else {
					tick.Reset(time.Duration(c.IntervalSeconds) * time.Second)
				}
				connectionMu.Lock()
				if live != nil && connectionBoot != "" && r.BootID != connectionBoot {
					pending, _ := m.Info()["maintenancePending"].(bool)
					if !pending {
						_ = live.Close()
					}
				}
				connectionMu.Unlock()
				b, _ := json.Marshal(r)
				credential, err := access.current(ctx)
				if err != nil {
					log.Printf("session refresh unavailable: %v", err)
					continue
				}
				connectionMu.Lock()
				if live != nil && connectionCredential != "" && connectionCredential != credential {
					_ = live.Close()
				}
				connectionMu.Unlock()
				v2URL := strings.Replace(httpURL, "/flow/engine/v1/traffic", "/flow/engine/v2/traffic", 1)
				pendingMaintenance, _ := m.Info()["maintenancePending"].(bool)
				if pendingMaintenance {
					v2URL = strings.Replace(v2URL, "/traffic", "/maintenance", 1)
				}
				req, e := http.NewRequestWithContext(ctx, "POST", v2URL, bytes.NewReader(b))
				if e != nil {
					continue
				}
				req.Header.Set("Authorization", "Bearer "+credential)
				req.Header.Set("Content-Type", "application/json")
				resp, e := client.Do(req)
				if e != nil {
					log.Print("traffic report unavailable; cumulative totals retained")
					continue
				}
				if resp.StatusCode == 404 || resp.StatusCode == 405 {
					resp.Body.Close()
					req, e = http.NewRequestWithContext(ctx, "POST", httpURL, bytes.NewReader(b))
					if e != nil {
						continue
					}
					req.Header.Set("Authorization", "Bearer "+credential)
					req.Header.Set("Content-Type", "application/json")
					resp, e = client.Do(req)
					if e != nil {
						continue
					}
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
				resp.Body.Close()
				if resp.StatusCode == 401 || resp.StatusCode == 403 {
					access.invalidate()
				}
				if resp.StatusCode == 200 && strings.TrimSpace(string(body)) != "ok" {
					var ack engine.Acknowledgement
					if e = json.Unmarshal(body, &ack); e == nil {
						e = m.Acknowledge(ack)
					}
					if e == nil && pendingMaintenance {
						e = m.CompleteMaintenance(ack)
					}
					if e == nil {
						e = m.InstallGrants(ack.Grants)
					}
					if e != nil {
						log.Printf("report acknowledgement rejected: %v", e)
					}
				} else if resp.StatusCode == 200 && strings.TrimSpace(string(body)) == "ok" {
					m.TransportAcknowledged()
				} else if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "ok" {
					log.Printf("traffic report rejected: HTTP %d", resp.StatusCode)
				}
			}
		}
	}()
	for ctx.Err() == nil {
		credential, err := access.current(ctx)
		if err != nil {
			log.Print("node session unavailable")
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
				continue
			}
		}
		headers := http.Header{}
		headers.Set("Authorization", "Bearer "+credential)
		conn, _, e := websocket.DefaultDialer.DialContext(ctx, wsURL, headers)
		if e != nil {
			access.invalidate()
			log.Print("panel connection unavailable; owned rules retained")
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
				continue
			}
		}
		log.Print("iptables agent connected")
		m.Connected(true)
		connectionMu.Lock()
		live = conn
		connectionBoot, _ = m.Info()["bootId"].(string)
		connectionCredential = credential
		connectionMu.Unlock()
		conn.SetReadLimit(16 << 20)
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
		hello, _ := json.Marshal(map[string]interface{}{"type": "EngineHello", "info": m.Info()})
		if e = writeFrame(hello); e != nil {
			conn.Close()
			continue
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
					info := metrics.sample()
					info["engine"] = "iptables"
					info["engineState"] = m.Info()
					body, _ := json.Marshal(info)
					if writeFrame(body) != nil {
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
			if reply != nil && (strings.Contains(string(plain), "ApplyForward") || strings.Contains(string(plain), "SetForwardState") || strings.Contains(string(plain), "DeleteForward") || strings.Contains(string(plain), "SubmitBatch")) {
				select {
				case wake <- struct{}{}:
				default:
				}
			}
			if reply != nil && writeFrame(reply) != nil {
				break
			}
		}
		close(done)
		m.Connected(false)
		connectionMu.Lock()
		if live == conn {
			live = nil
		}
		connectionMu.Unlock()
		conn.Close()
	}
	return nil
}
