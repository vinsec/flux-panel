package control

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/vinsec/flux-panel/node-agent/internal/engine"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type helperCall struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}
type helperReply struct {
	Success bool            `json:"success"`
	Message string          `json:"message,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func ServeHelper(ctx context.Context, path string, uid uint32, m *engine.Manager) error {
	if !filepath.IsAbs(path) || len(path) > 100 {
		return fmt.Errorf("helper socket must be an absolute short path")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0750); e != nil {
		return e
	}
	if st, e := os.Lstat(path); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing non-socket helper path")
		}
		if conn, e := net.DialTimeout("unix", path, 200*time.Millisecond); e == nil {
			conn.Close()
			return fmt.Errorf("helper socket already active")
		}
		if e = os.Remove(path); e != nil {
			return e
		}
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return e
	}
	defer listener.Close()
	defer os.Remove(path)
	if e = os.Chmod(path, 0660); e != nil {
		return e
	}
	m.StartJobs(ctx)
	if e = m.StartRuntime(ctx); e != nil {
		return e
	}
	var workers sync.WaitGroup
	defer workers.Wait()
	workers.Add(1)
	go func() {
		defer workers.Done()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		nextGC := time.Now().Add(time.Minute)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				_ = m.EnforceExpiration()
				if time.Now().After(nextGC) {
					_, _ = m.Collect(5 * time.Minute)
					nextGC = time.Now().Add(time.Minute)
				}
			}
		}
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				_ = m.RefreshRuntime(ctx)
			}
		}
	}()
	go func() { <-ctx.Done(); listener.Close() }()
	limit := make(chan struct{}, 16)
	for {
		conn, e := listener.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		if !helperPeerAllowed(conn, uid) {
			conn.Close()
			continue
		}
		select {
		case limit <- struct{}{}:
		case <-ctx.Done():
			conn.Close()
			return nil
		}
		workers.Add(1)
		go func(conn *net.UnixConn) {
			defer workers.Done()
			defer func() { <-limit }()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			reader := bufio.NewReader(io.LimitReader(conn, 16<<20))
			var call helperCall
			decoder := json.NewDecoder(reader)
			decoder.DisallowUnknownFields()
			if e := decoder.Decode(&call); e != nil {
				return
			}
			var data any
			var failure error
			switch call.Type {
			case "_Info":
				data = m.Info()
			case "_Report":
				data, failure = m.Report()
			case "_Ack":
				var ack engine.Acknowledgement
				if failure = json.Unmarshal(call.Data, &ack); failure == nil {
					failure = m.Acknowledge(ack)
				}
			case "_Grants":
				var grants []engine.LeaseGrant
				if failure = json.Unmarshal(call.Data, &grants); failure == nil {
					failure = m.InstallGrants(grants)
				}
			case "_CreditReady":
				var id string
				if failure = json.Unmarshal(call.Data, &id); failure == nil {
					data = m.CreditReady(id)
				}
			case "_Connected":
				var connected bool
				if failure = json.Unmarshal(call.Data, &connected); failure == nil {
					m.Connected(connected)
				}
			case "_TransportAck":
				m.TransportAcknowledged()
			case "_CompleteMaintenance":
				var ack engine.Acknowledgement
				if failure = json.Unmarshal(call.Data, &ack); failure == nil {
					failure = m.CompleteMaintenance(ack)
				}
			case "_Rules":
				data = m.Rules()
			default:
				allowed := map[string]bool{"RequireCreditPolicy": true, "RequestCredit": true, "InstallCredit": true, "CollectCounters": true, "GetCapabilities": true, "GetForwardStatus": true, "GetForwardStatuses": true, "DiagnoseForward": true, "SubmitBatch": true, "GetBatchStatus": true, "GetEngineStatePage": true, "ApplyForward": true, "SetForwardState": true, "DeleteForward": true, "GetEngineState": true}
				if !allowed[call.Type] {
					failure = fmt.Errorf("helper operation denied")
					break
				}
				frame, _ := json.Marshal(command{Type: call.Type, Data: call.Data, RequestID: "local"})
				body, e := Handle(m, frame)
				if e != nil {
					failure = e
					break
				}
				var result response
				if failure = json.Unmarshal(body, &result); failure == nil {
					if !result.Success {
						failure = fmt.Errorf("%s", result.Message)
					} else {
						data = result.Data
					}
				}
			}
			reply := helperReply{Success: failure == nil}
			if failure != nil {
				reply.Message = failure.Error()
			} else {
				reply.Data, _ = json.Marshal(data)
			}
			_ = json.NewEncoder(conn).Encode(reply)
		}(conn)
	}
}

type RemoteManager struct{ Socket string }

func (r *RemoteManager) call(method string, data, out any) error {
	conn, e := net.DialTimeout("unix", r.Socket, time.Second)
	if e != nil {
		return fmt.Errorf("kernel helper unavailable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	payload, e := json.Marshal(data)
	if e != nil {
		return e
	}
	if e = json.NewEncoder(conn).Encode(helperCall{Type: method, Data: payload}); e != nil {
		return e
	}
	var reply helperReply
	if e = json.NewDecoder(io.LimitReader(conn, 16<<20)).Decode(&reply); e != nil {
		return e
	}
	if !reply.Success {
		return fmt.Errorf("%s", reply.Message)
	}
	if out != nil {
		return json.Unmarshal(reply.Data, out)
	}
	return nil
}
func (r *RemoteManager) Info() map[string]any {
	v := map[string]any{}
	if e := r.call("_Info", nil, &v); e != nil {
		return map[string]any{"blocked": true, "helperError": e.Error()}
	}
	v["privilegedHelper"] = true
	if caps, ok := v["capabilities"].(map[string]any); ok {
		if features, ok := caps["features"].(map[string]any); ok {
			features["privilegedHelper"] = true
		}
	}
	return v
}
func (r *RemoteManager) RequireCreditPolicy() error { return r.call("RequireCreditPolicy", nil, nil) }
func (r *RemoteManager) Report() (engine.Report, error) {
	var v engine.Report
	e := r.call("_Report", nil, &v)
	return v, e
}
func (r *RemoteManager) Acknowledge(v engine.Acknowledgement) error { return r.call("_Ack", v, nil) }
func (r *RemoteManager) InstallGrants(v []engine.LeaseGrant) error  { return r.call("_Grants", v, nil) }
func (r *RemoteManager) CreditReady(id string) bool {
	var v bool
	_ = r.call("_CreditReady", id, &v)
	return v
}
func (r *RemoteManager) Collect(_ time.Duration) (int, error) {
	var v struct {
		Removed int `json:"removed"`
	}
	e := r.call("CollectCounters", nil, &v)
	return v.Removed, e
}
func (r *RemoteManager) Submit(b engine.Batch) (engine.Job, error) {
	var v engine.Job
	e := r.call("SubmitBatch", b, &v)
	return v, e
}
func (r *RemoteManager) Job(id string) (engine.Job, error) {
	var v engine.Job
	e := r.call("GetBatchStatus", map[string]string{"id": id}, &v)
	return v, e
}
func (r *RemoteManager) Page(after string, limit int, generation *uint64) (engine.Page, error) {
	var v engine.Page
	e := r.call("GetEngineStatePage", map[string]any{"after": after, "limit": limit, "generation": generation}, &v)
	return v, e
}
func (r *RemoteManager) Apply(s engine.Spec) error { return r.call("ApplyForward", s, nil) }
func (r *RemoteManager) Change(id string, revision int64, enabled, deleted bool) error {
	method := "SetForwardState"
	if deleted {
		method = "DeleteForward"
	}
	return r.call(method, map[string]any{"id": id, "revision": revision, "enabled": enabled}, nil)
}
func (r *RemoteManager) Rules() map[string]engine.Spec {
	var v map[string]engine.Spec
	_ = r.call("_Rules", nil, &v)
	return v
}
func (r *RemoteManager) RuntimeStatus(id string) map[string]any {
	var v map[string]any
	if e := r.call("GetForwardStatus", map[string]string{"id": id}, &v); e != nil {
		return map[string]any{"status": "unavailable", "error": e.Error()}
	}
	return v
}
func (r *RemoteManager) RuntimeStatuses(ids []string) map[string]map[string]any {
	var v map[string]map[string]any
	if e := r.call("GetForwardStatuses", map[string]any{"ids": ids}, &v); e != nil {
		return map[string]map[string]any{}
	}
	return v
}
func (r *RemoteManager) StartJobs(context.Context)            {}
func (r *RemoteManager) StartRuntime(context.Context) error   { return nil }
func (r *RemoteManager) RefreshRuntime(context.Context) error { return nil }
func (r *RemoteManager) EnforceExpiration() error             { return nil }
func (r *RemoteManager) Connected(v bool)                     { _ = r.call("_Connected", v, nil) }
func (r *RemoteManager) TransportAcknowledged()               { _ = r.call("_TransportAck", nil, nil) }
func (r *RemoteManager) CompleteMaintenance(v engine.Acknowledgement) error {
	return r.call("_CompleteMaintenance", v, nil)
}
func (r *RemoteManager) ConfigureResolver([]string) {}

func HelperUID(value string) (uint32, error) {
	n, e := strconv.ParseUint(value, 10, 32)
	return uint32(n), e
}

func (r *RemoteManager) Diagnostics(ctx context.Context, id string, probe bool) (map[string]any, error) {
	var v map[string]any
	e := r.call("DiagnoseForward", map[string]any{"id": id, "probe": probe}, &v)
	return v, e
}
