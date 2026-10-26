package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/vinsec/flux-panel/node-agent/internal/engine"
)

type tlsKernel struct{}

func (tlsKernel) Snapshot() (map[string]uint64, error) { return map[string]uint64{}, nil }
func (tlsKernel) Apply(map[string]string) error        { return nil }

func TestTrustedWSSAndHTTPS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, e := engine.New(filepath.Join(t.TempDir(), "state.json"), tlsKernel{})
	if e != nil {
		t.Fatal(e)
	}
	frameOK := make(chan bool, 1)
	reportOK := make(chan bool, 1)
	mux := http.NewServeMux()
	secret := "local-tls-test-only"
	mux.HandleFunc("/system-info", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("engine") != "iptables" || r.URL.Query().Get("secret") != "" || r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(403)
			return
		}
		conn, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer conn.Close()
		b, _ := json.Marshal(map[string]interface{}{"type": "ApplyForward", "requestId": "tls-test", "data": engine.Spec{ID: "1_1_0", Revision: 1, ListenIP: "0.0.0.0", ListenPort: 18000, TargetIP: "10.20.0.2", TargetPort: 9000, Enabled: true}})
		b, _ = Encrypt(b, secret)
		conn.WriteMessage(websocket.TextMessage, b)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var v response
		for attempt := 0; attempt < 3; attempt++ {
			_, b, e = conn.ReadMessage()
			if e != nil {
				break
			}
			b, e = Decrypt(b, secret)
			if e != nil {
				break
			}
			if e = json.Unmarshal(b, &v); e != nil {
				break
			}
			if v.Type == "EngineHello" {
				continue
			}
			break
		}
		select {
		case frameOK <- e == nil && v.Success && v.RequestID == "tls-test":
		default:
		}
		<-ctx.Done()
	})
	mux.HandleFunc("/flow/engine/v1/traffic", func(w http.ResponseWriter, r *http.Request) {
		var v engine.Report
		e := json.NewDecoder(r.Body).Decode(&v)
		select {
		case reportOK <- e == nil && r.Header.Get("Authorization") == "Bearer "+secret && v.Epoch != "" && v.Sequence > 0:
		default:
		}
		w.Write([]byte("ok"))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	transport := http.DefaultTransport
	dialer := websocket.DefaultDialer
	http.DefaultTransport = server.Client().Transport
	copyDialer := *dialer
	copyDialer.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig
	websocket.DefaultDialer = &copyDialer
	defer func() { http.DefaultTransport = transport; websocket.DefaultDialer = dialer }()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Config{Addr: server.URL, Secret: secret, IntervalSeconds: 1}, m) }()
	for _, ch := range []chan bool{frameOK, reportOK} {
		select {
		case ok := <-ch:
			if !ok {
				t.Fatal("trusted TLS protocol exchange failed")
			}
		case <-time.After(4 * time.Second):
			t.Fatal("TLS protocol exchange timed out")
		}
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS client failed to stop")
	}
}

func TestTransportSecurityAndProtocolMapping(t *testing.T) {
	for _, addr := range []string{"wss://panel.example", "https://panel.example"} {
		c := Config{Addr: addr, Secret: "test"}
		w, h, e := c.URLs()
		if e != nil || w[:6] != "wss://" || h[:8] != "https://" {
			t.Fatal(addr, w, h, e)
		}
	}
	for _, addr := range []string{"http://panel.example", "ws://panel.example", "panel.example", "https://user:pass@panel.example", "https://panel.example?secret=bad"} {
		if _, _, e := (Config{Addr: addr}).URLs(); e == nil {
			t.Fatal("insecure or ambiguous address accepted", addr)
		}
	}
}
