package control

import (
	"context"
	"encoding/json"
	"github.com/vinsec/flux-panel/node-agent/internal/engine"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExplicitLegacyURLAndHeaderDefault(t *testing.T) {
	c := Config{Addr: "wss://panel.test", Secret: "must-not-enter-url"}
	u, _, e := c.URLs()
	if e != nil || strings.Contains(u, c.Secret) || strings.Contains(u, "secret=") {
		t.Fatal(u, e)
	}
	c.LegacyQueryAuth = true
	u, _, e = c.URLs()
	if e != nil || !strings.Contains(u, "secret=") {
		t.Fatal("explicit legacy registration unavailable")
	}
}
func TestShortSessionRotationAndBootstrapHeader(t *testing.T) {
	var issued atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bootstrap-test" || r.URL.RawQuery != "" {
			t.Error("credential scope leaked")
		}
		count := issued.Add(1)
		token := strings.Repeat("a", 64)
		if count > 1 {
			token = strings.Repeat("b", 64)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": token, "expiresAt": time.Now().Add(time.Minute).UnixMilli(), "validForMillis": 60000})
	}))
	defer server.Close()
	a := &accessCredentials{config: Config{UseSessions: true, Secret: "bootstrap-test"}, url: server.URL + "/flow/engine/v1/traffic"}
	first, e := a.current(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	same, _ := a.current(context.Background())
	if same != first || issued.Load() != 1 {
		t.Fatal("unnecessary session issuance")
	}
	a.mu.Lock()
	a.refreshAfter = time.Now().Add(-time.Second)
	a.mu.Unlock()
	second, e := a.current(context.Background())
	if e != nil || second == first || issued.Load() != 2 {
		t.Fatal("short session did not rotate", e)
	}
}
func TestNetworkCannotInvokeHelperInternalsOrInjectRuntime(t *testing.T) {
	m, e := engine.New(filepath.Join(t.TempDir(), "state"), tlsKernel{})
	if e != nil {
		t.Fatal(e)
	}
	for _, frame := range []string{`{"type":"_Connected","data":true}`, `{"type":"ApplyForward","data":{"id":"1_2_3","revision":1,"exec":"reboot"}}`, `{"type":"ApplyForward","data":{"schemaVersion":3,"id":"1_2_3","revision":1,"runtime":{"targets":[{"host":"127.0.0.1"}]}}}`} {
		body, e := Handle(m, []byte(frame))
		if e != nil {
			continue
		}
		var result response
		_ = json.Unmarshal(body, &result)
		if result.Success {
			t.Fatal("invalid privileged request accepted", frame)
		}
	}
}
