package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ManagedGostConfig struct {
	Binary string `json:"binary"`
	SHA256 string `json:"sha256"`
	Socket string `json:"socket"`
}

func StartManagedGost(ctx context.Context, c Config) (func(), error) {
	if c.ManagedGost == nil {
		return func() {}, nil
	}
	g := c.ManagedGost
	if os.Geteuid() == 0 && !c.AllowInsecure {
		return nil, fmt.Errorf("managed GOST supervisor must run as an unprivileged account")
	}
	if !filepath.IsAbs(g.Binary) || !filepath.IsAbs(g.Socket) || len(g.Socket) > 100 {
		return nil, fmt.Errorf("managed GOST requires fixed absolute binary/socket paths")
	}
	file, e := os.Open(g.Binary)
	if e != nil {
		return nil, e
	}
	h := sha256.New()
	_, e = io.Copy(h, file)
	file.Close()
	if e != nil {
		return nil, e
	}
	if len(g.SHA256) != 64 || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(g.SHA256) {
		return nil, fmt.Errorf("managed GOST binary checksum mismatch")
	}
	dir := filepath.Dir(g.Socket)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	info, e := os.Stat(dir)
	if e != nil || info.Mode().Perm()&0007 != 0 {
		return nil, fmt.Errorf("GOST runtime directory must be private")
	}
	config := filepath.Join(dir, "services.json")
	b, _ := json.Marshal(map[string]any{"services": []any{}, "api": map[string]any{}})
	if e = os.WriteFile(config, b, 0600); e != nil {
		return nil, e
	}
	childCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if childCtx.Err() != nil {
				return
			}
			// The socket belongs exclusively to this managed worker directory.
			_ = os.Remove(g.Socket)
			cmd := exec.CommandContext(childCtx, g.Binary, "--agent-managed", "--agent-socket", g.Socket, "-C", config)
			cmd.Dir = dir
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			cmd.SysProcAttr = managedProcessAttributes()
			cmd.WaitDelay = 3 * time.Second
			if e := cmd.Start(); e == nil {
				if e := cmd.Wait(); e != nil && childCtx.Err() == nil {
					log.Printf("managed GOST exited: %v", e)
				}
			} else {
				log.Printf("managed GOST start failed: %v", e)
			}
			select {
			case <-childCtx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
	finish := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", g.Socket)
	}}}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && childCtx.Err() == nil {
		response, err := client.Get("http://managed/agent/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return finish, nil
			}
		}
		select {
		case <-childCtx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	finish()
	return nil, fmt.Errorf("managed GOST did not become ready; check worker startup logs")
}
