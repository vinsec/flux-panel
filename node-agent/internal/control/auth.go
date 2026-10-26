package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type accessCredentials struct {
	mu              sync.Mutex
	config          Config
	url             string
	token           string
	expires, issued int64
	refreshAfter    time.Time
}

func (a *accessCredentials) current(ctx context.Context) (string, error) {
	if !a.config.UseSessions {
		return a.config.Secret, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UnixMilli()
	if a.token != "" && time.Now().Before(a.refreshAfter) {
		return a.token, nil
	}
	started := time.Now()
	url := strings.Replace(a.url, "/flow/engine/v1/traffic", "/flow/engine/v3/session", 1)
	request, e := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader([]byte(`{}`)))
	if e != nil {
		return "", e
	}
	request.Header.Set("Authorization", "Bearer "+a.config.Secret)
	request.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 3 * time.Second}
	response, e := client.Do(request)
	if e != nil {
		return "", fmt.Errorf("node session endpoint unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", fmt.Errorf("node session authentication rejected: HTTP %d", response.StatusCode)
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 4096))
	if e != nil {
		return "", e
	}
	var issued struct {
		Access         string `json:"accessToken"`
		Expires        int64  `json:"expiresAt"`
		ValidForMillis int64  `json:"validForMillis"`
	}
	if e = json.Unmarshal(body, &issued); e != nil {
		return "", fmt.Errorf("invalid node session response")
	}
	if len(issued.Access) != 64 || issued.ValidForMillis < 5000 || issued.ValidForMillis > 3600000 {
		return "", fmt.Errorf("invalid node session lifetime")
	}
	a.token = issued.Access
	a.expires = issued.Expires
	a.issued = now
	a.refreshAfter = started.Add(time.Duration(issued.ValidForMillis*2/3) * time.Millisecond)
	return a.token, nil
}
func (a *accessCredentials) invalidate() { a.mu.Lock(); a.token = ""; a.expires = 0; a.mu.Unlock() }
