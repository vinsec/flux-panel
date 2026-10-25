package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/vinsec/flux-panel/node-agent/internal/engine"
	"io"
	"net/http"
	"strings"
	"time"
)

func SettleMaintenance(c Config, r engine.Report) (engine.Acknowledgement, error) {
	var ack engine.Acknowledgement
	_, url, e := c.URLs()
	if e != nil {
		return ack, e
	}
	url = strings.Replace(url, "/flow/engine/v1/traffic", "/flow/engine/v2/maintenance", 1)
	b, e := json.Marshal(r)
	if e != nil {
		return ack, e
	}
	req, e := http.NewRequest("POST", url, bytes.NewReader(b))
	if e != nil {
		return ack, e
	}
	req.Header.Set("Authorization", "Bearer "+c.Secret)
	req.Header.Set("Content-Type", "application/json")
	response, e := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if e != nil {
		return ack, fmt.Errorf("maintenance panel unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return ack, fmt.Errorf("maintenance panel status %d", response.StatusCode)
	}
	b, e = io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if e != nil {
		return ack, e
	}
	if e = json.Unmarshal(b, &ack); e != nil {
		return ack, e
	}
	if !ack.MaintenanceAccepted {
		return ack, fmt.Errorf("panel did not acknowledge paused desired state")
	}
	return ack, nil
}
