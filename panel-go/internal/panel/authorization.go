package panel

import (
	"context"
	"strings"
)

type ownerGate struct {
	token chan struct{}
	refs  int
}

func (p *Panel) lockOwner(ctx context.Context, id int64) func() {
	p.mu.Lock()
	gate := p.owners[id]
	if gate == nil {
		gate = &ownerGate{token: make(chan struct{}, 1)}
		gate.token <- struct{}{}
		p.owners[id] = gate
	}
	gate.refs++
	p.mu.Unlock()
	releaseRef := func() {
		p.mu.Lock()
		gate.refs--
		if gate.refs == 0 {
			delete(p.owners, id)
		}
		p.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		releaseRef()
		panic(ctx.Err())
	case <-gate.token:
	}
	return func() { gate.token <- struct{}{}; releaseRef() }
}

// Account-scoped authorization mutations serialize with forwarding creation,
// including operations on different physical nodes. Reads and other users proceed.
func (p *Panel) managementOwner(s store, c, b M, path string) int64 {
	if strings.HasPrefix(path, "/api/v1/forward/") {
		action := strings.TrimPrefix(path, "/api/v1/forward/")
		switch action {
		case "create":
			return num(c["sub"])
		case "update", "delete", "force-delete", "pause", "resume":
			if row := s.get("forward", b["id"]); row != nil {
				owner := num(row["userId"])
				if num(c["role_id"]) != 0 && owner != num(c["sub"]) {
					fail("转发不存在或无权限")
				}
				return owner
			}
		}
		return 0
	}
	switch path {
	case "/api/v1/user/update", "/api/v1/user/delete":
		return num(b["id"])
	case "/api/v1/user/updatePassword":
		return num(c["sub"])
	case "/api/v1/user/reset":
		if num(b["type"]) == 1 {
			return num(b["id"])
		}
		if row := s.get("user_tunnel", b["id"]); row != nil {
			return num(row["userId"])
		}
	case "/api/v1/tunnel/user/assign":
		return num(b["userId"])
	case "/api/v1/tunnel/user/update", "/api/v1/tunnel/user/remove":
		if row := s.get("user_tunnel", b["id"]); row != nil {
			return num(row["userId"])
		}
	}
	return 0
}
