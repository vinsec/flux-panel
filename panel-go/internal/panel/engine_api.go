package panel

import (
	"fmt"
)

func (p *Panel) issueSession(s store, authorization string) M {
	if len(authorization) < 8 || authorization[:7] != "Bearer " {
		fail("bootstrap authentication required")
	}
	v := authorization[7:]
	if len(v) > 128 {
		fail("invalid bootstrap credential")
	}
	n := s.one("SELECT * FROM node WHERE secret=? AND engine='kernel'", v)
	if n == nil {
		fail("invalid bootstrap credential")
	}
	nativeNode(n)
	instant := now()
	expiry := instant + max(60000, min(3600000, p.cfg.SessionMillis))
	access := randomHex(32)
	s.exec("INSERT INTO engine_session(token_hash,node_id,created_at,expires_at) VALUES(?,?,?,?)", digest(access), n["id"], instant, expiry)
	return M{"accessToken": access, "expiresAt": expiry, "validForMillis": expiry - instant, "nodeId": n["id"]}
}
func (p *Panel) audit(s store, user any, node int64, action, service, detail string) {
	detail = redact(detail)
	if len(detail) > 2048 {
		detail = detail[:2048]
	}
	var serviceValue any
	if service != "" {
		serviceValue = service
	}
	s.exec("INSERT INTO engine_audit(created_at,user_id,node_id,action,service_id,detail) VALUES(?,?,?,?,?,?)", now(), user, node, action, serviceValue, detail)
}
func (p *Panel) engineAPI(s store, c, b M, action string) any {
	node := num(b["nodeId"])
	switch action {
	case "switch-mode":
		return p.switchMode(s, c, b, false)
	case "mode-switch-status":
		return p.switchMode(s, c, b, true)
	case "socket-ticket":
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.tickets) > 4096 {
			fail("ticket capacity exceeded")
		}
		value := randomHex(32)
		p.tickets[digest(value)] = ticket{num(c["sub"]), now() + 30000}
		return M{"ticket": value, "expiresInMillis": 30000}
	case "revoke-sessions":
		s.exec("DELETE FROM engine_session WHERE node_id=?", node)
		p.mu.Lock()
		x := p.nodes[node]
		p.mu.Unlock()
		if x != nil && x.expiry > 0 {
			x.close()
		}
		p.audit(s, num(c["sub"]), node, "REVOKE_NODE_SESSIONS", "", "short lived sessions revoked")
		return nil
	case "capabilities":
		reply := p.rpc(node, M{}, "GetCapabilities")
		i := obj(reply["data"])
		if str(reply["message"]) != "OK" || len(i) == 0 {
			fail("node capabilities unavailable")
		}
		return i
	case "reconcile":
		return p.reconcile(s, node)
	case "batch-status":
		return p.commandOK(node, M{"id": b["id"]}, "GetBatchStatus")
	case "collect":
		return p.commandOK(node, M{}, "CollectCounters")
	case "tunnel-capabilities":
		t := found(s.get("tunnel", b["tunnelId"]), "隧道不存在")
		if num(c["role_id"]) != 0 && s.one("SELECT id FROM user_tunnel WHERE user_id=? AND tunnel_id=? AND status=1 AND exp_time>?", c["sub"], t["id"], now()) == nil {
			fail("无隧道权限")
		}
		m := M{"engine": t["engine"], "tcpListenAddr": t["tcpListenAddr"], "udpListenAddr": t["udpListenAddr"]}
		if str(t["engine"]) == "kernel" {
			m["node"] = p.capability(num(t["inNodeId"]))
		}
		return m
	case "forward-states":
		ids := arr(b["ids"])
		if len(ids) < 1 || len(ids) > 200 {
			fail("status page requires 1..200 forwarding IDs")
		}
		groups := map[int64]map[string]int64{}
		for _, id := range ids {
			f := s.get("forward", id)
			if f == nil {
				continue
			}
			if num(c["role_id"]) != 0 && num(f["userId"]) != num(c["sub"]) {
				fail("转发不存在或无权限")
			}
			t := s.get("tunnel", f["tunnelId"])
			if t == nil || str(t["engine"]) != "kernel" {
				continue
			}
			n := num(t["inNodeId"])
			if groups[n] == nil {
				groups[n] = map[string]int64{}
			}
			name, ut := serviceName(s, f)
			u := s.get("user", f["userId"])
			if u != nil && num(u["roleId"]) != 0 && ut == nil {
				continue
			}
			groups[n][name] = num(f["id"])
		}
		out := []M{}
		for n, g := range groups {
			names := []string{}
			for name := range g {
				names = append(names, name)
			}
			for offset := 0; offset < len(names); offset += 100 {
				page := names[offset:min(offset+100, len(names))]
				r := p.rpc(n, M{"ids": page}, "GetForwardStatuses")
				d := obj(r["data"])
				for _, name := range page {
					state := d[name]
					if str(r["message"]) != "OK" {
						state = M{"status": "unavailable"}
					}
					out = append(out, M{"id": g[name], "state": state})
				}
			}
		}
		return out
	case "bandwidth-groups":
		return s.rows("SELECT scope,owner_id ownerId,up_bits upBitsPerSecond,down_bits downBitsPerSecond FROM engine_bandwidth_group WHERE node_id=?", node)
	case "set-bandwidth-group":
		scope, owner := str(b["scope"]), num(b["ownerId"])
		if (scope != "user" && scope != "userTunnel") || owner < 1 {
			fail("invalid bandwidth group scope")
		}
		p.requireCapability(node, "shaping")
		rates(b)
		up, down := num(b["upBitsPerSecond"]), num(b["downBitsPerSecond"])
		s.exec("INSERT INTO engine_bandwidth_group(node_id,scope,owner_id,up_bits,down_bits,updated_at) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE up_bits=VALUES(up_bits),down_bits=VALUES(down_bits),updated_at=VALUES(updated_at)", node, scope, owner, up, down, now())
		p.queueReconcile(node)
		p.audit(s, num(c["sub"]), node, "SET_BANDWIDTH_GROUP", "", fmt.Sprintf("%s:%d", scope, owner))
		return nil
	case "audit":
		limit := max(1, min(200, num(b["limit"])))
		return s.rows("SELECT id,created_at,user_id,node_id,action,service_id,detail FROM engine_audit WHERE node_id=? ORDER BY id DESC LIMIT ?", node, limit)
	}
	panic("unknown engine action")
}
