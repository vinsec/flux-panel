package panel

import (
	"fmt"
	"strings"
	"sync"
)

func (p *Panel) tunnelAPI(s store, c, b M, action string) any {
	id := b["id"]
	switch action {
	case "list":
		return s.rows("SELECT * FROM tunnel")
	case "create", "update":
		p.tunnelNames.Lock()
		var once sync.Once
		unlockNames := func() { once.Do(p.tunnelNames.Unlock) }
		defer unlockNames()
		engine := normalizeEngine(b["engine"])
		m := pick(b, "name flow trafficRatio protocol tcpListenAddr udpListenAddr interfaceName")
		defaults(m, M{"trafficRatio": 1, "tcpListenAddr": "0.0.0.0", "udpListenAddr": "0.0.0.0"})
		if s.one("SELECT id FROM tunnel WHERE name=? AND id<>?", b["name"], num(id)) != nil {
			fail("隧道名称已存在")
		}
		var t M
		if action == "create" {
			n := found(s.get("node", b["inNodeId"]), "入口节点不存在")
			if num(n["status"]) != 1 {
				fail("入口节点当前离线，请确保节点正常运行")
			}
			if engine != normalizeEngine(n["engine"]) {
				fail("隧道与入口节点的转发引擎不匹配")
			}
			if engine == "kernel" {
				nativeNode(n)
			}
			m["inNodeId"] = n["id"]
			m["inIp"] = n["ip"]
			m["engine"] = engine
			m["type"] = b["type"]
			m["createdTime"] = now()
			m["updatedTime"] = now()
			m["status"] = 1
			if num(b["type"]) == 1 {
				m["outNodeId"] = n["id"]
				m["outIp"] = n["serverIp"]
				delete(m, "protocol")
			} else {
				require(b, "outNodeId protocol")
				if num(b["outNodeId"]) == num(n["id"]) {
					fail("隧道转发模式下，入口和出口不能是同一个节点")
				}
				out := found(s.get("node", b["outNodeId"]), "出口节点不存在")
				if num(out["status"]) != 1 {
					fail("出口节点当前离线，请确保节点正常运行")
				}
				m["outNodeId"] = out["id"]
				m["outIp"] = out["serverIp"]
			}
		} else {
			t = found(s.get("tunnel", id), "隧道不存在")
			if engine != normalizeEngine(t["engine"]) {
				fail("隧道引擎不可原地切换，请新建隧道迁移")
			}
			m["updatedTime"] = now()
		}
		kind := num(b["type"])
		if t != nil {
			kind = num(t["type"])
		}
		if engine == "kernel" && (kind != 1 || !ipv4(str(m["tcpListenAddr"])) || str(m["tcpListenAddr"]) != str(m["udpListenAddr"]) || strings.TrimSpace(str(m["interfaceName"])) != "") {
			fail("kernel schema1 需要相同的 IPv4 监听地址，且不支持指定网卡")
		}
		if action == "create" {
			s.insert("tunnel", m)
			return "隧道创建成功"
		}
		changed := false
		for _, k := range []string{"tcpListenAddr", "udpListenAddr", "protocol", "interfaceName"} {
			if str(t[k]) != str(m[k]) {
				changed = true
			}
		}
		s.update("tunnel", id, m)
		unlockNames()
		if changed {
			errors := 0
			for _, f := range s.rows("SELECT * FROM forward WHERE tunnel_id=?", id) {
				func() {
					defer func() {
						if v := recover(); v != nil {
							if _, expected := v.(apiError); !expected {
								panic(v)
							}
							errors++
						}
					}()
					unlockOwner := p.lockOwner(s.ctx, num(f["userId"]))
					defer unlockOwner()
					p.withPort(s, t, func(locked store) any {
						fresh := locked.get("forward", f["id"])
						if fresh != nil && num(fresh["tunnelId"]) == num(id) {
							p.validatePorts(locked, locked.get("tunnel", id), fresh, num(fresh["id"]))
							p.applyForward(locked, fresh, true)
						}
						return nil
					})
				}()
			}
			if errors > 0 {
				fail("隧道信息更新成功，但部分转发同步更新失败")
			}
		}
		return "隧道更新成功"
	case "delete":
		found(s.get("tunnel", id), "隧道不存在")
		if s.one("SELECT id FROM forward WHERE tunnel_id=? LIMIT 1", id) != nil {
			fail("该隧道还有转发在使用，请先删除相关转发")
		}
		if s.one("SELECT id FROM user_tunnel WHERE tunnel_id=? LIMIT 1", id) != nil {
			fail("该隧道还有用户权限关联，请先取消用户权限分配")
		}
		s.remove("tunnel", id)
		return "隧道删除成功"
	case "user/tunnel":
		query := "SELECT t.id,t.name,t.in_ip ip,t.type,t.protocol,n.port_sta inNodePortSta,n.port_end inNodePortEnd FROM tunnel t JOIN node n ON n.id=t.in_node_id WHERE t.status=1"
		if num(c["role_id"]) == 0 {
			return s.rows(query)
		}
		return s.rows(query+" AND EXISTS(SELECT 1 FROM user_tunnel ut WHERE ut.tunnel_id=t.id AND ut.user_id=?)", c["sub"])
	case "user/assign":
		found(s.get("user", b["userId"]), "用户不存在")
		found(s.get("tunnel", b["tunnelId"]), "隧道不存在")
		if s.one("SELECT id FROM user_tunnel WHERE user_id=? AND tunnel_id=?", b["userId"], b["tunnelId"]) != nil {
			fail("该用户已拥有此隧道权限")
		}
		m := pick(b, "userId tunnelId flow num flowResetTime expTime speedId")
		m["status"] = 1
		s.insert("user_tunnel", m)
		return "用户隧道权限分配成功"
	case "user/list":
		return s.rows("SELECT ut.*,t.name tunnelName,t.flow tunnelFlow,t.in_ip,t.out_ip,t.type,t.protocol,sl.name speedLimitName,sl.speed FROM user_tunnel ut LEFT JOIN tunnel t ON ut.tunnel_id=t.id LEFT JOIN speed_limit sl ON ut.speed_id=sl.id WHERE ut.user_id=? ORDER BY ut.id", b["userId"])
	case "user/update":
		old := found(s.get("user_tunnel", id), "用户隧道权限不存在")
		m := pick(b, "flow num flowResetTime expTime status")
		m["speedId"] = b["speedId"]
		s.update("user_tunnel", id, m)
		if str(old["speedId"]) != str(b["speedId"]) {
			for _, f := range s.rows("SELECT * FROM forward WHERE user_id=? AND tunnel_id=?", old["userId"], old["tunnelId"]) {
				p.withPort(s, found(s.get("tunnel", f["tunnelId"]), "隧道不存在"), func(locked store) any {
					if fresh := locked.get("forward", f["id"]); fresh != nil {
						p.applyForward(locked, fresh, true)
					}
					return nil
				})
			}
		}
		return "用户隧道权限更新成功"
	case "user/remove":
		ut := found(s.get("user_tunnel", id), "未找到对应的用户隧道权限记录")
		unavailable := map[int64]bool{}
		for _, f := range s.rows("SELECT * FROM forward WHERE user_id=? AND tunnel_id=?", ut["userId"], ut["tunnelId"]) {
			p.deleteRelatedForward(s, f, unavailable)
		}
		s.remove("user_tunnel", id)
		return "用户隧道权限删除成功"
	case "diagnose":
		t := found(s.get("tunnel", b["tunnelId"]), "隧道不存在")
		in := found(s.get("node", t["inNodeId"]), "入口节点不存在")
		if normalizeEngine(t["engine"]) == "kernel" {
			return p.diagnoseNativeTunnel(s, t, in)
		}
		results := []M{}
		label := "端口转发"
		if num(t["type"]) == 1 {
			results = append(results, p.diagnose(in, "www.google.com", 443, "入口->外网"))
		} else {
			label = "隧道转发"
			out := found(s.get("node", t["outNodeId"]), "出口节点不存在")
			port := int64(22)
			if f := s.one("SELECT out_port FROM forward WHERE tunnel_id=? AND status=1 LIMIT 1", t["id"]); f != nil {
				port = num(f["outPort"])
			}
			results = append(results, p.diagnose(in, str(out["serverIp"]), port, "入口->出口"), p.diagnose(out, "www.google.com", 443, "出口->外网"))
		}
		return M{"tunnelId": t["id"], "tunnelName": t["name"], "tunnelType": label, "results": results, "timestamp": now()}
	}
	panic("unknown tunnel action")
}

// Native tunnel diagnostics inspect the live engine and its rules. They do not
// issue legacy TcpPing commands or create public connections implicitly.
func (p *Panel) diagnoseNativeTunnel(s store, tunnel, node M) M {
	r := p.rpc(num(node["id"]), M{}, "GetCapabilities")
	info := obj(r["data"])
	ok := str(r["message"]) == "OK" && len(info) > 0 && !truth(info["blocked"]) && !truth(info["accountingBlocked"])
	message := str(r["message"])
	counts := M{}
	checked := 0
	forwards := s.rows("SELECT * FROM forward WHERE tunnel_id=? ORDER BY id LIMIT 101", tunnel["id"])
	ids := []string{}
	want := map[string]string{}
	for _, f := range forwards {
		if len(ids) == 100 {
			break
		}
		name, _ := serviceName(s, f)
		ids = append(ids, name)
		want[name] = "applied"
		if num(f["status"]) != 1 {
			want[name] = "paused"
		}
	}
	if ok && len(ids) > 0 {
		status := p.rpc(num(node["id"]), M{"ids": ids}, "GetForwardStatuses")
		if str(status["message"]) != "OK" {
			ok = false
			message = str(status["message"])
		} else {
			states := obj(status["data"])
			for _, id := range ids {
				state := str(obj(states[id])["status"])
				if state == "" {
					state = "unavailable"
				}
				counts[state] = num(counts[state]) + 1
				checked++
				if state != want[id] {
					ok = false
				}
			}
			message = fmt.Sprintf("已检查 %d 条规则，正常 %d 条", checked, num(counts["applied"])+num(counts["paused"]))
		}
	} else if ok {
		message = "节点在线，尚未创建转发"
	}
	if truth(info["blocked"]) || truth(info["accountingBlocked"]) {
		message = "节点转发或账本受阻"
	}
	result := M{"nodeId": node["id"], "nodeName": node["name"], "targetIp": node["serverIp"], "description": "节点与规则状态", "success": ok, "message": message, "probeKind": "runtimeState", "stateCounts": counts, "checkedForwards": checked, "truncated": len(forwards) > 100}
	return M{"tunnelId": tunnel["id"], "tunnelName": tunnel["name"], "tunnelType": "端口转发", "timestamp": now(), "probePerformed": false, "results": []M{result}}
}

func (p *Panel) diagnose(node M, host string, port int64, label string) M {
	r := p.rpc(num(node["id"]), M{"ip": host, "port": port, "count": 4, "timeout": 5000}, "TcpPing")
	d := obj(r["data"])
	m := M{"nodeId": node["id"], "nodeName": node["name"], "targetIp": host, "targetPort": port, "description": label, "timestamp": now(), "success": false, "message": r["message"], "averageTime": -1, "packetLoss": 100}
	if str(r["message"]) == "OK" {
		success := r["data"] == nil || truth(d["success"])
		m["success"] = success
		if success {
			m["message"] = "TCP连接成功"
			m["averageTime"] = d["averageTime"]
			m["packetLoss"] = d["packetLoss"]
		} else {
			m["message"] = d["errorMessage"]
		}
	}
	return m
}
func (p *Panel) limitAPI(s store, b M, action string) any {
	id := b["id"]
	switch action {
	case "list":
		return s.rows("SELECT * FROM speed_limit")
	case "tunnels":
		return s.rows("SELECT * FROM tunnel")
	case "create", "update":
		t := found(s.get("tunnel", b["tunnelId"]), "指定的隧道不存在")
		if str(t["name"]) != str(b["tunnelName"]) {
			fail("隧道名称与隧道ID不匹配")
		}
		m := pick(b, "name speed tunnelId tunnelName")
		m["updatedTime"] = now()
		if action == "create" {
			m["createdTime"] = now()
			m["status"] = 1
			id = s.insert("speed_limit", m)
			defer func() {
				if v := recover(); v != nil {
					s.remove("speed_limit", id)
					panic(v)
				}
			}()
		} else {
			found(s.get("speed_limit", id), "限速规则不存在")
		}
		node := num(t["inNodeId"])
		if normalizeEngine(t["engine"]) == "kernel" {
			p.requireCapability(node, "shaping")
			if action == "update" {
				s.update("speed_limit", id, m)
			}
			p.queueReconcile(node)
		} else {
			kind := "AddLimiters"
			if action == "update" {
				kind = "UpdateLimiters"
			}
			rate := gostRate(num(b["speed"]))
			data := M{"name": str(id), "limits": []string{"$ " + rate + "MB " + rate + "MB"}}
			var payload any = data
			if action == "update" {
				payload = M{"limiter": str(id), "data": data}
			}
			reply := p.rpc(node, payload, kind)
			if strings.Contains(str(reply["message"]), "not found") {
				reply = p.rpc(node, data, "AddLimiters")
			}
			if str(reply["message"]) != "OK" {
				if action == "create" {
					s.remove("speed_limit", id)
				}
				fail(str(reply["message"]))
			}
			if action == "update" {
				s.update("speed_limit", id, m)
			}
		}
		if action == "create" {
			return nil
		}
		return "限速规则更新成功"
	case "delete":
		m := found(s.get("speed_limit", id), "限速规则不存在")
		if s.one("SELECT id FROM user_tunnel WHERE speed_id=? LIMIT 1", id) != nil {
			fail("该限速规则还有用户在使用 请先取消分配")
		}
		t := s.get("tunnel", m["tunnelId"])
		if t != nil {
			if normalizeEngine(t["engine"]) == "kernel" {
				p.queueReconcile(num(t["inNodeId"]))
			} else {
				p.rpc(num(t["inNodeId"]), M{"limiter": str(id)}, "DeleteLimiters")
			}
		}
		s.remove("speed_limit", id)
		return "限速规则删除成功"
	}
	panic("unknown limiter action")
}
