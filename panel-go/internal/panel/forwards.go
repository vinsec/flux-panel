package panel

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func serviceName(s store, f M, snapshots ...*specSnapshot) (string, M) {
	var snap *specSnapshot
	if len(snapshots) > 0 {
		snap = snapshots[0]
	}
	var u M
	if snap != nil {
		u = snap.users[num(f["userId"])]
	} else {
		u = s.get("user", f["userId"])
	}
	var ut M
	permission := int64(0)
	if u != nil && num(u["roleId"]) != 0 {
		if snap != nil {
			ut = snap.permissions[fmt.Sprint(num(f["userId"]), "/", num(f["tunnelId"]))]
		} else {
			ut = s.one("SELECT * FROM user_tunnel WHERE user_id=? AND tunnel_id=?", f["userId"], f["tunnelId"])
		}
		if ut != nil {
			permission = num(ut["id"])
		}
	}
	return fmt.Sprintf("%d_%d_%d", num(f["id"]), num(f["userId"]), permission), ut
}
func (p *Panel) owned(s store, c M, id any) M {
	f := s.get("forward", id)
	if f == nil || (num(c["role_id"]) != 0 && num(f["userId"]) != num(c["sub"])) {
		fail("转发不存在或无权限")
	}
	return f
}
func (p *Panel) withPort(s store, t M, fn func(store) any) any {
	n := found(s.get("node", t["inNodeId"]), "节点不存在")
	host := str(n["serverIp"])
	if host == "" {
		host = "node:" + str(n["id"])
	}
	key := "flux-port-" + digest(strings.ToLower(host))[:40]
	conn, e := p.db.Conn(s.ctx)
	must(e)
	defer conn.Close()
	locked := store{conn, s.ctx}
	r := locked.one("SELECT GET_LOCK(?,10) acquired", key)
	if num(r["acquired"]) != 1 {
		fail("physical node port lock busy")
	}
	defer releaseNamedLock(conn, key)
	if !truth(t["_modeSwitch"]) {
		if row := locked.one("SELECT status FROM engine_mode_switch WHERE node_id=?", n["id"]); row != nil && (str(row["status"]) == "pending" || str(row["status"]) == "running" || str(row["status"]) == "blocked") {
			fail("节点正在切换或需要恢复，暂不接受规则变更")
		}
	}
	return fn(locked)
}
func (p *Panel) forwardAPI(s store, c, b M, action string) any {
	if action == "list" {
		query := "SELECT f.id,f.name,f.in_port,f.remote_addr,f.engine_options,t.engine,f.status,f.created_time,f.updated_time,t.name tunnelName,t.in_ip,f.user_name,f.user_id,f.tunnel_id,f.in_flow,f.out_flow,f.strategy,f.inx,f.interface_name FROM forward f LEFT JOIN tunnel t ON t.id=f.tunnel_id"
		args := []any{}
		if num(c["role_id"]) != 0 {
			query += " WHERE f.user_id=?"
			args = append(args, c["sub"])
		}
		return forwardListRows(s, query+" ORDER BY f.created_time DESC", args...)
	}
	if action == "update-order" {
		items := arr(b["forwards"])
		if len(items) == 0 {
			fail("forwards参数不能为空")
		}
		for _, item := range items {
			m := obj(item)
			p.owned(s, c, m["id"])
			num(m["inx"])
		}
		p.transaction(s.ctx, func(tx store) any {
			for _, item := range items {
				m := obj(item)
				tx.update("forward", m["id"], pick(m, "inx"))
			}
			return nil
		})
		return "排序更新成功"
	}
	if action == "diagnose" {
		b["id"] = b["forwardId"]
		if v, ok := b["probe"]; ok {
			if _, ok := v.(bool); !ok {
				fail("probe must be Boolean")
			}
		}
	}
	var t M
	var f M
	if action != "create" {
		f = p.owned(s, c, b["id"])
		t = found(s.get("tunnel", f["tunnelId"]), "隧道不存在")
	}
	if action == "create" || action == "update" {
		t = found(s.get("tunnel", b["tunnelId"]), "隧道不存在")
	}
	if action == "diagnose" {
		return p.diagnoseForward(s, f, t, b)
	}
	return p.withPort(s, t, func(s store) any {
		switch action {
		case "create", "update":
			if num(t["status"]) != 1 {
				fail("隧道已禁用，无法创建或更新转发")
			}
			owner := num(c["sub"])
			exclude := int64(0)
			if f != nil {
				owner = num(f["userId"])
				exclude = num(f["id"])
			}
			u := found(s.get("user", owner), "用户不存在")
			if action == "update" && num(c["role_id"]) == 0 && num(f["tunnelId"]) == num(t["id"]) {
				if num(u["roleId"]) != 0 {
					found(s.one("SELECT id FROM user_tunnel WHERE user_id=? AND tunnel_id=?", u["id"], t["id"]), "用户没有该隧道权限")
				}
			} else {
				p.checkPermission(s, u, t, exclude, action == "create" || num(f["tunnelId"]) != num(t["id"]), false)
			}
			m := pick(b, "name tunnelId remoteAddr strategy interfaceName")
			defaults(m, M{"strategy": "fifo"})
			o := options(str(b["engineOptions"]))
			if len(o) > 0 && normalizeEngine(t["engine"]) != "kernel" {
				fail("高级引擎选项仅用于 kernel 节点")
			}
			if len(o) > 0 {
				m["engineOptions"] = jsonText(o)
			} else {
				m["engineOptions"] = nil
			}
			m["userId"] = owner
			m["updatedTime"] = now()
			m["status"] = 1
			requested := b["inPort"]
			if requested == nil && f != nil && num(f["tunnelId"]) == num(t["id"]) {
				requested = f["inPort"]
			}
			m["inPort"] = p.allocatePort(s, t, requested, exclude, false)
			if num(t["type"]) == 2 {
				if f != nil && num(f["tunnelId"]) == num(t["id"]) {
					m["outPort"] = f["outPort"]
				} else {
					m["outPort"] = p.allocatePort(s, t, nil, exclude, true)
				}
			} else {
				m["outPort"] = nil
			}
			p.validatePorts(s, t, m, exclude)
			if action == "create" {
				m["userName"] = c["name"]
				m["createdTime"] = now()
				m["inFlow"] = 0
				m["outFlow"] = 0
				m["inx"] = 0
				m["id"] = s.insert("forward", m)
				defer func() {
					if v := recover(); v != nil {
						s.remove("forward", m["id"])
						p.queueReconcile(num(t["inNodeId"]))
						panic(v)
					}
				}()
				p.applyForward(s, m, false)
				return nil
			}
			m["id"] = f["id"]
			m["createdTime"] = f["createdTime"]
			m["userName"] = f["userName"]
			m["inFlow"] = f["inFlow"]
			m["outFlow"] = f["outFlow"]
			m["inx"] = f["inx"]
			changedTunnel := num(f["tunnelId"]) != num(t["id"])
			name, _ := serviceName(s, m)
			p.quotaMode(s, num(t["inNodeId"]), name)
			if normalizeEngine(t["engine"]) == "gost" {
				defer func() {
					if v := recover(); v != nil {
						func() {
							defer func() { recover() }()
							ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
							defer cancel()
							store{s.q, ctx}.update("forward", f["id"], M{"status": -1, "updatedTime": now()})
						}()
						panic(v)
					}
				}()
			}
			if changedTunnel {
				p.removeRule(s, f)
			}
			p.applyForward(s, m, !changedTunnel)
			changes := pick(m, "name tunnelId remoteAddr strategy interfaceName engineOptions inPort outPort status updatedTime")
			changes["engineOptions"] = m["engineOptions"]
			changes["outPort"] = m["outPort"]
			s.update("forward", f["id"], changes)
			return "端口转发更新成功"
		case "delete":
			p.deleteForward(s, f, false)
			return "端口转发删除成功"
		case "force-delete":
			p.deleteForward(s, f, true)
			return "端口转发强制删除成功"
		case "pause", "resume":
			enabled := action == "resume"
			if enabled {
				u := found(s.get("user", f["userId"]), "用户不存在")
				p.checkPermission(s, u, t, num(f["id"]), false, true)
				if num(t["status"]) != 1 {
					fail("隧道已禁用，无法恢复服务")
				}
			}
			p.setEnabled(s, f, enabled)
			status := 0
			if enabled {
				status = 1
			}
			s.update("forward", f["id"], M{"status": status, "updatedTime": now()})
			if enabled {
				return "服务已恢复"
			}
			return "服务已暂停"
		}
		panic("unknown forward action")
	})
}
func (p *Panel) checkPermission(s store, u, t M, exclude int64, counts, flow bool) {
	if num(u["roleId"]) == 0 {
		return
	}
	if num(u["status"]) != 1 || num(u["expTime"]) <= now() {
		fail("当前账号已到期或被禁用")
	}
	ut := found(s.one("SELECT * FROM user_tunnel WHERE user_id=? AND tunnel_id=?", u["id"], t["id"]), "你没有该隧道权限")
	if num(ut["status"]) != 1 {
		fail("隧道被禁用")
	}
	if num(ut["expTime"]) <= now() {
		fail("该隧道权限已到期")
	}
	if num(u["flow"]) <= 0 || num(ut["flow"]) <= 0 {
		fail("流量已用完")
	}
	if flow && (num(u["flow"])*(1<<30) <= num(u["inFlow"])+num(u["outFlow"]) || num(ut["flow"])*(1<<30) <= num(ut["inFlow"])+num(ut["outFlow"])) {
		fail("流量已用完，无法恢复服务")
	}
	if counts {
		if num(s.one("SELECT COUNT(*) n FROM forward WHERE user_id=? AND id<>?", u["id"], exclude)["n"]) >= num(u["num"]) {
			fail("用户总转发数量已达上限")
		}
		if num(s.one("SELECT COUNT(*) n FROM forward WHERE user_id=? AND tunnel_id=? AND id<>?", u["id"], t["id"], exclude)["n"]) >= num(ut["num"]) {
			fail("该隧道转发数量已达上限")
		}
	}
}
func (p *Panel) allocatePort(s store, t M, requested any, exclude int64, out bool) int64 {
	node := t["inNodeId"]
	if out {
		node = t["outNodeId"]
	}
	n := found(s.get("node", node), "节点不存在")
	start, end := num(n["portSta"]), num(n["portEnd"])
	used := map[int64]bool{}
	for _, r := range s.rows("SELECT f.id,f.in_port,f.out_port,t.in_node_id,t.out_node_id FROM forward f JOIN tunnel t ON f.tunnel_id=t.id WHERE (t.in_node_id=? OR t.out_node_id=?) AND f.id<>?", node, node, exclude) {
		if num(r["inNodeId"]) == num(node) {
			used[num(r["inPort"])] = true
		}
		if num(r["outNodeId"]) == num(node) {
			used[num(r["outPort"])] = true
		}
	}
	if requested != nil {
		port := num(requested)
		typed := !out && p.supports(num(node), "independentProtocols")
		if port < start || port > end || (!typed && used[port]) {
			fail("指定端口已被占用或不在允许范围内")
		}
		return port
	}
	for port := start; port <= end; port++ {
		if !used[port] {
			return port
		}
	}
	fail("节点端口已满，无法分配新端口")
	return 0
}
func (p *Panel) validatePorts(s store, t, f M, exclude int64) {
	n := found(s.get("node", t["inNodeId"]), "节点不存在")
	desired := listeners(f, t, options(str(f["engineOptions"])))
	main := false
	for _, l := range desired {
		port := num(l["port"])
		if port < num(n["portSta"]) || port > num(n["portEnd"]) {
			fail("listener port outside node allocation range")
		}
		if port == num(f["inPort"]) {
			main = true
		}
	}
	if !main {
		fail("at least one listener must use the allocated entry port")
	}
	peers := s.rows("SELECT f.*,t.in_node_id,t.out_node_id,t.type,t.engine,t.tcp_listen_addr,t.udp_listen_addr,ni.server_ip inHost,no.server_ip outHost FROM forward f JOIN tunnel t ON f.tunnel_id=t.id JOIN node ni ON ni.id=t.in_node_id JOIN node no ON no.id=t.out_node_id WHERE f.id<>?", exclude)
	for _, r := range peers {
		sameIn := num(r["inNodeId"]) == num(n["id"]) || (str(n["serverIp"]) != "" && str(r["inHost"]) == str(n["serverIp"]))
		sameOut := num(r["outNodeId"]) == num(n["id"]) || (str(n["serverIp"]) != "" && str(r["outHost"]) == str(n["serverIp"]))
		if sameIn {
			existing := listeners(r, r, options(str(r["engineOptions"])))
			for _, a := range desired {
				for _, b := range existing {
					if num(a["port"]) != num(b["port"]) || str(a["protocol"]) != str(b["protocol"]) {
						continue
					}
					lh, rh := str(a["host"]), str(b["host"])
					wild := lh == "::" || lh == "0.0.0.0" || rh == "::" || rh == "0.0.0.0"
					legacy := (normalizeEngine(r["engine"]) == "gost" && (rh == "::" || rh == "0.0.0.0")) || (normalizeEngine(n["engine"]) == "gost" && (lh == "::" || lh == "0.0.0.0"))
					if (str(a["family"]) == str(b["family"]) || legacy) && (lh == rh || wild) {
						fail("listener conflicts with a reserved forwarding endpoint")
					}
				}
			}
		}
		if sameOut && r["outPort"] != nil {
			for _, a := range desired {
				if num(a["port"]) == num(r["outPort"]) {
					fail("listener conflicts with relay egress reservation")
				}
			}
		}
	}
}
func (p *Panel) revision(s store, node int64, name string) int64 {
	s.exec("INSERT INTO engine_revision(node_id,service_id,revision) VALUES(?,?,1) ON DUPLICATE KEY UPDATE revision=revision+1", node, name)
	return num(s.one("SELECT revision FROM engine_revision WHERE node_id=? AND service_id=?", node, name)["revision"])
}
func (p *Panel) applyForward(s store, f M, update bool) {
	t := found(s.get("tunnel", f["tunnelId"]), "隧道不存在")
	node := num(t["inNodeId"])
	name, ut := serviceName(s, f)
	owner := found(s.get("user", f["userId"]), "用户不存在")
	if num(owner["roleId"]) != 0 && ut == nil {
		fail("用户没有该隧道权限")
	}
	p.quotaMode(s, node, name)
	if normalizeEngine(t["engine"]) == "gost" {
		p.applyGost(s, f, t, name, ut, update)
		return
	}
	p.verifyAgent(s, node)
	d := p.wireSpec(s, f, t, false)
	d["id"] = name
	d["revision"] = p.revision(s, node, name)
	d["enabled"] = num(f["status"]) == 1
	expires := int64(0)
	if ut != nil {
		u := s.get("user", f["userId"])
		expires = num(u["expTime"])
		if num(ut["expTime"]) > 0 && (expires == 0 || num(ut["expTime"]) < expires) {
			expires = num(ut["expTime"])
		}
	}
	d["expiresAt"] = expires
	if ut != nil && (p.supports(node, "creditLease") || p.strict(s, node)) {
		p.requireCapability(node, "creditLease")
		p.enableCredit(s, node)
		d["leaseRequired"] = true
	}
	p.commandOK(node, d, "ApplyForward")
	auditAction := "CREATE_FORWARD"
	if update {
		auditAction = "UPDATE_FORWARD"
	}
	p.audit(s, nil, node, auditAction, name, "revision="+str(d["revision"]))
	if truth(d["leaseRequired"]) {
		p.prime(s, node, name)
	}
}
func (p *Panel) removeRule(s store, f M) {
	t := found(s.get("tunnel", f["tunnelId"]), "隧道不存在")
	node := num(t["inNodeId"])
	name, _ := serviceName(s, f)
	if normalizeEngine(t["engine"]) == "kernel" {
		p.verifyAgent(s, node)
		d := p.commandOK(node, M{"id": name, "revision": p.revision(s, node, name), "enabled": false}, "DeleteForward")
		if len(d) > 0 {
			p.ingest(s, s.get("node", node), d, nil)
		}
	} else {
		p.commandOK(node, M{"services": []string{name + "_tcp", name + "_udp"}}, "DeleteService")
		if num(t["type"]) == 2 {
			p.commandOK(node, M{"chain": name + "_chains"}, "DeleteChains")
			p.commandOK(num(t["outNodeId"]), M{"services": []string{name + "_tls"}}, "DeleteService")
		}
	}
}
func (p *Panel) deleteForward(s store, f M, force bool) {
	if !force {
		p.removeRule(s, f)
	}
	s.remove("forward", f["id"])
	t := s.get("tunnel", f["tunnelId"])
	if t != nil {
		p.queueReconcile(num(t["inNodeId"]))
	}
}
func (p *Panel) setEnabled(s store, f M, enabled bool) {
	t := found(s.get("tunnel", f["tunnelId"]), "隧道不存在")
	node := num(t["inNodeId"])
	name, _ := serviceName(s, f)
	if normalizeEngine(t["engine"]) == "kernel" {
		p.verifyAgent(s, node)
		if enabled {
			p.quotaMode(s, node, name)
			if p.strict(s, node) {
				p.requireCapability(node, "creditLease")
			}
		}
		p.commandOK(node, M{"id": name, "revision": p.revision(s, node, name), "enabled": enabled}, "SetForwardState")
		if enabled && !strings.HasSuffix(name, "_0") {
			p.prime(s, node, name)
		}
	} else {
		kind := "PauseService"
		if enabled {
			kind = "ResumeService"
		}
		p.commandOK(node, M{"services": []string{name + "_tcp", name + "_udp"}}, kind)
		if num(t["type"]) == 2 {
			p.commandOK(num(t["outNodeId"]), M{"services": []string{name + "_tls"}}, kind)
		}
	}
}
func (p *Panel) diagnoseForward(s store, f, t, b M) M {
	node := found(s.get("node", t["inNodeId"]), "入口节点不存在")
	results := []M{}
	report := M{"forwardId": f["id"], "forwardName": f["name"], "timestamp": now()}
	if normalizeEngine(t["engine"]) == "kernel" && b["probe"] != false {
		p.requireCapability(num(node["id"]), "connectivityDiagnostics")
		name, _ := serviceName(s, f)
		d := p.commandOK(num(node["id"]), M{"id": name}, "ProbeForward")
		for _, v := range arr(d["results"]) {
			r := obj(v)
			ping, tcp := obj(r["icmp"]), obj(r["tcp"])
			results = append(results, M{"nodeId": node["id"], "nodeName": node["name"], "targetIp": r["target"], "targetPort": r["port"], "description": "转发到目标", "probeKind": "icmpTcp", "success": num(ping["received"]) > 0 || num(tcp["received"]) > 0, "icmp": ping, "tcp": tcp})
		}
		if len(results) == 0 {
			results = append(results, M{"nodeId": node["id"], "nodeName": node["name"], "targetIp": f["remoteAddr"], "description": "转发到目标", "success": false, "message": "目标尚未解析，暂时无法探测"})
		}
		report["results"], report["probePerformed"], report["truncated"] = results, d["probePerformed"], d["truncated"]
		return report
	}
	if normalizeEngine(t["engine"]) == "kernel" {
		name, _ := serviceName(s, f)
		query := M{"id": name, "probe": truth(b["probe"])}
		if str(b["clientIP"]) != "" || str(b["ingressInterface"]) != "" {
			p.requireCapability(num(node["id"]), "returnPathDiagnostics")
		}
		if p.supports(num(node["id"]), "returnPathDiagnostics") {
			query["clientIP"] = strings.TrimSpace(str(b["clientIP"]))
			query["ingressInterface"] = strings.TrimSpace(str(b["ingressInterface"]))
		}
		d := p.commandOK(num(node["id"]), query, "DiagnoseForward")
		for _, v := range arr(d["routes"]) {
			r := obj(v)
			performed := truth(r["probePerformed"])
			if r["probePerformed"] == nil {
				performed = truth(b["probe"]) && r["reachable"] != nil
			}
			success := truth(obj(r["routeEvidence"])["available"]) || r["route"] != nil
			kind, label, message := "routeOnly", "目标路由", ""
			if !success {
				message = "未找到可用路由"
			}
			if performed {
				success = truth(r["reachable"])
				kind = "tcpHandshake"
				label = "TCP 连接测试"
				message = "节点到目标的连接测试"
				if r["probeError"] != nil {
					message = str(r["probeError"])
				}
			}
			results = append(results, M{"nodeId": node["id"], "nodeName": node["name"], "targetIp": r["target"], "targetPort": r["port"], "description": label, "success": success, "averageTime": r["tcpHandshakeMs"], "probeKind": kind, "message": message, "routeEvidence": r["routeEvidence"], "forwardRouteEvidence": r["forwardRouteEvidence"]})
		}
		report["engineState"] = d["state"]
		report["returnPath"] = d["returnPath"]
		report["probePerformed"] = d["probePerformed"]
		report["routesTruncated"] = d["routesTruncated"]
	} else {
		target := node
		if num(t["type"]) == 2 {
			out := found(s.get("node", t["outNodeId"]), "出口节点不存在")
			results = append(results, p.diagnose(node, str(out["serverIp"]), num(f["outPort"]), "入口->出口"))
			target = out
		}
		for _, a := range strings.Split(str(f["remoteAddr"]), ",") {
			e := endpoint(strings.TrimSpace(a))
			results = append(results, p.diagnose(target, str(e["host"]), num(e["port"]), "转发->目标"))
		}
	}
	report["results"] = results
	return report
}

// Java's account/permission deletion is an administrative cascade even when a
// node is offline. Preserve that contract; reconciliation removes remote orphans.
func (p *Panel) deleteRelatedForward(s store, f M, unavailable ...map[int64]bool) {
	t := s.get("tunnel", f["tunnelId"])
	node := int64(0)
	if t != nil {
		node = num(t["inNodeId"])
	}
	var failed map[int64]bool
	if len(unavailable) > 0 {
		failed = unavailable[0]
	}
	remove := func(locked store) any {
		fresh := locked.get("forward", f["id"])
		if fresh == nil {
			return nil
		}
		p.mu.Lock()
		peer := p.nodes[node]
		p.mu.Unlock()
		live := peer != nil
		if live {
			select {
			case <-peer.done:
				live = false
			default:
			}
		}
		if live && (failed == nil || !failed[node]) {
			func() {
				defer func() {
					if v := recover(); v != nil {
						if _, expected := v.(apiError); !expected {
							panic(v)
						}
						if err, ok := v.(apiError); failed != nil && ok && nodeUnavailable(err) {
							failed[node] = true
						}
					}
				}()
				p.removeRule(locked, fresh)
			}()
		}
		locked.remove("forward", fresh["id"])
		return nil
	}
	if t != nil && s.get("node", node) != nil {
		p.withPort(s, t, remove)
	} else {
		remove(s)
	}
	if t != nil {
		p.queueReconcile(node)
	}
}
