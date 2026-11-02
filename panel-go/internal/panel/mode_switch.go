package panel

func init() {
	routeByPath["/api/v1/engine/switch-mode"] = route{"POST", true, false, false, ""}
	routeByPath["/api/v1/engine/mode-switch-status"] = route{"POST", true, false, false, ""}
}

func modeName(v any) string {
	mode := str(v)
	if mode != "gost" && mode != "kernel" {
		fail("转发模式必须为 gost 或 kernel")
	}
	return mode
}
func (p *Panel) switchMode(s store, c, b M, statusOnly bool) any {
	node := num(b["nodeId"])
	return p.withPort(s, M{"inNodeId": node, "_modeSwitch": true}, func(s store) any {
		n := found(s.get("node", node), "节点不存在")
		if normalizeEngine(n["engine"]) != "kernel" {
			fail("旧 GOST 节点须先升级为统一 Agent，不能直接切换")
		}
		if statusOnly {
			return p.resumeModeSwitch(s, node)
		}
		target := modeName(b["mode"])
		id := str(b["id"])
		if len(id) < 1 || len(id) > 100 {
			fail("invalid operation id")
		}
		info := p.commandOK(node, M{}, "GetCapabilities")
		if !truth(obj(obj(info["capabilities"])["features"])["engineSwitch"]) {
			fail("节点未启用受管 GOST，请先升级 Agent 安装包")
		}
		old := s.one("SELECT * FROM engine_mode_switch WHERE node_id=?", node)
		if old != nil && str(old["operationId"]) == id {
			if str(old["toMode"]) != target {
				fail("operation id conflict")
			}
			return p.resumeModeSwitch(s, node)
		}
		if old != nil && (str(old["status"]) == "pending" || str(old["status"]) == "running") {
			fail("节点已有切换任务")
		}
		if s.one("SELECT node_id FROM panel_pending_batch WHERE node_id=?", node) != nil {
			fail("请等待规则协调完成后切换")
		}
		from := str(info["forwardingMode"])
		if from == "" {
			from = "kernel"
		}
		s.exec("INSERT INTO engine_mode_switch(node_id,operation_id,from_mode,to_mode,status,error_text,updated_at) VALUES(?,?,?,?,'pending','',?) ON DUPLICATE KEY UPDATE operation_id=VALUES(operation_id),from_mode=VALUES(from_mode),to_mode=VALUES(to_mode),status='pending',error_text='',updated_at=VALUES(updated_at)", node, id, from, target, now())
		p.audit(s, c["sub"], node, "SWITCH_FORWARDING_MODE", "", from+" -> "+target)
		p.queueReconcile(node)
		return p.resumeModeSwitch(s, node)
	})
}
func (p *Panel) resumeModeSwitch(s store, node int64) M {
	record := s.one("SELECT * FROM engine_mode_switch WHERE node_id=?", node)
	if record == nil {
		return M{"status": "idle"}
	}
	status := str(record["status"])
	if status != "pending" && status != "running" {
		return M{"id": record["operationId"], "status": status, "from": record["fromMode"], "to": record["toMode"], "error": record["errorText"]}
	}
	id := str(record["operationId"])
	reply := p.rpc(node, M{"id": id}, "GetModeSwitchStatus")
	if str(reply["message"]) != "OK" {
		p.queueReconcile(node)
		return M{"id": id, "status": "pending", "error": "等待节点重连确认，未猜测切换结果"}
	}
	job := obj(reply["data"])
	if str(job["status"]) == "unknown" {
		reply = p.rpc(node, M{"id": id, "mode": record["toMode"]}, "SubmitModeSwitch")
		if str(reply["message"]) != "OK" {
			if success, known := reply["success"].(bool); known && !success {
				s.exec("UPDATE engine_mode_switch SET status='failed',error_text=?,updated_at=? WHERE node_id=? AND operation_id=?", redact(str(reply["message"])), now(), node, id)
				return M{"id": id, "status": "failed", "error": reply["message"]}
			}
			p.queueReconcile(node)
			return M{"id": id, "status": "pending", "error": "请求结果尚未确认，正在重查同一任务"}
		}
		job = obj(reply["data"])
	}
	switch str(job["status"]) {
	case "succeeded":
		if str(job["to"]) != str(record["toMode"]) {
			fail("node switch receipt mismatch")
		}
		p.transaction(s.ctx, func(tx store) any {
			tx.update("node", node, M{"forwardingMode": record["toMode"], "updatedTime": now()})
			tx.exec("UPDATE engine_mode_switch SET status='succeeded',error_text='',updated_at=? WHERE node_id=? AND operation_id=?", now(), node, id)
			return nil
		})
		// Complete the initial desired-state apply immediately after a mode job.
		p.queueReconcile(node)
	case "failed", "blocked":
		s.exec("UPDATE engine_mode_switch SET status=?,error_text=?,updated_at=? WHERE node_id=? AND operation_id=?", job["status"], redact(str(job["error"])), now(), node, id)
	default:
		p.queueReconcile(node)
	}
	return job
}
