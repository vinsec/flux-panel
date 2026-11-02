package panel

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
)

var secretLog = regexp.MustCompile(`(?i)("(?:secret|token|accessToken|password|pwd|authorization)"\s*:\s*)"[^"]*"`)
var jwtLog = regexp.MustCompile(`[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)

func redact(s string) string {
	s = secretLog.ReplaceAllString(s, `${1}"[REDACTED]"`)
	return jwtLog.ReplaceAllString(s, "[REDACTED]")
}
func (p *Panel) queueReconcile(node int64) {
	p.mu.Lock()
	peer := p.nodes[node]
	if peer == nil || peer.engine != "kernel" {
		p.mu.Unlock()
		return
	}
	peer.mu.Lock()
	info := peer.info
	peer.mu.Unlock()
	if info == nil || str(info["kernelBackend"]) != "nftables" {
		p.mu.Unlock()
		return
	}

	if p.reconcileQueue == nil {
		p.reconcileQueue = map[int64]bool{}
	}
	p.reconcileQueue[node] = true
	p.mu.Unlock()
}
func (p *Panel) Start(ctx context.Context) {
	if p.cfg.ReadOnly {
		return
	}
	if _, e := p.db.ExecContext(ctx, "SELECT node_id FROM engine_mode_switch LIMIT 0"); e != nil {
		panic("explicit migrations 006 and 007-managed-agent.sql are required")
	}
	conn, e := p.db.Conn(ctx)
	must(e)
	s := store{conn, ctx}
	r := s.one("SELECT GET_LOCK(CONCAT('flux-panel-',DATABASE()),0) acquired")
	if num(r["acquired"]) != 1 {
		conn.Close()
		panic("another Go control plane owns this database")
	}
	p.leader = conn
	ctx, p.jobsCancel = context.WithCancel(ctx)

	for i := 0; i < 2; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-p.quotaJobs:
					uid := num(job["userId"])
					func() {
						defer func() { p.mu.Lock(); delete(p.quotaPending, uid); p.mu.Unlock() }()
						p.background(func(s store) {
							lockCtx, cancel := context.WithTimeout(s.ctx, 50*time.Millisecond)
							unlock := p.lockOwner(lockCtx, uid)
							cancel()
							defer unlock()
							failedNodes := map[int64]bool{}
							for _, f := range invalidQuotaRows(s, uid) {
								t := s.get("tunnel", f["tunnelId"])
								if t == nil {
									continue
								}
								node := num(t["inNodeId"])
								if failedNodes[node] {
									continue
								}
								func() {
									defer func() {
										if v := recover(); v != nil {
											if _, expected := v.(apiError); !expected {
												panic(v)
											}
											if err, ok := v.(apiError); ok && nodeUnavailable(err) {
												failedNodes[node] = true
											}
										}
									}()
									p.withPort(s, t, func(locked store) any {
										current := locked.get("forward", f["id"])
										if current != nil && num(current["status"]) != 0 {
											p.setEnabled(locked, current, false)
											locked.update("forward", current["id"], M{"status": 0, "updatedTime": now()})
										}
										return nil
									})
								}()
							}
						})
					}()
				}
			}
		}()
	}

	p.runLoop(ctx, 200*time.Millisecond, func(s store) {
		p.mu.Lock()
		var n int64
		var cfg M
		for node, value := range p.gostCleanup {
			n = node
			cfg = value
			delete(p.gostCleanup, node)
			break
		}
		p.mu.Unlock()
		if cfg != nil {
			node := s.get("node", n)
			if node != nil {
				p.cleanGost(s, node, cfg)
			}
		}
	})

	p.runLoop(ctx, 200*time.Millisecond, func(s store) { p.enforceQuotas(s) })
	p.runLoop(ctx, time.Second, func(s store) {
		p.mu.Lock()
		node := int64(0)
		for n := range p.reconcileQueue {
			node = n
			delete(p.reconcileQueue, n)
			break
		}
		p.mu.Unlock()
		if node != 0 {
			func() {
				defer func() {
					if v := recover(); v != nil {
						slog.Error("node reconciliation failed", "nodeId", node, "error", redact(fmt.Sprint(v)))
						p.queueReconcile(node)
					}
				}()
				p.reconcile(s, node)
			}()
		}
	})
	p.runLoop(ctx, 5*time.Second, func(s store) {
		if e := p.leader.PingContext(s.ctx); e != nil {
			p.mu.Lock()
			p.writeFailed = true
			p.mu.Unlock()
			p.jobsCancel()
			p.closePeers()
			return
		}
		p.expireSessions(s)
	})
	p.runLoop(ctx, 30*time.Second, func(s store) {
		for _, n := range s.rows("SELECT id FROM node WHERE engine='kernel' AND status=1") {
			p.queueReconcile(num(n["id"]))
		}
	})
	p.runLoop(ctx, time.Second, func(s store) {
		location := time.Local
		if p.cfg.TimeZone != "" {
			l, e := time.LoadLocation(p.cfg.TimeZone)
			must(e)
			location = l
		}
		instant := time.Now().In(location)
		if instant.Minute() == 0 && instant.Second() < 5 {
			p.hourly(s, instant)
		}
		if instant.Hour() == 0 && instant.Minute() == 0 && instant.Second() >= 5 && instant.Second() < 15 {
			p.daily(s, instant)
		}
	})
}
func (p *Panel) runLoop(ctx context.Context, interval time.Duration, fn func(store)) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				func() {
					defer func() {
						if recover() != nil {
							slog.Error("background task failed", "interval", interval)
						}
					}()
					task, cancel := context.WithTimeout(ctx, 3*time.Minute)
					defer cancel()
					fn(store{p.db, task})
				}()
			}
		}
	}()
}
func (p *Panel) closePeers() {
	p.mu.Lock()
	xs := []*peer{}
	for _, x := range p.nodes {
		xs = append(xs, x)
	}
	for x := range p.admins {
		xs = append(xs, x)
	}
	p.mu.Unlock()
	for _, x := range xs {
		x.close()
	}
}
func (p *Panel) Close() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.writeFailed = true
		p.mu.Unlock()
		close(p.stop)
		if p.jobsCancel != nil {
			p.jobsCancel()
		}
		p.closePeers()
		p.wg.Wait()
		if p.leader != nil {
			ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
			p.leader.ExecContext(ctx, "SELECT RELEASE_LOCK(CONCAT('flux-panel-',DATABASE()))")
			c()
			p.leader.Close()
		}
	})
}
func (p *Panel) expireSessions(s store) {
	instant := now()
	p.mu.Lock()
	xs := []*peer{}
	for k, t := range p.tickets {
		if t.Expiry < instant {
			delete(p.tickets, k)
		}
	}
	for _, x := range p.nodes {
		if x.expiry > 0 && x.expiry <= instant {
			xs = append(xs, x)
		}
	}
	p.mu.Unlock()
	for _, x := range xs {
		x.close()
	}
	s.exec("DELETE FROM engine_session WHERE expires_at<?", instant-60000)
	p.captcha.expire(instant)
}
func (p *Panel) hourly(s store, t time.Time) {
	p.transaction(s.ctx, func(tx store) any {
		key := t.Format("2006-01-02T15-0700")
		r := tx.exec("INSERT IGNORE INTO panel_job_run(job_name,period_key,completed_at) VALUES('hourly',?,?)", key, now())
		n, e := r.RowsAffected()
		must(e)
		if n == 0 {
			return nil
		}
		tx.exec("DELETE FROM statistics_flow WHERE created_time<?", now()-48*60*60*1000)
		for _, u := range tx.rows("SELECT id,in_flow,out_flow FROM user ORDER BY id") {
			total := checkedAdd(num(u["inFlow"]), num(u["outFlow"]))
			increment := total
			old := tx.one("SELECT total_flow FROM statistics_flow WHERE user_id=? ORDER BY id DESC LIMIT 1", u["id"])
			if old != nil {
				increment = total - num(old["totalFlow"])
				if increment < 0 {
					increment = total
				}
			}
			tx.insert("statistics_flow", M{"userId": u["id"], "flow": increment, "totalFlow": total, "time": t.Format("15:00"), "createdTime": now()})
		}
		return nil
	})
}
func (p *Panel) daily(s store, t time.Time) {
	p.transaction(s.ctx, func(tx store) any {
		r := tx.exec("INSERT IGNORE INTO panel_job_run(job_name,period_key,completed_at) VALUES('daily',?,?)", t.Format("2006-01-02"), now())
		n, e := r.RowsAffected()
		must(e)
		if n == 0 {
			return nil
		}
		day := t.Day()
		last := time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, t.Location()).Day()
		for _, table := range []string{"user", "user_tunnel"} {
			predicate := "flow_reset_time=?"
			if day == last {
				predicate = "flow_reset_time>=?"
			}
			tx.exec("UPDATE `"+table+"` SET in_flow=0,out_flow=0 WHERE flow_reset_time<>0 AND "+predicate, day)
		}
		tx.exec("UPDATE user SET status=0 WHERE role_id<>0 AND status=1 AND exp_time<?", now())
		tx.exec("UPDATE user_tunnel SET status=0 WHERE status=1 AND exp_time<?", now())
		return nil
	})
	p.enforceQuotas(s)
}

const invalidQuotaPredicate = " FROM forward f JOIN user u ON u.id=f.user_id LEFT JOIN user_tunnel ut ON ut.user_id=f.user_id AND ut.tunnel_id=f.tunnel_id WHERE f.status<>0 AND u.role_id<>0 AND (u.status<>1 OR u.exp_time<=? OR u.in_flow+u.out_flow>u.flow*1073741824 OR ut.id IS NULL OR ut.status<>1 OR ut.exp_time<=? OR ut.in_flow+ut.out_flow>=ut.flow*1073741824)"

func invalidQuotaRows(s store, uid int64) []M {
	return s.rows("SELECT f.*"+invalidQuotaPredicate+" AND f.user_id=? ORDER BY f.id LIMIT 10000", now(), now(), uid)
}
func (p *Panel) enforceQuotas(s store) {
	for _, row := range s.rows("SELECT DISTINCT f.user_id"+invalidQuotaPredicate+" ORDER BY f.user_id LIMIT 1024", now(), now()) {
		uid := num(row["userId"])
		p.mu.Lock()
		if !p.quotaPending[uid] {
			select {
			case p.quotaJobs <- M{"userId": uid}:
				p.quotaPending[uid] = true
			default:
			}
		}
		p.mu.Unlock()
	}
}

func (p *Panel) reconcile(s store, node int64) M {
	n := found(s.get("node", node), "节点不存在")
	nativeNode(n)
	return p.withPort(s, M{"inNodeId": node, "_modeSwitch": true}, func(s store) any { return p.reconcileLocked(s, node) }).(M)
}
func (p *Panel) reconcileLocked(s store, node int64) M {
	if row := s.one("SELECT status FROM engine_mode_switch WHERE node_id=?", node); row != nil && (str(row["status"]) == "pending" || str(row["status"]) == "running") {
		return p.resumeModeSwitch(s, node)
	}
	if row := s.one("SELECT status FROM engine_mode_switch WHERE node_id=?", node); row != nil && str(row["status"]) == "blocked" {
		fail("节点切换回滚失败，等待恢复")
	}

	p.verifyAgent(s, node)
	p.requireCapability(node, "batch")
	pending := s.one("SELECT body FROM panel_pending_batch WHERE node_id=?", node)
	if pending != nil {
		body := decode([]byte(str(pending["body"])))
		state := p.commandOK(node, M{"id": body["id"]}, "GetBatchStatus")
		switch str(state["status"]) {
		case "running", "queued":
			return state
		case "unknown":
			return p.commandOK(node, body, "SubmitBatch")
		}
		s.exec("DELETE FROM panel_pending_batch WHERE node_id=?", node)
		if str(state["status"]) == "failed" {
			fail("batch failed: " + str(state["error"]))
		}
	}
	actual := map[string]M{}
	after := ""
	var generation any
	for pageCount := 0; ; pageCount++ {
		if pageCount > 400 {
			fail("snapshot exceeds configured safety bound")
		}
		q := M{"after": after, "limit": 500}
		if generation != nil {
			q["generation"] = generation
		}
		snapshot := p.commandOK(node, q, "GetEngineStatePage")
		generation = snapshot["generation"]
		if snapshot["items"] == nil {
			fail("invalid snapshot page")
		}
		for _, v := range arr(snapshot["items"]) {
			m := obj(v)
			actual[str(m["id"])] = m
		}
		next := str(snapshot["next"])
		if next == "" {
			break
		}
		if next == after {
			fail("non advancing snapshot page")
		}
		after = next
		if len(actual) > 200000 {
			fail("snapshot exceeds configured safety bound")
		}
	}
	desired := map[string]M{}
	snap := p.specSnapshot(s, node)
	rows := s.rows("SELECT f.* FROM forward f JOIN tunnel t ON t.id=f.tunnel_id WHERE t.in_node_id=? AND t.engine='kernel' ORDER BY f.id", node)
	if len(rows) > 10000 {
		fail("node exceeds the validated 10,000-forward capacity")
	}
	lease := p.supports(node, "creditLease") || p.strict(s, node)
	creditEnabled := false
	for _, f := range rows {
		u := snap.users[num(f["userId"])]
		if u == nil {
			continue
		}
		name, ut := serviceName(s, f, snap)
		admin := num(u["roleId"]) == 0
		if !admin && ut == nil {
			continue
		}
		t := snap.tunnels[num(f["tunnelId"])]
		d := p.wireSpec(s, f, t, true, snap)
		d["id"] = name
		expires := int64(0)
		if !admin {
			expires = min(expiry(u), expiry(ut))
		}
		enabled := num(f["status"]) == 1 && num(u["status"]) == 1 && (admin || num(ut["status"]) == 1 && expires > now())
		d["expiresAt"] = expires
		d["enabled"] = enabled
		if !enabled && num(f["status"]) == 1 {
			s.update("forward", f["id"], M{"status": 0})
		}
		if !admin && lease {
			if !creditEnabled {
				p.enableCredit(s, node)
				creditEnabled = true
			}
			d["leaseRequired"] = true
		}
		desired[name] = d
	}
	delta := []M{}
	for _, name := range keysOfMap(actual) {
		if desired[name] == nil && !truth(actual[name]["deleted"]) {
			delta = append(delta, M{"id": name, "deleted": true})
		}
	}
	for _, name := range keysOfMap(desired) {
		if specChanged(desired[name], actual[name]) {
			delta = append(delta, desired[name])
		}
	}
	if len(delta) == 0 {
		return M{"status": "converged", "generation": generation}
	}
	if len(delta) > 10000 {
		delta = delta[:10000]
	}
	versions := p.revisionBatch(s, node, delta)
	for _, d := range delta {
		d["revision"] = versions[str(d["id"])]
	}
	id := randomHex(16)
	body := M{"id": id, "baseGeneration": generation, "specs": delta}
	s.exec("INSERT INTO panel_pending_batch(node_id,batch_id,body,created_at) VALUES(?,?,?,?)", node, id, jsonText(body), now())
	return p.commandOK(node, body, "SubmitBatch")
}
func specChanged(desired, actual M) bool {
	if actual == nil || truth(actual["deleted"]) {
		return true
	}
	if num(desired["schemaVersion"]) >= 3 {
		if str(desired["intentHash"]) != str(actual["intentHash"]) {
			return true
		}
	} else {
		for _, k := range []string{"listenIP", "targetIP", "listenPort", "targetPort"} {
			if str(desired[k]) != str(actual[k]) {
				return true
			}
		}
	}
	return num(desired["expiresAt"]) != num(actual["expiresAt"]) || truth(desired["enabled"]) != truth(actual["enabled"]) || truth(desired["leaseRequired"]) != truth(actual["leaseRequired"])
}
func (p *Panel) revisionBatch(s store, node int64, delta []M) map[string]int64 {
	versions := map[string]int64{}
	for off := 0; off < len(delta); off += 500 {
		page := delta[off:min(off+500, len(delta))]
		args := []any{}
		marks := []string{}
		names := []any{node}
		for _, d := range page {
			name := str(d["id"])
			serviceID(name)
			args = append(args, node, name)
			marks = append(marks, "(?,?,1)")
			names = append(names, name)
		}
		s.exec("INSERT INTO engine_revision(node_id,service_id,revision) VALUES "+strings.Join(marks, ",")+" ON DUPLICATE KEY UPDATE revision=revision+1", args...)
		for _, r := range s.rows("SELECT service_id,revision FROM engine_revision WHERE node_id=? AND service_id IN ("+placeholders(len(page))+")", names...) {
			versions[str(r["serviceId"])] = num(r["revision"])
		}
	}
	return versions
}
