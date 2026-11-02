package panel

import (
	"math"
	"math/big"
	"regexp"
	"sort"
)

var reservationVersion = regexp.MustCompile(`^(?:iptables-v[345]|kernel-v[67])(?:[.-].*)?$`)

func expiry(r M) int64 {
	if r["expTime"] == nil {
		return math.MaxInt64
	}
	return num(r["expTime"])
}
func quotaBytes(r M) int64 { return checkedMul(num(r["flow"]), 1<<30) }
func (p *Panel) exchange(s store, node, report M, maintenance bool) M {
	return p.transaction(s.ctx, func(tx store) any { return p.exchangeTx(tx, node, report, maintenance) }).(M)
}
func (p *Panel) exchangeTx(s store, node, report M, maintenance bool) M {
	nativeNode(node)
	maxGrant, leaseDuration := p.cfg.LeaseMaxBytes, p.cfg.LeaseDurationMillis
	epoch, boot := str(report["epoch"]), str(report["bootId"])
	sequence := exact(report["sequence"])
	usage, requests, claims := arr(report["usage"]), arr(report["requests"]), arr(report["leases"])
	if requests == nil {
		requests = []any{}
	}
	if claims == nil {
		claims = []any{}
	}
	if !epochPattern.MatchString(epoch) || !bootPattern.MatchString(boot) || sequence < 1 || report["usage"] == nil || len(usage) > 10000 {
		fail("invalid report identity")
	}
	if len(requests) > 10000 || len(claims) > 10000 {
		fail("credit report too large")
	}
	if maintenance {
		if len(requests) > 0 {
			fail("maintenance cannot allocate credit")
		}
		for _, v := range claims {
			if !truth(obj(v)["closed"]) {
				fail("maintenance requires final closed lease snapshots")
			}
		}
	}
	advertised := p.capability(num(node["id"]))
	if !maintenance && advertised != nil && advertised["bootId"] != nil && boot != str(advertised["bootId"]) {
		fail("report boot does not match active node session")
	}
	s.exec("INSERT INTO engine_report_cursor(node_id,epoch,sequence) VALUES(?,?,0) ON DUPLICATE KEY UPDATE sequence=sequence", node["id"], epoch)
	cursor := num(s.one("SELECT sequence FROM engine_report_cursor WHERE node_id=? AND epoch=? FOR UPDATE", node["id"], epoch)["sequence"])
	bodyHash := digest(jsonText(report))
	replay := s.one("SELECT body_hash,response FROM engine_credit_request WHERE node_id=? AND epoch=? AND sequence=?", node["id"], epoch, sequence)
	var response M
	if replay != nil {
		if str(replay["bodyHash"]) != bodyHash {
			fail("report sequence payload conflict")
		}
		response = decode([]byte(str(replay["response"])))
	} else {
		response = M{"epoch": epoch, "sequence": sequence, "usage": usage, "counters": validatedCounters(arr(report["counters"]), usage), "closedLeases": []any{}, "grants": []any{}}
		if sequence <= cursor {
			p.ingest(s, node, report, nil)
		} else {
			services := map[string]bool{}
			for _, v := range requests {
				id := str(v)
				serviceID(id)
				if services[id] {
					fail("duplicate credit request")
				}
				services[id] = true
			}
			users, permissions := map[int64]bool{}, map[int64]bool{}
			for _, v := range usage {
				a := serviceID(str(obj(v)["id"]))
				users[num(a[1])] = true
				if a[2] != "0" {
					permissions[num(a[2])] = true
				}
			}
			for id := range services {
				a := serviceID(id)
				users[num(a[1])] = true
				if a[2] != "0" {
					permissions[num(a[2])] = true
				}
			}
			claimRows := map[string]M{}
			claimServices := map[string]M{}
			for _, v := range claims {
				claim := obj(v)
				id := str(claim["id"])
				if !epochPattern.MatchString(id) {
					fail("invalid lease identity")
				}
				r := s.one("SELECT * FROM engine_credit_lease WHERE lease_id=? AND node_id=? AND epoch=? AND boot_id=?", id, node["id"], epoch, boot)
				if r == nil {
					fail("unknown lease")
				}
				service := str(r["serviceId"])
				if service != str(claim["serviceId"]) || claimServices[service] != nil || exact(claim["generation"]) > num(r["generation"]) {
					fail("lease owner/generation mismatch")
				}
				claimServices[service] = claim
				claimRows[id] = r
				users[num(r["userId"])] = true
				permissions[num(r["userTunnelId"])] = true
			}
			lockRows(s, "user", users)
			lockRows(s, "user_tunnel", permissions)
			p.ingest(s, node, report, nil)
			instant := now()
			for _, v := range claims {
				claim := obj(v)
				id := str(claim["id"])
				r := claimRows[id]
				up, down := p.watermark(s, node["id"], epoch, str(r["serviceId"]))
				consumed := checkedAdd(max(0, up-num(r["startUp"])), max(0, down-num(r["startDown"])))
				if consumed > num(r["totalRaw"]) {
					fail("lease usage exceeds reserved credit")
				}
				if exact(claim["used"]) != consumed {
					fail("lease usage does not match settled cumulative ledger")
				}
				closed := truth(claim["closed"])
				reserved := int64(0)
				if !closed {
					reserved = bill(num(r["totalRaw"])-consumed, price{str(r["ratio"]), num(r["flowType"])}, true)
				}
				s.exec("UPDATE engine_credit_lease SET consumed_raw=?,reserved_bill=?,closed=?,updated_at=? WHERE lease_id=?", consumed, reserved, closed, instant, id)
				if closed {
					response["closedLeases"] = append(arr(response["closedLeases"]), id)
				}
			}
			response["leaseWatermarks"] = claims
			s.exec("UPDATE engine_credit_lease SET lost=1 WHERE node_id=? AND epoch=? AND boot_id<>? AND closed=0", node["id"], epoch, boot)
			if len(services) > 0 {
				p.requireCapability(num(node["id"]), "creditLease")
				p.enableCredit(s, num(node["id"]))
				counts := map[int64]int64{}
				names := []string{}
				for service := range services {
					a := serviceID(service)
					counts[num(a[1])]++
					names = append(names, service)
				}
				sort.Strings(names)
				for _, service := range names {
					ids := serviceID(service)
					uid, pid := num(ids[1]), num(ids[2])
					owner, permission := s.get("user", uid), s.get("user_tunnel", pid)
					f := s.one("SELECT f.status,f.user_id,f.tunnel_id,t.in_node_id,t.engine,t.traffic_ratio,t.flow FROM forward f JOIN tunnel t ON t.id=f.tunnel_id WHERE f.id=?", ids[0])
					if f == nil || owner == nil || permission == nil {
						continue
					}
					if num(f["userId"]) != uid || num(f["inNodeId"]) != num(node["id"]) || str(f["engine"]) != "kernel" || num(permission["userId"]) != uid || num(permission["tunnelId"]) != num(f["tunnelId"]) || num(owner["roleId"]) == 0 {
						continue
					}
					expires := min(expiry(owner), expiry(permission))
					if num(f["status"]) != 1 || num(owner["status"]) != 1 || num(permission["status"]) != 1 || expires <= instant {
						continue
					}
					limit, plimit := quotaBytes(owner), quotaBytes(permission)
					spent, pspent := checkedAdd(num(owner["inFlow"]), num(owner["outFlow"])), checkedAdd(num(permission["inFlow"]), num(permission["outFlow"]))
					if spent >= limit || pspent >= plimit {
						continue
					}
					peers := s.rows("SELECT DISTINCT n.engine,n.version,COALESCE(p.strict_credit,0) strict_credit FROM forward f JOIN tunnel t ON t.id=f.tunnel_id JOIN node n ON n.id=t.in_node_id LEFT JOIN engine_node_policy p ON p.node_id=n.id WHERE f.user_id=? AND f.status=1", uid)
					mixed := false
					for _, peer := range peers {
						if str(peer["engine"]) != "kernel" || !reservationVersion.MatchString(str(peer["version"])) || num(peer["strictCredit"]) != 1 {
							mixed = true
						}
					}
					if mixed {
						continue
					}
					old := s.one("SELECT * FROM engine_credit_lease WHERE node_id=? AND epoch=? AND boot_id=? AND service_id=? AND closed=0 AND lost=0 ORDER BY updated_at DESC FOR UPDATE", node["id"], epoch, boot, service)
					pr := price{str(f["trafficRatio"]), num(f["flow"])}
					claim := claimServices[service]
					if old != nil && (claim == nil || num(claim["generation"]) < num(old["generation"])) {
						grant := M{"id": old["leaseId"], "serviceId": service, "epoch": epoch, "bootId": boot, "generation": old["generation"], "totalGranted": old["totalRaw"], "windowBytes": min(maxGrant, num(old["totalRaw"])), "requestSequence": sequence, "validForMillis": max(1, min(60000, num(old["expiresAt"])-instant))}
						response["grants"] = append(arr(response["grants"]), grant)
						continue
					}
					if old != nil {
						a, _ := new(big.Rat).SetString(str(old["ratio"]))
						b, _ := new(big.Rat).SetString(pr.Ratio)
						if a.Cmp(b) != 0 || num(old["flowType"]) != pr.Flow {
							continue
						}
					}
					outstanding := num(s.one("SELECT COALESCE(SUM(reserved_bill),0) n FROM engine_credit_lease WHERE user_id=? AND closed=0", uid)["n"])
					poutstanding := num(s.one("SELECT COALESCE(SUM(reserved_bill),0) n FROM engine_credit_lease WHERE user_tunnel_id=? AND closed=0", pid)["n"])
					available := max(0, min(limit-spent-outstanding, plimit-pspent-poutstanding))
					remaining := int64(0)
					if old != nil {
						remaining = num(old["totalRaw"]) - num(old["consumedRaw"])
					}
					if old != nil && remaining >= max(1, maxGrant*3/4) && num(old["expiresAt"])-instant > leaseDuration/2 {
						continue
					}
					extra := rawCredit(available/max(1, counts[uid]), pr, max(0, min(maxGrant-remaining, 1<<32)))
					if old != nil && remaining >= max(1, maxGrant*3/4) {
						extra = 0
					}
					if old == nil && extra < 128 {
						continue
					}
					total, generation, lease := extra, int64(1), randomHex(16)
					if old != nil {
						total = checkedAdd(num(old["totalRaw"]), extra)
						generation = num(old["generation"]) + 1
						lease = str(old["leaseId"])
					}
					deadline := min(expires, instant+leaseDuration)
					if deadline-instant < 1000 {
						continue
					}
					if old == nil {
						up, down := p.watermark(s, node["id"], epoch, service)
						s.exec("INSERT INTO engine_credit_lease(lease_id,node_id,epoch,boot_id,service_id,user_id,user_tunnel_id,generation,total_raw,consumed_raw,reserved_bill,start_up,start_down,ratio,flow_type,closed,lost,expires_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,0,?,?,?,?,?,0,0,?,?)", lease, node["id"], epoch, boot, service, uid, pid, generation, total, bill(total, pr, true), up, down, pr.Ratio, pr.Flow, deadline, instant)
					} else {
						s.exec("UPDATE engine_credit_lease SET generation=?,total_raw=?,reserved_bill=?,expires_at=?,updated_at=? WHERE lease_id=?", generation, total, bill(total-num(old["consumedRaw"]), pr, true), deadline, instant, lease)
					}
					response["grants"] = append(arr(response["grants"]), M{"id": lease, "serviceId": service, "epoch": epoch, "bootId": boot, "generation": generation, "totalGranted": total, "windowBytes": min(total, maxGrant), "requestSequence": sequence, "validForMillis": deadline - instant})
				}
			}
			s.exec("UPDATE engine_report_cursor SET sequence=? WHERE node_id=? AND epoch=?", sequence, node["id"], epoch)
			s.exec("INSERT INTO engine_credit_request(node_id,epoch,sequence,body_hash,response,created_at) VALUES(?,?,?,?,?,?)", node["id"], epoch, sequence, bodyHash, jsonText(response), instant)
			s.exec("DELETE FROM engine_credit_request WHERE node_id=? AND epoch=? AND sequence<?", node["id"], epoch, max(0, sequence-64))
		}
	}
	if maintenance {
		s.exec("UPDATE forward f JOIN tunnel t ON t.id=f.tunnel_id SET f.status=0 WHERE t.in_node_id=? AND t.engine='kernel'", node["id"])
		response["maintenanceAccepted"] = true
	}
	return response
}
func lockRows(s store, table string, ids map[int64]bool) {
	validTable(table)
	sorted := sortedIDs(ids)
	for off := 0; off < len(sorted); off += 500 {
		page := sorted[off:min(off+500, len(sorted))]
		args := []any{}
		for _, id := range page {
			args = append(args, id)
		}
		s.rows("SELECT id FROM `"+table+"` WHERE id IN ("+placeholders(len(page))+") ORDER BY id FOR UPDATE", args...)
	}
}

func (p *Panel) prime(s store, node int64, service string) {
	if !p.supports(node, "creditPush") {
		return
	}
	for i := 0; i < 3; i++ {
		r := p.rpc(node, M{}, "RequestCredit")
		if str(r["message"]) != "OK" || r["data"] == nil {
			return
		}
		ack := p.exchange(s, found(s.get("node", node), "节点不存在"), obj(r["data"]), false)
		ack["serviceId"] = service
		installed := p.rpc(node, ack, "InstallCredit")
		if str(installed["message"]) != "OK" || truth(obj(installed["data"])["ready"]) {
			return
		}
	}
}
