package panel

import (
	"database/sql"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

var servicePattern = regexp.MustCompile(`^[0-9]+_[0-9]+_[0-9]+$`)
var epochPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var bootPattern = regexp.MustCompile(`^[a-zA-Z0-9-]{1,100}$`)

func serviceID(id string) []string {
	if len(id) > 100 || !servicePattern.MatchString(id) {
		fail("invalid service ID")
	}
	a := strings.Split(id, "_")
	for _, n := range a {
		value := num(n)
		if str(value) != n {
			fail("noncanonical service ID")
		}
	}
	return a
}
func exact(v any) int64 {
	if v == nil {
		fail("invalid usage integer")
	}
	n := num(v)
	if n < 0 {
		fail("negative usage")
	}
	return n
}
func checkedAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b || b < 0 && a < math.MinInt64-b {
		fail("usage overflow")
	}
	return a + b
}
func checkedMul(a, b int64) int64 {
	v := new(big.Int).Mul(big.NewInt(a), big.NewInt(b))
	if !v.IsInt64() {
		fail("usage overflow")
	}
	return v.Int64()
}

type price struct {
	Ratio string
	Flow  int64
}

func bill(raw int64, pr price, ceil bool) int64 {
	r, ok := new(big.Rat).SetString(pr.Ratio)
	if !ok || r.Sign() < 0 || pr.Flow < 1 || pr.Flow > 2 || raw < 0 {
		fail("invalid billing policy")
	}
	r.Mul(r, new(big.Rat).SetInt64(raw))
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(r.Num(), r.Denom(), rem)
	if ceil && rem.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	q.Mul(q, big.NewInt(pr.Flow))
	if !q.IsInt64() {
		fail("usage overflow")
	}
	return q.Int64()
}
func rawCredit(available int64, pr price, cap int64) int64 {
	r, ok := new(big.Rat).SetString(pr.Ratio)
	if !ok || r.Sign() < 0 || pr.Flow < 1 || pr.Flow > 2 || available < 0 || cap < 0 {
		fail("invalid credit bounds")
	}
	if r.Sign() == 0 {
		return cap
	}
	r.Quo(new(big.Rat).SetInt64(available/pr.Flow), r)
	q := new(big.Int).Quo(r.Num(), r.Denom())
	if q.Cmp(big.NewInt(cap)) > 0 {
		return cap
	}
	if !q.IsInt64() {
		fail("credit overflow")
	}
	return q.Int64()
}
func inTransaction(s store) bool { _, ok := s.q.(*sql.Tx); return ok }
func placeholders(n int) string {
	if n < 1 {
		panic("empty placeholders")
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
func (p *Panel) ingest(s store, n, report M, prices map[string]price) {
	if !inTransaction(s) {
		p.transaction(s.ctx, func(tx store) any { p.ingest(tx, n, report, prices); return nil })
		return
	}
	epoch, seq := str(report["epoch"]), exact(report["sequence"])
	usage := arr(report["usage"])
	if !epochPattern.MatchString(epoch) || seq < 1 || report["usage"] == nil || len(usage) > 10000 {
		fail("invalid usage report")
	}
	if prices == nil {
		prices = map[string]price{}
		claims := arr(report["leases"])
		if len(claims) > 10000 {
			fail("too many leases")
		}
		for off := 0; off < len(claims); off += 500 {
			page := claims[off:min(off+500, len(claims))]
			args := []any{}
			for _, v := range page {
				id := str(obj(v)["id"])
				if !epochPattern.MatchString(id) {
					fail("invalid lease ID")
				}
				args = append(args, id)
			}
			args = append(args, n["id"], epoch, report["bootId"])
			for _, r := range s.rows("SELECT service_id,ratio,flow_type FROM engine_credit_lease WHERE lease_id IN ("+placeholders(len(page))+") AND node_id=? AND epoch=? AND boot_id=?", args...) {
				prices[str(r["serviceId"])] = price{str(r["ratio"]), num(r["flowType"])}
			}
		}
	}
	input := map[string]M{}
	zero := []string{}
	forwardIDs := map[int64]bool{}
	for _, v := range usage {
		u := obj(v)
		id := str(u["id"])
		parts := serviceID(id)
		if input[id] != nil {
			fail("invalid or duplicate service ID")
		}
		input[id] = u
		if exact(u["up"]) == 0 && exact(u["down"]) == 0 {
			zero = append(zero, id)
		} else {
			forwardIDs[num(parts[0])] = true
		}
	}
	for off := 0; off < len(zero); off += 500 {
		page := zero[off:min(off+500, len(zero))]
		args := []any{n["id"], epoch}
		for _, id := range page {
			args = append(args, id)
		}
		for _, old := range s.rows("SELECT service_id,sequence FROM engine_usage WHERE node_id=? AND epoch=? AND service_id IN ("+placeholders(len(page))+") AND (up_bytes>0 OR down_bytes>0)", args...) {
			if seq > num(old["sequence"]) {
				fail("cumulative counters regressed")
			}
		}
		for _, id := range page {
			delete(input, id)
		}
	}
	if len(input) == 0 {
		return
	}
	metas := map[int64][]M{}
	ids := sortedIDs(forwardIDs)
	for off := 0; off < len(ids); off += 500 {
		page := ids[off:min(off+500, len(ids))]
		args := []any{}
		for _, id := range page {
			args = append(args, id)
		}
		for _, r := range s.rows("SELECT f.id,f.user_id,f.tunnel_id,t.in_node_id,t.engine,t.traffic_ratio,t.flow,u.role_id,ut.id permission_id FROM forward f JOIN tunnel t ON t.id=f.tunnel_id JOIN user u ON u.id=f.user_id LEFT JOIN user_tunnel ut ON ut.user_id=f.user_id AND ut.tunnel_id=f.tunnel_id WHERE f.id IN ("+placeholders(len(page))+")", args...) {
			id := num(r["id"])
			metas[id] = append(metas[id], r)
		}
	}
	metadata := map[string]M{}
	owners := map[int64]bool{}
	for _, id := range keysOfMap(input) {
		parts := serviceID(id)
		for _, r := range metas[num(parts[0])] {
			if num(r["inNodeId"]) != num(n["id"]) || str(r["engine"]) != "kernel" || num(r["userId"]) != num(parts[1]) {
				continue
			}
			if num(r["roleId"]) == 0 {
				if parts[2] != "0" {
					continue
				}
			} else if r["permissionId"] == nil || num(r["permissionId"]) != num(parts[2]) {
				continue
			}
			metadata[id] = r
			owners[num(r["userId"])] = true
			break
		}
	}
	lockRows(s, "user", owners)
	valid := keysOfMap(metadata)
	previous := map[string]M{}
	for off := 0; off < len(valid); off += 500 {
		page := valid[off:min(off+500, len(valid))]
		marks := []string{}
		args := []any{}
		queryArgs := []any{n["id"], epoch}
		for _, id := range page {
			marks = append(marks, "(?,?,?,0,0,0)")
			args = append(args, n["id"], epoch, id)
			queryArgs = append(queryArgs, id)
		}
		s.exec("INSERT IGNORE INTO engine_usage(node_id,epoch,service_id,sequence,up_bytes,down_bytes) VALUES "+strings.Join(marks, ","), args...)
		for _, r := range s.rows("SELECT service_id,sequence,up_bytes,down_bytes FROM engine_usage WHERE node_id=? AND epoch=? AND service_id IN ("+placeholders(len(page))+") ORDER BY service_id FOR UPDATE", queryArgs...) {
			previous[str(r["serviceId"])] = r
		}
	}
	watermarks := []M{}
	forwardDelta, userDelta, permissionDelta := map[int64][2]int64{}, map[int64][2]int64{}, map[int64][2]int64{}
	for _, id := range valid {
		r, u, old := metadata[id], input[id], previous[id]
		if seq <= num(old["sequence"]) {
			continue
		}
		up, down := exact(u["up"]), exact(u["down"])
		if up < num(old["upBytes"]) || down < num(old["downBytes"]) {
			fail("cumulative counters regressed")
		}
		pr, ok := prices[id]
		if !ok {
			pr = price{str(r["trafficRatio"]), num(r["flow"])}
		}
		bu, bd := bill(up-num(old["upBytes"]), pr, false), bill(down-num(old["downBytes"]), pr, false)
		watermarks = append(watermarks, M{"id": id, "up": up, "down": down})
		addDelta(forwardDelta, num(r["id"]), bu, bd)
		addDelta(userDelta, num(r["userId"]), bu, bd)
		if !strings.HasSuffix(id, "_0") {
			addDelta(permissionDelta, num(r["permissionId"]), bu, bd)
		}
	}
	for off := 0; off < len(watermarks); off += 500 {
		page := watermarks[off:min(off+500, len(watermarks))]
		marks := []string{}
		args := []any{}
		for _, m := range page {
			marks = append(marks, "(?,?,?,?,?,?)")
			args = append(args, n["id"], epoch, m["id"], seq, m["up"], m["down"])
		}
		s.exec("INSERT INTO engine_usage(node_id,epoch,service_id,sequence,up_bytes,down_bytes) VALUES "+strings.Join(marks, ",")+" ON DUPLICATE KEY UPDATE sequence=VALUES(sequence),up_bytes=VALUES(up_bytes),down_bytes=VALUES(down_bytes)", args...)
	}
	updateDeltas(s, "forward", forwardDelta)
	updateDeltas(s, "user", userDelta)
	updateDeltas(s, "user_tunnel", permissionDelta)
}
func sortedIDs(ids map[int64]bool) []int64 {
	out := []int64{}
	for id := range ids {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func addDelta(m map[int64][2]int64, id, up, down int64) {
	old := m[id]
	m[id] = [2]int64{checkedAdd(old[0], up), checkedAdd(old[1], down)}
}
func updateDeltas(s store, table string, m map[int64][2]int64) {
	validTable(table)
	set := map[int64]bool{}
	for id := range m {
		set[id] = true
	}
	ids := sortedIDs(set)
	for off := 0; off < len(ids); off += 500 {
		page := ids[off:min(off+500, len(ids))]
		up, down := []string{}, []string{}
		upArgs, downArgs, idArgs := []any{}, []any{}, []any{}
		for _, id := range page {
			up = append(up, "WHEN ? THEN ?")
			down = append(down, "WHEN ? THEN ?")
			upArgs = append(upArgs, id, m[id][0])
			downArgs = append(downArgs, id, m[id][1])
			idArgs = append(idArgs, id)
		}
		args := append(append(upArgs, downArgs...), idArgs...)
		s.exec("UPDATE `"+table+"` SET in_flow=in_flow+(CASE id "+strings.Join(up, " ")+" ELSE 0 END),out_flow=out_flow+(CASE id "+strings.Join(down, " ")+" ELSE 0 END) WHERE id IN ("+placeholders(len(page))+")", args...)
	}
}

func keysOfMap(m map[string]M) []string {
	k := []string{}
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}
func (p *Panel) strict(s store, node int64) bool {
	return s.one("SELECT node_id FROM engine_node_policy WHERE node_id=? AND strict_credit=1", node) != nil
}
func (p *Panel) enableCredit(s store, node int64) {
	info := p.capability(node)
	if !truth(obj(info)["strictCreditPolicy"]) {
		p.requireCapability(node, "creditPolicy")
		applied := p.commandOK(node, M{}, "RequireCreditPolicy")
		if !truth(applied["strictCreditPolicy"]) {
			fail("node did not acknowledge strict credit policy")
		}
		p.mu.Lock()
		x := p.nodes[node]
		p.mu.Unlock()
		if x == nil {
			fail("node disconnected during credit policy change")
		}
		x.mu.Lock()
		x.info = applied
		x.mu.Unlock()
	}
	s.exec("INSERT INTO engine_node_policy(node_id,strict_credit,updated_at) VALUES(?,1,?) ON DUPLICATE KEY UPDATE strict_credit=1,updated_at=VALUES(updated_at)", node, now())
}
func (p *Panel) quotaMode(s store, node int64, service string) {
	parts := serviceID(service)
	if parts[2] == "0" {
		return
	}
	n := found(s.get("node", node), "节点不存在")
	incoming := normalizeEngine(n["engine"]) == "kernel" && (p.supports(node, "creditPolicy") || p.strict(s, node))
	for _, peer := range s.rows("SELECT t.in_node_id,n.engine,COALESCE(p.strict_credit,0) strict_credit FROM forward f JOIN tunnel t ON t.id=f.tunnel_id JOIN node n ON n.id=t.in_node_id LEFT JOIN engine_node_policy p ON p.node_id=n.id WHERE f.user_id=? AND f.status=1 AND f.id<>?", parts[1], parts[0]) {
		strict := str(peer["engine"]) == "kernel" && num(peer["strictCredit"]) == 1
		if incoming && num(peer["inNodeId"]) == node {
			continue
		}
		if incoming != strict {
			fail("同一用户的共享配额不能混用预留额度和旧模式；请先暂停并结算旧转发，再切换模式")
		}
	}
	if !incoming && s.one("SELECT lease_id FROM engine_credit_lease WHERE user_id=? AND closed=0 LIMIT 1", parts[1]) != nil {
		fail("该用户仍有未结算的预留额度；请先暂停并结算，再使用旧模式")
	}
}
func (p *Panel) reportAPI(r *http.Request, s store, b M) any {
	defer func() {
		if v := recover(); v != nil {
			if e, ok := v.(apiError); ok && strings.HasPrefix(r.URL.Path, "/flow/engine/v3/") {
				e.Code = -2
				e.Status = 200
				panic(e)
			}
			if e, ok := v.(apiError); ok && e.Status == 200 {
				e.Status = 400
				e.Code = 400
				panic(e)
			}
			panic(v)
		}
	}()

	if r.URL.Path == "/flow/engine/v3/session" {
		return rawJSON{p.issueSession(s, r.Header.Get("Authorization"))}
	}
	n, _ := p.identity(s, r.Header.Get("Authorization"))
	if n == nil || str(n["engine"]) != "kernel" {
		statusError(401, "engine protocol rejected")
	}
	nativeNode(n)
	switch r.URL.Path {
	case "/flow/engine/v3/session":
		return rawJSON{p.issueSession(s, r.Header.Get("Authorization"))}
	case "/flow/engine/v1/traffic":
		if p.strict(s, num(n["id"])) {
			statusError(409, "strict credit nodes require v2 reporting")
		}
		p.ingest(s, n, b, nil)
		return plain("ok")
	case "/flow/engine/v2/traffic":
		return rawJSON{p.exchange(s, n, b, false)}
	case "/flow/engine/v2/maintenance":
		return rawJSON{p.exchange(s, n, b, true)}
	}
	panic("unknown report route")
}
func (p *Panel) watermark(s store, node any, epoch, service string) (int64, int64) {
	r := s.one("SELECT up_bytes,down_bytes FROM engine_usage WHERE node_id=? AND epoch=? AND service_id=?", node, epoch, service)
	if r == nil {
		return 0, 0
	}
	return num(r["upBytes"]), num(r["downBytes"])
}
func validatedCounters(counters, usage []any) []any {
	if len(counters) > 20000 {
		fail("too many counter watermarks")
	}
	out := []any{}
	totals := map[string]M{}
	for _, v := range usage {
		u := obj(v)
		totals[str(u["id"])] = u
	}
	for _, v := range counters {
		c := obj(v)
		id, set := str(c["id"]), str(c["set"])
		serviceID(id)
		switch set {
		case "FPV2_UP", "FPV2_DOWN", "FP4_UP", "FP4_DOWN", "FP6_UP", "FP6_DOWN":
		default:
			fail("invalid counter watermark")
		}
		if c["key"] == nil || len(str(c["key"])) > 100 {
			fail("invalid counter watermark")
		}
		field := "down"
		if strings.HasSuffix(set, "_UP") {
			field = "up"
		}
		u := totals[id]
		if u == nil || exact(c["bytes"]) > exact(u[field]) {
			fail("counter watermark exceeds cumulative usage")
		}
		out = append(out, c)
	}
	return out
}
