package panel

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

func gostForwarder(remote, strategy string) M {
	if strategy == "" {
		strategy = "fifo"
	}
	nodes := []M{}
	for i, a := range strings.Split(remote, ",") {
		nodes = append(nodes, M{"name": fmt.Sprintf("node_%d", i+1), "addr": a})
	}
	return M{"nodes": nodes, "selector": M{"strategy": strategy, "maxFails": 1, "failTimeout": "600s"}}
}
func gostServices(f, t M, name string, ut M) []M {
	services := []M{}
	for _, protocol := range []string{"tcp", "udp"} {
		handler := M{"type": protocol}
		listener := M{"type": protocol}
		if protocol == "udp" {
			listener["metadata"] = M{"keepAlive": true}
		}
		service := M{"name": name + "_" + protocol, "addr": str(t[protocol+"ListenAddr"]) + ":" + str(f["inPort"]), "handler": handler, "listener": listener}
		if ut != nil && ut["speedId"] != nil {
			service["limiter"] = str(ut["speedId"])
		}
		if num(t["type"]) == 1 {
			service["forwarder"] = gostForwarder(str(f["remoteAddr"]), str(f["strategy"]))
			if str(f["interfaceName"]) != "" {
				service["metadata"] = M{"interface": f["interfaceName"]}
			}
		} else {
			handler["chain"] = name + "_chains"
		}
		services = append(services, service)
	}
	return services
}
func (p *Panel) applyGost(s store, f, t M, name string, ut M, update bool) {
	node := num(t["inNodeId"])
	if !update {
		defer func() {
			if v := recover(); v != nil {
				p.rpc(node, M{"services": []string{name + "_tcp", name + "_udp"}}, "DeleteService")
				if num(t["type"]) == 2 {
					p.rpc(node, M{"chain": name + "_chains"}, "DeleteChains")
					p.rpc(num(t["outNodeId"]), M{"services": []string{name + "_tls"}}, "DeleteService")
				}
				panic(v)
			}
		}()
	}
	kind := "AddService"
	if update {
		kind = "UpdateService"
	}
	if num(t["type"]) == 2 {
		dialer := M{"type": t["protocol"]}
		if str(t["protocol"]) == "quic" {
			dialer["metadata"] = M{"keepAlive": true, "ttl": "10s"}
		}
		entry := M{"name": "node-" + name, "addr": str(t["outIp"]) + ":" + str(f["outPort"]), "connector": M{"type": "relay"}, "dialer": dialer}
		if str(t["interfaceName"]) != "" {
			entry["interface"] = t["interfaceName"]
		}
		chain := M{"name": name + "_chains", "hops": []M{{"name": "hop-" + name, "nodes": []M{entry}}}}
		chainKind := "AddChains"
		var request any = chain
		if update {
			chainKind = "UpdateChains"
			request = M{"chain": name + "_chains", "data": chain}
		}
		r := p.rpc(node, request, chainKind)
		if update && strings.Contains(str(r["message"]), "not found") {
			r = p.rpc(node, chain, "AddChains")
		}
		if str(r["message"]) != "OK" {
			fail(str(r["message"]))
		}
		remote := M{"name": name + "_tls", "addr": ":" + str(f["outPort"]), "handler": M{"type": "relay"}, "listener": M{"type": t["protocol"]}, "forwarder": gostForwarder(str(f["remoteAddr"]), str(f["strategy"]))}
		if str(f["interfaceName"]) != "" {
			remote["metadata"] = M{"interface": f["interfaceName"]}
		}
		r = p.rpc(num(t["outNodeId"]), []M{remote}, kind)
		if update && strings.Contains(str(r["message"]), "not found") {
			r = p.rpc(num(t["outNodeId"]), []M{remote}, "AddService")
		}
		if str(r["message"]) != "OK" {
			fail(str(r["message"]))
		}
	}
	services := gostServices(f, t, name, ut)
	r := p.rpc(node, services, kind)
	if update && strings.Contains(str(r["message"]), "not found") {
		r = p.rpc(node, services, "AddService")
	}
	if str(r["message"]) != "OK" {
		fail(str(r["message"]))
	}
}
func (p *Panel) legacyFlow(r *http.Request, s store, b M) any {
	if r.URL.Path == "/flow/test" {
		return plain("test")
	}
	secret := r.URL.Query().Get("secret")
	n := s.one("SELECT * FROM node WHERE secret=? AND engine<>'kernel'", secret)
	if n == nil {
		return plain("ok")
	}
	if truth(b["encrypted"]) {
		b = decode(decrypt(secret, []byte(jsonText(b))))
	}
	if r.URL.Path == "/flow/config" {
		for _, k := range []string{"services", "chains", "limiters"} {
			if len(arr(b[k])) > 20000 {
				statusError(413, "configuration snapshot exceeds safe bound")
			}
		}
		p.mu.Lock()
		if len(p.gostCleanup) >= 32 && p.gostCleanup[num(n["id"])] == nil {
			p.mu.Unlock()
			statusError(503, "configuration queue is full")
		}
		p.gostCleanup[num(n["id"])] = b
		p.mu.Unlock()
		return plain("ok")
	}
	name := str(b["n"])
	if name == "web_api" {
		return plain("ok")
	}
	parts := strings.Split(name, "_")
	if len(parts) < 3 {
		fail("invalid service ID")
	}
	parts = parts[:3]
	serviceID(strings.Join(parts, "_"))
	up, down := exact(b["u"]), exact(b["d"])
	// Legacy GOST sends deltas without a report ID. Do not invent retry IDs or replay it twice.
	p.transaction(s.ctx, func(tx store) any {
		f := tx.get("forward", parts[0])
		pr := price{"1", 2}
		if f != nil {
			t := tx.get("tunnel", f["tunnelId"])
			if t != nil {
				pr = price{str(t["trafficRatio"]), num(t["flow"])}
			}
		}
		bu, bd := bill(up, pr, false), bill(down, pr, false)
		tx.exec("UPDATE forward SET in_flow=in_flow+?,out_flow=out_flow+? WHERE id=?", bd, bu, parts[0])
		tx.exec("UPDATE user SET in_flow=in_flow+?,out_flow=out_flow+? WHERE id=?", bd, bu, parts[1])
		if parts[2] != "0" {
			tx.exec("UPDATE user_tunnel SET in_flow=in_flow+?,out_flow=out_flow+? WHERE id=?", bd, bu, parts[2])
		}
		return nil
	})
	p.enforceQuotas(s)
	return plain("ok")
}
func (p *Panel) cleanGost(s store, node, config M) {
	for _, v := range arr(config["services"]) {
		name := str(obj(v)["name"])
		parts := strings.Split(name, "_")
		if len(parts) != 4 || !servicePattern.MatchString(strings.Join(parts[:3], "_")) {
			continue
		}
		if s.get("forward", parts[0]) != nil {
			continue
		}
		if parts[3] == "tcp" {
			base := strings.Join(parts[:3], "_")
			if str(p.rpc(num(node["id"]), M{"services": []string{base + "_tcp", base + "_udp"}}, "DeleteService")["message"]) != "OK" {
				return
			}
		}
		if parts[3] == "tls" {
			if str(p.rpc(num(node["id"]), M{"services": []string{name}}, "DeleteService")["message"]) != "OK" {
				return
			}
		}
	}
	for _, v := range arr(config["chains"]) {
		name := str(obj(v)["name"])
		parts := strings.Split(name, "_")
		if len(parts) == 4 && parts[3] == "chains" && servicePattern.MatchString(strings.Join(parts[:3], "_")) && s.get("forward", parts[0]) == nil {
			if str(p.rpc(num(node["id"]), M{"chain": name}, "DeleteChains")["message"]) != "OK" {
				return
			}
		}
	}
	for _, v := range arr(config["limiters"]) {
		name := str(obj(v)["name"])
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(name) {
			continue
		}
		if s.get("speed_limit", name) == nil {
			if str(p.rpc(num(node["id"]), M{"limiter": name}, "DeleteLimiters")["message"]) != "OK" {
				return
			}
		}
	}
}

// The Java limiter contract rounds Mbps/8 to one decimal with HALF_UP.
func gostRate(speed int64) string {
	if speed < 1 {
		fail("速度限制必须大于0")
	}
	tenths := (checkedMul(speed, 10) + 4) / 8
	return fmt.Sprintf("%d.%d", tenths/10, tenths%10)
}
