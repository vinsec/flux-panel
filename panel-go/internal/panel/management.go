package panel

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func (p *Panel) dispatch(r *http.Request, w http.ResponseWriter, s store, c, b M) any {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/api/v1/user/"):
		return p.userAPI(s, c, b, strings.TrimPrefix(path, "/api/v1/user/"))
	case strings.HasPrefix(path, "/api/v1/node/"):
		return p.nodeAPI(s, c, b, strings.TrimPrefix(path, "/api/v1/node/"))
	case strings.HasPrefix(path, "/api/v1/config/"):
		return p.configAPI(s, b, strings.TrimPrefix(path, "/api/v1/config/"))
	case strings.HasPrefix(path, "/api/v1/tunnel/"):
		return p.tunnelAPI(s, c, b, strings.TrimPrefix(path, "/api/v1/tunnel/"))
	case strings.HasPrefix(path, "/api/v1/speed-limit/"):
		return p.limitAPI(s, b, strings.TrimPrefix(path, "/api/v1/speed-limit/"))
	case strings.HasPrefix(path, "/api/v1/forward/"):
		return p.forwardAPI(s, c, b, strings.TrimPrefix(path, "/api/v1/forward/"))
	case strings.HasPrefix(path, "/api/v1/captcha/"):
		return p.captchaAPI(s, b, strings.TrimPrefix(path, "/api/v1/captcha/"))
	case strings.HasPrefix(path, "/api/v1/engine/"):
		return p.engineAPI(s, c, b, strings.TrimPrefix(path, "/api/v1/engine/"))
	case strings.HasPrefix(path, "/flow/engine/"):
		return p.reportAPI(r, s, b)
	case strings.HasPrefix(path, "/flow/"):
		return p.legacyFlow(r, s, b)
	case path == "/api/v1/open_api/sub_store":
		return p.openAPI(w, r, s)
	case path == "/error":
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		return written
	}
	statusError(404, "Not Found")
	return nil
}
func found(m M, message string) M {
	if m == nil {
		fail(message)
	}
	return m
}
func (p *Panel) userAPI(s store, c, b M, action string) any {
	id := b["id"]
	if action == "create" || action == "update" || action == "updatePassword" {
		p.userNames.Lock()
		defer p.userNames.Unlock()
	}
	switch action {
	case "login":
		if p.configValue(s, "captcha_enabled") == "true" && !p.captcha.consume(str(b["captchaId"])) {
			fail("验证码校验失败")
		}
		u := s.one("SELECT * FROM user WHERE user=?", b["username"])
		if u == nil || str(u["pwd"]) != passwordHash(str(b["password"])) {
			fail("账号或密码错误")
		}
		if num(u["status"]) == 0 {
			fail("账户停用")
		}
		return M{"token": p.token(u), "name": u["user"], "role_id": u["roleId"], "requirePasswordChange": str(b["username"]) == "admin_user" || str(b["password"]) == "admin_user"}
	case "list":
		return s.rows("SELECT * FROM user WHERE role_id<>0")
	case "create", "update":
		if s.one("SELECT id FROM user WHERE user=? AND id<>?", b["user"], num(id)) != nil {
			fail("用户名已存在")
		}
		m := pick(b, "user flow num expTime flowResetTime status")
		m["updatedTime"] = now()
		if action == "create" {
			m["pwd"] = passwordHash(str(b["pwd"]))
			defaults(m, M{"status": 1, "roleId": 1, "inFlow": 0, "outFlow": 0, "createdTime": now()})
			s.insert("user", m)
			return "用户创建成功"
		}
		u := found(s.get("user", id), "用户不存在")
		if num(u["roleId"]) == 0 {
			fail("不能修改管理员用户信息")
		}
		if strings.TrimSpace(str(b["pwd"])) != "" {
			m["pwd"] = passwordHash(str(b["pwd"]))
		}
		s.update("user", id, m)
		return "用户更新成功"
	case "delete":
		u := found(s.get("user", id), "用户不存在")
		if num(u["roleId"]) == 0 {
			fail("不能删除管理员用户")
		}
		unavailable := map[int64]bool{}
		for _, f := range s.rows("SELECT * FROM forward WHERE user_id=?", id) {
			p.deleteRelatedForward(s, f, unavailable)
		}
		s.exec("DELETE FROM user_tunnel WHERE user_id=?", id)
		s.exec("DELETE FROM statistics_flow WHERE user_id=?", id)
		s.remove("user", id)
		return "用户及关联数据删除成功"
	case "updatePassword":
		u := found(s.get("user", c["sub"]), "用户不存在")
		if str(b["newPassword"]) != str(b["confirmPassword"]) {
			fail("新密码和确认密码不匹配")
		}
		if str(u["pwd"]) != passwordHash(str(b["currentPassword"])) {
			fail("当前密码错误")
		}
		if s.one("SELECT id FROM user WHERE user=? AND id<>?", b["newUsername"], u["id"]) != nil {
			fail("用户名已被其他用户使用")
		}
		s.update("user", u["id"], M{"user": b["newUsername"], "pwd": passwordHash(str(b["newPassword"])), "updatedTime": now()})
		return "账号密码修改成功"
	case "reset":
		table := "user_tunnel"
		if num(b["type"]) == 1 {
			table = "user"
		}
		found(s.get(table, id), "用户或隧道不存在")
		s.update(table, id, M{"inFlow": 0, "outFlow": 0})
		return nil
	case "package":
		u := found(s.get("user", c["sub"]), "用户不存在")
		delete(u, "pwd")
		delete(u, "roleId")
		u["name"] = nil
		stats := s.rows("SELECT * FROM statistics_flow WHERE user_id=? ORDER BY id DESC LIMIT 24", c["sub"])
		h := time.Now().Hour()
		if len(stats) > 0 {
			fmt.Sscanf(str(stats[len(stats)-1]["time"]), "%d:", &h)
			h--
		}
		for len(stats) < 24 {
			if h < 0 {
				h = 23
			}
			stats = append(stats, M{"id": nil, "createdTime": nil, "userId": num(c["sub"]), "flow": 0, "totalFlow": 0, "time": fmt.Sprintf("%02d:00", h)})
			h--
		}
		return M{"userInfo": u, "statisticsFlows": stats, "tunnelPermissions": s.rows("SELECT ut.id,ut.user_id,ut.tunnel_id,t.name tunnelName,t.flow tunnelFlow,ut.flow,ut.in_flow,ut.out_flow,ut.num,ut.flow_reset_time,ut.exp_time,ut.speed_id,sl.name speedLimitName,sl.speed FROM user_tunnel ut LEFT JOIN tunnel t ON t.id=ut.tunnel_id LEFT JOIN speed_limit sl ON sl.id=ut.speed_id WHERE ut.user_id=? ORDER BY ut.id", c["sub"]), "forwards": s.rows("SELECT f.id,f.name,f.tunnel_id,t.name tunnelName,t.in_ip,f.in_port,f.remote_addr,f.in_flow,f.out_flow,f.status,f.created_time FROM forward f LEFT JOIN tunnel t ON t.id=f.tunnel_id WHERE f.user_id=? ORDER BY f.created_time DESC", c["sub"])}
	}
	panic("unknown user action")
}
func (p *Panel) configValue(s store, k string) string {
	m := s.one("SELECT value FROM vite_config WHERE name=?", k)
	if m == nil {
		return ""
	}
	return str(m["value"])
}
func (p *Panel) configAPI(s store, b M, action string) any {
	switch action {
	case "list":
		m := M{}
		for _, r := range s.rows("SELECT name,value FROM vite_config") {
			m[str(r["name"])] = r["value"]
		}
		return m
	case "get":
		require(b, "name")
		return found(s.one("SELECT * FROM vite_config WHERE name=?", b["name"]), "配置不存在")
	case "update-single":
		require(b, "name value")
		p.setConfig(s, str(b["name"]), str(b["value"]))
	case "update":
		if len(b) == 0 {
			fail("配置数据不能为空")
		}
		p.transaction(s.ctx, func(t store) any {
			for k, v := range b {
				if strings.TrimSpace(k) != "" {
					p.setConfig(t, k, str(v))
				}
			}
			return nil
		})
	}
	return "配置更新成功"
}
func (p *Panel) setConfig(s store, k, v string) {
	s.exec("INSERT INTO vite_config(name,value,time) VALUES(?,?,?) ON DUPLICATE KEY UPDATE value=VALUES(value),time=VALUES(time)", k, v, now())
}
func (p *Panel) nodeAPI(s store, c, b M, action string) any {
	id := b["id"]
	switch action {
	case "list":
		r := s.rows("SELECT * FROM node")
		for _, n := range r {
			n["secret"] = nil
		}
		return r
	case "create", "update":
		engine := normalizeEngine(b["engine"])
		backend := str(b["kernelBackend"])
		if engine == "kernel" {
			if backend != "" && backend != "nftables" {
				fail("只支持 nftables 内核后端")
			}
			backend = "nftables"
		} else if backend != "" {
			fail("GOST 不接受 kernelBackend")
		}
		if num(b["portEnd"]) < num(b["portSta"]) {
			fail("结束端口不能小于起始端口")
		}
		m := pick(b, "name ip serverIp portSta portEnd http tls socks")
		m["engine"] = engine
		m["updatedTime"] = now()
		if action == "create" {
			m["kernelBackend"] = "nftables"
			mode := str(b["forwardingMode"])
			if mode == "" {
				mode = "kernel"
			}
			if mode != "kernel" && mode != "gost" {
				fail("invalid forwarding mode")
			}
			if engine != "kernel" && mode != "kernel" {
				fail("旧 GOST 节点不接受统一 Agent 转发模式")
			}
			m["forwardingMode"] = mode
			m["secret"] = randomHex(16)
			defaults(m, M{"status": 0, "http": 0, "tls": 0, "socks": 0, "createdTime": now()})
			s.insert("node", m)
			return "节点创建成功"
		}
		n := found(s.get("node", id), "节点不存在")
		if normalizeEngine(n["engine"]) != engine {
			fail("节点引擎不可原地切换，请新建节点后迁移")
		}
		if engine == "kernel" {
			nativeNode(n)
		}
		changed := false
		for _, k := range []string{"http", "tls", "socks"} {
			if b[k] != nil && num(b[k]) != num(n[k]) {
				changed = true
			}
		}
		if changed && engine == "kernel" && (num(b["http"]) != 0 || num(b["tls"]) != 0 || num(b["socks"]) != 0) {
			p.requireCapability(num(id), "protocolBlocking")
		}
		if changed && engine == "gost" && num(n["status"]) == 1 {
			p.commandOK(num(id), pick(b, "http tls socks"), "SetProtocol")
		}
		s.update("node", id, m)
		s.exec("UPDATE tunnel SET in_ip=? WHERE in_node_id=?", b["ip"], id)
		s.exec("UPDATE tunnel SET out_ip=? WHERE out_node_id=?", b["serverIp"], id)
		if changed && engine == "kernel" {
			p.queueReconcile(num(id))
		}
		return "节点更新成功"
	case "delete":
		found(s.get("node", id), "节点不存在")
		if s.one("SELECT id FROM tunnel WHERE in_node_id=? OR out_node_id=? LIMIT 1", id, id) != nil {
			fail("该节点仍有隧道在使用，请先删除相关隧道")
		}
		s.remove("node", id)
		return "节点删除成功"
	case "install":
		n := found(s.get("node", id), "节点不存在")
		return p.installCommand(s, n)
	}
	panic("unknown node action")
}

var hashPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func (p *Panel) installCommand(s store, n M) string {
	panel := p.configValue(s, "ip")
	if panel == "" {
		fail("请先前往网站配置中设置ip")
	}
	if !hashPattern.MatchString(p.cfg.ManifestSHA) || !hashPattern.MatchString(p.cfg.InstallerSHA) {
		fail("请先发布经过验证的节点安装包，并配置固定 release URL、manifest SHA256 和 installer SHA256；也可使用已校验的离线包。未回退到未经验证的上游 GOST 下载。")
	}
	base, e := url.Parse(p.cfg.ReleaseBase)
	if e != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		fail("release URL must be a pinned HTTPS base")
	}
	if !strings.Contains(panel, "://") {
		panel = "wss://" + panel
	}
	u, e := url.Parse(panel)
	if e != nil || (u.Scheme != "wss" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		fail("节点安装需要有效的 WSS/HTTPS 面板地址")
	}
	engine := normalizeEngine(n["engine"])
	cfg := M{"addr": panel, "secret": n["secret"]}
	if engine == "kernel" {
		nativeNode(n)
		defaults(cfg, M{"kernelBackend": "nftables", "apply": true, "helperSocket": "/run/flux-agent/kernel.sock", "useSessions": true, "statePath": "/var/lib/flux-agent/state.json", "intervalSeconds": 5, "forwardingMode": n["forwardingMode"]})
	}
	baseURL := strings.TrimRight(p.cfg.ReleaseBase, "/")
	return "umask 077\nFLUX_SETUP=$(mktemp -d)\ntrap 'rm -rf -- \"$FLUX_SETUP\"' EXIT\ncurl --fail --location --proto '=https' --proto-redir '=https' " + quote(baseURL+"/install.sh") + " -o \"$FLUX_SETUP/install.sh\"\nprintf '%s  %s\\n' " + quote(strings.ToLower(p.cfg.InstallerSHA)) + " \"$FLUX_SETUP/install.sh\" | sha256sum --strict -c -\ncat > \"$FLUX_SETUP/config.json\" <<'FLUX_NODE_CONFIG'\n" + jsonText(cfg) + "\nFLUX_NODE_CONFIG\nbash \"$FLUX_SETUP/install.sh\" --engine " + engine + " --release-url " + quote(baseURL) + " --manifest-sha256 " + quote(strings.ToLower(p.cfg.ManifestSHA)) + " --config \"$FLUX_SETUP/config.json\""
}
func ipv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && !strings.Contains(s, ":")
}
func (p *Panel) openAPI(w http.ResponseWriter, r *http.Request, s store) any {
	q := r.URL.Query()
	name, pwd := q.Get("user"), q.Get("pwd")
	if name == "" {
		fail("用户不能为空")
	}
	if pwd == "" {
		fail("密码不能为空")
	}
	u := s.one("SELECT * FROM user WHERE user=?", name)
	if u == nil || str(u["pwd"]) != passwordHash(pwd) {
		fail("鉴权失败")
	}
	t := q.Get("tunnel")
	if t != "" && t != "-1" {
		ut := s.get("user_tunnel", t)
		if ut == nil || num(ut["userId"]) != num(u["id"]) {
			fail("隧道不存在")
		}
		u = ut
	}
	v := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", num(u["inFlow"]), num(u["outFlow"]), num(u["flow"])*(1<<30), num(u["expTime"])/1000)
	w.Header().Set("subscription-userinfo", v)
	return plain(v)
}
