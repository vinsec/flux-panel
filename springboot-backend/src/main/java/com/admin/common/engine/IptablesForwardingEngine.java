package com.admin.common.engine;

import com.admin.common.dto.GostDto;
import com.admin.common.utils.WebSocketServer;
import com.admin.entity.User;
import com.admin.entity.UserTunnel;
import com.admin.mapper.NodeMapper;
import com.admin.mapper.UserMapper;
import com.admin.mapper.UserTunnelMapper;
import com.alibaba.fastjson.JSONObject;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class IptablesForwardingEngine implements ForwardingEngine {
    @Resource private EngineRevision revisions;
    @Resource private UserMapper users;
    @Resource private UserTunnelMapper userTunnels;
    @Resource private NodeMapper nodes;
    @Resource @Lazy private EngineTrafficService traffic;
    @Resource private EngineCreditService credits;
    @Resource private EngineCreditPrimer primer;
    @Resource private EngineQuotaModeGuard quotaModes;

    public static boolean ipv4(String value) {
        if (value == null || !value.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) return false;
        for (String p : value.split("\\."))
            if (Integer.parseInt(p) > 255 || (p.length() > 1 && p.startsWith("0"))) return false;
        return true;
    }

    public static void validate(ForwardSpec s) {
        if (s.getTunnelType() != 1)
            throw new IllegalArgumentException("iptables v1 only supports direct port forwarding");
        if (s.getLimiter() != null && s.getLimiter() != 0)
            throw new IllegalArgumentException("iptables v1 does not support bandwidth shaping");
        if (s.getInterfaceName() != null && !s.getInterfaceName().isBlank())
            throw new IllegalArgumentException("iptables v1 does not support interface routing");
        if (s.getStrategy() != null
                && !s.getStrategy().isBlank()
                && !s.getStrategy().equals("fifo"))
            throw new IllegalArgumentException("iptables v1 only supports one target");
        Endpoint target = Endpoint.parse(s.getTarget());
        if (!"ip".equals(target.getKind()) || !"ipv4".equals(target.getFamily()))
            throw new IllegalArgumentException(
                    "node currently supports IPv4 targets; DNS/IPv6 capabilities are disabled");
        String ip = s.getTunnel().getTcpListenAddr();
        if (!ipv4(ip) || !ip.equals(s.getTunnel().getUdpListenAddr()))
            throw new IllegalArgumentException(
                    "iptables v1 requires identical IPv4 TCP/UDP listen addresses");
        if (!"iptables".equals(EngineRegistry.normalize(s.getTunnel().getEngine())))
            throw new IllegalArgumentException("node and tunnel engine mismatch");
    }

    public GostDto apply(Long node, ForwardSpec s, boolean update) {
        try {
            validate(s);
            quotaModes.verify(node, s.getName());
            Endpoint target = Endpoint.parse(s.getTarget());
            com.admin.entity.Node identity = nodes.selectById(node);
            if (identity != null
                    && identity.getVersion() != null
                    && identity.getVersion().startsWith("iptables-v3"))
                EngineCapabilities.negotiate(node);
            if (credits.strict(node)) EngineCapabilities.require(node, "creditLease");
            JSONObject d = new JSONObject();
            d.put("id", s.getName());
            d.put("revision", revisions.next(node, s.getName()));
            d.put("listenIP", s.getTunnel().getTcpListenAddr());
            d.put("listenPort", s.getPort());
            d.put("targetIP", target.getHost());
            d.put("targetPort", target.getPort());
            d.put("enabled", !Boolean.FALSE.equals(s.getEnabled()));
            String[] ids = s.getName().split("_");
            long expires = 0;
            if (ids.length == 3 && !ids[2].equals("0")) {
                User u = users.selectById(ids[1]);
                UserTunnel ut = userTunnels.selectById(ids[2]);
                if (u != null && u.getExpTime() != null) expires = u.getExpTime();
                if (ut != null
                        && ut.getExpTime() != null
                        && (expires == 0 || ut.getExpTime() < expires)) expires = ut.getExpTime();
            }
            d.put("expiresAt", expires);
            if (EngineCapabilities.supports(node, "structuredEndpoint")) {
                d.put("schemaVersion", 2);
                d.put(
                        "listen",
                        Endpoint.parse(s.getTunnel().getTcpListenAddr() + ":" + s.getPort())
                                .json());
                d.put("target", target.json());
                d.put("protocols", java.util.List.of("tcp", "udp"));
            }
            if (ids.length == 3
                    && !ids[2].equals("0")
                    && (EngineCapabilities.supports(node, "creditLease") || credits.strict(node))) {
                EngineCapabilities.require(node, "creditLease");
                credits.enable(node);
                d.put("leaseRequired", true);
            }
            GostDto result = WebSocketServer.send_msg(node, d, "ApplyForward");
            if ("OK".equals(result.getMsg()) && d.getBooleanValue("leaseRequired"))
                primer.afterCommit(node, s.getName());
            return result;
        } catch (Exception e) {
            return error(e.getMessage());
        }
    }

    public GostDto delete(Long node, String name) {
        GostDto result = command(node, name, false, "DeleteForward");
        if ("OK".equals(result.getMsg()) && result.getData() != null) {
            try {
                traffic.ingest(
                        nodes.selectById(node), (JSONObject) JSONObject.toJSON(result.getData()));
            } catch (Exception e) {
                return error("final usage settlement failed: " + e.getMessage());
            }
        }
        return result;
    }

    public GostDto setEnabled(Long node, String name, boolean enabled) {
        return command(node, name, enabled, "SetForwardState");
    }

    private GostDto command(Long node, String name, boolean enabled, String command) {
        try {
            if (enabled) quotaModes.verify(node, name);
            if (enabled && credits.strict(node)) EngineCapabilities.require(node, "creditLease");
            JSONObject d = new JSONObject();
            d.put("id", name);
            d.put("revision", revisions.next(node, name));
            d.put("enabled", enabled);
            GostDto result = WebSocketServer.send_msg(node, d, command);
            if (enabled && "OK".equals(result.getMsg()) && !name.endsWith("_0"))
                primer.afterCommit(node, name);
            return result;
        } catch (Exception e) {
            return error(e.getMessage());
        }
    }

    public static GostDto error(String msg) {
        GostDto r = new GostDto();
        r.setMsg(msg);
        return r;
    }
}
