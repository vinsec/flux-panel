package com.admin.common.engine;

import com.admin.common.dto.GostDto;
import com.admin.common.utils.WebSocketServer;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.Resource;

/** One paginated snapshot + one bounded delta job, not one apply per forward. */
@Service
public class EngineBatchReconciler {
    @Resource private JdbcTemplate jdbc;
    @Resource private EngineRevision revisions;
    @Resource private EngineCreditService credits;
    private final ConcurrentHashMap<Long, JSONObject> pending = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long, Object> locks = new ConcurrentHashMap<>();

    private static long n(Map<String, Object> r, String key) {
        return ((Number) r.get(key)).longValue();
    }

    private static long expiry(Map<String, Object> r, String key) {
        return r.get(key) == null ? Long.MAX_VALUE : n(r, key);
    }

    private static JSONObject rpc(Long node, String method, Object data) {
        GostDto result = WebSocketServer.send_msg(node, data, method);
        if (!"OK".equals(result.getMsg()) || result.getData() == null)
            throw new IllegalStateException(method + ": " + result.getMsg());
        return (JSONObject) JSONObject.toJSON(result.getData());
    }

    public JSONObject reconcile(Long node) {
        synchronized (locks.computeIfAbsent(node, x -> new Object())) {
            EngineCapabilities.require(node, "batch");
            JSONObject existing = pending.get(node);
            if (existing != null) {
                JSONObject query = new JSONObject();
                query.put("id", existing.getString("id"));
                JSONObject status = rpc(node, "GetBatchStatus", query);
                String state = status.getString("status");
                if ("running".equals(state) || "queued".equals(state)) return status;
                if ("unknown".equals(state)) return rpc(node, "SubmitBatch", existing);
                pending.remove(node);
                if ("failed".equals(state))
                    throw new IllegalStateException("batch failed: " + status.getString("error"));
            }
            if (EngineCapabilities.supports(node, "creditPolicy")
                    && jdbc.queryForObject(
                                    "SELECT COUNT(*) FROM forward f JOIN tunnel t ON"
                                        + " t.id=f.tunnel_id JOIN user u ON u.id=f.user_id WHERE"
                                        + " t.in_node_id=? AND t.engine='iptables' AND"
                                        + " u.role_id<>0",
                                    Integer.class,
                                    node)
                            > 0) credits.enable(node);
            Map<String, JSONObject> actual = new TreeMap<>();
            String after = "";
            Long generation = null;
            do {
                JSONObject page = new JSONObject();
                page.put("after", after);
                page.put("limit", 500);
                if (generation != null) page.put("generation", generation);
                JSONObject snapshot = rpc(node, "GetEngineStatePage", page);
                generation = snapshot.getLong("generation");
                JSONArray items = snapshot.getJSONArray("items");
                if (items == null) throw new IllegalStateException("invalid snapshot page");
                for (Object value : items) {
                    JSONObject s = (JSONObject) JSONObject.toJSON(value);
                    actual.put(s.getString("id"), s);
                }
                after = snapshot.getString("next");
                if (actual.size() > 200000)
                    throw new IllegalStateException("snapshot exceeds configured safety bound");
            } while (after != null && !after.isEmpty());
            Map<String, JSONObject> desired = new TreeMap<>();
            List<Object[]> expiredStates = new ArrayList<>();
            long now = System.currentTimeMillis();
            boolean lease =
                    EngineCapabilities.supports(node, "creditLease") || credits.strict(node);
            List<Map<String, Object>> rows =
                    jdbc.queryForList(
                            "SELECT"
                                + " f.id,f.user_id,f.in_port,f.remote_addr,f.status,f.strategy,f.interface_name,t.type,t.tcp_listen_addr,t.udp_listen_addr,u.role_id,u.status"
                                + " user_status,u.exp_time user_exp,ut.id"
                                + " permission_id,ut.speed_id,ut.status"
                                + " permission_status,ut.exp_time permission_exp FROM forward f"
                                + " JOIN tunnel t ON t.id=f.tunnel_id JOIN user u ON u.id=f.user_id"
                                + " LEFT JOIN user_tunnel ut ON ut.user_id=f.user_id AND"
                                + " ut.tunnel_id=f.tunnel_id WHERE t.in_node_id=? AND"
                                + " t.engine='iptables' ORDER BY f.id",
                            node);
            for (var r : rows) {
                boolean admin = n(r, "role_id") == 0;
                if (!admin && r.get("permission_id") == null) continue;
                String id =
                        n(r, "id")
                                + "_"
                                + n(r, "user_id")
                                + "_"
                                + (admin ? 0 : n(r, "permission_id"));
                if (desired.containsKey(id)) continue;
                if (n(r, "type") != 1
                        || r.get("interface_name") != null
                                && !r.get("interface_name").toString().isBlank()
                        || !"fifo".equals(r.get("strategy"))
                        || !admin && r.get("speed_id") != null && n(r, "speed_id") != 0)
                    throw new IllegalArgumentException("unsupported desired capability in " + id);
                Endpoint target = Endpoint.parse(r.get("remote_addr").toString());
                if (!"ip".equals(target.getKind()) || !"ipv4".equals(target.getFamily()))
                    throw new IllegalArgumentException("DNS/IPv6 is not enabled");
                String listen = r.get("tcp_listen_addr").toString();
                if (!IptablesForwardingEngine.ipv4(listen)
                        || !listen.equals(r.get("udp_listen_addr")))
                    throw new IllegalArgumentException("invalid shared IPv4 listener");
                long expires =
                        admin ? 0 : Math.min(expiry(r, "user_exp"), expiry(r, "permission_exp"));
                boolean enabled =
                        n(r, "status") == 1
                                && n(r, "user_status") == 1
                                && (admin || n(r, "permission_status") == 1 && expires > now);
                if (!enabled && n(r, "status") == 1) expiredStates.add(new Object[] {n(r, "id")});
                JSONObject s = new JSONObject();
                s.put("id", id);
                s.put("listenIP", listen);
                s.put("listenPort", n(r, "in_port"));
                s.put("targetIP", target.getHost());
                s.put("targetPort", target.getPort());
                s.put("expiresAt", expires);
                s.put("enabled", enabled);
                if (!admin && lease) {
                    EngineCapabilities.require(node, "creditLease");
                    credits.enable(node);
                    s.put("leaseRequired", true);
                }
                desired.put(id, s);
            }
            if (!expiredStates.isEmpty())
                jdbc.batchUpdate(
                        "UPDATE forward SET status=0 WHERE id=? AND status=1", expiredStates);
            if (desired.size() > 10000)
                throw new IllegalArgumentException(
                        "node exceeds the validated 10,000-forward capacity");
            List<JSONObject> delta = new ArrayList<>();
            for (var e : actual.entrySet())
                if (!desired.containsKey(e.getKey()) && !e.getValue().getBooleanValue("deleted")) {
                    JSONObject s = new JSONObject();
                    s.put("id", e.getKey());
                    s.put("deleted", true);
                    delta.add(s);
                }
            for (var e : desired.entrySet())
                if (changed(e.getValue(), actual.get(e.getKey()))) delta.add(e.getValue());
            if (delta.isEmpty()) {
                JSONObject status = new JSONObject();
                status.put("status", "converged");
                status.put("generation", generation);
                return status;
            }
            if (delta.size() > 10000) delta = new ArrayList<>(delta.subList(0, 10000));
            List<String> ids = new ArrayList<>();
            for (JSONObject s : delta) {
                String id = s.getString("id");
                if (!id.matches("[0-9]+_[0-9]+_[0-9]+"))
                    throw new IllegalArgumentException("invalid snapshot service");
                ids.add(id);
            }
            Map<String, Long> versions = revisions.nextBatch(node, ids);
            for (JSONObject s : delta) s.put("revision", versions.get(s.getString("id")));
            JSONObject batch = new JSONObject();
            batch.put("id", UUID.randomUUID().toString());
            batch.put("baseGeneration", generation);
            batch.put("specs", delta);
            pending.put(node, batch);
            return rpc(node, "SubmitBatch", batch);
        }
    }

    private static boolean changed(JSONObject desired, JSONObject actual) {
        if (actual == null || actual.getBooleanValue("deleted")) return true;
        for (String key : List.of("listenIP", "targetIP"))
            if (!Objects.equals(desired.getString(key), actual.getString(key))) return true;
        for (String key : List.of("listenPort", "targetPort", "expiresAt"))
            if (desired.getLongValue(key) != actual.getLongValue(key)) return true;
        return desired.getBooleanValue("enabled") != actual.getBooleanValue("enabled")
                || desired.getBooleanValue("leaseRequired")
                        != actual.getBooleanValue("leaseRequired");
    }
}
