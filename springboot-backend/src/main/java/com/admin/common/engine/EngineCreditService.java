package com.admin.common.engine;

import com.admin.common.dto.GostDto;
import com.admin.common.utils.WebSocketServer;
import com.admin.entity.Node;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import javax.annotation.Resource;

/**
 * A reservation belongs to a user AND permission; neither scope can lend it to another node before
 * the old node settles it. Expiry without a final checkpoint keeps the reservation, rather than
 * guessing unused bytes.
 */
@Service
public class EngineCreditService {
    @Resource private JdbcTemplate jdbc;
    @Resource private EngineTrafficService traffic;
    @Resource private EngineQuotaEnforcer quotas;

    @Value("${engine.lease.max-bytes:4294967296}")
    private long maxGrant;

    @Value("${engine.lease.duration-millis:30000}")
    private long duration;

    @javax.annotation.PostConstruct
    public void validateConfiguration() {
        if (maxGrant < 128 || maxGrant > (1L << 32) || duration < 1000 || duration > 60000)
            throw new IllegalArgumentException("invalid credit lease configuration");
    }

    private static long n(Map<String, Object> r, String key) {
        return ((Number) r.get(key)).longValue();
    }

    private static String slots(int n) {
        return EngineTrafficService.slots(n);
    }

    public boolean strict(Long node) {
        return !jdbc.queryForList(
                        "SELECT node_id FROM engine_node_policy WHERE node_id=? AND"
                                + " strict_credit=1",
                        node)
                .isEmpty();
    }

    public void enable(Long node) {
        if (strict(node)
                && EngineCapabilities.info(node) != null
                && EngineCapabilities.info(node).getBooleanValue("strictCreditPolicy")) return;
        JSONObject info = EngineCapabilities.info(node);
        if (info == null || !info.getBooleanValue("strictCreditPolicy")) {
            EngineCapabilities.require(node, "creditPolicy");
            GostDto ack = WebSocketServer.send_msg(node, new JSONObject(), "RequireCreditPolicy");
            JSONObject applied =
                    ack.getData() == null ? null : (JSONObject) JSONObject.toJSON(ack.getData());
            if (!"OK".equals(ack.getMsg())
                    || applied == null
                    || !applied.getBooleanValue("strictCreditPolicy"))
                throw new IllegalArgumentException("node did not acknowledge strict credit policy");
            String session = WebSocketServer.nodeSessionId(node);
            if (session == null)
                throw new IllegalArgumentException("node disconnected during credit policy change");
            EngineCapabilities.register(node, session, applied);
        }
        jdbc.update(
                "INSERT INTO engine_node_policy(node_id,strict_credit,updated_at) VALUES(?,1,?) ON"
                        + " DUPLICATE KEY UPDATE strict_credit=1,updated_at=VALUES(updated_at)",
                node,
                System.currentTimeMillis());
    }

    private static String hash(JSONObject report) {
        try {
            return HexFormat.of()
                    .formatHex(
                            MessageDigest.getInstance("SHA-256")
                                    .digest(
                                            JSON.toJSONString(
                                                            report, SerializerFeature.MapSortField)
                                                    .getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String identity() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    @Transactional(isolation = org.springframework.transaction.annotation.Isolation.READ_COMMITTED)
    public JSONObject exchange(Node node, JSONObject report) {
        return exchangeInternal(node, report, false);
    }

    @Transactional(
            propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW,
            isolation = org.springframework.transaction.annotation.Isolation.READ_COMMITTED)
    public JSONObject exchangeNew(Node node, JSONObject report) {
        return exchangeInternal(node, report, false);
    }

    static boolean reservationVersion(Object version) {
        return version != null && version.toString().matches("iptables-v[345](?:[.-].*)?");
    }

    private JSONObject exchangeInternal(Node node, JSONObject report, boolean maintenance) {
        String epoch = report.getString("epoch"), boot = report.getString("bootId");
        long sequence = EngineTrafficService.exact(report.get("sequence"));
        JSONArray usage = report.getJSONArray("usage"),
                requests = report.getJSONArray("requests"),
                claims = report.getJSONArray("leases");
        if (epoch == null
                || !epoch.matches("[a-f0-9]{32}")
                || boot == null
                || !boot.matches("[a-zA-Z0-9-]{1,100}")
                || sequence < 1
                || usage == null
                || usage.size() > 10000)
            throw new IllegalArgumentException("invalid report identity");
        if (requests == null) requests = new JSONArray();
        if (claims == null) claims = new JSONArray();
        if (requests.size() > 10000 || claims.size() > 10000)
            throw new IllegalArgumentException("credit report too large");
        JSONObject advertised = EngineCapabilities.info(node.getId());
        if (!maintenance
                && advertised != null
                && advertised.getString("bootId") != null
                && !boot.equals(advertised.getString("bootId")))
            throw new IllegalArgumentException("report boot does not match active node session");
        jdbc.update(
                "INSERT INTO engine_report_cursor(node_id,epoch,sequence) VALUES(?,?,0) ON"
                        + " DUPLICATE KEY UPDATE sequence=sequence",
                node.getId(),
                epoch);
        long cursor =
                jdbc.queryForObject(
                        "SELECT sequence FROM engine_report_cursor WHERE node_id=? AND epoch=? FOR"
                                + " UPDATE",
                        Long.class,
                        node.getId(),
                        epoch);
        String bodyHash = hash(report);
        List<Map<String, Object>> replay =
                jdbc.queryForList(
                        "SELECT body_hash,response FROM engine_credit_request WHERE node_id=? AND"
                                + " epoch=? AND sequence=?",
                        node.getId(),
                        epoch,
                        sequence);
        if (!replay.isEmpty()) {
            if (!bodyHash.equals(replay.get(0).get("body_hash")))
                throw new IllegalArgumentException("report sequence payload conflict");
            return JSONObject.parseObject(replay.get(0).get("response").toString());
        }
        JSONObject response = new JSONObject();
        response.put("epoch", epoch);
        response.put("sequence", sequence);
        response.put("usage", usage);
        response.put("counters", validatedCounters(report.getJSONArray("counters"), usage));
        response.put("closedLeases", new JSONArray());
        response.put("grants", new JSONArray());
        if (sequence <= cursor) {
            // Report pages are independent cumulative watermarks. A newer
            // page need not contain an older page's services; settle the old
            // page before acknowledging it, but never renew old credit.
            traffic.ingest(node, report);
            return response;
        }
        Set<String> serviceIDs = new TreeSet<>();
        for (Object value : requests) {
            String id = String.valueOf(value);
            validateID(id);
            if (!serviceIDs.add(id)) throw new IllegalArgumentException("duplicate credit request");
        }
        Set<Long> users = new TreeSet<>(), permissions = new TreeSet<>();
        for (Object value : usage) {
            String id = ((JSONObject) JSONObject.toJSON(value)).getString("id");
            validateID(id);
            String[] p = id.split("_");
            users.add(parseID(p[1]));
            if (!p[2].equals("0")) permissions.add(parseID(p[2]));
        }
        for (String id : serviceIDs) {
            String[] p = id.split("_");
            users.add(parseID(p[1]));
            if (!p[2].equals("0")) permissions.add(parseID(p[2]));
        }
        Map<String, Map<String, Object>> claimRows = new HashMap<>();
        Set<String> claimServices = new HashSet<>();
        for (Object value : claims) {
            JSONObject claim = (JSONObject) JSONObject.toJSON(value);
            String id = claim.getString("id");
            if (id == null || !id.matches("[a-f0-9]{32}"))
                throw new IllegalArgumentException("invalid lease identity");
            List<Map<String, Object>> rows =
                    jdbc.queryForList(
                            "SELECT * FROM engine_credit_lease WHERE lease_id=? AND node_id=? AND"
                                    + " epoch=? AND boot_id=?",
                            id,
                            node.getId(),
                            epoch,
                            boot);
            if (rows.isEmpty()) throw new IllegalArgumentException("unknown lease");
            Map<String, Object> r = rows.get(0);
            String service = r.get("service_id").toString();
            if (!service.equals(claim.getString("serviceId"))
                    || !claimServices.add(service)
                    || EngineTrafficService.exact(claim.get("generation")) > n(r, "generation"))
                throw new IllegalArgumentException("lease owner/generation mismatch");
            claimRows.put(id, r);
            users.add(n(r, "user_id"));
            permissions.add(n(r, "user_tunnel_id"));
        }
        Map<Long, Map<String, Object>> ownerRows = lockRows("user", users),
                permissionRows = lockRows("user_tunnel", permissions);
        traffic.ingest(node, report);
        long now = System.currentTimeMillis();
        for (Object value : claims) {
            JSONObject claim = (JSONObject) JSONObject.toJSON(value);
            String id = claim.getString("id");
            Map<String, Object> r = claimRows.get(id);
            String service = r.get("service_id").toString();
            long[] totals = watermark(node.getId(), epoch, service);
            long consumed;
            try {
                consumed =
                        Math.addExact(
                                Math.max(0, totals[0] - n(r, "start_up")),
                                Math.max(0, totals[1] - n(r, "start_down")));
            } catch (ArithmeticException e) {
                throw new IllegalArgumentException("lease usage overflow");
            }
            if (consumed > n(r, "total_raw"))
                throw new IllegalArgumentException("lease usage exceeds reserved credit");
            if (EngineTrafficService.exact(claim.get("used")) != consumed)
                throw new IllegalArgumentException(
                        "lease usage does not match settled cumulative ledger");
            boolean closed = claim.getBooleanValue("closed");
            long reserved =
                    closed
                            ? 0
                            : billCeil(
                                    n(r, "total_raw") - consumed,
                                    new BigDecimal(r.get("ratio").toString()),
                                    (int) n(r, "flow_type"));
            jdbc.update(
                    "UPDATE engine_credit_lease SET"
                        + " consumed_raw=?,reserved_bill=?,closed=?,updated_at=? WHERE lease_id=?",
                    consumed,
                    reserved,
                    closed ? 1 : 0,
                    now,
                    id);
            if (closed) {
                response.getJSONArray("closedLeases").add(id);
                String[] owner = service.split("_");
                quotas.afterCommit(owner[1], owner[2], service);
            }
        }
        response.put("leaseWatermarks", claims);
        // A reboot cannot prove how much of an uncheckpointed old grant was
        // spent. Keep its reservation until explicit reconciliation.
        jdbc.update(
                "UPDATE engine_credit_lease SET lost=1 WHERE node_id=? AND epoch=? AND boot_id<>?"
                        + " AND closed=0",
                node.getId(),
                epoch,
                boot);
        if (!serviceIDs.isEmpty()) {
            EngineCapabilities.require(node.getId(), "creditLease");
            enable(node.getId());
            Map<Long, Integer> requestsPerOwner = new HashMap<>();
            for (String id : serviceIDs)
                requestsPerOwner.merge(parseID(id.split("_")[1]), 1, Integer::sum);
            for (String service : serviceIDs) {
                String[] p = service.split("_");
                long uid = parseID(p[1]), pid = parseID(p[2]);
                Map<String, Object> owner = ownerRows.get(uid),
                        permission = permissionRows.get(pid);
                List<Map<String, Object>> rows =
                        jdbc.queryForList(
                                "SELECT"
                                    + " f.status,f.user_id,f.tunnel_id,t.in_node_id,t.engine,t.traffic_ratio,t.flow"
                                    + " FROM forward f JOIN tunnel t ON t.id=f.tunnel_id WHERE"
                                    + " f.id=?",
                                parseID(p[0]));
                if (rows.isEmpty() || owner == null || permission == null) continue;
                Map<String, Object> f = rows.get(0);
                if (n(f, "user_id") != uid
                        || n(f, "in_node_id") != node.getId()
                        || !"iptables".equals(f.get("engine"))
                        || n(permission, "user_id") != uid
                        || n(permission, "tunnel_id") != n(f, "tunnel_id")
                        || n(owner, "role_id") == 0) continue;
                // Read current quota values after ingestion (locked copies may
                // predate this report's billing).
                owner = jdbc.queryForMap("SELECT * FROM user WHERE id=?", uid);
                permission = jdbc.queryForMap("SELECT * FROM user_tunnel WHERE id=?", pid);
                long expires = Math.min(expiry(owner), expiry(permission));
                if (n(f, "status") != 1
                        || n(owner, "status") != 1
                        || n(permission, "status") != 1
                        || expires <= now) {
                    quotas.afterCommit(p[1], p[2], service);
                    continue;
                }
                long limit = quotaBytes(owner), permissionLimit = quotaBytes(permission);
                if (n(owner, "in_flow") + n(owner, "out_flow") >= limit
                        || n(permission, "in_flow") + n(permission, "out_flow")
                                >= permissionLimit) {
                    quotas.afterCommit(p[1], p[2], service);
                    continue;
                }
                // Strong shared bounds require all active peers of this user
                // to support reservations; legacy peers keep their own mode.
                List<Map<String, Object>> peers =
                        jdbc.queryForList(
                                "SELECT DISTINCT"
                                    + " t.in_node_id,n.engine,n.version,COALESCE(p.strict_credit,0)"
                                    + " strict_credit FROM forward f JOIN tunnel t ON"
                                    + " t.id=f.tunnel_id JOIN node n ON n.id=t.in_node_id LEFT JOIN"
                                    + " engine_node_policy p ON p.node_id=n.id WHERE f.user_id=?"
                                    + " AND f.status=1",
                                uid);
                boolean mixed =
                        peers.stream()
                                .anyMatch(
                                        peer ->
                                                !"iptables".equals(peer.get("engine"))
                                                        || !reservationVersion(peer.get("version"))
                                                        || n(peer, "strict_credit") != 1);
                if (mixed) continue;
                List<Map<String, Object>> active =
                        jdbc.queryForList(
                                "SELECT * FROM engine_credit_lease WHERE node_id=? AND epoch=? AND"
                                    + " boot_id=? AND service_id=? AND closed=0 AND lost=0 ORDER BY"
                                    + " updated_at DESC FOR UPDATE",
                                node.getId(),
                                epoch,
                                boot,
                                service);
                Map<String, Object> old = active.isEmpty() ? null : active.get(0);
                BigDecimal ratio = new BigDecimal(f.get("traffic_ratio").toString());
                int flow = (int) n(f, "flow");
                if (old != null
                        && (!claimServices.contains(service)
                                || claims.stream()
                                        .map(v -> (JSONObject) JSONObject.toJSON(v))
                                        .anyMatch(
                                                c ->
                                                        service.equals(c.getString("serviceId"))
                                                                && c.getLongValue("generation")
                                                                        < n(old, "generation")))) {
                    JSONObject resend = new JSONObject();
                    resend.put("id", old.get("lease_id"));
                    resend.put("serviceId", service);
                    resend.put("epoch", epoch);
                    resend.put("bootId", boot);
                    resend.put("generation", n(old, "generation"));
                    resend.put("totalGranted", n(old, "total_raw"));
                    resend.put("windowBytes", Math.min(maxGrant, n(old, "total_raw")));
                    resend.put("requestSequence", sequence);
                    resend.put(
                            "validForMillis",
                            Math.max(1, Math.min(60000, n(old, "expires_at") - now)));
                    response.getJSONArray("grants").add(resend);
                    continue;
                }
                if (old != null
                        && (new BigDecimal(old.get("ratio").toString()).compareTo(ratio) != 0
                                || n(old, "flow_type") != flow))
                    continue; // old price expires, then new price applies.
                long outstandingUser =
                        jdbc.queryForObject(
                                "SELECT COALESCE(SUM(reserved_bill),0) FROM engine_credit_lease"
                                        + " WHERE user_id=? AND closed=0",
                                Long.class,
                                uid);
                long outstandingPermission =
                        jdbc.queryForObject(
                                "SELECT COALESCE(SUM(reserved_bill),0) FROM engine_credit_lease"
                                        + " WHERE user_tunnel_id=? AND closed=0",
                                Long.class,
                                pid);
                long available =
                        Math.max(
                                0,
                                Math.min(
                                        limit
                                                - n(owner, "in_flow")
                                                - n(owner, "out_flow")
                                                - outstandingUser,
                                        permissionLimit
                                                - n(permission, "in_flow")
                                                - n(permission, "out_flow")
                                                - outstandingPermission));
                long remaining = old == null ? 0 : n(old, "total_raw") - n(old, "consumed_raw");
                if (old != null
                        && remaining >= Math.max(1, maxGrant * 3 / 4)
                        && n(old, "expires_at") - now > duration / 2) continue;
                long extra =
                        rawCredit(
                                available / Math.max(1, requestsPerOwner.get(uid)),
                                ratio,
                                flow,
                                Math.max(0, Math.min(maxGrant - remaining, 1L << 32)));
                if (old != null && remaining >= Math.max(1, maxGrant * 3 / 4)) extra = 0;
                if (old == null && extra < 128) continue;
                long total = old == null ? extra : Math.addExact(n(old, "total_raw"), extra);
                long generation = old == null ? 1 : n(old, "generation") + 1;
                String lease = old == null ? identity() : old.get("lease_id").toString();
                long deadline = Math.min(expires, now + Math.min(60000, Math.max(1000, duration)));
                if (deadline - now < 1000) continue;
                if (old == null) {
                    long[] start = watermark(node.getId(), epoch, service);
                    jdbc.update(
                            "INSERT INTO"
                                + " engine_credit_lease(lease_id,node_id,epoch,boot_id,service_id,user_id,user_tunnel_id,generation,total_raw,consumed_raw,reserved_bill,start_up,start_down,ratio,flow_type,closed,lost,expires_at,updated_at)"
                                + " VALUES(?,?,?,?,?,?,?,?,?,0,?,?,?,?,?,0,0,?,?)",
                            lease,
                            node.getId(),
                            epoch,
                            boot,
                            service,
                            uid,
                            pid,
                            generation,
                            total,
                            billCeil(total, ratio, flow),
                            start[0],
                            start[1],
                            ratio,
                            flow,
                            deadline,
                            now);
                } else {
                    jdbc.update(
                            "UPDATE engine_credit_lease SET"
                                + " generation=?,total_raw=?,reserved_bill=?,expires_at=?,updated_at=?"
                                + " WHERE lease_id=?",
                            generation,
                            total,
                            billCeil(total - n(old, "consumed_raw"), ratio, flow),
                            deadline,
                            now,
                            lease);
                }
                JSONObject grant = new JSONObject();
                grant.put("id", lease);
                grant.put("serviceId", service);
                grant.put("epoch", epoch);
                grant.put("bootId", boot);
                grant.put("generation", generation);
                grant.put("totalGranted", total);
                grant.put("windowBytes", Math.min(total, maxGrant));
                grant.put("requestSequence", sequence);
                grant.put("validForMillis", deadline - now);
                response.getJSONArray("grants").add(grant);
            }
        }
        jdbc.update(
                "UPDATE engine_report_cursor SET sequence=? WHERE node_id=? AND epoch=?",
                sequence,
                node.getId(),
                epoch);
        jdbc.update(
                "INSERT INTO"
                    + " engine_credit_request(node_id,epoch,sequence,body_hash,response,created_at)"
                    + " VALUES(?,?,?,?,?,?)",
                node.getId(),
                epoch,
                sequence,
                bodyHash,
                response.toJSONString(),
                now);
        jdbc.update(
                "DELETE FROM engine_credit_request WHERE node_id=? AND epoch=? AND sequence<?",
                node.getId(),
                epoch,
                Math.max(0, sequence - 64));
        return response;
    }

    @Transactional(isolation = org.springframework.transaction.annotation.Isolation.READ_COMMITTED)
    public JSONObject maintenance(Node node, JSONObject report) {
        if (report.getJSONArray("requests") != null && !report.getJSONArray("requests").isEmpty())
            throw new IllegalArgumentException("maintenance cannot allocate credit");
        JSONArray claims = report.getJSONArray("leases");
        if (claims != null)
            for (int i = 0; i < claims.size(); i++)
                if (!claims.getJSONObject(i).getBooleanValue("closed"))
                    throw new IllegalArgumentException(
                            "maintenance requires final closed lease snapshots");
        JSONObject ack = exchangeInternal(node, report, true);
        jdbc.update(
                "UPDATE forward f JOIN tunnel t ON t.id=f.tunnel_id SET f.status=0 WHERE"
                        + " t.in_node_id=? AND t.engine='iptables'",
                node.getId());
        ack.put("maintenanceAccepted", true);
        return ack;
    }

    private Map<Long, Map<String, Object>> lockRows(String table, Set<Long> ids) {
        Map<Long, Map<String, Object>> out = new HashMap<>();
        if (ids.isEmpty()) return out;
        for (var r :
                jdbc.queryForList(
                        "SELECT * FROM "
                                + table
                                + " WHERE id IN ("
                                + slots(ids.size())
                                + ") ORDER BY id FOR UPDATE",
                        ids.toArray())) out.put(n(r, "id"), r);
        return out;
    }

    private long[] watermark(Long node, String epoch, String service) {
        var rows =
                jdbc.queryForList(
                        "SELECT up_bytes,down_bytes FROM engine_usage WHERE node_id=? AND epoch=?"
                                + " AND service_id=?",
                        node,
                        epoch,
                        service);
        return rows.isEmpty()
                ? new long[2]
                : new long[] {n(rows.get(0), "up_bytes"), n(rows.get(0), "down_bytes")};
    }

    private static long expiry(Map<String, Object> r) {
        return r.get("exp_time") == null ? Long.MAX_VALUE : n(r, "exp_time");
    }

    private static long quotaBytes(Map<String, Object> r) {
        try {
            return Math.multiplyExact(n(r, "flow"), 1073741824L);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("quota overflow");
        }
    }

    private static long parseID(String id) {
        try {
            return Long.parseLong(id);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid service ID");
        }
    }

    private static void validateID(String id) {
        if (id == null || id.length() > 100 || !id.matches("[0-9]+_[0-9]+_[0-9]+"))
            throw new IllegalArgumentException("invalid service ID");
    }

    static long billCeil(long raw, BigDecimal ratio, int flow) {
        if (ratio.signum() < 0 || flow < 1 || flow > 2)
            throw new IllegalArgumentException("invalid billing policy");
        try {
            return Math.multiplyExact(
                    new BigDecimal(raw)
                            .multiply(ratio)
                            .setScale(0, RoundingMode.CEILING)
                            .longValueExact(),
                    flow);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("credit overflow");
        }
    }

    static long rawCredit(long available, BigDecimal ratio, int flow, long cap) {
        if (available < 0 || ratio.signum() < 0 || flow < 1 || flow > 2 || cap < 0)
            throw new IllegalArgumentException("invalid credit bounds");
        if (ratio.signum() == 0) return cap;
        return BigDecimal.valueOf(available / flow)
                .divide(ratio, 0, RoundingMode.DOWN)
                .min(BigDecimal.valueOf(cap))
                .longValueExact();
    }

    static JSONArray validatedCounters(JSONArray counters, JSONArray usage) {
        JSONArray out = new JSONArray();
        if (counters == null) return out;
        if (counters.size() > 20000)
            throw new IllegalArgumentException("too many counter watermarks");
        Map<String, JSONObject> totals = new HashMap<>();
        for (Object v : usage) {
            JSONObject u = (JSONObject) JSONObject.toJSON(v);
            totals.put(u.getString("id"), u);
        }
        for (Object v : counters) {
            JSONObject c = (JSONObject) JSONObject.toJSON(v);
            String id = c.getString("id"), set = c.getString("set");
            validateID(id);
            if (set==null || !Set.of("FPV2_UP","FPV2_DOWN","FP4_UP","FP4_DOWN","FP6_UP","FP6_DOWN").contains(set)
                    || c.getString("key") == null
                    || c.getString("key").length() > 100)
                throw new IllegalArgumentException("invalid counter watermark");
            long bytes = EngineTrafficService.exact(c.get("bytes"));
            JSONObject u = totals.get(id);
            if (u == null
                    || bytes
                            > EngineTrafficService.exact(
                                    u.get(set.endsWith("_UP") ? "up" : "down")))
                throw new IllegalArgumentException("counter watermark exceeds cumulative usage");
            out.add(c);
        }
        return out;
    }
}
