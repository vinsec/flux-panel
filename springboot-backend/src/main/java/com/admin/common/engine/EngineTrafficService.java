package com.admin.common.engine;

import com.admin.entity.Node;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.*;

import javax.annotation.Resource;

@Service
public class EngineTrafficService {
    @Resource private JdbcTemplate jdbc;
    @Resource private EngineQuotaEnforcer quotas;

    public record Price(BigDecimal ratio, int flowType) {}

    public static long exact(Object value) {
        try {
            long n = new BigDecimal(String.valueOf(value)).longValueExact();
            if (n < 0) throw new IllegalArgumentException("negative usage");
            return n;
        } catch (ArithmeticException | NumberFormatException e) {
            throw new IllegalArgumentException("invalid usage integer");
        }
    }

    static long number(Map<String, Object> row, String key) {
        return ((Number) row.get(key)).longValue();
    }

    static String slots(int n) {
        return String.join(",", Collections.nCopies(n, "?"));
    }

    @Transactional
    public void ingest(Node node, JSONObject report) {
        ingestWithPrices(node, report, frozenPrices(node, report));
    }

    public Map<String, Price> frozenPrices(Node node, JSONObject report) {
        Map<String, Price> prices = new HashMap<>();
        JSONArray leases = report.getJSONArray("leases");
        if (leases == null || leases.isEmpty()) return prices;
        if (leases.size() > 10000) throw new IllegalArgumentException("too many leases");
        for (int offset = 0; offset < leases.size(); offset += 500) {
            List<String> ids = new ArrayList<>();
            for (int i = offset; i < Math.min(offset + 500, leases.size()); i++) {
                String id = leases.getJSONObject(i).getString("id");
                if (id == null || !id.matches("[a-f0-9]{32}"))
                    throw new IllegalArgumentException("invalid lease ID");
                ids.add(id);
            }
            List<Object> args = new ArrayList<>(ids);
            args.add(node.getId());
            args.add(report.getString("epoch"));
            args.add(report.getString("bootId"));
            for (Map<String, Object> r :
                    jdbc.queryForList(
                            "SELECT service_id,ratio,flow_type FROM engine_credit_lease WHERE"
                                    + " lease_id IN ("
                                    + slots(ids.size())
                                    + ") AND node_id=? AND epoch=? AND boot_id=?",
                            args.toArray()))
                prices.put(
                        r.get("service_id").toString(),
                        new Price(
                                new BigDecimal(r.get("ratio").toString()),
                                ((Number) r.get("flow_type")).intValue()));
        }
        return prices;
    }

    public void ingestWithPrices(Node node, JSONObject report, Map<String, Price> prices) {
        String epoch = report.getString("epoch");
        long seq = report.getLongValue("sequence");
        JSONArray usage = report.getJSONArray("usage");
        if (epoch == null
                || !epoch.matches("[a-f0-9]{32}")
                || seq < 1
                || usage == null
                || usage.size() > 10000) throw new IllegalArgumentException("invalid usage report");
        Map<String, JSONObject> input = new TreeMap<>();
        Set<Long> forwardIDs = new TreeSet<>();
        for (int i = 0; i < usage.size(); i++) {
            JSONObject u = usage.getJSONObject(i);
            String name = u.getString("id");
            if (name == null
                    || !name.matches("[0-9]+_[0-9]+_[0-9]+")
                    || name.length() > 100
                    || input.put(name, u) != null)
                throw new IllegalArgumentException("invalid or duplicate service ID");
            exact(u.get("up"));
            exact(u.get("down"));
            try {
                forwardIDs.add(Long.parseLong(name.split("_")[0]));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid service ID");
            }
        }
        List<String> zero = new ArrayList<>();
        for (var e : input.entrySet())
            if (exact(e.getValue().get("up")) == 0 && exact(e.getValue().get("down")) == 0)
                zero.add(e.getKey());
        if (!zero.isEmpty()) {
            List<Object> zeroArgs = new ArrayList<>();
            zeroArgs.add(node.getId());
            zeroArgs.add(epoch);
            zeroArgs.addAll(zero);
            for (var old :
                    jdbc.queryForList(
                            "SELECT service_id,sequence FROM engine_usage WHERE node_id=? AND"
                                + " epoch=? AND service_id IN ("
                                    + slots(zero.size())
                                    + ") AND (up_bytes>0 OR down_bytes>0)",
                            zeroArgs.toArray()))
                if (seq > number(old, "sequence"))
                    throw new IllegalArgumentException("cumulative counters regressed");
            for (String id : zero) input.remove(id);
            forwardIDs.clear();
            for (String id : input.keySet()) forwardIDs.add(Long.parseLong(id.split("_")[0]));
        }
        // A zero cumulative record has no money to transfer. Acknowledge it
        // without creating/updating four ledger rows for an idle forwarding.
        if (input.isEmpty()) return;
        Map<Long, List<Map<String, Object>>> metadata = new HashMap<>();
        List<Object> args = new ArrayList<>(forwardIDs);
        for (var r :
                jdbc.queryForList(
                        "SELECT"
                            + " f.id,f.user_id,f.tunnel_id,t.in_node_id,t.engine,t.traffic_ratio,t.flow,u.role_id,ut.id"
                            + " permission_id FROM forward f JOIN tunnel t ON t.id=f.tunnel_id JOIN"
                            + " user u ON u.id=f.user_id LEFT JOIN user_tunnel ut ON"
                            + " ut.user_id=f.user_id AND ut.tunnel_id=f.tunnel_id WHERE f.id IN ("
                                + slots(args.size())
                                + ")",
                        args.toArray()))
            metadata.computeIfAbsent(number(r, "id"), x -> new ArrayList<>()).add(r);
        Map<String, Map<String, Object>> valid = new TreeMap<>();
        Set<Long> owners = new TreeSet<>();
        for (String id : input.keySet()) {
            String[] parts = id.split("_");
            for (var r : metadata.getOrDefault(Long.parseLong(parts[0]), List.of())) {
                if (number(r, "in_node_id") != node.getId()
                        || !"iptables".equals(r.get("engine"))
                        || !parts[1].equals(r.get("user_id").toString())) continue;
                boolean admin = number(r, "role_id") == 0;
                if (admin
                        ? !parts[2].equals("0")
                        : r.get("permission_id") == null
                                || !parts[2].equals(r.get("permission_id").toString())) continue;
                valid.put(id, r);
                owners.add(number(r, "user_id"));
                break;
            }
        }
        // A stale/deleted owner is acknowledged but never credited to another user.
        if (valid.isEmpty()) return;
        if (!owners.isEmpty())
            jdbc.queryForList(
                    "SELECT id FROM user WHERE id IN ("
                            + slots(owners.size())
                            + ") ORDER BY id FOR UPDATE",
                    owners.toArray());
        List<Object[]> inserts = new ArrayList<>();
        for (String id : valid.keySet()) inserts.add(new Object[] {node.getId(), epoch, id});
        jdbc.batchUpdate(
                "INSERT IGNORE INTO"
                        + " engine_usage(node_id,epoch,service_id,sequence,up_bytes,down_bytes)"
                        + " VALUES(?,?,?,0,0,0)",
                inserts);
        List<Object> keys = new ArrayList<>();
        keys.add(node.getId());
        keys.add(epoch);
        keys.addAll(valid.keySet());
        Map<String, Map<String, Object>> previous = new HashMap<>();
        for (var r :
                jdbc.queryForList(
                        "SELECT service_id,sequence,up_bytes,down_bytes FROM engine_usage WHERE"
                                + " node_id=? AND epoch=? AND service_id IN ("
                                + slots(valid.size())
                                + ") ORDER BY service_id FOR UPDATE",
                        keys.toArray())) previous.put(r.get("service_id").toString(), r);
        List<Object[]> watermarks = new ArrayList<>();
        Map<Long, long[]> forwardDelta = new TreeMap<>(),
                userDelta = new TreeMap<>(),
                permissionDelta = new TreeMap<>();
        for (var entry : valid.entrySet()) {
            String id = entry.getKey();
            Map<String, Object> meta = entry.getValue(), old = previous.get(id);
            if (seq <= number(old, "sequence")) continue;
            JSONObject u = input.get(id);
            long up = exact(u.get("up")),
                    down = exact(u.get("down")),
                    oldUp = number(old, "up_bytes"),
                    oldDown = number(old, "down_bytes");
            if (up < oldUp || down < oldDown)
                throw new IllegalArgumentException("cumulative counters regressed");
            Price price =
                    prices.getOrDefault(
                            id,
                            new Price(
                                    new BigDecimal(meta.get("traffic_ratio").toString()),
                                    ((Number) meta.get("flow")).intValue()));
            long billedUp = bill(up - oldUp, price), billedDown = bill(down - oldDown, price);
            watermarks.add(new Object[] {seq, up, down, node.getId(), epoch, id});
            add(forwardDelta, number(meta, "id"), billedUp, billedDown);
            add(userDelta, number(meta, "user_id"), billedUp, billedDown);
            if (!id.endsWith("_0")) {
                add(permissionDelta, number(meta, "permission_id"), billedUp, billedDown);
                String[] p = id.split("_");
                quotas.afterCommit(p[1], p[2], id);
            }
        }
        jdbc.batchUpdate(
                "UPDATE engine_usage SET sequence=?,up_bytes=?,down_bytes=? WHERE node_id=? AND"
                        + " epoch=? AND service_id=?",
                watermarks);
        update("forward", forwardDelta);
        update("user", userDelta);
        update("user_tunnel", permissionDelta);
    }

    private static long bill(long raw, Price price) {
        try {
            if (price.ratio().signum() < 0 || price.flowType() < 1 || price.flowType() > 2)
                throw new IllegalArgumentException("invalid billing policy");
            return Math.multiplyExact(
                    new BigDecimal(raw)
                            .multiply(price.ratio())
                            .setScale(0, java.math.RoundingMode.DOWN)
                            .longValueExact(),
                    price.flowType());
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("usage overflow");
        }
    }

    private static void add(Map<Long, long[]> values, long id, long up, long down) {
        long[] sum = values.computeIfAbsent(id, x -> new long[2]);
        try {
            sum[0] = Math.addExact(sum[0], up);
            sum[1] = Math.addExact(sum[1], down);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("usage overflow");
        }
    }

    private void update(String table, Map<Long, long[]> delta) {
        List<Object[]> rows = new ArrayList<>();
        for (var e : delta.entrySet())
            rows.add(new Object[] {e.getValue()[0], e.getValue()[1], e.getKey()});
        jdbc.batchUpdate(
                "UPDATE " + table + " SET in_flow=in_flow+?,out_flow=out_flow+? WHERE id=?", rows);
    }
}
