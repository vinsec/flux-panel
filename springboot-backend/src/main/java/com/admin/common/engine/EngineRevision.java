package com.admin.common.engine;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;

@Service
public class EngineRevision {
    @Resource private JdbcTemplate jdbc;

    @Transactional
    public long next(Long node, String name) {
        jdbc.update(
                "INSERT IGNORE INTO engine_revision(node_id,service_id,revision) VALUES(?,?,0)",
                node,
                name);
        Long v =
                jdbc.queryForObject(
                        "SELECT revision FROM engine_revision WHERE node_id=? AND service_id=? FOR"
                            + " UPDATE",
                        Long.class,
                        node,
                        name);
        jdbc.update(
                "UPDATE engine_revision SET revision=? WHERE node_id=? AND service_id=?",
                v + 1,
                node,
                name);
        return v + 1;
    }

    @Transactional
    public java.util.Map<String, Long> nextBatch(Long node, java.util.Collection<String> names) {
        java.util.List<String> sorted = new java.util.ArrayList<>(new java.util.TreeSet<>(names));
        java.util.Map<String, Long> result = new java.util.HashMap<>();
        if (sorted.isEmpty()) return result;
        for (int offset = 0; offset < sorted.size(); offset += 500) {
            java.util.List<String> part =
                    sorted.subList(offset, Math.min(offset + 500, sorted.size()));
            String values = String.join(",", java.util.Collections.nCopies(part.size(), "(?,?,0)"));
            java.util.List<Object> args = new java.util.ArrayList<>();
            for (String id : part) {
                args.add(node);
                args.add(id);
            }
            jdbc.update(
                    "INSERT IGNORE INTO engine_revision(node_id,service_id,revision) VALUES"
                            + values,
                    args.toArray());
        }
        java.util.List<Object> args = new java.util.ArrayList<>();
        args.add(node);
        args.addAll(sorted);
        String where =
                "node_id=? AND service_id IN ("
                        + String.join(",", java.util.Collections.nCopies(sorted.size(), "?"))
                        + ")";
        for (var row :
                jdbc.queryForList(
                        "SELECT service_id,revision FROM engine_revision WHERE "
                                + where
                                + " ORDER BY service_id FOR UPDATE",
                        args.toArray()))
            result.put(
                    row.get("service_id").toString(),
                    ((Number) row.get("revision")).longValue() + 1);
        jdbc.update(
                "UPDATE engine_revision SET revision=revision+1 WHERE " + where, args.toArray());
        return result;
    }
}
