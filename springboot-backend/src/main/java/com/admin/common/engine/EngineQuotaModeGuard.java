package com.admin.common.engine;

import com.admin.entity.Node;
import com.admin.mapper.NodeMapper;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

/** Never silently mix a bounded reservation with an unbounded legacy peer. */
@Service
public class EngineQuotaModeGuard {
    @Resource private JdbcTemplate jdbc;
    @Resource private NodeMapper nodes;

    public void verify(Long node, String service) {
        if (service == null || !service.matches("[0-9]+_[0-9]+_[0-9]+"))
            throw new IllegalArgumentException("invalid forwarding identity");
        String[] ids = service.split("_");
        if (ids[2].equals("0")) return;
        long user = Long.parseLong(ids[1]), forward = Long.parseLong(ids[0]);
        Node target = nodes.selectById(node);
        if (target == null) throw new IllegalArgumentException("node not found");
        boolean incoming =
                "iptables".equals(target.getEngine())
                        && (EngineCapabilities.supports(node, "creditPolicy")
                                || !jdbc.queryForList(
                                                "SELECT node_id FROM engine_node_policy WHERE"
                                                        + " node_id=? AND strict_credit=1",
                                                node)
                                        .isEmpty());
        var peers =
                jdbc.queryForList(
                        "SELECT t.in_node_id,n.engine,n.version,COALESCE(p.strict_credit,0)"
                            + " strict_credit FROM forward f JOIN tunnel t ON t.id=f.tunnel_id JOIN"
                            + " node n ON n.id=t.in_node_id LEFT JOIN engine_node_policy p ON"
                            + " p.node_id=n.id WHERE f.user_id=? AND f.status=1 AND f.id<>?",
                        user,
                        forward);
        for (var peer : peers) {
            boolean strict =
                    "iptables".equals(peer.get("engine"))
                            && ((Number) peer.get("strict_credit")).intValue() == 1;
            if (incoming && ((Number) peer.get("in_node_id")).longValue() == node) continue;
            if (incoming && !strict || !incoming && strict)
                throw new IllegalArgumentException("同一用户的共享配额不能混用预留额度和旧模式；请先暂停并结算旧转发，再切换模式");
        }
        if (!incoming
                && jdbc.queryForObject(
                                "SELECT COUNT(*) FROM engine_credit_lease WHERE user_id=? AND"
                                        + " closed=0",
                                Integer.class,
                                user)
                        > 0) throw new IllegalArgumentException("该用户仍有未结算的预留额度；请先暂停并结算，再使用旧模式");
    }
}
