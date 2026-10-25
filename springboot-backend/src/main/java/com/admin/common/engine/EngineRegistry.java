package com.admin.common.engine;

import com.admin.entity.Node;
import com.admin.mapper.NodeMapper;
import org.springframework.stereotype.Component;
import javax.annotation.PostConstruct;
import javax.annotation.Resource;

/** Legacy static entry points resolve an adapter here; all lifecycle callers use it. */
@Component
public class EngineRegistry {
    @Resource private NodeMapper nodes;
    @Resource private GostForwardingEngine gost;
    @Resource private IptablesForwardingEngine iptables;
    private static EngineRegistry instance;
    @PostConstruct public void init() { instance=this; }
    public static String normalize(String engine) {
        if (engine==null || engine.isBlank()) return "gost";
        if (!engine.equals("gost") && !engine.equals("iptables")) throw new IllegalArgumentException("unsupported forwarding engine");
        return engine;
    }
    public static boolean isIptables(Long id) {
        Node n=instance.nodes.selectById(id);
        return n!=null && "iptables".equals(normalize(n.getEngine()));
    }
    public static ForwardingEngine forNode(Long id) { return isIptables(id) ? instance.iptables : instance.gost; }
}
