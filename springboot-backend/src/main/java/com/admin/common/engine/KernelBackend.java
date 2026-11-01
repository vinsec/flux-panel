package com.admin.common.engine;

import com.admin.entity.Node;
import com.alibaba.fastjson.JSONObject;

/** Node-owned backend; tunnels never carry a separate override. */
public final class KernelBackend {
    private KernelBackend() {}

    private static String normalize(String value, String fallback) {
        if (value == null || value.isBlank()) return fallback;
        if (!value.equals("iptables") && !value.equals("nftables"))
            throw new IllegalArgumentException("unsupported kernel backend");
        return value;
    }

    public static String forCreate(String engine, String value) {
        if (!"iptables".equals(EngineRegistry.normalize(engine))) {
            if (value != null && !value.isBlank())
                throw new IllegalArgumentException("GOST 节点不使用内核后端");
            return "iptables"; // Inert DB default; never sent to GOST.
        }
        return normalize(value, "nftables");
    }

    public static String forNode(Node node) {
        if (node == null) throw new IllegalArgumentException("node not found");
        return normalize(node.getKernelBackend(), "iptables");
    }

    public static void validateUpdate(Node node, String requested) {
        // Old clients omit this field. They must preserve existing configuration.
        if (requested == null || requested.isBlank()) return;
        if (!"iptables".equals(EngineRegistry.normalize(node.getEngine())))
            throw new IllegalArgumentException("GOST 节点不使用内核后端");
        if (!forNode(node).equals(normalize(requested, "iptables")))
            throw new IllegalArgumentException("节点内核后端不可原地切换，请新建节点后迁移");
    }

    public static void verifyAgent(Node node, JSONObject info) {
        if (info == null) throw new IllegalStateException("node capabilities unavailable");
        // Pre-native agents did not advertise a backend and used iptables.
        String actual = normalize(info.getString("kernelBackend"), "iptables");
        if (!forNode(node).equals(actual))
            throw new IllegalArgumentException("节点实际内核后端与面板配置不匹配，请检查 Agent 安装配置");
    }
}
