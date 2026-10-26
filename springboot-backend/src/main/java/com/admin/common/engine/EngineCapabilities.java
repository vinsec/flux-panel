package com.admin.common.engine;

import com.admin.common.dto.GostDto;
import com.admin.common.utils.WebSocketServer;
import com.alibaba.fastjson.JSONObject;

import java.util.concurrent.ConcurrentHashMap;

/** Session-scoped advertisement. An old session cannot overwrite a new one. */
public final class EngineCapabilities {
    private record Entry(String session, JSONObject info) {}

    private static final ConcurrentHashMap<Long, Entry> entries = new ConcurrentHashMap<>();

    public static void register(Long node, String session, JSONObject info) {
        if (info == null || info.getJSONObject("capabilities") == null) return;
        entries.put(node, new Entry(session, JSONObject.parseObject(info.toJSONString())));
    }

    public static void remove(Long node, String session) {
        entries.computeIfPresent(node, (n, e) -> e.session().equals(session) ? null : e);
    }

    public static JSONObject info(Long node) {
        Entry e = entries.get(node);
        return e == null ? null : JSONObject.parseObject(e.info().toJSONString());
    }

    public static boolean supports(Long node, String feature) {
        JSONObject i = info(node);
        return i != null
                && i.getJSONObject("capabilities").getJSONObject("features") != null
                && i.getJSONObject("capabilities")
                        .getJSONObject("features")
                        .getBooleanValue(feature);
    }

    public static JSONObject negotiate(Long node) {
        JSONObject current = info(node);
        if (current != null) return current;
        String expectedSession=WebSocketServer.nodeSessionId(node);
        GostDto result = WebSocketServer.send_msg(node, new JSONObject(), "GetCapabilities");
        if ("OK".equals(result.getMsg()) && result.getData() != null) {
            JSONObject value = (JSONObject) JSONObject.toJSON(result.getData());
            String session = WebSocketServer.nodeSessionId(node);
            if (session != null && session.equals(expectedSession)) register(node, session, value);
        }
        return info(node);
    }

    public static void require(Long node, String feature) {
        // Short-lived credentials rotate the socket. Its new EngineHello may
        // still be queued when a batch arrives; negotiate the current session
        // instead of treating a missing advertisement as an unsupported engine.
        if(info(node)==null)negotiate(node);
        if (!supports(node, feature))
            throw new IllegalArgumentException("node does not advertise capability: " + feature);
    }
}
