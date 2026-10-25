package com.admin.common.engine;

import static org.junit.jupiter.api.Assertions.*;

import com.alibaba.fastjson.JSONObject;

import org.junit.jupiter.api.Test;

class CapabilityTest {
    @Test
    void oldSessionCannotEraseNewAdvertisement() {
        Long node = 91919191L;
        JSONObject info =
                JSONObject.parseObject(
                        "{\"capabilities\":{\"features\":{\"ipv4\":true,\"ipv6\":false}}}");
        EngineCapabilities.register(node, "new", info);
        EngineCapabilities.remove(node, "old");
        assertTrue(EngineCapabilities.supports(node, "ipv4"));
        assertThrows(
                IllegalArgumentException.class, () -> EngineCapabilities.require(node, "ipv6"));
        EngineCapabilities.remove(node, "new");
        assertFalse(EngineCapabilities.supports(node, "ipv4"));
    }
}
