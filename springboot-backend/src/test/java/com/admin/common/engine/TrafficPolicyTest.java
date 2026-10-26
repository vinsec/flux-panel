package com.admin.common.engine;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class TrafficPolicyTest {
    @Test void reservationVersionsStayExplicit() {
        for(String version:new String[]{"iptables-v3","iptables-v4","iptables-v5","iptables-v5.1","iptables-v4-test"})assertTrue(EngineCreditService.reservationVersion(version),version);
        for(String version:new String[]{"iptables-v1","iptables-v2","iptables-v6","iptables-v30","gost","iptables-v5unknown"})assertFalse(EngineCreditService.reservationVersion(version),version);
        assertFalse(EngineCreditService.reservationVersion(null));
    }
    @Test void explicitPolicyIsPreserved() {
        String normalized=EngineSpecFactory.normalizeOptions("{\"traffic\":{\"localOutput\":true,\"localTargets\":true,\"sourceMode\":\"preserve\",\"returnPathConfirmed\":true}}");
        assertTrue(normalized.contains("preserve"));
    }
    @Test void rejectsAmbiguousOrContradictoryPolicies() {
        for(String json:new String[]{
            "{\"traffic\":{\"sourceMode\":\"preserve\"}}",
            "{\"traffic\":{\"sourceMode\":\"masquerade\",\"returnPathConfirmed\":true}}",
            "{\"traffic\":{\"localOutput\":\"true\"}}",
            "{\"traffic\":{\"sourceMode\":\"auto\"}}",
            "{\"traffic\":{\"exec\":\"anything\"}}",
            "{\"traffic\":{\"sourceMode\":\"preserve\",\"returnPathConfirmed\":true},\"egress\":{\"interface\":\"eth1\",\"sourceIPv4\":\"192.0.2.1\"}}"
        }) assertThrows(IllegalArgumentException.class,()->EngineSpecFactory.normalizeOptions(json),json);
    }
}
